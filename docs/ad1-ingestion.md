# AD1 forensic image ingestion (Phase 7)

Native support for ingesting an AccessData Logical Image (AD1) -- the
proprietary container FTK Imager writes for a "Custom Content"/logical
(file-level, not full-disk) acquisition -- into Tracefall's existing
Discover → Select → Import evidence workflow. This document records why
the format could be supported at all, and the design decisions made
along the way; see each package's own doc comments for the mechanics.

## Was this safe to implement at all?

AD1 has **no official published specification** -- AccessData/Exterro
has never released one. Before writing a single line of the parser, this
phase's own instructions required determining whether native, safe
parsing was actually achievable, or whether the right outcome was to
stop and report a blocker instead of guessing at an undocumented binary
format.

The answer turned out to be yes, on the strength of an actively
maintained, professionally-run reference implementation:
[`dissect.evidence`](https://github.com/fox-it/dissect.evidence) (Fox-IT,
part of NCC Group), which ships a byte-accurate, tested AD1v4 reader as
part of real incident-response tooling, cross-referenced against
[`pyad1`](https://github.com/pcbje/pyad1) (an earlier independent
reverse-engineering effort) and
[`AD1-tools`](https://github.com/al3ks1s/AD1-tools). That gave a verified
structural understanding (magic bytes, segment/logical-image headers, the
FileEntry tree, the FileMeta linked list, the zlib chunk layout,
ADCRYPT's encryption marker) confident enough to port -- not guess at --
into a native Go implementation.

No Go library for AD1 exists (the only implementations found were
Python, and one C/CLI tool), and none was needed: [`internal/ad1`](../internal/ad1)
is a from-scratch, pure-Go, read-only parser with **zero new
dependencies** in `go.mod`. `internal/ad1/ad1gen` is a from-scratch,
pure-Go **writer** used only to build test fixtures (see "Testing"
below) -- Tracefall never emits AD1 files as part of real ingestion.

Two things are explicitly and deliberately *not* implemented, both
correctly reported as clear errors (never silently treated as an empty
or valid image -- see `internal/ad1`'s sentinel errors):

- **ADCRYPT-encrypted containers.** Decrypting one needs a passphrase or
  private key from the investigator, which is real added scope (a
  credential-entry UI, key material handling) out of bounds for this
  phase. Detected immediately (`internal/ad1.ErrEncrypted`) from the
  first 8 bytes, before any other parsing is attempted.
- **AD1v3.** The reference implementation itself only documents/tests
  v4 (FTK Imager's version for years); v3's tail-of-header layout isn't
  verified anywhere available. Reported as
  `internal/ad1.ErrUnsupportedVersion` rather than parsed against a
  guessed layout.

## Architecture: extend, don't replace

The explicit instruction for this phase was to extend Tracefall's
existing two-phase Discover → Select → Import workflow, not build a
parallel pipeline. Concretely:

```
AD1 (upload or local path)
  → internal/ad1.Open + Walk           (cheap: headers + small metadata only, no decompression)
  → internal/api.catalogAD1            (turns each ad1.Entry into a model.SourceFile row)
  → investigator selects files in the SAME evidence-selection UI
  → internal/api.ImportEvidence's existing loop, +1 adapter:
      extractAD1Entry materializes exactly the selected file's bytes
      under the collection's EvidenceDirectory, THEN
  → internal/ingest.ParseFile (completely unmodified -- it just opens
    a real file on disk, has no idea it came from an AD1)
  → Event → Detect → Correlate → Investigate (all completely unmodified)
```

`internal/ingest.ParseFile`, `internal/detect`, `internal/correlate`, and
`internal/investigate` were **not touched**. The only new integration
code is in `internal/api/ad1.go` (the adapter layer) and small,
additive changes to `internal/api/service.go` (format-sniffing dispatch
in `DiscoverEvidenceFromUpload`/`DiscoverEvidenceFromPath`, the
extraction call in `ImportEvidence`, and one line in `DeleteSourceFiles`'
on-disk cleanup condition).

## Evidence model: Collection = container, SourceFile = child

Requirement: extend the existing source-file/collection model only where
necessary, and document the decision. Tracefall's existing
`Collection`/`SourceFile` pair (one `Collection` row per
"independent evidence-gathering event," many `SourceFile` rows for the
files inside it) already matches AD1's actual shape almost exactly --
one AD1 image, containing many files:

- **One `Collection` row** per AD1 image. `SourceType` gets a new value,
  `model.SourceTypeAD1`. `ArchiveHash` is the AD1's own real SHA-256
  (computed by hashing the raw file(s), streamed, never loaded into
  memory in full). `EvidenceDirectory` is a Tracefall-managed directory
  where **selected** files get extracted lazily on import -- never the
  AD1's own location.
- **One `SourceFile` row per file inside it**, `Path` set to the file's
  path exactly as found inside the AD1 (e.g.
  `Users/jdoe/AppData/Local/Temp/update.exe`) -- this is what answers
  "which file/path inside the AD1 produced this event," together with
  the collection's `ArchiveHash`/`OriginalFilename` answering "which
  AD1." No new provenance concept was needed; `Event.SourceFileID` /
  `EventObservation` already carry this the same way they do for a
  ZIP-sourced file.

One schema addition was needed: `source_files.embedded_hash` (a single
new column, migrated via the existing `addColumnIfMissing` pattern) --
see "Hashes" below for why.

### Why `SourceType` describes format, not delivery mechanism

Every other `SourceType` value describes *how the evidence arrived*
(`kape_upload` vs `local_path`). AD1 breaks that pattern on purpose:
whether an AD1 image was uploaded through the browser or pointed at via
a local path, it behaves identically after discovery (lazy per-file
extraction, same catalog shape, same "AD1 Forensic Image" label) -- the
interesting fact about an AD1 collection is what it *is*, not how it got
here. Preserving the delivery-mechanism distinction as well would have
meant either a second field nobody reads, or overloading `SourceType`
with a second axis of meaning. Collapsing it into one value was the
simpler, equally-truthful choice; the audit log's summary text still
says "uploaded" vs "from local path" for anyone who wants that detail.

`Collection.OriginalFilename` is display-only for an AD1 collection
(e.g. `"DiskDrigger.ad1"`, the investigator's own upload filename) --
**never** used to locate the container on disk. An uploaded AD1's actual
bytes always live at the deterministic path
`casefiles.Store.AD1Path(caseID, collectionID)`;
`ad1SegmentPathsForCollection` checks that path first, and only falls
back to treating `OriginalFilename` as a real filesystem path for a
local-path collection (where it genuinely is one, and is never copied --
Tracefall does not take ownership of an investigator's own files, the
same rule the existing local-path ZIP-less flow already follows).

## Hashes: reported vs. verified, and why discovery leaves SHA-256 blank

Requirement 3 asks for "hash where reasonably available" during
discovery; requirement 8 says discovery must stay cheap and must not
decompress every file up front. Those pull in opposite directions for
AD1 specifically, in a way they don't for a ZIP:

- For a ZIP/local-path collection, `ingest.Discover` computes a real
  SHA-256 for free -- the whole archive was already extracted to disk as
  a normal file *before* discovery runs, so hashing it is a cheap
  sequential disk read.
- For AD1, nothing is extracted during discovery (by design -- see
  below). Computing a true SHA-256 would mean decompressing every file's
  zlib chunks just to catalog it, exactly the "don't parse every file
  during discovery" cost this phase explicitly rules out.

So: **`SourceFile.SHA256` is left blank at AD1 discovery time**, and only
populated once a file is actually selected and imported (`extractAD1Entry`
computes it in the same pass that writes the extracted bytes to disk --
free, not a second read). Separately, AD1 itself sometimes records an
MD5 or SHA-1 for a file as acquisition-time metadata (only if FTK
Imager was configured to compute one -- often absent). That's free to
read (it's a small metadata item, not file content) and is surfaced
immediately, in a **new, clearly separate** field,
`SourceFile.EmbeddedHash` (format `"algo:hexdigest"`, e.g.
`"sha1:abc123..."`). It is deliberately never merged into `SHA256`:
that field means "Tracefall itself computed this from the actual bytes,"
and conflating a hash AD1 merely *reported* with one Tracefall
*verified* would be a real, if subtle, provenance mistake in a tool
whose whole value proposition rests on that distinction being
trustworthy. The UI shows `EmbeddedHash` labeled "(as reported by AD1,
not yet independently verified)" wherever `SHA256` isn't yet known.

One consequence: intra-batch duplicate-content detection during AD1
discovery (`catalogAD1`) can only catch two files sharing an
*embedded* hash -- weaker than the ZIP path's guarantee (which always has
a real SHA-256 to compare). Two AD1 entries with identical content but no
embedded hash will both be marked importable; if both are actually
imported, the existing file-level dedup constraint
(`idx_source_files_collection_sha256_active`, keyed on Tracefall's own
SHA-256, computed at import time) still catches it -- see "Bug found"
below for why `ImportEvidence` had to change to handle that gracefully
instead of failing the whole request.

## Performance: discovery reads headers, never file content

`internal/ad1.Container.Walk` reads each entry's fixed-size header plus
its (typically tens-of-bytes) metadata items -- it never touches the
zlib-compressed file content, so cataloging a large image costs roughly
one small read per file/directory, not one decompression pass. Bounded
resource limits (`internal/ad1.Limits`, mirroring
`internal/archive.Limits`'s existing role for ZIP) cap entries visited,
name/metadata/path lengths, and per-file decompressed output during
`Extract` -- see that type's doc comment for the exact defaults and the
reasoning (including how a hard entry-count cap is what makes a
corrupt/hostile `next`/`child` pointer cycle fail closed instead of
looping forever, since every dereference -- cyclic or not -- counts
against the same cap).

Only files the investigator actually selects in "Import Selected" are
ever decompressed (`extractAD1Entry`, called once per selected file
inside `ImportEvidence`'s existing loop) -- an image with 100,000 files
where only 5 are selected only ever decompresses those 5.

## Segmented images: full support locally, a clear limit on upload

A real AD1 acquisition can be split into numbered segments
(`.ad1`, `.ad2`, `.ad3`, ...). Tracefall's browser upload is a single
multipart file, so uploading only the first segment of a segmented image
is detected (the segment header declares the true segment count) and
rejected with a clear, actionable error --
`internal/ad1.ErrSegmentsMissing` -- rather than silently cataloging
whatever happens to fit in segment 1. A **local-path** discovery, which
already has full filesystem access, automatically locates and opens
every sibling segment (`internal/ad1.FindSiblingSegments`, matching by
stem + `.adN` extension) and catalogs the complete image.

## Security controls

- **Read-only, always.** Every segment file is opened `O_RDONLY`.
  Nothing in `internal/ad1` ever writes to, truncates, or renames a
  segment file. A local-path AD1's original file(s) are never copied,
  moved, or modified; an uploaded AD1's staged copy is the *only* copy
  Tracefall writes anywhere, in a case-scoped directory it fully owns.
- **Path traversal.** Every `FileEntry.name` is validated
  (`internal/ad1.validateEntryName`) to be exactly one plain path
  component -- empty, `.`, `..`, or containing a `/`, `\`, or NUL byte is
  rejected and fails the whole walk closed. A second, independent check
  happens where extraction actually touches disk
  (`internal/api.extractAD1Entry`, mirroring `internal/archive.safeJoin`'s
  belt-and-suspenders pattern) verifying the resolved destination stays
  inside the collection's `EvidenceDirectory`. Covered by both a unit
  test (`internal/ad1`) and an end-to-end test through the real upload
  path (`internal/api`).
- **Resource limits.** See "Performance" above --
  `internal/ad1.DefaultLimits` bounds entries visited, name/metadata/path
  lengths, and per-file decompressed size; a metadata chain has its own,
  much smaller cap (`maxMetaChainItems`) so a single hostile entry can't
  multiply cost by the whole-tree limit.
- **No uncontrolled temp files.** Discovery writes nothing to disk at
  all beyond the (already-existing, generic) multipart-upload staging
  file, which is either renamed into the collection's directory on
  success or removed on failure -- exactly the same lifecycle the ZIP
  path already has. Extraction writes only the specific file(s) selected
  for import, directly into the collection's own managed directory.
- **Case/evidence isolation.** Unchanged: every AD1-derived
  `Collection`/`SourceFile`/`Event` carries the same `CaseID` scoping
  every other evidence source already has, enforced the same way.
  Deleting one imported AD1-sourced file removes only its own
  contribution (events with no surviving observation) and its own
  extracted copy on disk, never a sibling's.

## Deletion semantics

There is no separate "delete the whole AD1 container" operation --
matching every other evidence source, an investigator deletes individual
imported files (or bulk-deletes a selection). Deleting an AD1-sourced
file's on-disk extracted copy is handled by `DeleteSourceFiles`'
existing cleanup path, extended to also cover `SourceTypeAD1` collections
(previously that cleanup only ran for `SourceTypeUpload`) -- an AD1
collection's `EvidenceDirectory` is always Tracefall's own managed
extraction destination, regardless of whether the AD1 arrived by upload
or local path, so it's always safe to remove a deleted file's extracted
copy from it (unlike a non-AD1 local-path collection, whose
`EvidenceDirectory` is the investigator's own folder, which Tracefall
must never write into or delete from).

## Bug found and fixed while integration-testing this

`ImportEvidence`'s per-file loop treated *any* error from
`Store.MarkSourceFileImported` as fatal to the whole request (a 500,
aborting every other file in the batch). For a ZIP/local-path collection
this essentially never fires, because discovery-time SHA-256-based
dedup already prevents two same-content files from both being
selectable. AD1's weaker discovery-time dedup (see "Hashes" above) made
this reachable in an ordinary case (two different AD1 paths, identical
content, neither embeds a hash) -- surfacing a real, if latent,
robustness gap. Fixed by catching `store.ErrDuplicateSourceFile`
specifically and skipping just that one file (added to `ImportResult.Skipped`
with a clear reason), matching how "already imported"/"not found"/
"unsupported" are already handled per-file rather than as whole-request
failures. Covered by `TestAD1_DuplicateContentWithinOneImage` and the
sibling-content setup in `TestAD1_DeletingOneArtifactDoesNotAffectSiblings`.

## Testing

- `internal/ad1/ad1_test.go` -- unit tests against synthetic AD1v4
  images built by `internal/ad1/ad1gen` (a small, from-scratch, pure-Go
  AD1 *writer*, used only for tests/fixtures -- see that package's doc
  comment on why it's never part of real ingestion): magic detection,
  ADCRYPT/version/corruption/truncation rejection, empty images, nested
  paths, chunked extraction across multiple zlib chunks, embedded-hash
  surfacing, the raw-size fallback, segmented-image validation, the
  entry-count and per-file-size limits, `EntryType.Deleted` entries
  staying visible (never silently dropped), and the path-traversal
  defense.
- `internal/api/ad1_test.go` -- integration tests through the real HTTP
  API: detection and cataloging, nested paths, empty/corrupt/encrypted/
  segmented-upload error handling, partial selection, the complete
  provenance chain (case → AD1 → file → event → finding → investigation)
  driven through the **unmodified** detect/correlate/investigate
  pipeline, sibling-safe single and bulk deletion, duplicate-content
  handling, case isolation (including a cross-case import attempt),
  the path-traversal defense exercised through the real upload endpoint,
  and local-path discovery (including a check that the original file's
  bytes are untouched afterward).
- `testdata/ad1_samples/DiskDrigger.ad1` -- a checked-in, byte-valid
  AD1v4 image (built by the same `ad1gen` package, so there is one
  source of truth for what it contains) used for browser verification --
  see that directory's `README.md`.

## Known limitations

- ADCRYPT-encrypted images and AD1v3 are detected and clearly rejected,
  not supported (see "Was this safe to implement at all?" above).
- A segmented AD1 can only be ingested via local path, not browser
  upload (see "Segmented images" above).
- AD1 metadata attributes beyond size/timestamps/MD5/SHA1 (NTFS
  attributes, ACLs, MFT record numbers, alternate data streams, reparse
  points/symlinks) are not read or exposed -- out of scope for a
  file-catalog-and-import workflow; see `internal/ad1`'s package doc
  comment.
- Intra-batch duplicate-content detection during discovery only catches
  files AD1 itself hashed (see "Hashes" above); true content duplicates
  are still caught at import time, just with a per-file skip instead of
  an earlier discovery-time flag.
- The "Custom Content Image([Multi])" multi-source root-name convention
  (a small set of unrelated logical images bundled into one AD1) is
  presented with a flat root label rather than re-split per source --
  correct and non-lossy (every file is still cataloged, just under one
  root name), just less polished for that specific, uncommon case.
