# Adding a new artifact parser

Tracefall's parser architecture is designed so that adding support for a
new KAPE artifact never requires changing ingestion, normalization's
shared helpers, detection, correlation, storage, or the API. This
document walks through the interface and how to add one.

## The `ArtifactParser` interface

Defined in [`internal/parsers/parser.go`](../internal/parsers/parser.go):

```go
type ArtifactParser interface {
	Name() string                        // e.g. "evtxcsv@1"
	ArtifactType() string                // a model.Artifact* constant
	Detect(relPath string) bool          // filename/path pattern match
	Parse(absPath string) (ParseResult, error)
}

type ParseResult struct {
	Events []model.Event       // CaseID/SourceFileID/ID left blank -- ingestion fills them in
	Raw    []model.RawEvidence // Raw[i] is the untouched source record for Events[i]
}
```

`internal/ingest.Registry()` returns the ordered list of known parsers.
`internal/ingest.Walk` walks the evidence directory, and for each file,
tries each registered parser's `Detect` in order (first match wins) and
calls its `Parse` if matched. Unmatched files are recorded in
`Result.Skipped`, not treated as an error — a real KAPE package routinely
contains far more files than Tracefall has parsers for.

## Existing parsers, as a reference

| Package | Artifact | Format consumed | Why |
|---|---|---|---|
| `internal/parsers/evtxcsv` | Windows Event Logs (Security 4624/4625/4688, PowerShell 4104, Sysmon Network Connect 3) | EvtxECmd CSV | see ARCHITECTURE.md's "why CSV, not raw binary formats" |
| `internal/parsers/pecmd` | Prefetch | PECmd CSV | same |
| `internal/parsers/recmd` | Registry Run keys | RECmd batch CSV | same |
| `internal/parsers/scheduledtasks` | Scheduled Tasks | raw Task Scheduler XML (UTF-16LE) | KAPE collects this directly; simple enough to parse natively |
| `internal/parsers/browsercache` | Browser cache entries | Chromium Simple Cache and blockfile `data_1`; Firefox cache2 and cache1 `_CACHE_00x_` | four generations, one artifact type -- the claim is identical, the layout is not |
| `internal/parsers/browsercacheindex` | Browser cache containers | Chromium blockfile `index`; Firefox `_CACHE_MAP_` | a *different artifact type*: containers hold no cache keys, so they yield no URLs and no events |
| `internal/parsers/lnk` | Windows shortcuts | Shell Link Binary File Format | one event per recorded target timestamp; content-only detection |
| `internal/parsers/recyclebin` | Recycle Bin `$I` records | versions 1 and 2 | content-only detection; the paired `$R` file is stat'd, never read |
| `internal/parsers/recyclebincontent` | Recycle Bin `$R` content | the deleted file's bytes | the only parser that reads a SECOND file: a `$R` is meaningless without its `$I` |
| `internal/parsers/jumplist` | Jump Lists | OLE compound files and concatenated shell links | TWO parsers in one package, over `internal/olecf` and `internal/shelllink` -- nothing about either format is reimplemented |

**Two parsers must not share a `Name()`.** Import re-resolves a file's
parser by name (`api.findParserFor`), so two parsers reporting the same
name send every file to whichever registered first. The Jump List
parsers learned this the hard way: every Custom Destinations file was
handed to the Automatic parser and refused for having the wrong
container.

**`FilePath` is part of an event's dedup identity**
(`model.Event.ComputeDedupHash`). A parser that emits several events per
file must put something DISTINGUISHING there -- the target, not the
artifact -- or two events sharing a timestamp will collapse into one and
lose evidence.

Those last two are the reference for three patterns worth copying:

**One file, many events.** `browsercache` returns one `model.Event` per
record found in a `data_1` or `_CACHE_00x_` file, plus a single
`browsercache:parse-report` raw record carrying blocks scanned, entries
emitted, and entries skipped by reason. A parse report is how a
zero-entry file stays distinguishable from a failed one -- ingestion
carries raw records that have no matching event, so a report survives
even when the file produced nothing.

**Two parsers, two artifact types, one reader package.** `ArtifactType()`
returns a single constant, so evidence that deserves its own capability
row needs its own parser. Both of these are thin wrappers over
`internal/browsercache`; the format knowledge lives in one place and
neither parser can claim the other's file.

**Filename detection, when and only when the format leaves no choice.**
`browsercache.Detect` matches exactly three names -- `_CACHE_001_`,
`_CACHE_002_`, `_CACHE_003_` -- because those files open with a 4096-byte
allocation bitmap and put no signature in the 512-byte sniff window.
Everything else it reads is content-detected. If you find yourself
matching a name, say in a comment why the structure could not be used.

`evtxcsv` is the most instructive example of the "one parser, several
event types" pattern: EvtxECmd's CSV shape is identical regardless of
channel/EventID, so one parser dispatches on `(Channel, EventId)` inside
`toEvent` to produce different `model.Event` shapes. Extending coverage
to another channel/EventID pair already-parsed by EvtxECmd (e.g. Sysmon
Process Create, Event ID 1) is a new `case` in that switch, not a new
parser package.

## Step by step: adding a new parser

1. **Create a package** under `internal/parsers/<name>/`.
2. **Pick a `Name()`** of the form `<tool>@<version>`, e.g. `amcache@1`.
   Bump the version suffix if you ever change what fields a given input
   shape produces — it's stored on every `Event`/`SourceFile` for
   provenance, and an investigator (or a future you) may need to know
   "was this event produced before or after the parser's field mapping
   changed."
3. **Pick or add a `model.ArtifactType`** constant in `internal/model/model.go`
   if this is a genuinely new artifact type.
4. **Write `Detect`**. Match on filename/path patterns, following the
   existing parsers' convention (case-insensitive, checking the tool
   name and file extension). Don't content-sniff — KAPE/EZ Tools output
   naming is predictable and documented, and content-sniffing is slower
   and easier to get subtly wrong across encodings.
5. **Write `Parse`**. Read the file, and for each record:
   - Parse the timestamp with `normalize.Timestamp` — if it fails, skip
     the record rather than fabricating a time (an unplaceable event
     would corrupt the timeline and any temporal correlation).
   - Map artifact-specific fields to `model.Event`'s common fields
     (`process_name` via `normalize.ProcessName` for a bare path, or
     `normalize.ExecutableFromCommandLine` for a string that may include
     arguments — see [data-model.md](data-model.md) for the distinction and
     the regression it exists to prevent).
   - Put anything that doesn't have a first-class `Event` field into
     `Extra`, with a short, documented snake_case key.
   - Set `ArtifactType`, `Parser`, and a `Confidence` reflecting how much
     you trust the field mapping (`1.0` for an unambiguous field like a
     registry value; lower, with a comment explaining why, for something
     like Prefetch's `LastRun`, which only approximates actual execution
     time).
   - Append the exact original record (JSON-encoded) to `ParseResult.Raw`,
     index-aligned with `ParseResult.Events` — this is what makes the
     provenance chain (see [data-model.md](data-model.md)) work; never
     skip it.
6. **Register it** in `internal/ingest.Registry()`.
7. **Write tests** in `<name>_test.go`: at least one `Detect` test with
   both a matching and non-matching path, and one `Parse` test against a
   small inline fixture asserting the resulting `Event` fields. See
   `internal/parsers/evtxcsv/evtxcsv_test.go` for the fullest example,
   including a regression test for a real bug this codebase hit (a raw
   Windows path containing spaces, like `C:\Program Files\...`, must not
   be naively space-split when extracting the executable name).
8. **If you're adding a genuinely new binary format parser** (raw
   `.evtx`, raw Prefetch, a raw registry hive) instead of consuming a
   companion tool's CSV, keep the binary-decoding logic isolated inside
   that parser package — nothing else in Tracefall should need to know
   the raw format exists. `internal/parsers/scheduledtasks`'s UTF-16
   decoding (`decodeUTF16`) is the existing example of self-contained
   binary/encoding handling inside a parser package.

## Making a new parser's events findable

Nothing extra is required. The forensic timeline
([docs/forensic-search.md](forensic-search.md)) queries the `events`
table directly, and its filter dropdowns are built from the values a case
actually contains, so a new parser's artifact type and event types appear
as filter options as soon as the first file is imported.

Two things are worth getting right so the events are searchable by what
an analyst would actually type:

- **Put values in typed columns where one exists.** `file_path`,
  `process_name`, `command_line`, `network_dest` and the rest are what
  free-text search and the field-scoped filters read.
- **If a value has no typed column, check whether its `extra` key is one
  free-text search already covers** — `url`, `page_title`,
  `original_path`, `original_name`, `target_path`, `file_name`,
  `application`, `executable_name`, `content_type`. Reusing an existing
  key makes the value searchable immediately. Introducing a new key that
  ought to be searchable means adding it to `freeTextJSONKeys` in
  `internal/store/eventquery.go` AND to the table in
  docs/forensic-search.md — a test fails if the two disagree.

### Reading several artifacts out of one file

Discovery assigns **exactly one parser per evidence file**, so a
container that holds more than one artifact must be read by the parser
that claims it. A registry hive is the standing example: `NTUSER.DAT`
carries persistence values, UserAssist, ShellBags and five MRU
structures, and `Amcache.hve` carries the application inventory — all
read by `internal/parsers/registry`.

Adding a competing parser for such a file does not work: the first
match wins, and the loser never runs.

The EVENTS still carry their own artifact types. Implement the optional
`parsers.EventArtifactTypeSource` interface to declare them:

```go
func (Parser) EventArtifactTypes() []string {
    return []string{model.ArtifactUserAssist, model.ArtifactAmcache}
}
```

That tells the capability registry those types are supported, so they
get real labels and priorities instead of a generated fallback. The
FILE's classification is unchanged — an `Amcache.hve` is still reported
as the registry hive it is, which is what was collected and hashed.

### A filename match that needs confirming

`Detect(relPath)` sees only a path. When the name a parser matches is
also an ordinary word — `SAM`, `SYSTEM`, `NTUSER.DAT` — a name match
alone will claim files that are not the artifact at all, mark them
supported, and then fail at import. That reports *"your hive is
corrupt"* about a file that was never a hive.

Implement the optional `parsers.ContentConfirmer` so the name match has
to be backed by the bytes:

```go
func (Parser) ConfirmContent(header []byte) bool { return regf.Sniff(header) }
```

Discovery then returns a refused file to content-based detection, and if
nothing claims it there it is reported as **unrecognized** — which is
what it is. A parser whose filenames are produced by a tool (the EZ
Tools CSVs) should NOT implement this: those names really are proof.

### A content detector that is too broad on its own

`ContentConfirmer`'s mirror image. A signature can identify a **format**
correctly and still be the wrong answer about the **artifact**.

A JPEG signature says "this is a picture" and nothing more, so the image
parser's content detector claims every JPEG in a collection — including
the cached response bodies inside a Chromium cache directory, 84 of them
on one real image. Those really are JPEGs. They are also already
correctly catalogued as browser-cache evidence, and reclassifying them
lost the context that made them meaningful.

Implement the optional `parsers.PathScopedDetector` to say where your
content detection should be consulted at all:

```go
func (Parser) DetectPath(relPath string) bool {
	return !browsercache.InCacheDirectory("/" + strings.ToLower(relPath))
}
```

Returning `false` skips `DetectContent` for that file and leaves it to
whatever else claims or recognizes it. Returning `true` means *"ask the
bytes"* — never *"this is the artifact"*. A parser that does not
implement it is consulted for every file, exactly as before.

Reach for this only when your detector really is that broad. A parser
with a distinctive magic number does not need it.

### A parser that needs a DIFFERENT file

Parsing is file-local by design, and one artifact genuinely is not: a
SAM hive's NT hashes are encrypted under a key stored in the SYSTEM
hive. Implement `parsers.ContextualParser` and read what you need from
`parsers.ParseContext`, which the import prepares **once per collection**
before any file is parsed.

Do not go looking on the filesystem for a sibling file. That was tried
and it is wrong for AD1 images, where entries are materialized one at a
time immediately before each is parsed — the SAM parser was scanning a
directory the SYSTEM hive had not been written into yet, and reporting
every hash as undecodable while the hive sat in the same collection.
Anything a parser needs from outside its own file belongs in
`ParseContext`, derived where the whole collection is in view.

The zero `ParseContext` must always be handled: it means "no context
available", and the parser still has to produce its best honest answer.

### Reading credential material

If a parser can extract credential material — `internal/parsers/registry`
does, from the SAM hive — three rules apply, and the SAM tests in
`internal/api/sam_integration_test.go` enforce all three:

1. Keep it out of the **free-text search index**. `freeTextJSONKeys` is
   an allowlist; do not add a credential key to it. Search must not
   become a way to confirm a secret by guessing it.
2. Keep it out of the **Detail column**, timeline rows, URLs and logs.
   It belongs in the event's own detail view, with its own label.
3. Never let its mere existence become a **finding** or a
   **correlation**. Every Windows machine has account hashes; alerting
   on that buries the alerts that matter.

And extract only. Tracefall does not crack, and a parser must not turn
a hash back into anything.

### Enumerating a wide key

Use `regf.Hive.ChildKeys` to read a key's children, not `Subkeys`
followed by `OpenKey` on each name. `OpenKey` restarts at the hive root
and scans siblings at every level, so the second pattern is quadratic:
on a 20,000-entry Amcache inventory it was measured at **9 minutes and
30 GiB of allocation**, against 1.7 seconds and 226 MiB with
`ChildKeys`.

A parser that deliberately produces no events (see the `$LogFile` and
Recycle Bin `$R` parsers) needs nothing here, but should say so in its
package comment: docs/forensic-search.md lists those cases explicitly so
an analyst does not read "no events" as "nothing was found".

## When one file holds several artifacts

Discovery assigns exactly ONE parser per evidence file, so a container
that holds more than one artifact cannot be split across parsers -- a
second parser for the same file would simply never run. An `NTUSER.DAT`
is the worked example: it is a registry hive, and it also holds
UserAssist entries and a ShellBags tree.

The pattern, implemented in `internal/parsers/registry`:

- The parser claims the FILE and keeps the file's own artifact type.
  That is what was collected, hashed and attested.
- Its EVENTS carry their own `ArtifactType`, because an analyst
  filtering a timeline is asking what an observation IS, not where it
  was stored.
- The parser implements `parsers.EventArtifactTypeSource` to declare
  those extra types, which is what makes the capability registry list
  them as supported with real labels and priorities.

Reach for this only when the structures are genuinely different
artifacts with different forensic meaning. Emitting several event TYPES
from one artifact type is the ordinary case and needs none of it.

## Say what the artifact proves

Windows artifacts differ enormously in evidentiary strength, and the
event model carries that distinction in three places. Fill all three:

- The **event type** names what the artifact records
  (`userassist_activity`, not `process_create`).
- **`evidence_meaning`** states what the artifact does and does not
  establish, in a sentence an analyst can quote.
- **`timestamp_meaning`** states what the time IS. Where the artifact
  records no time, leave `Timestamp` zero and set `timestamp_basis` --
  never substitute the file's mtime, the key's last-write time, or any
  other surrogate.

`ProcessName` and `CommandLine` assert that a process existed. Do not
populate them from an artifact that does not record one. See
docs/windows-artifacts.md for how each existing artifact is placed.

## Regenerating or extending the synthetic test dataset

`testdata/synthetic_case` is a hand-built, **clearly synthetic — not
real** — evidence package resembling KAPE + `!EZParser` output, covering
a representative attack-like sequence (phishing document → Office →
PowerShell → payload → persistence via both a registry Run key and a
scheduled task → outbound connection), plus an unrelated brute-force
sub-plot. It exists so the full pipeline can be exercised without a real
forensic image, and the same ingestion/parsing/detection/correlation code
path processes it exactly as it would real evidence — nothing in the
pipeline branches on "is this synthetic."

If you add a new parser and want to extend the synthetic dataset to cover
it, add the new source file(s) under `testdata/synthetic_case/<Tool>/`
following the existing files' shape, and extend
`internal/ingest.TestWalk_SyntheticCase` and
`internal/api.TestEndToEnd_SyntheticCase`'s assertions (source file
count, event count) to match. Keep the dataset's own internal narrative
consistent (same host, same timestamps for a given step) if the new
artifact type ties into the existing attack-chain story — that's what
lets `internal/correlate`'s activity-chain reconstruction keep working
end-to-end.
