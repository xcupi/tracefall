# Evidence integrity

Tracefall records a cryptographic hash of every evidence object it
ingests, so that an investigator can later prove the bytes analysed are
the bytes collected. This document states exactly what is hashed, with
which algorithm, and what each value does and does not prove.

## Two hashes, two jobs

A collection carries two independent digests. They are not
interchangeable and neither replaces the other.

| Field | Algorithm | Length | Purpose |
| --- | --- | --- | --- |
| `archive_hash` | SHA-256 | 64 hex chars | Identity for **duplicate detection** |
| `integrity_sha512` | SHA-512 | 128 hex chars | Evidence **integrity attestation** |

`archive_hash` is what the duplicate-evidence check compares, and its
algorithm is deliberately unchanged. Adding SHA-512 did not weaken,
replace, or re-key deduplication — a collection ingested before and
after this change produces the same `archive_hash`.

`integrity_sha512` is the value to quote in a report or hand to another
examiner. SHA-512 is used here because an integrity attestation should
outlive the tool that produced it, and a 512-bit digest leaves more
headroom than the 256-bit identity hash.

### Per-file hashes

Every discovered source file additionally carries its own `sha256`,
computed over that file's own bytes at discovery. This is what makes it
possible to show that parsing did not alter an individual artifact (see
"Parsing never mutates evidence" below).

## What gets hashed

### Uploaded files

For an uploaded archive (ZIP, AD1), both digests are computed over the
**bytes as received**, streamed during the upload itself — before the
archive is opened, validated, or extracted. Hashing the received bytes
rather than the extracted contents means the recorded value covers the
exact object the investigator supplied, including any part of it
Tracefall later refuses to extract.

The upload is hashed once, in a single pass, while it is being written
to disk. There is no second read of the file to hash it.

### Local directories

A directory is not a byte stream, so there is nothing to hash directly.
Tracefall therefore computes a **deterministic digest over the
directory's contents and structure**. `hashDirectory` walks the tree
with `filepath.WalkDir`, which visits entries in **lexical order** — that
ordering is what makes the result deterministic, without an explicit
sort step. Directories themselves are skipped. For every other entry, in
walk order, it feeds into the digest:

1. the entry's path **relative to the collection root**, converted to
   forward slashes so the digest is identical on any host platform,
2. a `NUL` byte,
3. the entry's **contents**, streamed,
4. a `NUL` byte.

Both the SHA-256 and the SHA-512 are computed from this one stream in a
single pass, so a directory's `archive_hash` and `integrity_sha512` are
two digests of exactly the same input.

The `NUL` separators matter: a `NUL` cannot appear in a valid path
component, so no combination of path and content can be re-cut to
produce the same byte stream as a different tree.

Properties this gives:

- **Deterministic.** The same directory always produces the same digest,
  on any platform, regardless of how or when the files were copied
  there.
- **Metadata-independent.** Modification times and permissions are not
  hashed. Two copies of the same evidence hash identically even though
  copying rewrote every mtime.
- **Path-sensitive.** Renaming or moving a file changes the digest,
  because the relative path is part of the hashed stream.
- **Content-sensitive.** Changing one byte of one file changes the
  digest.

Directories contribute nothing of their own, so an empty directory is
invisible to the digest. Non-regular entries are read as whatever
`os.Open` yields for them; symbolic links are followed rather than
hashed as links.

### Segmented AD1 images

A segmented AD1 (`.ad1`, `.ad2`, …) is one logical evidence object split
across several files. Its digests are computed across **every segment's
raw bytes, concatenated in segment order**, as one continuous stream —
so the hash covers the whole image rather than each part separately.
Segments are streamed, never buffered, because an AD1 image can be far
larger than available memory.

Re-hashing requires the same segments in the same order. A missing or
reordered segment produces a different digest, which is the intended
behaviour: it is a different evidence object.

### What the directory digest does not prove

It is a digest of the *contents of the files Tracefall could read*, at
the moment it read them. It is not a signature, it is not timestamped by
a third party, and it does not prove the directory was unmodified before
Tracefall saw it. It proves that two Tracefall runs saw the same bytes
under the same relative paths.

It is also not comparable to a digest of an archive of the same files: a
ZIP of a directory hashes the archive's bytes, while the directory
hashes this constructed stream. The two will never match, and are not
meant to.

## Parsing never mutates evidence

Integrity hashing would be worthless if analysis changed the files.
Every parser reads evidence read-only, and one case required specific
handling:

**Browser history databases are copied before being opened.** A browser
history file is a live SQLite database. Opening it with a SQLite driver
— even read-only — can cause the engine to checkpoint and **delete** a
hot `-wal` sidecar, which changes the evidence on disk. Tracefall
therefore copies the database and its `-wal`, `-shm` and `-journal`
sidecars into a scratch directory and opens the copy. The originals are
never opened by SQLite.

This is enforced by a regression test that hashes the evidence before
and after parsing and fails if the digest changes.

## Where it appears in the UI

A collection's SHA-512 is shown in the **Evidence integrity & metadata**
panel of its collection card. Because a 128-character hash is unreadable
inline, it is displayed truncated to the first 32 characters, with the
complete value available three ways:

- the element's `title` attribute (hover),
- **Show full**, which expands it in place,
- **Copy**, which always copies the **complete** digest.

Truncation is display-only. What gets copied is never the truncated
form — a partially copied hash is worse than no hash at all.

Tracefall is commonly reached over plain HTTP on a LAN, where the async
clipboard API is unavailable. The copy control falls back to
`execCommand`, and if that also fails, expands the hash and selects it
so that Ctrl+C copies the full value, reporting `Selected - press
Ctrl+C` rather than asking the investigator to copy nothing.

## Verifying integrity later

Phase 11 added an explicit **Verify Integrity** action that recomputes a
collection's SHA-512 and compares it with the digest recorded here at
ingestion. It re-uses the exact functions documented above — the same
upload-bytes, AD1-segment and directory-stream semantics — rather than a
second implementation that could canonicalize differently.

Verification is read-only and never rewrites the recorded digest, which
is the historical fact it exists to check. See
[provenance-and-custody.md](provenance-and-custody.md) for the three
outcomes it distinguishes (`verified` / `mismatch` / `unavailable`), why
"could not check" is kept separate from "changed", and what a mismatch
does and does not prove.

## Collections ingested before integrity hashing

`integrity_sha512` was added in Phase 10A. Collections ingested by an
earlier build have no value for it, and the UI says so explicitly:

> Not recorded (collection predates integrity hashing)

Tracefall does **not** backfill the hash by re-reading the evidence.
Doing so would compute a digest for whatever the files contain *now* and
present it as if it attested to what was collected *then* — which is
exactly the claim an integrity hash is supposed to make and exactly the
claim that backfilling cannot support.
