# Bounded native NTFS import

**Update:** [source-atomic admission and owned staging recovery](source-atomic-parser-import.md)
supersede the corresponding shared-path limitations below. Reader-specific
limits and unverified largest-source gates remain unchanged.

MFT and USN now opt into the existing `StreamingParser` import path. Legacy
`Parse` callers keep their existing result shape and event ceilings; normal
imports no longer collect those whole-file results or silently stop at those
legacy event ceilings. SRUM and EVTX are not changed by this work.

## Bounds and contract

- The MFT scanner retains one record and a 4096-entry directory LRU, using
  read-only random access to the same copied MFT. Directory references must
  match both record number and sequence and name a base directory record,
  including the volume root. Reused or missing parents yield explicitly
  incomplete paths, not an invented linkage. Walks are limited to 256 edges.
- MFT keeps the existing 8 GiB input ceiling and per-record name bounds. Its
  streaming slot bound is derived from that byte ceiling and the minimum
  supported 512-byte record stride, replacing the legacy 1,000,000-slot
  retention-era ceiling only in the streaming path. No global process memory
  or time setting is increased. Each eligible base record still yields one
  event per usable recorded SI timestamp; FN timestamps and free-record status
  remain context, not invented deletion instants. Streaming adds physical slot
  offset and stride metadata.
- USN keeps a bounded sliding reader and emits one event per eligible V2/V3
  record. USN/offset, reason mask, sequence references, names, recorded times
  and lack of actor attribution retain their original semantics.
- Both readers use synchronous batches of at most 128 events with positional
  event/raw pairing. Worker framing and ID normalization operate per batch;
  staging is disk-backed. Persistence coalesces native transport batches into
  at most 1024 events and 16 MiB of decoded serialization at a time to amortize
  database commits. It never collects a complete source.
- Native batches use lossless gzip inside framed worker messages and in staging
  files. The existing 1 GiB worker **wire-byte** budget, 1 GiB per-source staging
  **disk-byte** budget, and shared 1 GiB aggregate staging budget are unchanged.
  Compression changes serialized representation, not evidence content. A decoded
  batch has a 16 MiB ceiling as well as the existing encoded-frame ceiling;
  compressed bombs, invalid JSON and bad gzip checksums are refused before a
  batch reaches the sink. SQL keeps its uncompressed serialization and budgets.
- Completed staging closes its descriptor and releases its compression buffers;
  persistence reopens one source reader. Ordinary cancellation and failure paths
  discard staging. These are not crash-recovery guarantees.
- Optional coverage `emitted_events` separates one-to-many output counts from
  `mapped` source-record counts. Without it the historical one-record/one-event
  terminal check remains. A successful terminal must reconcile emitted and
  undated events with received batches, have sufficient read/mapped records,
  and report no failed records, failed chunks or reached limits. Existing
  event/raw cardinality and nonempty matching reference guards remain in force.

## Malformed data and coverage caveats

Streaming MFT refuses malformed slot/header/fixup/attribute/name data rather
than labelling a partial table complete. Partial slots and lossy UTF-16 decoding
are errors. Legacy direct-reader compatibility behavior is unchanged.

The USN scanner historically resynchronizes over sparse/non-record alignment
words. Streaming retains this generic behavior **with explicit source-level
coverage notes**: it counts bytes in nonzero non-record words and records the
first offset. Once framing is lost, a complete bounded V2/V3 layout, valid name
and plausible recorded instant are required to regain it; random words are not
promoted to records merely because a version field looks familiar. At an
established boundary, genuinely missing times remain unmapped, not invented.
Those non-record bytes are not called USN records, nor does an imported source
with those notes claim full byte coverage. A file with no coherent records still
fails, rather than manufacturing an empty activity history. Identifiable
truncated records, invalid filename bounds/UTF-16 and unsupported record versions
fail the source and discard its staged batches. No acquisition bytes are repaired
or rewritten. A non-record suffix is not a decoded record failure; the terminal
failed-record guard has not been relaxed.

MFT and USN dedup identities now include recorded source reference and MFT file
reference, scoped to those artifact types only. Tied timestamps/names and reused
slots no longer collapse distinct observations. Recollection of identical
records still deduplicates while retaining every raw record and observation.
Old cases are not reconstructed or rehashed: use a fresh-case reimport.

## Source-specific coverage and failure (NTFS coverage)

MFT, USN and `$LogFile` sources now persist an `ntfs` object inside
`parse_coverage` (reason classes for unmapped records, empty slots, free
records, attribute-list records, non-record bytes with the first offset, and,
for a failed source, the failure class and byte offset). A failed source keeps
that record, states zero emitted events, and is listed in the report's coverage
diagnostics and limitations with the sentence "this source produced no events;
it is not evidence of no activity". Old imports without it read as "not
recorded". See [ntfs-coverage.md](ntfs-coverage.md) for the fields, the
diagnosis of a failed journal, the second-decoder comparison and the list of
what was not verified. The event ceilings above are still legacy-`Parse`-only:
no triage import path (folder, ZIP, AD1, disk image) reaches them.

## Validation and outstanding gates

Tests cover bounded batches, legacy fidelity, tied-record persistence and
recollection through the isolated worker, source-reference pairing, cancellation,
malformed names/records/frames, decoded expansion, aggregate staging behavior,
physical offsets, sequence-mismatched parents and a sparse synthetic table beyond
the old slot ceiling. Validation outputs, source census scripts, hashes and
measurements are restricted external artifacts, not committed evidence fixtures.

This does not implement source-atomic database persistence, restart cleanup,
durable staging manifests or resumable imports. A persistence failure can leave
partial raw/events/observations and must not label the source imported. SQL
largest-output-budget and crash recovery gates remain unverified. Later
SRUM/diagnostic EVTX streaming is tracked in
[bounded SRUM and EVTX import](bounded-srum-evtx-import.md); neither slice means
completion of item 1. Independent review and parent full-suite acceptance remain
separate gates.
