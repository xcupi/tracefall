# Bounded SRUM and EVTX import

SRUM and native EVTX now implement `StreamingParser`. Imports automatically use
that path through the existing isolated-worker, normalization, staging, host
census and bounded-persistence pipeline. Legacy `Parse` callers retain the
whole-result API and its historical ceilings/recovery behavior.

## SRUM

- ESE provider rows are already scanned through callbacks. The import path now
  emits synchronous batches of at most 128 paired events/raw records rather
  than retaining every event. It does not apply the legacy five-million-event
  retention ceiling. The existing 8 GiB source ceiling remains.
- The complete ID map is indexed in a disposable SQLite file in an owner-only
  directory, with a 4 MiB SQLite page-cache target, memory mapping disabled and
  a 1 GiB database page ceiling. Only the two identities needed by the current
  provider row are retained in the lookup map. Repeated IDs retain the legacy
  last-entry-wins semantics. Individual decoded ID blobs over 64 KiB fail as a
  visible reader limit rather than expanding many retained events.
- This is a **file-backed index, not a guarantee of physical-disk backing**:
  the unchanged bubblewrap sandbox supplies a private `/tmp` tmpfs. In-process
  and non-bubblewrap runs use the configured host temporary filesystem. The
  index bounds temporary storage separately from SQLite heap use; private tmpfs
  pages still consume system memory. No additional host bind mount is exposed.
- The ESE page cache remains capped at 256 pages. Existing bounded tree-depth,
  value-size and file-size guards remain; the reader's per-tree visited-page
  set is still proportional to visited pages within the file ceiling. Catalog
  retention and one decoded ESE value are not replaced by this change.
- ID-map records are counted separately in source notes; provider records read,
  mapped and unmapped are not inflated by the ID-map count. Unknown provider
  tables remain explicitly counted and named, not interpreted as another
  provider. Missing IDs remain unresolved instead of inventing identities.
- Live unreadable ID/provider rows fail the streamed source. Sink failures are
  propagated without being counted as damaged evidence. SQLite-full, oversized
  IDs and the source byte ceiling classify as reader/resource limits.
- Worker batches and normalized staging opt into the same bounded lossless
  compression already used for MFT/USN. Encoded/decoded frame limits and both
  per-source and aggregate staging allowances remain unchanged.

## EVTX

- The binary reader retains one 64 KiB chunk. The parser now retains at most
  128 emitted event/raw pairs and targets 1 MiB of decoded pair serialization per
  batch. A single pair may exceed that target but must fit an 8 MiB ceiling;
  resolved raw records over 4 MiB fail visibly. Existing BinXML depth, value and
  substitution limits remain. Worker decoded-frame limits still apply.
- Streaming admits files up to 8 GiB and derives its physical-record ceiling
  from that byte bound and the minimum 28-byte record size. The compatibility
  reader keeps its historical 1 GiB/one-million-record defaults. No global
  process memory, worker deadline, output allowance or security cap is raised.
- Strict streaming examines every physical complete chunk, not merely a
  possibly deflated header chunk-count claim. Completely zero-filled
  preallocation is separately noted. Partial trailing chunks, malformed record
  signatures, decoder failures and failed chunk validation fail the source;
  incomplete recovery is not certified as a successful import. Legacy recovery
  behavior remains available through `Parse`.
- Coverage's `undated` in the streaming path counts emitted undated events, so
  it reconciles with framed output. The compatibility parser retains its old
  count. Provider/channel/EventID census and unmapped counts remain bounded and
  source-level, including when no record has an event mapping.
- No new event mapping or detector is introduced. Successfully reading an
  entirely unmapped diagnostic log means coverage is retained, **not** that its
  payloads are persisted as raw evidence or timeline events. Source bytes remain
  the reference for such records. Chunk-header CRC checks are not a promise of
  complete file/record-data checksum validation.

## Shared acceptance and limits

Tests cover compatibility parity, bounded batches/bytes, tied source identities,
recollection, real sandboxed persistence, cancellation and sink errors, ID-index
permissions/cleanup/resource errors, malformed sources, strict physical chunk
coverage and zero-filled preallocation. Real-file tests are opt-in through
`TRACEFALL_REAL_SRUM_STREAM*` and `TRACEFALL_REAL_EVTX_STREAM*`, with source hash
and independent expected counts supplied explicitly. Scale outputs and native
fidelity reports are restricted external examination derivatives, not fixtures.

The full selected SRUM and diagnostic EVTX sources have been exercised through
an actual compiled sandboxed worker and a fresh API import. The SRUM comparison
covers every mapped row's retained raw cells, independent application/SID
identity checks, and a full parser-event/raw versus persisted-event/raw
canonical digest. EVTX physical counts and the complete returned kind census
match an independent native census; its unmapped payload retention limitation
remains explicit. Scoped race/build/vet checks are separate from parent full-suite
and independent-review acceptance.

The existing 1 GiB total worker output, 1 GiB per-source staging and shared
1 GiB aggregate staging budgets can still stop a larger mapped source. Completed
staging releases descriptors/compression buffers; ordinary completion, error
and cancellation remove staging and ID indexes. These are not crash recovery
or source-atomic persistence: partial committed rows and orphan temporary files
can remain after a storage failure or process crash. No resumable manifest,
restart reconciliation, source-wide transaction or largest-SQL-rotation fix is
implemented here. This closes tested SRUM/EVTX scalability slices, **not item 1
as a whole**, semantic coverage of every provider, or whole-case examination.
