# Bounded SQL text-log import (partial scalability work)

The SQL engine and Agent text parsers expose an optional `StreamingParser`
contract. Import uses it automatically; the existing `Parse`/`ParseWithContext`
API remains compatible and retains its 64 MiB whole-result ceiling. Other
artifact parsers still use their existing paths.

## Memory and evidence semantics

- The reader makes two bounded passes: first the source-wide recorded-server
  census, then logical records. This retains attribution from late headers and
  refuses contradictory names exactly as the compatibility parser does.
- UTF-8 and BOM-prefixed UTF-16LE are validated. Continuations, original line
  references, tied timestamps and raw decoded text retain legacy semantics.
  Unzoned timestamps remain undated.
- Batches contain at most 128 records and flush at approximately 1 MiB of
  raw/message text. Encoded lines and logical records have a 1 MiB safety
  ceiling. A record exceeding a ceiling fails explicitly; it is not truncated.
- An opt-in NDJSON worker protocol carries bounded batches, then a mandatory
  terminal coverage/error frame. The legacy worker response remains unchanged.
  Synchronous sink calls apply backpressure through the pipe. Worker process
  memory, sandbox, deadline, gate and total-output limits are unchanged.
- Import stamps IDs per batch and stages normalized batches in owner-only
  temporary files, rather than retaining the entire selected result in RAM.
  Temporary files are removed on normal, error and cancellation returns.
  Per-source staging is capped at 1 GiB, matching the existing worker output
  budget. A staging/output/time limit is a visible parser-limit failure, never
  successful EOF or an imported source. No source batches are persisted until
  its parse has completed successfully.
- Host enrichment uses bounded per-source host summaries and a scoped SQL
  distinct-host census, including active recollection observations. It no
  longer loads every stored event and its raw Extra JSON merely to find hosts.
  More than 4096 distinct names fails explicitly rather than choosing from a
  truncated prefix.
- Persistence reads one staged batch at a time. Deduplication sees earlier
  batches through the store; every source record retains its raw evidence and
  observation. The source event count is the actual emitted count, not the
  compact host-summary length.

## Limits and remaining acceptance gates

This is a validated SQL vertical slice, not completion of large-artifact work.
At the SQL-slice revision, the MFT, SRUM, USN and diagnostic EVTX readers were
unchanged. Later MFT/USN bounded import work is documented separately in
[bounded native NTFS import](bounded-ntfs-import.md); subsequent SRUM/diagnostic
EVTX implementation and validation are tracked in
[bounded SRUM and EVTX import](bounded-srum-evtx-import.md).
SQL sources whose normalized output exceeds the existing 1 GiB per-job budget
still fail without import. Resumable bounded jobs and the largest SQL rotations
remain unverified; this change must not be described as unlimited ingestion.

Cancellation reaches a streaming parse even before its first emitted batch.
Persistence retains the existing per-source cancellation safe point: once
writing a completed source starts, cancellation waits for that source. Like the
pre-existing path, a storage error during persistence can leave partial writes
with the source not marked imported; transactional source persistence and
restart cleanup of temporary staging files are not implemented here.

Tests generate large synthetic logs independently without committed large
fixtures. Real-source counts, hashes, timings, measured peak memory and native
reference reconciliation are kept in the restricted external validation
workspace, never in fixtures or parser logic. Full-suite integration remains a
separate parent verification gate.
