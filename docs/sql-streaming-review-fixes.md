# SQL streaming review fixes: scope and remaining gates

The SQL streaming import stages normalized batches on disk before persistence.
Completed sources now close their staging writer immediately; persistence opens
one staging reader at a time. Ordinary success, parser failure, cancellation,
enrichment failure and persistence-error returns release staged files through
source-local or import-level cleanup. Cleanup is not crash recovery.

The staging limits are 1 GiB per source and 1 GiB across all staged SQL sources
in one import. The aggregate allowance counts serialized event/raw batches,
not input file sizes. A source that would exceed the allowance fails visibly
as a parser/resource limit; earlier successfully staged sources remain eligible
for persistence. The rejected source's staging is discarded. No parser worker
memory, sandbox, deadline or output limit was increased. Non-streaming parsers
retain their existing behavior and are not covered by this staging allowance.

The framed worker reader rejects event/raw cardinality and source-reference
mismatches before invoking the sink. Successful terminal coverage must match
the events and undated events actually received. Records read may exceed events
mapped; unmapped records and missing/local time are not grounds to fabricate
values or reject otherwise valid coverage. Limit/failure coverage without a
terminal error is a worker failure, not a successful complete import.

## Persistence is not source-atomic

Parsing must finish before persistence starts, but raw evidence, events and
observations are still committed in separate operations and batches. A later
persistence failure may leave earlier batches, or raw records without matching
events/observations. The import returns an error warning that partial evidence
may remain and attempts to mark the source failed, never imported. An injected
second-batch failure is covered by a regression test. Failure to update source
status (for example a broken database) cannot be guaranteed recoverable.

A process crash can still leave partial database state, a discovered source,
and orphaned staging files. There is no durable staging manifest, per-source
transaction, restart reconciliation or resumable staging checkpoint. Restart
recovery has NOT been implemented or verified by these fixes; a fresh-case
reimport remains the safe recovery path for affected examination results.

## Acceptance boundaries

The low-descriptor regression imports 100 distinct synthetic SQL sources under
a child-process soft RLIMIT_NOFILE of 64. Additional tests cover aggregate-limit
classification/cleanup, partial persistence and malformed stream frames. These
are software checks, not real-evidence fidelity or analytical completeness.
The full suite is reserved for integration by the parent task.

The largest SQL source/rotations remain NOT VERIFIED. At this SQL-slice revision,
MFT, SRUM, USN and EVTX scalability were unchanged and NOT COMPLETE. Subsequent
MFT/USN work is tracked in [bounded native NTFS import](bounded-ntfs-import.md);
subsequent SRUM/diagnostic EVTX work is tracked in
[bounded SRUM and EVTX import](bounded-srum-evtx-import.md). Neither slice closes
crash recovery or the entire multi-parser acceptance scope.
