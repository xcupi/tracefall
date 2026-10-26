# Source-atomic persistence and owned parser staging

This supersedes the non-atomic persistence and global-temporary-staging limitations
in the earlier bounded-import slice reports. It does **not** close the complete
large-parser acceptance request.

## Admission and cancellation

Every source's raw evidence, deduplicated events, observations, event count,
coverage and imported status now commit in one SQLite transaction. Persistence
still reads bounded batches from the completed spool. Dedup lookups use the same
transaction, including earlier batches; the shared Store is never rebound to a
transaction. A later error, a duplicate-content admission conflict, or lost
imported-status transition rolls back all writes for that attempt.

Cancellation is checked between bounded persistence batches and before admission.
An interrupted source remains discovered and can be retried; earlier complete
sources remain valid. Cancellation is not an interrupt inside an individual row
statement or batch. SQLite recovery discards an uncommitted source transaction
after server death. A persistence error attempts to mark the source failed only
after rollback. Existing partial rows from older revisions are not repaired.

The database still has one shared connection. The transaction holds it for the
whole source: other database-backed requests wait. In-memory import progress and
cancellation do not need that connection. This is a responsiveness limitation,
not a claim that bounded batches bound transaction duration or journal/disk use.

## Staging ownership and restart

The compiled server owns `data-dir/.parser-staging` exclusively for its lifetime.
Linux/macOS use a directory flock; Windows uses an exclusive byte lock in a
separate lock file (cross-compiled here, not runtime-validated). Unsupported
platforms fail closed. A second server cannot clean a live owner's staging.

After acquiring ownership, startup enumerates in bounded pages and removes only
regular files matching `tracefall-parse-*.partial` in that dedicated directory.
It refuses a symlink root and never follows staged symlinks or removes unrelated
names/subdirectories. Directory and temporary-file permissions remain owner-only.
An abandoned complete spool is also discarded: the source retries from the
beginning. This is deterministic cleanup and atomic source rollback, **not a
persisted parser checkpoint or resumed byte offset**. Legacy global temporary
files are not swept because their ownership cannot be established safely.

## Verification and remaining gates

An assertion regression reproduced 128 visible events after a later-batch error;
it now requires zero events, raw records and observations with a failed source.
A cancellation regression rolls back an earlier batch, leaves the source
discovered, and retries it without row loss. Isolation import tests exercise SQL,
MFT, USN, SRUM and EVTX through their existing bounded paths.

A disposable compiled-binary test used a neutral 20,000-record SQL log, stopped
the server with an active rollback journal during source persistence, SIGKILLed
it, and restarted. All three evidence tables were empty after SQLite recovery;
one abandoned spool became zero after restart. A retry persisted 20,000 events,
raw records and observations, all undated, with zero orphan/reference mismatches
and an `ok` integrity check. The driver stopped its servers and verified the port
closed. This synthetic test does not prove real-file fidelity or resource peaks.

Import progress jobs are still memory-only: after restart the old import-job URL
returns 404, not a fabricated success. Persisted pipeline job recovery exists
separately and was not re-proven by this test. Worker-kill checkpoints, server
crashes during staging/final admission, durable per-source retry status,
responsive database reads during a source transaction, all-parser real boundary
regressions, and the largest SQL rotations remain acceptance work. The existing
1 GiB output/staging caps, worker sandbox, deadlines and memory limits are not
increased. No complete import or resumable EOF proof exists for the largest SQL
rotations in this slice. Full-suite integration is reserved for the parent.
