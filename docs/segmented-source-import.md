# Segmented import of very large sources

A very large source cannot be admitted in one transaction: that holds the
store's only connection for hours, journals the whole source, and restarts from
byte zero after a crash. A source that qualifies is instead admitted in bounded
segments that stay **hidden** until the whole source is verified.

## What qualifies

A streaming parser of a verified artifact type and a source of at least 512 MiB
(`DefaultSegmentedMinBytes`). Today the only verified type is the SQL Server
error log. Other sources keep the single-transaction path. The reason for the
allow-list: a blank host is resolved from the source's own host first and from
the collection second, which needs the whole source read beforehand. A verified
type never names a host, so only the collection scope applies. If such a source
does name a host, the import stops rather than guess.

## How it works

1. The source moves `discovered` -> `importing`. Rows of an `importing` source
   are invisible to every reader (one shared SQL predicate), so nothing partial
   is ever evidence.
2. The parser streams records. Every 5000 events a segment is committed together
   with its checkpoint, in one transaction. Deduplication sees visible events
   and the source's own earlier segments.
3. At the end the committed rows are verified against the checkpoints and the
   expected totals, a duplicate dedup hash is refused, and ONE status flip
   publishes the source (`imported`).
4. Any failure or cancel removes every segment and leaves the source `failed`
   (or back to `discovered` for a cancel or a duplicate) with a disclosed reason.
5. After a crash, startup lists the interrupted sources and cleans them in the
   background: the server listens at once, the orphan stays hidden, and its case
   refuses imports and deletions (HTTP 409, with the reason) until it is clean.

While a segmented import is pending, the case also refuses evidence deletion and
other imports, and reports state that the source is not part of the analysis.
The worker's deadline is a stall limit that restarts after every committed
segment, and its output cap bounds one run between segments, not the whole source.

## Limits

- Only the SQL Server error log takes this path.
- Checkpoints are written but not used to resume: after a failure the source is
  imported again from the beginning.
- No lock between two server processes on one database: a second process runs
  startup recovery and would abort the first one's live import.
- Progress is reported per file, not per segment.
- It reduces neither the database size nor the total parse time.
- The cleanup after a crash takes minutes for millions of rows (about 286 s for
  800,000 and about 44 min for 4.6 million in the synthetic test).

## What was verified

On a synthetic 4,600,000-record log (3.2 GB, about 17 GB database), through the
real server binary and sandboxed parser worker with the default limits: exact
record, raw, observation and dedup counts; the expected dated/undated split;
kill -9 mid-import and just before publication leaves nothing visible and
recovers cleanly; anonymous memory peaked at 64 MB. A real 15 GiB SQL log has
not been imported (it needs about 230 GB of database).
