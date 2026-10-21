# Capacity and load

What the server holds in memory, what bounds it, and what was measured. Numbers
come from a load harness run against the real binary and one real case: a
disk image imported into 525 files, **363,370 events**, 2,168 findings, on a
machine with 15 GB of RAM and 18 cores. They describe that case. Another case
scales roughly with its event count, not with these figures.

## What bounds memory

| Limit | Setting | Default | Holds back |
|---|---|---|---|
| Imports at once | `TRACEFALL_MAX_IMPORTS` | 1 | an import parses every selected file into memory before saving any |
| Report builds and analyses at once | `TRACEFALL_MAX_HEAVY_OPS` | 2 | building a report or running analysis |
| Parser workers at once | `TRACEFALL_PARSER_CONCURRENCY` | = imports | worker processes, each up to `TRACEFALL_PARSER_MEM_MB` (4096) |

A request over a limit waits. It holds a goroutine, not memory, and leaves when
its client does. An import that waits shows the phase "Waiting for another import
to finish"; cancelling it there imports nothing.

**Sizing an import.** Plan about 10 KB of server memory per event of the
collection being imported, plus the parser worker. The measured single import was
3.6 GB for 363,370 events. Raise `TRACEFALL_MAX_IMPORTS` only when
`imports x that figure` fits in RAM with room for the report builds.

## Measurements

Same harness, same data, before and after. "Peak" is the resident memory of the
server and every process descended from it, sampled five times a second.

| Scenario | Before | After |
|---|---|---|
| `GET /timeline`, 2 clients | 4,376 MB | 284 MB |
| `GET /export`, 2 clients | 2,153 MB | 566 MB |
| `report.zip`, 1 / 4 / 8 clients (readers running) | 356 / 682 / 1,225 MB | 416 / 580 / 642 MB |
| `report.zip`, 1 client, nothing else running | 13 s, 213 MB | 16 s, 252 MB |
| `timeline.csv`, 4 clients | 282 MB | 285 MB |
| `report/latest`, 8 clients | 211 MB | 201 MB |
| 3 imports started together | stopped at 7,990 MB after 48 s | 3,751 MB, all three completed in 891 s |

The three imports in the last row each produced the same result: 363,370 new
events, 319 files imported, no parse failures. "Stopped" means the harness
stopped the test server because the machine's available memory fell below
2.5 GB, to protect the machine; it is not a crash of the product.

Two rows are not improvements and are reported as they were measured: a single
report is about 3 s slower (paging, below) and its memory is not lower. What
changed is that memory no longer grows with the number of clients.

## One database connection

The store has a single SQLite connection. Before this change a stream held a
cursor open while it wrote to the client, so one slow download stopped every
other request. Event streams are now read a page at a time (2,000 events) and
each page's cursor is closed before any event is sent.

- A full pass over 363,370 events costs 10-20% more (6.4 s → 7.1-8.2 s).
- A stream no longer sees a single instant of the data if the case is written to
  meanwhile.
- Reads still queue behind each other and behind writes. With only the readers
  running, the dashboard's slowest endpoints on this case answer in a median of
  1.1 s and a 95th percentile of 4.0 s. During a report build or an import the
  95th percentile was 5-17 s.

Write-ahead logging with a separate read connection would remove most of that
queueing. It changes the on-disk format and is not part of this change.

## Not solved

- One import's memory still grows with its collection; only the number of imports
  is bounded.
- `GET /timeline` still sends the whole case (482 MB here) to whoever asks. The
  server no longer holds it in memory.
- The dashboard's Correlations tab fetches the events its correlations cite, about
  220 lookup requests on this case, because it resolves them when it draws the
  tab. It should fetch them when a correlation is expanded.
- Reads are slow under write load for the reason above.
- The memory guard in the harness stops its own test server; there is no such
  guard in the product. Set the limits for the machine.
