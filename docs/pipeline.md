# Server-side pipeline and resumable upload

Status: backend, HTTP API and dashboard integration implemented and tested.

## Why

A forensic image is tens of GB. One HTTP request loses everything on a
dropped connection, and the earlier "upload then analyse" chain lived in
browser JavaScript, so closing the tab stopped it. Here the chain is a
persisted job that runs on the server.

## Resumable upload

    POST /api/cases/{id}/uploads                    {"filename","size","sha256"?}  -> 201 session
    PUT  /api/cases/{id}/uploads/{uploadId}         header Upload-Offset: N, body = chunk
    GET  /api/cases/{id}/uploads/{uploadId}         -> {"received": N, ...}
    POST /api/cases/{id}/uploads/{uploadId}/complete
    POST /api/cases/{id}/uploads/{uploadId}/abort

- `received` is always a contiguous prefix. A chunk is accepted only at
  `Upload-Offset == received`; otherwise 409 with the true `received`, which
  is also how a client finds where to resume after any failure or restart.
- Bytes are fsynced before `received` advances, and the counter moves by
  compare-and-swap, so a crash can leave extra bytes but never a gap, and
  two chunks cannot both claim an offset.
- The file is named from the server-generated session id only. No client
  string becomes part of a path.
- A declared `size` above the server limit is refused before any byte is sent.
  Writing past the declared size is refused (413) and does not advance.
- `complete` confirms every declared byte is on disk. It does not hash:
  hashing 50 GB inside one request would outlast any timeout.
  The optional client `sha256` is verified by the pipeline job, and a
  mismatch fails the job before any evidence is recorded.
- Sessions idle for 7 days are discarded and their bytes deleted.

## Pipeline job

    POST /api/cases/{id}/pipeline/jobs   {"upload_id": "..."} or {"local_path": "..."}, "analyze": false to skip analysis
    GET  /api/cases/{id}/pipeline/jobs[/{jobId}]
    POST /api/cases/{id}/pipeline/jobs/{jobId}/cancel

Stages: discover -> import (every supported file; the collection's host time zone
is read from its SYSTEM hive first) -> analyze -> report (a ZIP bundle is written
to the case's reports folder and its hash is audited; `GET /api/cases/{id}/report/latest`
serves it). `analyze: false` skips the analyze and report stages. The job row
(stage + collection id) is the checkpoint. Results report files imported,
skipped and failed, event, finding and correlation counts.

Restart behaviour:
- A job left `running` by a dead process is re-queued at startup and
  continues from its checkpoint. Discovery is not repeated; if the server
  died after committing a collection but before saving the checkpoint, the
  resumed job adopts that collection.
- A first attempt on evidence already in the case fails with the duplicate
  message instead of adopting it.
- A job started 3 times (it keeps killing the server) is failed, not retried.

Other rules:
- One worker, one job at a time, oldest first.
- Cancel: a queued job is cancelled at once; a running one stops at the next
  stage boundary. A stage in progress is allowed to finish.
- The uploaded staging file is deleted when the job ends, success or not.
  Retrying a failed upload means uploading again.
- Closed or locked cases refuse jobs and uploads up front (409).
- The creating user is recorded and used for audit entries
  `pipeline_queued` / `pipeline_finished`; each step also keeps its own
  audit entry.
- Jobs and upload sessions are operational state, deleted with the case,
  and feed no finding.

## Dashboard

With "Automatically import all supported files and run analysis" ticked
(the default), Upload Evidence sends the file in 8 MiB chunks
(`uploadResumable` in `app.js`), then starts a pipeline job and follows it
in a panel with stage, counts and a Cancel button (`runServerPipeline`).

- Chunks are Blob slices; the file is never read into memory.
- A failed chunk is retried with backoff (up to 6 times). Before resending,
  the browser asks the server for `received` and adopts it, and a 409 does
  the same.
- The session id is kept in `localStorage` under name+size+mtime. After a
  page reload, choosing the SAME file again continues from the bytes the
  server holds. Browsers cannot reopen a file by themselves, so the file
  must be picked again.
- Opening the case's Evidence tab re-attaches to a queued or running job.
  Poll failures are tolerated for about a minute so a restarting server does
  not look like a failure.
- Unticked, the old flow (multipart upload, select files, import, analyze)
  is unchanged. The "ingest from a local path" box is also unchanged.
- The panel shows file COUNTS; the per-file parse-failure reasons stay in the
  Evidence tab.

## Not done

- Streaming analysis: detection, correlation and reports still load the
  case's events into memory (audit gap 8).
- Parsers run in the server process, not a sandbox.
- Hash is computed in a separate pass for a declared `sha256` plus the
  pass the ingest does; a single combined pass is possible later.
