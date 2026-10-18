# Tracefall

Tracefall is an automated forensic triage and investigation platform. It
takes a KAPE-style Windows triage evidence package and turns it into a
normalized timeline, deterministic findings backed by concrete evidence,
correlated activity chains, and MITRE ATT&CK technique mappings — exposed
through an API and a minimal investigation dashboard.

**This is Phase 1 + 1.5**: a real, working, but intentionally small
vertical slice, now reachable from a browser upload and from other
machines on your LAN. It is not a full-disk forensics platform, not a
memory forensics tool, and it has no AI/LLM in its detection or
correlation path — see [ARCHITECTURE.md](ARCHITECTURE.md) for the full
scope and reasoning.

## What it does

1. Create a case.
2. Upload a KAPE triage package as a ZIP archive straight from the
   browser (or, for local/dev use, point Tracefall at an evidence
   directory already on disk) — Windows Event Logs, Prefetch, Registry
   Run keys, Scheduled Tasks.
3. Safely extract the archive, discover which files are supported
   artifacts, and parse and normalize them into a common event schema.
4. Build a unified, chronologically sorted timeline.
5. Run seven deterministic detection rules over the timeline.
6. Correlate events into process chains, entity linkages, temporal
   bursts, and full evidenced activity-chain narratives.
7. Map findings to MITRE ATT&CK techniques.
8. Serve everything through a JSON API, reachable from other machines on
   your LAN if you choose to configure it that way.
9. Display it in a minimal web dashboard, with every finding traceable
   down to the original raw evidence record it came from.

A synthetic (clearly-marked, not real) evidence package is bundled at
[testdata/synthetic_case](testdata/synthetic_case) so the whole pipeline
can be exercised without a real forensic image.

## Requirements

- Go 1.24+ (developed and tested on Go 1.26). No other runtime
  dependencies — Tracefall uses a pure-Go SQLite driver, so no cgo, no
  system SQLite, no Node, no Docker.

## Running it

From the repository root:

```bash
go run ./cmd/tracefall
```

This starts the API and dashboard on `http://127.0.0.1:8080` (loopback
only, by default), backed by a SQLite database file `tracefall.db` and a
`data/` directory (both created in the working directory).

Configuration is via flags or environment variables (flag wins, then env
var, then default):

```bash
go run ./cmd/tracefall -host 0.0.0.0 -port 9000 -db /path/to/case.db
# equivalently:
TRACEFALL_HOST=0.0.0.0 TRACEFALL_PORT=9000 TRACEFALL_DB=/path/to/case.db go run ./cmd/tracefall
```

| Flag | Env var | Default | Meaning |
|---|---|---|---|
| `-host` | `TRACEFALL_HOST` | `127.0.0.1` | listen host — set to `0.0.0.0` for LAN access |
| `-port` | `TRACEFALL_PORT` | `8080` | listen port |
| `-db` | `TRACEFALL_DB` | `tracefall.db` | SQLite database file |
| `-data-dir` | `TRACEFALL_DATA_DIR` | `./data` | root directory for uploaded/extracted case evidence |
| `-max-upload-mb` | `TRACEFALL_MAX_UPLOAD_MB` | `2048` | maximum accepted KAPE package upload size |

**LAN access requires authentication.** Set `-host 0.0.0.0` (or
`TRACEFALL_HOST=0.0.0.0`) *together with* `TRACEFALL_AUTH=on` to make
Tracefall reachable from other machines at
`http://<this-machine's-LAN-IP>:8080`:

```bash
TRACEFALL_AUTH=on TRACEFALL_HOST=0.0.0.0 ./tracefall
```

A non-loopback bind **without** authentication is refused at startup —
it would publish every case, all evidence, the audit log and every
destructive endpoint to the network.

On first start with authentication enabled, Tracefall creates a
`tracefall` administrator, prints its generated password **once**, and
requires that password to be changed before the account can do anything
else. Restarting never regenerates or reprints it.

Traffic is plain HTTP; put a TLS terminator in front for anything beyond
a trusted network. See [docs/security.md](docs/security.md) for the
security model and [docs/deployment.md](docs/deployment.md) for
configuration and firewall setup.

Open `http://localhost:8080` in a browser for the dashboard.

## Development

A `Makefile` wraps the commands above for everyday use. It doesn't add
any configuration of its own — `make run`/`make run-lan` just pass the
existing `-host` flag documented above.

```bash
make run       # local development: binds to 127.0.0.1:8080 (the safe default)
make run-lan   # LAN testing: binds to 0.0.0.0:8080, reachable from other machines
make build     # build the binary to ./bin/tracefall
make test      # go test ./...
make test-race # go test -race ./...
make clean     # remove ./bin (never touches the database, data/, or uploaded evidence)
```

`make run` and `make run-lan` print a short startup summary — listening
address, URL (or, for LAN mode, the bind address plus a reminder to
substitute this machine's own LAN IP), data directory, and database
path — so it's immediately clear what you're connected to.

## Walkthrough: analyzing a KAPE package

A case can hold more than one evidence **collection** — e.g. a morning
triage and an afternoon follow-up on the same host — and the timeline,
findings, and correlations always cover the case's complete evidence set,
not just the most recent upload.

1. Open `http://localhost:8080`.
2. Fill in **New case** (e.g. name "WKSTN-042 Phishing Triage") and click
   **Create case**.
3. Click **+ Add Evidence**, choose a ZIP archive of a KAPE triage
   collection or a single AD1 forensic image, and click **Upload Evidence**.
   By default Tracefall discovers the files, imports every supported file,
   and runs analysis automatically; progress, parse failures, unsupported
   files, and coverage remain visible. Turn off **Automatically import all
   supported files and run analysis after upload** to choose files manually.
4. Review the **Timeline**, **Findings**, **ATT&CK**, **Activity Chains**,
   and **Evidence** tabs. Click any finding to expand its supporting events,
   then click **raw** on an event to see the exact source record it was
   normalized from and which collection(s) it was observed in.
5. Click **+ Add Evidence** again to add a second collection (e.g. a
   follow-up triage) to the same case; automatic analysis reruns across
   both collections after import.

To try this immediately without a real KAPE collection, zip up the
bundled synthetic dataset at [testdata/synthetic_case](testdata/synthetic_case)
and upload that — or use the **Advanced: ingest from a local path**
option under Add Evidence (only useful when the evidence is already on
the same machine running Tracefall), pre-filled with
`testdata/synthetic_case`.

## API

All endpoints are under `/api`. See [ARCHITECTURE.md](ARCHITECTURE.md#api)
for the full list; in short:

```
POST /api/cases                            create a case
GET  /api/cases                            list cases
GET  /api/cases/{id}                       case detail + summary (spans all collections)
POST /api/cases/{id}/evidence              add a collection via KAPE ZIP upload (multipart, field "file")
GET  /api/cases/{id}/evidence              list the case's evidence collections
GET  /api/cases/{id}/evidence/{collId}     one collection's detail (its source files)
POST /api/cases/{id}/ingest                add a collection from a local evidence directory
GET  /api/cases/{id}/sources               source files across all collections
GET  /api/cases/{id}/events/{eventID}      one event's full provenance chain (all collections it was observed in)
POST /api/cases/{id}/analyze               run detection + correlation across the complete case
GET  /api/cases/{id}/timeline              unified timeline (optionally ?collection=<id>)
GET  /api/cases/{id}/findings              case-level findings list
GET  /api/cases/{id}/findings/{fid}        finding + resolved evidence (each event labeled with its collection)
GET  /api/cases/{id}/attack                ATT&CK technique coverage
GET  /api/cases/{id}/correlations          process/entity/temporal/activity chains (may span collections)
GET  /api/cases/{id}/report.html           deterministic forensic report (self-contained HTML)
GET  /api/cases/{id}/report.zip            report + manifest.json (SHA-256) + timeline.csv + findings.csv
GET  /api/cases/{id}/report.pdf            the report as PDF (needs headless Chrome/Chromium; 501 otherwise)
```

Verify a downloaded bundle offline with `tracefall verify-report report.zip`.

Disk images (raw/dd and E01, MBR/GPT, NTFS) are added like any other evidence; Tracefall
finds the partitions and reads the artifacts itself. See `docs/disk-images.md` for what is
supported, how it was validated, and its limits.

Resumable upload and server-side pipeline (details in `docs/pipeline.md`):

```
POST /api/cases/{id}/uploads                          open a session {"filename","size","sha256"?}
PUT  /api/cases/{id}/uploads/{uploadId}               append a chunk (Upload-Offset header)
GET  /api/cases/{id}/uploads/{uploadId}               bytes received so far
POST /api/cases/{id}/uploads/{uploadId}/complete|abort
POST /api/cases/{id}/pipeline/jobs                    discover -> import -> analyze on the server
GET  /api/cases/{id}/pipeline/jobs[/{jobId}]          status; POST .../cancel
```
See [docs/forensic-report.md](docs/forensic-report.md).

Two paths changed meaning from an earlier version of this API:
`GET/POST /cases/{id}/evidence` used to mean "source files" / "upload a
ZIP" for a case's one-and-only collection; a case can now hold several
collections, so those verbs now operate on collections themselves, and
what they used to return moved to `/sources` and `/events/{id}`. See
[docs/data-model.md](docs/data-model.md) for the full reasoning.

## Running the tests

```bash
go test ./...
# or: make test
```

For coverage and the race detector:

```bash
go test -race -cover ./...
# or: make test-race (without -cover)
```

This includes unit tests for every layer (archive extraction safety,
casefiles, config, parsers, normalization, detection, correlation,
storage) and two full end-to-end tests: `internal/api.TestEndToEnd_SyntheticCase`
(local-path ingest) and `internal/api.TestUploadFlow_ValidKAPEPackage`
(browser ZIP upload), both driving the synthetic dataset through the
real HTTP API: ingest/upload → normalize → detect → correlate →
ATT&CK-map → verify the API response, exactly as the dashboard does.
`internal/archive`'s tests specifically cover the untrusted-input
handling: path traversal, absolute paths, symlinks, oversized/too-many
files, and zip-bomb compression ratios.

## Project layout

```
cmd/tracefall/          entrypoint: wires config, storage, API, and the dashboard together
internal/model/         shared domain types (Case, Event, Finding, Correlation, ...)
internal/parsers/       artifact parsers (one package per artifact type)
internal/normalize/     shared normalization helpers (timestamps, paths, entities)
internal/procclass/     shared process/path classification used by detect + correlate
internal/ingest/        evidence-directory walking + artifact-parser dispatch
internal/detect/        deterministic detection rules
internal/correlate/     deterministic correlation engine
internal/attck/         MITRE ATT&CK technique mapping registry
internal/store/         SQLite persistence layer
internal/archive/       safe ZIP extraction for untrusted KAPE package uploads
internal/casefiles/     per-case on-disk layout for uploaded/extracted evidence
internal/config/        host/port/db/data-dir/upload-limit resolution (flags + env vars)
internal/api/           HTTP API + case-lifecycle orchestration service
internal/web/           embedded static dashboard (HTML/CSS/vanilla JS)
testdata/synthetic_case/ synthetic (fake) KAPE-like evidence package
docs/                    architecture and engine documentation
```

See also: [ARCHITECTURE.md](ARCHITECTURE.md),
[docs/data-model.md](docs/data-model.md),
[docs/forensic-search.md](docs/forensic-search.md),
[docs/windows-artifacts.md](docs/windows-artifacts.md),
[docs/detection-engine.md](docs/detection-engine.md),
[docs/correlation-engine.md](docs/correlation-engine.md),
[docs/adding-parsers.md](docs/adding-parsers.md),
[docs/deployment.md](docs/deployment.md).

## Known limitations

- Single-host cases only: the ingestion pipeline assumes one evidence
  package corresponds to one machine.
- Parsers consume EZ Tools (EvtxECmd/PECmd/RECmd) CSV output and raw
  Task Scheduler XML, not raw binary EVTX/Prefetch/registry hive
  formats directly — see ARCHITECTURE.md for why, and
  docs/adding-parsers.md for how to add a raw-format parser later.
- **No TLS.** Tracefall speaks plain HTTP and does not terminate TLS;
  put a reverse proxy in front of it on any shared network.
- **No per-case access control.** Any authenticated analyst can read and
  export every case; the model is "everyone on this team may see this
  team's cases". Roles separate *analysis* from *deletion and user
  administration*, not case from case. See docs/security.md.
- Deleting a case still removes that case's audit log with it; the
  system-wide security log survives.
- Detection rules are a representative starter set (7 rules), not
  comprehensive coverage.
- **No password cracking, ever.** Tracefall extracts Windows local
  account records and their stored NTLM hashes from a SAM hive
  ([docs/windows-artifacts.md](docs/windows-artifacts.md#windows-sam)),
  and stops there. An NTLM hash is not the plaintext password and is not
  reversible into one; there is no wordlist, no brute force, and no
  integration with Hashcat, John the Ripper or anything comparable.
  Decoding the hash requires the SYSTEM hive to be collected alongside
  the SAM: the key it is wrapped under lives there, not in the SAM.
  Without it every account is still reported, with its hash marked as
  still encrypted (not "missing" — the material is there) and the reason
  stated.
- **SECURITY hive secrets** (LSA secrets, cached domain credentials) are
  not extracted.
- No LLM/AI anywhere in this phase, by design.

See ARCHITECTURE.md's "Recommended Phase 2" section for what's next.

## Memory images

Set `TRACEFALL_VOLATILITY` to a Volatility 3 `vol` executable and upload a memory image (`.vmem`, `.mem`, `.dmp`, `.lime`, `.raw`, or a known format). It runs sandboxed and feeds the same timeline, findings and report. See `docs/memory-analysis.md` for what is and is not validated.
