# Tracefall Architecture

## Scope

Tracefall is an automated forensic triage and investigation platform.
Phase 1 (this document describes the system as built for Phase 1, plus
Phase 1.5's upload/LAN additions noted where relevant) covers:

```
KAPE ZIP upload (or local path) -> validate/extract -> ingestion
  -> artifact parsing -> normalization -> deterministic correlation
  -> timeline -> findings
```

Explicitly out of scope through Phase 1.5 (and not attempted): memory
forensics, full disk imaging or raw disk analysis, malware sandboxing,
automatic malware verdicts, LLM/AI integration of any kind, threat
intelligence integrations, distributed architecture, Kubernetes, or
authentication/authorization of any kind. The detection and correlation
engine is 100% deterministic and works with no network access and no AI
model. An LLM investigation copilot is an explicit future phase, not
something this codebase depends on today. Phase 1.5 makes Tracefall
reachable from other machines on a LAN, but does not add any concept of
"logged in" or "not logged in" -- see docs/deployment.md for exactly
what that does and doesn't protect against.

## Starting point

This repository was empty before Phase 1 (no existing project, no prior
language choice). The toolchain available in the build environment was
Go 1.26 and SQLite's CLI; there was no Node.js and no working `pip`, which
ruled out both a JS/TS frontend build and Python. Go was chosen because:

- It has a capable standard library (`net/http`, `encoding/csv`,
  `encoding/xml`, `database/sql`) that covers almost everything Phase 1
  needs without third-party dependencies.
- It compiles to a single static binary, which matches "runnable locally
  with one documented command" better than a multi-process/multi-runtime
  stack would.
- A pure-Go SQLite driver (`modernc.org/sqlite`) is available, so the
  practical local database requirement is met with zero system
  dependencies (no cgo, no system SQLite install).
- Static typing and a real module system make a layered, modular monolith
  (parsers / normalization / detection / correlation / storage / API)
  easy to keep honestly decoupled — a package can be prevented from
  importing another simply by not adding the import.

The dashboard is a small amount of hand-written HTML/CSS/vanilla
JavaScript, embedded into the Go binary via `go:embed`. With no Node.js
available, there was no framework build step to reach for anyway, and a
local investigator-facing MVP dashboard doesn't need one — see
`internal/web`.

## Layers

Each of these is a separate Go package with a one-directional dependency
graph (an arrow means "imports"):

```
parsers/*  ─┐
            ├─▶ normalize ─┐
procclass ──┴──────────────┼─▶ detect ─┐
                            ├─▶ correlate ┤
                            │             ├─▶ api ─▶ web (HTTP only, no logic)
                         model ───────────┤   │
                            │             │   ├─▶ store
                          attck ──────────┘   ├─▶ archive   (untrusted ZIP extraction)
                            │                 └─▶ casefiles (per-case disk layout)
                         ingest (parsers + model, dispatch only)

config (flags/env -> Config; imported only by cmd/tracefall)
```

In prose:

1. **Ingestion** (`internal/ingest`) walks an evidence directory, matches
   each file against a registry of artifact parsers by filename/path
   pattern, and dispatches to the matching one.
2. **Artifact detection** is that same filename/path-pattern matching
   (`ArtifactParser.Detect`) — deliberately simple and explicit rather
   than content-sniffing, since KAPE and its companion tools use
   predictable, documented output naming conventions.
3. **Artifact parsers** (`internal/parsers/*`) turn one source file into
   normalized `model.Event` values. Each artifact type is its own
   package implementing one shared interface
   (`parsers.ArtifactParser`) — see [docs/adding-parsers.md](docs/adding-parsers.md).
4. **Normalization** (`internal/normalize`) holds parsing/canonicalization
   logic shared across parsers (timestamps, host/user casing, path→
   executable-name extraction) so every parser produces events on the
   same conventions instead of inventing its own.
5. **Event/evidence model** (`internal/model`) is the common schema
   everything downstream depends on — see [docs/data-model.md](docs/data-model.md).
6. **Detection engine** (`internal/detect`) runs seven deterministic rules
   over a case's normalized events and produces evidence-backed findings
   — see [docs/detection-engine.md](docs/detection-engine.md).
7. **Correlation engine** (`internal/correlate`) builds explicit
   relationships between events (process chains, entity linkages,
   temporal bursts, full activity-chain narratives) — see
   [docs/correlation-engine.md](docs/correlation-engine.md).
8. **ATT&CK mapping** (`internal/attck`) is a small static registry of
   technique metadata, referenced by ID from detection rules and resolved
   to full metadata only at the API boundary. No package other than
   `attck` defines technique names, tactics, or URLs.
9. **Case storage** (`internal/store`) is a thin SQLite wrapper — the only
   package that runs SQL.
10. **Archive extraction** (`internal/archive`, added in Phase 1.5) safely
    extracts an untrusted ZIP upload before ingestion ever sees it —
    path-traversal/Zip-Slip/absolute-path/symlink rejection, zip-bomb
    limits, fail-closed on any single unsafe entry. It has no knowledge
    of cases, KAPE, or forensic parsing at all; it's a generic "extract
    an untrusted zip safely" primitive. See docs/deployment.md.
11. **Case file layout** (`internal/casefiles`, added in Phase 1.5,
    made collection-aware in Phase 1.6) resolves where each of a case's
    evidence *collections* stores its uploaded archive and extracted
    evidence on disk (`.../collections/<collection-id>/...`), and cleans
    up fully on a failed upload -- without touching any other
    collection's already-ingested evidence in the same case.
12. **API** (`internal/api`) is a `Service` that orchestrates
    ingest → store → detect → correlate → attck for the case lifecycle
    (plus, for an uploaded ZIP, casefiles → archive → ingest), and HTTP
    handlers that expose it as JSON. It contains no forensic analysis
    logic itself.
13. **UI** (`internal/web`) is a static dashboard that only ever talks to
    the JSON API. It cannot make a detection or correlation decision —
    there is no code path for it to do so.

Runtime configuration (`internal/config`, added in Phase 1.5) is a
leaf package imported only by `cmd/tracefall`'s `main`: it resolves the
listen host/port, database path, evidence data directory, and upload
size limit from CLI flags and environment variables. It's deliberately
outside the layer graph above -- nothing about *how Tracefall is
configured to run* should leak into *how it analyzes evidence*.

This separation is what makes "parsers aren't tightly coupled to
detection logic" and "the UI is never responsible for forensic analysis"
true by construction, not just by convention: `internal/parsers/*` cannot
import `internal/detect` (nothing pulls it in), and `internal/web` is
static assets with no Go code in the request path at all.

## Why parsers consume EZ Tools CSV, not raw binary formats

KAPE itself only *collects* raw artifact files (`.evtx`, `.pf`, registry
hives, raw Task Scheduler XML). In real-world usage, KAPE's `!EZParser`
module runs alongside collection and processes those raw files with Eric
Zimmerman's companion tools (EvtxECmd, PECmd, RECmd, etc.), producing
structured CSV. Tracefall's Phase 1 parsers for Windows Event Logs,
Prefetch, and Registry Run keys consume that CSV rather than
re-implementing the underlying binary formats (EVTX's binary XML, the
Prefetch compression/MAM header format for Windows 10+, or raw registry
hive parsing) from scratch.

This is a deliberate scope decision, not an oversight: reimplementing
those binary formats is a large, solved problem that companion tools
already handle well, and spending Phase 1's budget there would come at
the direct expense of the parts of Tracefall that are actually novel —
normalization, deterministic detection, correlation, and ATT&CK mapping.
It also means Tracefall's Phase 1 parsers are exercised against exactly
the file shapes a real KAPE + `!EZParser` run produces.

Scheduled Tasks are the exception: KAPE collects the raw Task Scheduler
XML directly, and that format is simple, well-documented, and already
textual, so Tracefall parses it natively with `encoding/xml` (including
handling the UTF-16LE-with-BOM encoding real Task Scheduler XML files
use).

Because every parser is just an `ArtifactParser` implementation
registered in `internal/ingest.Registry()`, adding a parser for a raw
binary format later (or for an artifact type not covered yet) requires
no changes to ingestion, normalization's shared helpers, detection,
correlation, or the API — see [docs/adding-parsers.md](docs/adding-parsers.md).

## Normalized event model

Summarized here; full field-by-field rationale in
[docs/data-model.md](docs/data-model.md). The model largely follows the
field list from the product brief, with two adjustments explained there:
`ppid`/`parent_process_path` were added (Windows Security 4688 events
carry parent lineage directly, and it's directly useful to
`internal/correlate`), and low-frequency artifact-specific fields (e.g. a
registry value's `value_name`, a scheduled task's `task_name`, a logon's
`logon_type`) live in a `map[string]string` `Extra` field rather than as
first-class columns, keeping the common schema small and stable while
still preserving that detail for rules and investigators that need it.

Provenance is preserved end-to-end and is always traceable in one
direction:

```
Finding -> supporting Event(s) -> RawEvidence (the exact original row/record)
                                -> SourceFile (which file, which parser, its SHA-256)
```

This chain is exposed directly in the API
(`GET /cases/{id}/evidence/{eventID}`) and in the dashboard (click a
finding, then "raw" on any of its supporting events).

## Detection engine

Deterministic, rule-based, evidence-backed. See
[docs/detection-engine.md](docs/detection-engine.md) for the full list of
rules, their thresholds, and the severity/confidence philosophy (a single
weak indicator is reported as an observation at low confidence, never as
a malware verdict).

## Correlation engine

Deterministic. Builds four kinds of relationship — process parent/child
chains, entity correlations (the same executable observed across
multiple independent artifact types), temporal clusters, and full
evidenced activity-chain narratives (e.g. logon → Office → PowerShell →
payload → persistence → network) — never fabricating a step the evidence
doesn't support. See [docs/correlation-engine.md](docs/correlation-engine.md).

## MITRE ATT&CK mapping

A dedicated, small, expandable registry (`internal/attck`) maps technique
IDs to name/tactic/URL. Detection rules attach technique IDs to findings;
nothing outside `internal/attck` hard-codes technique metadata, including
the UI, which resolves IDs through the API's `/attack` endpoint.

## Case storage

SQLite via a pure-Go driver (`modernc.org/sqlite`), accessed only through
`internal/store`. Chosen as "a practical local database for the MVP" per
the brief: zero setup, a single file, and a schema
(`internal/store/schema.go`) that maps cleanly onto PostgreSQL if/when
Tracefall needs concurrent multi-user writes — see
[docs/data-model.md](docs/data-model.md) for the specific migration path
and the one deliberate simplification (JSON columns instead of join
tables for a finding's supporting-event and technique lists) made to
avoid over-engineering the MVP's storage layer.

## API

See [README.md](README.md#api) for the endpoint list.
`internal/api.Service` is the only place ingest → store → detect →
correlate → attck get sequenced together; HTTP handlers
(`internal/api/handlers.go`) are a thin JSON translation over it.

Case lifecycle is a simple state machine: `created -> ingested ->
analyzed`, except it isn't strictly one-way -- adding a new evidence
**collection** to an `analyzed` case moves it back to `ingested`,
signaling that the analysis is now stale. A case accepts any number of
collections: `AddEvidenceFromPath` (a local directory) and
`AddEvidenceFromUpload` (a browser-uploaded ZIP) can both be called
repeatedly per case, each call creating a new `model.Collection` row and
sharing a single private `ingestFromDirectory` helper, so
`internal/ingest.Walk` -- the actual discover/parse/normalize pipeline --
is invoked from exactly one place regardless of how or how many times
evidence arrived. `ingestFromDirectory` also deduplicates the newly
parsed events against everything already in the case (see
docs/data-model.md's "Deduplication" section) before saving. Analysis is
idempotent and re-runnable (prior findings/correlations are cleared and
regenerated, so running it twice on unchanged evidence produces the same
result, never duplicates) and always operates on the case's complete,
deduplicated event list -- `internal/detect` and `internal/correlate`
have no notion of "collection" at all, so a relationship between
evidence in two different collections is found exactly when the same
deterministic rule would find it within one collection. That's most of
why cross-collection correlation "just works": the only new work this
phase actually needed was correct multi-collection ingestion and
deduplication, not any change to detection or correlation logic itself.

Before either call creates a `model.Collection` row, it hashes the
evidence source (the archive bytes for an upload, a deterministic
directory fingerprint for a local path — see docs/data-model.md's
"Duplicate evidence collections" section) and rejects an exact match
against an existing collection **in the same case** with `409
Conflict`, identifying which collection it duplicates, before
extracting or parsing anything. A `(case_id, archive_hash)` partial
unique index is the race-safe backstop behind the upfront check
(`internal/api.Service.createCollectionOrDuplicateError`).

`AddEvidenceFromUpload` additionally: creates a clean per-collection
directory (`internal/casefiles`), saves the original archive unmodified
(provenance requirement), safely extracts it (`internal/archive` — see
docs/deployment.md for the full untrusted-input threat model), and — on
*any* failure at any of those steps — removes everything written for
that collection's attempt and marks it `failed`, without touching any
other collection already in the case. No half-ingested collection is
left in an ambiguous state, and no failure can corrupt evidence a
previous, successful collection already contributed.

## Web UI

`internal/web` embeds a static dashboard (`index.html` + `app.js` +
`style.css`) via `go:embed` and serves it alongside the API from the same
binary. The frontend is plain JavaScript using hash-based client-side
routing and `fetch` against `/api/*` — no build step, no framework,
consistent with "do not spend excessive time on visual polish" and with
there being no Node.js toolchain available to build one anyway. It shows
case summary/severity rollup (spanning every collection), an **Evidence
Collections** panel, the unified timeline (each row labeled with which
collection it came from, with an optional collection filter), findings
(with click-to-expand supporting evidence, per-event collection labels,
and raw-record drill-down showing every collection an event was observed
in), ATT&CK coverage, and correlated activity chains.

The case page's primary action is **+ Add Evidence**, which reveals an
upload form: a file picker posts a ZIP as `multipart/form-data` to `POST
/cases/{id}/evidence` (via a dedicated `apiUpload` helper in `app.js`,
since a plain `fetch` needs to set its own multipart boundary rather than
the JSON `Content-Type` the rest of the dashboard uses), and the
response's file/artifact/event counts (including how many events were
new vs. already known from another collection) are rendered immediately
as upload/ingestion status before the user continues into the case
dashboard. If the archive/path exactly duplicates a collection already
in the case, the API's `409` is shown as a distinct "Evidence already
exists" message (naming the existing collection) rather than the
generic error box, and no fake success/"Collection #N" result is ever
rendered for a rejected duplicate. This can be repeated any number of
times per case for genuinely new evidence. Ingesting
from a local filesystem path — no browser upload involved — remains
available as a collapsed "Advanced" option under the same form, for
local/dev use. The **Evidence** tab lists every collection with its
counts and status, expandable to that collection's own source files.

## Assumptions made

- **One case = one host.** Prefetch and registry-hive-derived artifacts
  don't carry a hostname field themselves; Tracefall backfills them with
  the dominant host seen among artifacts that do (Windows Event Logs
  always do) -- first within the collection being ingested
  (`internal/ingest.backfillHost`), and, if that collection alone has no
  host-bearing artifact at all (e.g. a follow-up collection that's only a
  registry export and a Task Scheduler XML), by falling back to the
  dominant host already established elsewhere in the case
  (`internal/api.Service.enrichMissingHosts`). A multi-host evidence
  package is a Phase 2 concern.
- **Evidence arrives either as a browser-uploaded ZIP or from a local
  filesystem path already on the machine running Tracefall.** The
  browser upload path is now the primary, recommended flow (added in
  Phase 1.5); the local-path flow remains available as a secondary
  option since it's genuinely useful for local/dev work (e.g. the
  bundled synthetic dataset) and removing working functionality that
  wasn't asked to be removed isn't warranted.
- **A case can hold any number of evidence collections, not just one.**
  Phase 1.5 rejected a second upload per case outright; that restriction
  is gone, and re-uploading (a follow-up KAPE triage, evidence added
  mid-investigation) is now the normal, expected workflow rather than an
  error. Every collection's events are deduplicated against the rest of
  the case (see docs/data-model.md's "Deduplication" section) so
  re-collecting the same still-live evidence twice doesn't double-count
  it, while still preserving that it *was* independently observed twice.
- **An uploaded archive is untrusted input.** It was collected on
  a possibly-compromised machine; Tracefall extracts it defensively
  (path traversal / absolute path / symlink rejection, size and
  compression-ratio limits, fail-closed on any single unsafe entry,
  never-executable extracted files) and never executes anything from it
  — see docs/deployment.md for the complete list of protections and
  their rationale.
- **LAN reachability is not authentication.** Phase 1.5 makes the host
  and port configurable so Tracefall can be reached from other machines,
  but adds no login, no access control, and no TLS. This is a
  deliberate, explicitly-scoped-out omission for this phase, not an
  oversight — see docs/deployment.md and the Phase 2 list below.
- **KAPE's `!EZParser` module was run during collection**, so EvtxECmd /
  PECmd / RECmd CSV output is present alongside the raw files, per the
  "why CSV, not raw binary formats" section above.
- **Confidence is coarse (low/medium/high) on findings**, deliberately,
  to avoid manufacturing false precision from heuristics; **confidence on
  events (`Event.Confidence`) is a parser's confidence in field
  extraction fidelity**, a distinct concept from a finding's confidence.
- **Synthetic test data is clearly and only synthetic** — see
  `testdata/synthetic_case`'s own note in `docs/adding-parsers.md` and
  the README. It is never used as if it were real evidence anywhere in
  the codebase or docs.

## Recommended Phase 2

Roughly in priority order:

1. **Basic authentication/authorization and TLS**, now that Tracefall is
   easy to make LAN-reachable (Phase 1.5) — this is the most
   security-relevant gap remaining, and should land before recommending
   anyone leave a Tracefall instance running for long stretches on a
   shared network.
2. **Raw binary format parsers** behind the same `ArtifactParser`
   interface (raw `.evtx`, raw Prefetch, raw registry hives), so
   Tracefall doesn't require `!EZParser` to have been run.
3. **Multi-host cases** — accept a KAPE collection covering several
   machines, extend the normalized model's `host` handling accordingly
   (drop the dominant-host backfill assumption; ingestion should be able
   to determine host from the collection's own directory layout when
   present).
4. **More detection rules and a rule-authoring guide** — the current
   seven are a representative starter set, not comprehensive coverage of
   even the currently-supported artifact types.
5. **PostgreSQL migration** once concurrent multi-user access is needed
   (see docs/data-model.md's migration notes — the schema was kept
   deliberately close to a straightforward Postgres port).
6. **Threat intelligence enrichment** (e.g. IOC/reputation lookups on the
   `network_dest` field already present in the model) — additive, and
   must stay clearly separated from the deterministic detection engine.
7. **Optional LLM investigation copilot** — explicitly last, and
   explicitly additive/read-only over the deterministic findings this
   phase already produces, never a replacement for them and never part
   of the detection/correlation path itself.
