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

Memory images are analysed by driving Volatility 3 in a sandbox (see
docs/memory-analysis.md); Tracefall does not implement memory parsing
itself. Disk images are read and extracted per docs/disk-images.md.

Explicitly out of scope (and not attempted): acquiring images, malware sandboxing, automatic malware
verdicts, LLM/AI integration of any kind, threat intelligence
integrations, distributed architecture, or Kubernetes.

Authentication and authorization arrived in Phase 12: local accounts,
server-side sessions, and two roles (analyst / admin) separating
analysis from deletion and user administration. A non-loopback bind
without authentication is refused at startup. TLS is still not
terminated by Tracefall. See docs/security.md. The detection and correlation
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
   `internal/parsers/regpersist` (added in Phase 4) is a small shared
   *classification* helper, not itself an `ArtifactParser` — it lets the
   RECmd (hive-snapshot) and Sysmon (real-time event) parsers agree on
   which registry locations count as persistence, mirroring
   `internal/procclass`'s precedent for process/path classification.
4. **Normalization** (`internal/normalize`) holds parsing/canonicalization
   logic shared across parsers (timestamps, host/user casing, path→
   executable-name extraction) so every parser produces events on the
   same conventions instead of inventing its own.
5. **Event/evidence model** (`internal/model`) is the common schema
   everything downstream depends on — see [docs/data-model.md](docs/data-model.md).
6. **Detection engine** (`internal/detect`) runs fifteen deterministic
   rules over a case's normalized events and produces evidence-backed
   findings — see [docs/detection-engine.md](docs/detection-engine.md).
7. **Correlation engine** (`internal/correlate`) builds explicit
   relationships between events (process chains, entity linkages,
   temporal bursts, full activity-chain narratives) — see
   [docs/correlation-engine.md](docs/correlation-engine.md).
7a. **Investigation assessment layer** (`internal/investigate`, added in
    Phase 5) groups related findings/correlations into scored,
    narrated investigative stories — a read-time-only view, never
    persisted. See "Investigation assessment layer" above and
    [docs/investigation-assessment.md](docs/investigation-assessment.md).
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

Deterministic. Builds six kinds of relationship — process parent/child
chains, entity correlations (the same executable observed across
multiple independent artifact types), temporal clusters, full evidenced
activity-chain narratives (e.g. logon → Office → PowerShell/script host →
payload → persistence → network), credential chains (brute force;
explicit-credential use into subsequent activity), and service chains
(installation → the service actually starting → any network activity) —
never fabricating a step the evidence doesn't support. See
[docs/correlation-engine.md](docs/correlation-engine.md).

## Investigation assessment layer (Phase 5)

`internal/investigate` sits above detect/correlate, never beside or below
them: it takes their already-persisted output (Findings, Correlations)
plus the case's Events and groups them into a small number of
evidence-backed "investigations" — e.g. Office → PowerShell → payload →
persistence → network reported as one investigative story instead of
five separate findings an analyst would otherwise have to mentally
stitch together. Deterministic and pure, like detect/correlate: no LLM,
no network calls, same input always produces the same investigations in
the same order.

Grouping is based entirely on real evidence links — shared supporting
events between findings, or a correlation (process_chain, entity, or one
of the three narrative chain types) bridging events from two different
findings — **never** merely "same host" or "same time window" (a
temporal cluster specifically is excluded from grouping for this reason;
see `internal/investigate/group.go`'s doc comment). Each investigation
carries a documented, additive, explainable 0–100 risk score and a
confidence rating computed independently of severity (from correlation
strength and evidence diversity, not how bad a finding looks), plus a
deterministic, template-generated narrative — never an AI-written one.

Investigations are **never persisted** — no new table, no migration.
`Service.Investigations`/`Investigation` call `investigate.Run` at read
time against whatever Findings/Correlations are currently in the
database, the same "compute on read from existing store queries" pattern
`CaseSummary` and `AttackSummary` already use. This means deleting
evidence and re-running analysis can never leave a stale investigation
behind: the next `GET` simply recomputes from the current state. See
[docs/investigation-assessment.md](docs/investigation-assessment.md) for
the full grouping/scoring/confidence/narrative model.

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

Case names are unique across the whole installation (trimmed of
whitespace, case-insensitive) -- `Service.CreateCase` rejects a
duplicate with `409 Conflict` before creating anything, backed by a
database-level unique index for race safety. See docs/data-model.md's
"Case name uniqueness" section for the normalization rule and the
migration story for a database with pre-existing duplicate names.

Case lifecycle is a simple state machine: `created -> ingested ->
analyzed`, except it isn't strictly one-way -- importing new evidence
into an `analyzed` case, or deleting evidence from one, both move it
back to `ingested` (or all the way back to `created` if a deletion
removed the case's last remaining event), signaling that the analysis is
now stale. A case accepts any number of collections.

Adding evidence is two explicit calls, not one --
`Service.DiscoverEvidenceFromPath`/`DiscoverEvidenceFromUpload` catalog
every file in a package (supported or not) into `model.SourceFile` rows
without parsing anything, and a separate `Service.ImportEvidence` parses
exactly the file IDs an investigator selected from that catalog. See
docs/data-model.md's "Evidence selection workflow" section for the full
state machine (`discovered -> imported`, or `unsupported`/`duplicate`/
`failed`) and why this is deliberately two steps: a real KAPE package
routinely contains far more files than are relevant to a given
investigation, and Tracefall must not parse all of them automatically
just because a parser recognizes them. Both discovery calls share a
private `catalogEvidenceDirectory` helper (built on
`internal/ingest.Discover`), and `ImportEvidence` parses one file at a
time via `internal/ingest.ParseFile`, deduplicating each result against
everything already in the case (see docs/data-model.md's "Deduplication"
section) exactly the way ingestion always has. Analysis itself is
unchanged: idempotent and re-runnable (prior findings/correlations are
cleared and regenerated, so running it twice on unchanged evidence
produces the same result, never duplicates) and always operates on the
case's complete, deduplicated event list -- `internal/detect` and
`internal/correlate` have no notion of "collection" or "import batch" at
all, so this two-phase workflow needed zero changes to either.

Before either discovery call creates a `model.Collection` row, it hashes
the evidence source (the archive bytes for an upload, a deterministic
directory fingerprint for a local path — see docs/data-model.md's
"Duplicate evidence collections" section) and rejects an exact match
against an existing collection **in the same case** with `409
Conflict`, identifying which collection it duplicates, before
extracting or cataloging anything. A `(case_id, archive_hash)` partial
unique index is the race-safe backstop behind the upfront check
(`internal/api.Service.createCollectionOrDuplicateError`). Within a
single collection's own catalog, a file whose content (SHA-256) matches
one already discovered there is marked `duplicate` and can't be
selected for import -- but that check is deliberately *not* case-wide,
since the same file legitimately reappears across separate collections
(a follow-up triage re-collecting the same artifact); see
docs/data-model.md's "Evidence selection workflow" section.

`DiscoverEvidenceFromUpload` additionally: creates a clean per-collection
directory (`internal/casefiles`), saves the original archive unmodified
(provenance requirement), safely extracts it (`internal/archive` — see
docs/deployment.md for the full untrusted-input threat model), and — on
*any* failure at any of those steps — removes everything written for
that collection's attempt and marks it `failed`, without touching any
other collection already in the case. No half-discovered collection is
left in an ambiguous state, and no failure can corrupt evidence a
previous, successful collection already contributed.

Deleting evidence (`Service.DeleteSourceFile(s)`) and deleting a case
(`Service.DeleteCase(s)`) are the mirror image of adding it -- see
docs/data-model.md's "Evidence deletion" section for exactly how an
event that's still observed elsewhere survives a file deletion while
one that isn't gets removed, and how a case deletion's ordered,
transactional store-level cascade (`store.DeleteCase`) plus filesystem
cleanup (`casefiles.Store.RemoveCaseDir`) leaves no orphaned data
anywhere. Neither path touches `internal/detect`/`internal/correlate`
directly; both rely on the existing idempotent `AnalyzeCase` to
recompute findings/correlations correctly against whatever the current
event list turns out to be.

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
the JSON `Content-Type` the rest of the dashboard uses). If the
archive/path exactly duplicates a collection already in the case, the
API's `409` is shown as a distinct "Evidence already exists" message
(naming the existing collection) rather than the generic error box, and
no fake success/"Collection #N" result is ever rendered for a rejected
duplicate. Ingesting from a local filesystem path — no browser upload
involved — remains available as a collapsed "Advanced" option under the
same form, for local/dev use; both paths funnel into the same discovery
response shape.

Otherwise, the response is a **file selection screen**
(`renderDiscoveryResults`/`wireDiscoverySelection`), not a finished
result: every discovered file gets a row (filename, path, artifact type,
size, SHA-256), a checkbox pre-checked for anything selectable
(`discovered` status) and disabled for anything not (`unsupported`/
`duplicate`), and Select All/Select Supported/Clear All controls. Only
clicking **Import Selected** actually parses anything, via `POST
.../evidence/{collectionId}/import`; its result (files imported, events
parsed, new vs. already-known) is what's shown before continuing into
the dashboard. This can be repeated any number of times per case for
genuinely new evidence.

The **Evidence** tab is where investigators manage evidence at the
individual-file level (distinct from the dashboard's compact
collection-level summary panel): every imported file gets its own
checkbox and **Delete** button, grouped by the collection it came from,
with that collection's still-merely-discovered/unsupported files tucked
into a collapsed detail so the main list stays focused on actual
evidence. Checking files surfaces a bulk action bar (only while
something's selected) with a **Delete Selected (N)** action. Every
delete — single file, bulk files, single case (from the case header), or
bulk cases (from the case list, which gets the same checkbox/bulk-bar
treatment) — requires an explicit confirmation dialog naming what will
be removed before calling the corresponding `DELETE` endpoint; none of
these are ever a plain link click. After any deletion the page reloads,
so the "evidence changed, re-run analysis" banner (driven by the case's
`ingested`-not-`analyzed` status, see above) is never stale.

### Investigation views: cross-referencing client-side, not new APIs

The **Timeline**, **Findings**, **ATT&CK**, and **Activity Chains** tabs
were substantially reworked into a real investigation workspace without
adding a single new read endpoint -- every cross-reference they show
(which finding covers this event, which correlation an event
participates in, which tactic a technique belongs to) is a join over IDs
the existing `/timeline`, `/findings`, `/correlations`, and `/attack`
responses already carry (`Finding.SupportingEvents`,
`Correlation.EventIDs`, `attck.Technique.Tactic`), computed once
client-side in `app.js` (`buildEventFindingIndex`,
`buildEventCorrelationIndex`) after each tab's one fetch of its own
data. This was a deliberate call, not an oversight: Tracefall's target
scale (one KAPE-triage case at a time, hundreds to low thousands of
events) makes loading a tab's full dataset once and filtering/joining it
in the browser strictly cheaper than round-tripping to the server per
filter change, and "before adding endpoints, determine whether existing
ones already provide the data" is a standing project rule, not specific
to this phase.

The one genuine backend addition this phase needed was
`Service.Summary.ImportedSourceFiles` (see docs/data-model.md) -- the
existing `SourceFiles` count already active-cataloged files regardless
of import status, and the case overview needed the imported subset
specifically.

**Timeline** rows now show PID/PPID, a category badge
(`app.js`'s `EVENT_CATEGORIES`: authentication/execution/persistence/
network, a fixed table over `model.Event.EventType`, never inferred from
the string), a rolled-up severity badge and ATT&CK chips from any
finding that covers the row, and a "chain" indicator when the event is
part of a reconstructed activity chain. Clicking a row (or a Findings
raw-evidence row, or an Activity Chain node -- all three now share one
`loadProvenanceInto` helper) expands the same provenance drill-down:
Event -> RawEvidence -> SourceFile -> every collection that observed it.
A shared, config-driven filter bar (`renderFilterBar`/`wireFilterBar`/
`readFilterBar`) covers severity, category, host, user, process, ATT&CK
technique, evidence collection, and a UTC-labeled time range on Timeline,
and severity/confidence/rule/technique/host/user/collection/time range on
Findings -- entirely client-side over each tab's own already-fetched
data.

**ATT&CK** groups techniques by tactic in MITRE's own kill-chain order
(`CANONICAL_TACTICS`), not alphabetically; a technique belonging to more
than one tactic (a real, sometimes multi-valued field on
`attck.Technique`) is shown once per tactic, which is accurate coverage,
not duplication.

**Activity Chains** get an actual visual reconstruction -- vertical
steps connected by arrows (User Logon -> Office -> PowerShell ->
payload -> persistence -> network), each step showing the underlying
event's timestamp/process, a severity/ATT&CK rollup from covering
findings, and a click-to-expand provenance panel. Steps render in
exactly the order `correlate.BuildActivityChains` recorded them
(`Correlation.EventIDs`, never re-sorted or re-inferred client-side) --
`TestBuildActivityChains_FullNarrative` locks that ordering guarantee in
on the Go side, which is what makes it safe for the frontend to trust
positionally. Every other correlation type (process/entity/temporal)
still renders as a compact card, unchanged.

The case overview's **Investigation Summary** is a short, template-built
paragraph from counts already on the page (`buildInvestigationSummary`)
-- e.g. "11 finding(s) were observed across 2 evidence collection(s) (2
execution, 2 persistence)... 2 critical and 7 high-severity finding(s)
warrant immediate review." Every number is a direct count or grouping of
existing finding/technique data; there is no AI narrative and nothing is
estimated. A case with no evidence, or evidence that hasn't been
analyzed yet, gets an explicit sentence saying so rather than an empty
or misleading summary -- "insufficient evidence" as a stated fact, never
fabricated certainty.

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
- **LAN reachability now requires authentication** (Phase 12). Binding
  to a non-loopback address without it is refused at startup rather than
  warned about. Authorization is enforced by one middleware every API
  request passes through, so a route added later is protected by
  default. TLS is still **not** terminated by Tracefall — see
  docs/security.md for what that does and does not protect.
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

1. ~~**Basic authentication/authorization and TLS**~~ — authentication
   and authorization landed in Phase 12 (see docs/security.md). TLS
   termination is still delegated to a reverse proxy.
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
