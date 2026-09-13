# Data model

All types referenced here are defined in [`internal/model/model.go`](../internal/model/model.go),
Tracefall's only dependency-free domain package. Every other layer
(parsers, detect, correlate, store, api) depends on `model`; `model`
depends on nothing in this codebase.

## Provenance chain

An investigator must always be able to trace a finding back to the exact
original evidence it's built on. A case can hold more than one evidence
**Collection** (e.g. a morning KAPE triage and an afternoon follow-up),
and a real-world event that was independently re-collected in more than
one of them is deduplicated to a single `Event` row rather than stored
twice — so the chain is a full DAG at the bottom, not a single line:

```
Finding
  -> SupportingEvents  ([]model.Event, by ID; may span more than one Collection)
       -> EventObservation (one per Collection the event was actually seen in)
            -> RawEvidence   (that observation's exact original row/record, untouched)
                 -> SourceFile (which file, which parser, its SHA-256)
                      -> Collection (which upload/ingest this file arrived in)
```

This is not a documentation aspiration — it's enforced by the schema:
every `Event` carries a `RawEvidenceID` and a `SourceFileID` for its
*first* observation, and `event_observations` carries the complete list
for every observation. The API
(`GET /cases/{id}/events/{eventID}`) resolves the full chain — including
every collection the event was observed in — in one call. The
dashboard's finding-detail view uses exactly that endpoint, and shows
"Observed in: Collection #1, Collection #2" wherever it applies.

## `Case`

An investigation container. Every other row in the database is scoped to
exactly one case via `case_id`. A case is not tied to a single upload:
`GET/POST /cases/{id}/evidence` can add any number of Collections to it
over the life of an investigation.

| Field | Type | Notes |
|---|---|---|
| `id` | string (UUID) | |
| `name`, `description` | string | `name` is unique across the entire installation — see below |
| `status` | string | one of `created`, `ingested`, `analyzed` — see the case lifecycle state machine in [ARCHITECTURE.md](../ARCHITECTURE.md#api). Adding a new Collection to an `analyzed` case moves it back to `ingested`, signaling that analysis is stale. |
| `created_at`, `updated_at` | time (UTC) | |

### Case name uniqueness

Case names are unique across the whole Tracefall installation, not just
within some scope — enforced at the database level by
`idx_cases_name_unique`, a unique index on `LOWER(TRIM(name))`
(`internal/store/migrate.go`'s `enforceCaseNameUniqueness`, not the
static schema — see below). `internal/api.Service.CreateCase` also
trims the name before storing it, so what's persisted and displayed
never carries leading/trailing whitespace either.

Normalization decisions, and why:

- **Leading/trailing whitespace** is trimmed before storing and before
  comparing — `"WKSTN-042 Phishing Triage"` and
  `"  WKSTN-042 Phishing Triage  "` are the same case. Whitespace
  differences carry no investigative meaning and are almost always a
  copy-paste accident, not an intentional distinction.
- **Case differences are ignored for uniqueness** —
  `"WKSTN-042 Phishing Triage"` and `"wkstn-042 phishing triage"` are
  the same case. Case names are human-facing labels investigators read
  and type, not case-sensitive identifiers, so two entries differing
  only in capitalization are far more likely to be the same
  investigation created twice than two deliberately distinct ones.
  Unlike whitespace, the *stored* name keeps its original casing as
  typed — only the uniqueness comparison folds case, via `LOWER()` in
  the index expression and in `Store.FindCaseByName`'s query.
- **Exact duplicates** (identical after the above normalization) are
  always rejected — the case this feature exists for.

Duplicate detection is two-layered, the same pattern
`idx_collections_case_archive_hash` uses for evidence collections: a
SELECT-based pre-check (`Service.checkDuplicateCase`) avoids a doomed
`INSERT` in the common case and can identify the existing case by
name up front, and the unique index is the authoritative, race-safe
backstop for two concurrent requests that both pass the pre-check
before either has inserted — `Store.CreateCase` translates that
constraint violation to `ErrDuplicateCase`, which the API layer
re-resolves (via `FindCaseByName`) to a `DuplicateCaseError` identifying
whichever case actually won the race. `POST /cases` returns `409
Conflict` with a JSON body carrying `duplicate_case_id` and
`duplicate_case_name` so the dashboard can show "Case already exists"
without parsing it back out of a sentence.

**Migrating an existing database**: unlike the migrations described
below, a database that already contains two cases with colliding names
(from before this constraint existed) has no safe automatic fix —
deleting or merging either case would destroy investigation data, and
silently renaming one would be an unrequested, opinionated change to
case identity that could confuse an investigator relying on that name.
So `enforceCaseNameUniqueness` checks for existing collisions before
creating the index, and if any exist, `Open()` (and therefore Tracefall
itself) refuses to start, returning an error that lists exactly which
case names collide and their case IDs. An operator resolves this by
renaming one of the conflicting cases by hand (e.g. directly in the
database, or via a future rename endpoint) and restarting.

## `Collection`

One independent evidence-gathering event ingested into a case — one
KAPE ZIP uploaded through the browser, or one local-path ingest.
Everything downstream (timeline, findings, correlations, ATT&CK
coverage) always operates across every collection in the case; a
collection exists to preserve *when and how* evidence arrived, not to
scope analysis.

| Field | Type | Notes |
|---|---|---|
| `collection_id`, `case_id` | string (UUID) | |
| `created_at` | time (UTC) | |
| `source_type` | string | `kape_upload`, `local_path`, or `legacy` (synthesized for evidence ingested before collections existed — see "Migrating an existing database" below) |
| `original_filename` | string | the uploaded ZIP's filename, or the given local path |
| `archive_hash` | string | SHA-256 of the uploaded archive, or a deterministic fingerprint of a local-path source's relative file paths + contents (see below); empty for `legacy` collections that predate this field |
| `evidence_directory` | string | where this collection's extracted evidence lives on disk — see [docs/deployment.md](deployment.md) for the on-disk layout |
| `ingestion_status` | string | `pending` (discovered, nothing imported yet), `ingested` (at least one file imported), or `failed` |
| `file_count`, `supported_file_count`, `unsupported_file_count` | int | active (non-deleted) files discovered; `file_count == supported_file_count + unsupported_file_count` |
| `imported_file_count` | int | of the supported files, how many have actually been imported (see "Evidence selection workflow" below) |
| `parsed_event_count` | int | total events produced by imported files, **including** ones that turned out to be duplicates of an event from another collection |

### Duplicate evidence collections

Before a collection is created, its evidence source is hashed and
checked against every existing collection in the same case
(`case_id`, `archive_hash`) — a match is rejected with `409 Conflict`
identifying the existing collection, before anything is extracted,
parsed, or ingested. A `(case_id, archive_hash)` partial unique index
(`WHERE archive_hash != ''`) is the authoritative backstop against two
concurrent requests both passing the pre-check before either has
inserted; the SELECT-based check exists only to short-circuit the
common (non-racing) case before doing the work of hashing's downstream
steps. `archive_hash` is deliberately **not** globally unique — the
same evidence may legitimately be added to more than one case, just not
twice to the same one.

For an uploaded ZIP, the hash is the SHA-256 of the archive bytes,
computed while staging the upload (before extraction). For a
local-path source, `internal/api.hashDirectory` walks the directory in
lexical order and hashes each regular file's path-relative-to-root and
content — deliberately excluding mtimes, permissions, and other
directory metadata that don't reflect the evidence itself. Either way,
this is exact-hash equality only: two archives with identical file
contents but different ZIP metadata (e.g. two independent re-zips of
the same KAPE output) currently hash differently and are **not**
detected as duplicates. Content-level fingerprinting is a possible
future enhancement, not implemented here.

## `SourceFile`

One individual evidence file *discovered* inside a collection — the
unit an investigator selects, imports, inspects, and deletes
independently. First link in the provenance chain below `Collection`.
Source files are never deduplicated across collections — if the same
physical file is present in two collections, it's two `SourceFile` rows,
because "this file was included in this collection" is itself a fact
worth preserving, distinct from whether the *events* inside it turned
out to be new.

| Field | Type | Notes |
|---|---|---|
| `id` | string (UUID) | |
| `case_id`, `collection_id` | string | |
| `original_filename` | string | basename as it appeared in the package |
| `path` | string | relative to the collection's evidence root |
| `artifact_type` | string | one of the `model.Artifact*` constants; empty if unsupported |
| `parser` | string | parser name **and version**, e.g. `evtxcsv@1` — bumping a parser's output shape should bump this; empty if unsupported |
| `supported` | bool | a parser was detected for this file, whether or not it has since been imported |
| `size_bytes` | int64 | |
| `sha256` | string | hash of the file's content, for integrity/chain-of-custody and duplicate detection |
| `import_status` | string | `discovered`, `imported`, `unsupported`, `duplicate`, or `failed` — see "Evidence selection workflow" below |
| `event_count` | int | how many events this file produced; 0 until imported |
| `discovered_at` | time (UTC) | when this file was first cataloged |
| `imported_at` | time (UTC), nullable | when it was actually parsed; unset until imported |
| `deleted_at` | time (UTC), nullable | soft-delete marker (see "Evidence deletion" below); unset while active |

### Evidence selection workflow

Adding evidence is two explicit steps, not one: **discover**, then
**import**. `POST /cases/{id}/evidence` (upload) and `POST
/cases/{id}/ingest` (local path) safely extract/read the package and
catalog *every* file inside as a `SourceFile` row — supported or not —
without parsing any of them. Nothing becomes evidence yet: no events
exist, no finding is possible, until `POST
/cases/{id}/evidence/{collectionId}/import` is called with the specific
file IDs an investigator selected from that catalog. Only those files
are actually parsed (`internal/ingest.ParseFile`), deduplicated exactly
the way a whole-directory ingest always has (see "Deduplication"
below), and turned into events.

This is a deliberate choice, not a staging inefficiency: a real KAPE
package routinely contains far more files than are relevant to a given
investigation, and parsing happens once, on purpose, for exactly the
files an investigator chose — not automatically for everything a parser
merely recognizes.

A file's `import_status` is one of:

- `discovered` — cataloged, supported, selectable for import.
- `imported` — selected and successfully parsed into events.
- `unsupported` — no parser recognizes it; cannot be selected.
- `duplicate` — content (by SHA-256) identical to another file already
  discovered *in this same collection* (e.g. the same file appearing
  twice in one package); cannot be selected. Deliberately **not**
  checked against other collections in the case — the same file
  legitimately reappears across separate collections all the time (a
  follow-up KAPE triage re-collecting `Security.csv` hours later), and
  that's exactly what event-level `DedupHash`/`EventObservation` exists
  to handle; a file-level check spanning collections would incorrectly
  block it. A `(collection_id, sha256)` partial unique index enforces
  this scope race-safely, the same pattern
  `idx_collections_case_archive_hash` uses one level up.
- `failed` — selected for import, but its parser returned an error.

### Evidence deletion

Deleting a `SourceFile` (`DELETE /cases/{id}/evidence/{fileId}`, or in
bulk via `DELETE /cases/{id}/evidence` with `source_file_ids`) is a soft
delete (`deleted_at` set); it's excluded from every active listing and
count from then on, and its on-disk copy is removed too — but only for
evidence Tracefall itself extracted and owns (an uploaded ZIP's
contents). A local-path collection's evidence directory is wherever the
investigator's own files already live on disk; Tracefall never deletes
files it doesn't own.

Deleting a file removes its contribution to the case's events:

1. Each of its `EventObservation` rows (see below) is deleted.
2. If that was an event's *last* observation, the `Event` row itself is
   deleted — nothing supports it anymore.
3. If the event survives via another observation (the same real-world
   event was also seen through a different file), it's kept, and if its
   own denormalized provenance fields (see `Event`, below) pointed at
   the file just deleted, they're re-pointed at a surviving observation
   so nothing dangles.
4. The case's status is set to `ingested` (or `created`, if that was the
   case's last remaining event) — never left at `analyzed` — so the
   dashboard prompts a re-run rather than continuing to show findings
   computed from evidence that's now gone. `internal/detect` and
   `internal/correlate` need no special-casing for deletion at all: they
   always recompute from the case's complete *current* event list, the
   same way they already do when evidence is added, so the next
   `POST /analyze` naturally drops findings/correlations no longer
   supported and keeps ones that are.

Deleting a case (`DELETE /cases/{id}`, or in bulk via `DELETE /cases`
with `case_ids`) is permanent, not soft: every row anywhere in the
database belonging to that case (collections, source files, raw
evidence, events, observations, findings, correlations) is removed in
one transaction, in dependency order, followed by removing the case's
entire on-disk directory. It never affects another case, even one that
happens to hold evidence with an identical archive/source hash (hash
uniqueness is scoped per case, never global — see "Duplicate evidence
collections" above).

## Case deletion

Deleting a case destroys the case and everything belonging to it. It is
**synchronous**: the HTTP response is written only after every row and
the case's own storage are gone. There is no background job, and nothing
in the UI reports completion earlier than the server does.

### What is deleted

Database, in one transaction (`store.DeleteCase`), in dependency order:

`event_observations`, `raw_evidence`, `events`, `findings`,
`correlations`, `source_files`, `collections`, `notes`, `tags`,
`analyst_status`, `audit_log`, `analysis_runs`, and finally `cases`.

Filesystem (`Service.DeleteCase` → `casefiles.RemoveCaseDir`): the
case's whole directory — the original uploaded ZIP or AD1, the staged
upload, every extracted evidence file, and collection metadata.

Derived views need no deletion because they are not stored:
**investigations** and **ATT&CK mappings** are computed from findings,
correlations and events at request time, so they cease to exist the
moment those do.

### What is retained, and why

| Kept | Reason |
| --- | --- |
| `security_log` rows naming the case | System-wide record of who used the SYSTEM. A denied request against a case still says which case it concerned, and deleting the case must not erase the record that someone was refused access to it. Its `case_id` is deliberately unconstrained. See [security.md](security.md). |
| Evidence ingested from a **local folder** | It is the investigator's own data, not storage Tracefall owns. Only the case's own directory is removed. |

The deletion itself is recorded in the `security_log` — not in the
case's `audit_log`, which is part of the case and is deleted with it. An
entry written there would erase itself.

### Ordering, and what happens when it fails

The database transaction commits first, then the filesystem removal.
The two cannot be atomic across a database and a disk, so the failure is
pushed into the direction that stays honest: storage may outlive its
record, but a case never lists evidence it no longer has.

A filesystem failure therefore returns an error that says the rows were
deleted and the directory was not fully removed — never "the files are
still there", because removal is depth-first and a partial failure
leaves an unknown mixture. **Repeating the delete request completes the
cleanup**: the operation is idempotent, and a case whose rows are gone
but whose directory remains is recognized and finished rather than
refused with "not found". A case that never existed is still refused.

### Cost

Deletion is `DELETE ... WHERE case_id = ?` against an indexed column,
plus one `RemoveAll`. Measured on this build:

| Events | Case-owned rows | Time |
| ---: | ---: | ---: |
| 1,000 | 3,017 | 23 ms |
| 10,000 | 30,017 | 204 ms |
| 100,000 | 300,017 | 2.4 s |

A real 1,353-file case with 7,642 events, 8,832 raw records and 220 MB
of extracted evidence deleted in **485 ms end to end** through the HTTP
API. It is fast because the work is genuinely small, not because it was
deferred.

---

## `RawEvidence`

The untouched original record a parser read — a CSV row (as JSON) or an
XML document (as JSON), verbatim. Normalization never mutates this; it's
what "auditable and reversible" normalization means in practice.

| Field | Type | Notes |
|---|---|---|
| `id` | string (UUID) | |
| `case_id`, `source_file_id` | string | |
| `source_reference` | string | e.g. `row:12` or `task:MyTaskName` — human-readable locator within the source file |
| `raw` | string | the original record, as parsed (JSON-encoded) |

## `Event`

Tracefall's normalized evidence record — the schema every parser targets
and every downstream layer (detect, correlate, api) reasons over. Once an
`Event` exists, nothing downstream ever looks at the artifact-specific
format it came from again.

| Field | Type | Notes |
|---|---|---|
| `id`, `case_id` | string | |
| `timestamp` | time | **always normalized to UTC** |
| `host`, `user` | string | `host` is uppercased for stable comparison (Windows hostnames are case-insensitive); backfilled from the dominant host in the case for artifacts that don't carry one natively (Prefetch, registry) — see ARCHITECTURE.md's assumptions |
| `event_type` | string | normalized, artifact-agnostic vocabulary (`process_create`, `logon_success`, `registry_run_key_set`, ...) — deliberately a smaller set than the Windows Event IDs / artifact formats it's derived from |
| `provider` | string | e.g. `Security`, `Microsoft-Windows-PowerShell/Operational` |
| `event_id` | int | the Windows Event ID, where applicable (0 otherwise) |
| `process_name`, `process_path` | string | `process_name` is always the lowercased basename; `process_path` the full path when available |
| `parent_process`, `parent_process_path` | string | same convention, for the parent process |
| `pid`, `ppid` | int64 | |
| `command_line` | string | also used for a PowerShell script block's text |
| `file_path` | string | overloaded per artifact: a Prefetch executable's source path, a registry Run key's value data, etc. |
| `registry_path` | string | full `KeyPath\ValueName` |
| `network_source`, `network_dest`, `network_dest_port` | string/string/int | |
| `artifact_type`, `collection_id`, `source_file_id`, `source_reference`, `parser` | | provenance fields for this event's *first* observation — see "Deduplication" below for why that qualifier matters |
| `confidence` | float64 | **the parser's confidence in field-extraction fidelity** — e.g. Prefetch's `LastRun` approximates but doesn't guarantee exact execution time, so `pecmd` emits `0.9`, not `1.0`. This is *not* a finding's confidence (see below) — a different concept, deliberately named the same because it answers the same underlying question ("how much do I trust this") at a different layer. |
| `raw_evidence_id` | string | this event's first observation's raw record |
| `dedup_hash` | string | see "Deduplication" below |
| `extra` | `map[string]string` | see "Why `Extra` instead of more columns" below |

### Phase 4 artifact coverage

Phase 4 ("Expand Windows DFIR Triage Coverage") added nine new
`event_type` values and their supporting parser coverage, prioritizing
Event IDs/Sysmon events that feed a specific new detection rule or
correlation over exhaustive coverage (see `docs/detection-engine.md` and
`docs/correlation-engine.md`):

| `event_type` | Source | Feeds |
|---|---|---|
| `logon_explicit_credentials` | Security 4648 | `explicit-credential-use`, `credential_chain` |
| `privileged_logon` | Security 4672 | `privileged-logon-observed` |
| `kerberos_tgt_request` | Security 4768 | timeline/correlation visibility only (no dedicated rule) |
| `kerberos_service_ticket_request` | Security 4769 | timeline/correlation visibility only |
| `ntlm_authentication` | Security 4776 | timeline/correlation visibility only |
| `service_install` | System 7045 (Service Control Manager) | `service-persistence`, `service_chain`, extends `execution-persistence-temporal` |
| `file_create` | Sysmon Event ID 11 | activity-chain step labeling (observing a payload land on disk) |
| `registry_persistence` | Sysmon Event ID 12/13 *or* RECmd, classified by `internal/parsers/regpersist` | `registry-persistence-extended`, extends `execution-persistence-temporal` and the activity chain |
| `dns_query` | Sysmon Event ID 22 | timeline/correlation visibility (`network_dest` carries the queried domain, not an IP, for this type specifically) |

Existing types gained additional sources: `process_create` and
`network_connection` are now also produced by Sysmon Event ID 1
(ProcessCreate) and a corrected Event ID 3 (NetworkConnect, which now
actually populates the typed `network_dest_port` int field — Phase 1's
code only stashed it as a string in `Extra`, a gap Phase 4 fixed) — so a
case collected with only Sysmon telemetry (no Security auditing enabled)
still gets full process/network coverage, not a second-class subset.
PowerShell 4103 (module logging) is normalized to the same
`powershell_script_block` type as 4104 (script block logging), so
`powershell-encoded-command` scans both sources identically;
`Extra["log_type"]` records which one a given event actually was.

**No new `Event` columns, no database migration.** Every Phase 4 field
(target user name, service name, integrity level, run level, task path,
volume info, DNS query name, ...) lives in the existing `Extra
map[string]string` field, per the "why `Extra` instead of more columns"
rationale above — Phase 4 is exactly the kind of artifact-specific,
per-type detail that rationale was written for. `internal/store`'s schema
was untouched by Phase 4; an existing database upgrades with zero new
migration steps.

`internal/parsers/regpersist` is a new small shared package (mirroring
`internal/procclass`'s precedent) that classifies a registry key/value
path against Tracefall's fixed set of recognized persistence locations
(Run/RunOnce, Winlogon Shell/Userinit, IFEO Debugger hijacking,
AppInit_DLLs, a service's `ImagePath`) — used identically by the RECmd
hive-snapshot parser and the Sysmon real-time registry-event handling in
`evtxcsv`, so the same real-world key is classified the same way
regardless of which artifact reported it.

### Deduplication

When a collection is added to a case that already has evidence, every
newly-parsed event is checked against everything already in the case
(across every prior collection) by `Event.ComputeDedupHash()` — a SHA-256
over a fixed set of identity fields: event type, timestamp, host, user,
process name, parent process name, PID, PPID, file path, registry path,
artifact type, Windows event ID, and network destination. A match means
the same real-world event was independently observed again — the
canonical example is a Windows Event Log record still present in the log
at both an 08:00 and a 14:00 KAPE triage of the same host — and no
second `Event` row is created for it.

`CommandLine`/script text is deliberately **excluded** from the hash:
host + process + PID + an exact timestamp already pin an execution down
about as precisely as anything short of a full content hash could, a
genuine re-collection reproduces the command line byte-for-byte anyway,
and excluding it keeps the hash insensitive to a field that can be
arbitrarily large (an encoded PowerShell command). `CaseID` and
`CollectionID` are excluded too, on purpose — hashing either in would
defeat cross-case or cross-collection matching entirely, which is the
whole point of the function. See `internal/model/dedup.go`'s doc comment
for the complete rationale.

Deduplication **never discards provenance**: every parsed record —
whether it turned out to be new or a duplicate — gets an
`EventObservation` row (below). An event observed in two collections has
two observations and one `Event` row.

## `EventObservation`

Records that a (deduplicated) `Event` was observed in one specific
collection, via one specific source file and raw record. This is the
data behind an "Observed in: Collection #1, Collection #2" display, and
the reason deduplication doesn't mean information loss: every collection
that actually contained a copy of the event is still recorded, just not
as a second competing `Event`.

| Field | Type | Notes |
|---|---|---|
| `id`, `event_id`, `case_id`, `collection_id` | string | |
| `source_file_id` | string | |
| `raw_evidence_id` | string | this observation's own raw record (distinct from the event's `raw_evidence_id`, which is specifically the *first* observation's) |
| `source_reference` | string | |

### Deviations from the brief's suggested field list

The brief suggested a field list "similar to" what's implemented, and
explicitly invited deviating from it where the architecture suggests a
better model. Two deviations, both additive:

- **`ppid` / `parent_process_path` were added.** Windows Security 4688
  events carry the parent process's image name (and, via `ProcessId`,
  its PID) directly — Tracefall doesn't need to walk a PID tree to know
  a process's parent, so it was natural (and directly useful to
  `internal/correlate`'s process-chain correlation) to carry that
  through as first-class fields rather than discarding it.
- **`Extra map[string]string` instead of more first-class columns.**
  Windows event log providers each define dozens of fields; making every
  artifact-specific field name (`logon_type`, `value_name`, `task_name`,
  `script_block_id`, `run_count`, ...) a first-class `Event` column would
  produce a schema that's mostly empty for any given event and that
  every new artifact type would need to extend. `Extra` keeps the common
  schema small, stable, and detection/correlation-relevant, while still
  preserving that detail (each field a short, documented snake_case key)
  for rules and investigators that need it. Every parser package's doc
  comments and code list exactly which `Extra` keys it sets.

## `Finding`

The output of one detection rule firing once, always case-level: a
finding's supporting events can come from more than one collection (e.g.
an execution event from a morning triage and a persistence event a
follow-up triage discovered hours later), because `internal/detect` runs
against the case's complete, deduplicated event list, not a
per-collection one — see [ARCHITECTURE.md](../ARCHITECTURE.md) and
[docs/detection-engine.md](detection-engine.md). Always backed by
concrete evidence.

| Field | Type | Notes |
|---|---|---|
| `finding_id`, `case_id` | string | |
| `detection_rule` | string | the rule's ID, e.g. `office-spawns-powershell` |
| `title`, `description` | string | |
| `severity` | string | `low` / `medium` / `high` / `critical` |
| `confidence` | string | `low` / `medium` / `high` — deliberately coarse; see docs/detection-engine.md |
| `supporting_event_ids` | `[]string` | never empty — see docs/detection-engine.md |
| `attack_techniques` | `[]string` | ATT&CK technique IDs, resolved to full metadata only at the API boundary via `internal/attck` |
| `first_seen`, `last_seen`, `created_at` | time | |

## `Correlation`

A deterministic relationship between two or more events, also case-level
for the same reason findings are: `internal/correlate` never sees
"collection" as a concept, only the case's full event list, so a process
chain, entity correlation, or activity chain can span collections
whenever the underlying rule's evidence supports it. See
[docs/correlation-engine.md](correlation-engine.md) for the four types
and how each is built.

| Field | Type | Notes |
|---|---|---|
| `correlation_id`, `case_id` | string | |
| `correlation_type` | string | `temporal` / `entity` / `process_chain` / `activity_chain` |
| `title`, `description` | string | |
| `event_ids` | `[]string` | ordered where sequence is meaningful (e.g. `activity_chain`) |
| `first_seen`, `last_seen` | time | |

## Storage schema notes

The SQLite schema (`internal/store/schema.go`) mirrors these types
closely, with one deliberate simplification: a `Finding`'s
`supporting_event_ids` and `attack_techniques`, and a `Correlation`'s
`event_ids`, are stored as JSON text columns rather than normalized join
tables. Tracefall never needs to query "which findings reference event
X" at the SQL level — the API loads a case's findings/correlations
wholesale and works with them in Go. This is an intentional MVP
simplification ("do not over-engineer infrastructure"), not an
oversight: if a future phase needs that query pattern, normalizing these
into `finding_events` / `finding_techniques` / `correlation_events` join
tables is a mechanical, low-risk migration.

`event_observations`, by contrast, *is* a proper join-shaped table
(`event_id` / `collection_id` / ...) rather than a JSON column, because
"which collections was this event observed in" is queried directly
(`store.ListEventObservations`) on essentially every event-detail view.

### Migrating an existing database

Tracefall has had exactly one schema change that needed an in-place
upgrade: introducing `collections` and `event_observations`, and adding
`collection_id`/`dedup_hash` to `source_files`/`events`. Rather than
build a general migration framework for that one change, `internal/store/migrate.go`
runs a small, idempotent upgrade on every `Open()`:

1. `ALTER TABLE ... ADD COLUMN` for any column a pre-existing
   `source_files`/`events` table is missing (a **brand new** database
   never hits this path — its tables are created with every current
   column directly, via `schema.go`).
2. For any case with source files/events that predate collections
   (`collection_id == ""`), synthesizes one `Collection` (`source_type =
   "legacy"`) and backfills `collection_id` onto them, so old evidence
   remains fully visible through the current, collection-aware API
   instead of erroring or silently disappearing.
3. Backfills `dedup_hash` for any event that doesn't have one yet, so
   deduplication works correctly the next time evidence is added to an
   old case. Events already stored as separate rows before deduplication
   existed are **not** retroactively merged — only made hash-comparable
   going forward.

This was tested against a real pre-collections database from manual
testing, not just synthetic fixtures (see
`internal/store.TestMigrate_LegacyDatabase`).

### Migrating to PostgreSQL

The schema was written to make this straightforward when it's needed
(multi-user/concurrent-write access, which SQLite doesn't handle well):

- Every table already uses explicit `TEXT`/`INTEGER`/`REAL` columns with
  UUID primary keys (no SQLite-specific rowid reliance) and explicit
  foreign keys.
- Timestamps are stored as fixed-width UTC strings
  (`2006-01-02T15:04:05.000000000Z`) specifically so they sort correctly
  as plain text — this maps directly onto a Postgres `timestamptz`
  column without any data transformation.
- The JSON text columns described above map directly onto Postgres
  `jsonb` columns (which additionally allows indexing/querying into them
  natively, if that's ever needed, without a join-table migration at
  all).
- `internal/store` is the *only* package that imports the database
  driver or writes SQL — switching drivers is a change to one file.
