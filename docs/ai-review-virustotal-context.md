# Stored VirusTotal context in AI Case Review

Stored reputation is optional additional input to **Case Review**, not a new lookup.
No VT key, connection, request or quota entry is needed. Core analysis, findings,
severity and legacy findings-only Summary are unchanged. Neither Case Review nor
its VT context is added to the report appendix or an analyst-acceptance workflow.

## Permission and outbound contract

The preparation receipt is `parsed-review-privacy-v2`. Selection and a successful
privacy check are not permission. External models still require case
`pseudonymized` egress and explicit acknowledgement bound to the current preview
or batch plan. Hash-only VT permission is **not** LLM permission. Local models keep
the existing exception. Status, preview, plan and citation reads send nothing.
No VT request/ledger entry is made by this feature, including synthesis.

Only same-case `provider=virustotal` records participate. The model sees `V1`,
`V2`, etc., a stable packet-local `[HASH_n]` pseudonym, fixed lookup status,
original recorded lookup time (or `unknown`), numerical verdict counts when
validated, and aliases of selected original events. Aliases are scoped by packet;
equal-looking aliases in different packets are not equal identities.

Raw hashes, enrichment/event/case IDs, filenames, paths, URLs, API keys,
`ResultJSON`, `Error`, provider labels/names/type descriptions/last-analysis text
are not reputation input. The existing selected normalized event contract still
applies to event excerpts; it does not gain arbitrary provider fields. Provider
prose is not used to teach the reversible dictionary. The exact combined system
and user bytes, including VT instructions/facts/coverage, enter existing payload
hashes, consent binding and request/input/output budgets.

V records are **point-in-time stored external opinion**, not primary forensic
evidence, proof of compromise, a fresh/current check, or a safety verdict. A
`not_found` lookup means no matching accessible record at that lookup time; it
proves neither safety nor that the file was never submitted. Zero detections
also do not establish safety. Unknown lookup time is not filled from the event,
server clock or year 0001. The model is instructed to preserve time, denominator
and uncertainty. Structural citation/type validation is not semantic truth.

### Linkage and numerical validation

* Require lowercase hexadecimal MD5/SHA1/SHA256 of exactly 32/40/64 characters,
  with matching `indicator_type`. No trimming or case normalization. Reuse VT
  candidate exclusions for all-zero and empty-content hashes.
* Resolve only explicit `SourceEventIDs`, within the same current or frozen
  case snapshot, with exact matching content hash fields: `content_sha256`,
  `response_sha256`, `sha256` for SHA256, `sha1` for SHA1, `md5` for MD5.
  No filename, process/name, host or time join; no foreign/wrong-hash references.
* Include an opinion only alongside at least one selected, verified original
  event excerpt. Relevant VT context attaches to each eligible packet; there
  are no separate VT-only packets deferred beyond a large case's request budget.
* `found` requires a JSON object with `found:true` and all seven explicit integer
  fields: `malicious`, `suspicious`, `harmless`, `undetected`, `timeout`, `failure`,
  `type_unsupported`. Each and their combined sum must be 0..10000. Missing,
  null, fractional, negative, overflow, malformed or contradictory found records
  are `unusable`, never zero detections.
* `engines` is derived as malicious+suspicious+harmless+undetected: engines with
  a verdict. Timeout/failure/type-unsupported stay separate, outside that
  denominator. `not_found` and `error` retain their fixed status without invented
  numerical verdicts. Unknown status prose becomes `unusable` locally and never
  exits. These derived statuses do not rewrite stored provider answers.

## Coverage and limits

The existing single preview/latest and each prepared batch packet have integer
`coverage.vt_total`, `vt_included`, `vt_omitted`, `vt_invalid`, `vt_unlinked`.

These integers are meaningful only when **`coverage.vt_recorded === true`**.
New preparation records this boolean even for an actual zero-row VT census,
before the no-VT prompt early return. Raw new snapshots, prepared initial
packets and prepared synthesis use the same coverage marker. A plan additionally
has **top-level `vt_recorded`** for its distinct included/omitted census; the raw
catalog marker remains at `snapshot.coverage.vt_recorded`. Both booleans always
serialize, including `false` on typed old-row/status/plan/history readbacks.
Absent or false means **not recorded**, regardless of any zero-valued integer
fields introduced by typed decoding. Raw old packet pages may still omit the
marker; the UI treats that identically. Budget-disabled/unprepared packets have
no prepared census and do not claim one. Never infer presence from the counts,
backfill historical rows, or confuse a new recorded zero with old unknown data.
The marker is local metadata, not an extra prompt line or canonical input field;
no-VT payload bytes and fingerprints stay compatible.

* `total`: all same-case stored VT rows in the relevant full source catalog.
* `included`: distinct original enrichment IDs actually present in this payload.
* `omitted = total - included`: exclusive complement, including unavailable
  linkage, invalid indicators, event selection, record cap and byte omissions.
* `invalid`: invalid/trivial indicator or derived unusable answer. This overlaps
  omitted **and** included: a valid linked hash with unusable statistics may
  still be sent as `status=unusable`, with no invented counts.
* `unlinked`: valid nontrivial indicator with no verified original event in the
  full snapshot. It overlaps omitted and can overlap invalid for an unusable
  answer. Invalid indicators are counted invalid, not additionally unlinked.
  An opinion linked to an unselected event is omitted, not unlinked.

Whole-catalog values are carried separately from the bounded retained rows; caps
never turn the catalog census into a sample. A raw frozen snapshot itself has
`vt_included=0`, `vt_omitted=vt_total` because it is not an outbound selection.
The batch plan adds top-level **distinct** `vt_included` and `vt_omitted` across
budget-enabled initial packets. Do not sum repeated VT context over packets or
synthesis. Whole-catalog totals/invalid/unlinked remain in `snapshot.coverage`.
Primary/distinct successful **event** counts are unchanged and do not count VT.
Plan omission marks input incomplete; reviewed coverage is never inferred from
model prose.

At most 60 opinions per payload, 120 selected event aliases, and 120 local
readback event references per opinion. Over-cap VT records remain omitted. The
existing combined 160000-byte payload ceiling remains; VT rows are admitted
only with room for fixed VT coverage text (512 bytes reserved), otherwise
explicitly omitted rather than displacing primary excerpts. Existing primary
payloads that exceed the overall ceiling are still refused. No-VT prompt bytes
and historical no-VT canonical fingerprints remain unchanged.

VT source rows stream in ID pages of 60, rejecting raw rows above 128 KiB in
SQLite before scanning (all scalar/reference/result/error fields included).
Serialized rows above 1 MiB, more than 1000000 records, or more than 256 MiB
serialized VT input are refused. Batch snapshot caps also cover all primary and
VT records together (1000000 / 256 MiB). Existing privacy dictionary name/byte
caps still apply; arbitrary VT strings never enter it. Batch VT preparation keeps
one bounded page plus at most 60 linked records, not a whole-case VT slice.
The legacy single path still materializes primary case events: this feature does
not make that path bounded-RAM. Scans and explicit reference resolution can take
O(case-size) work and multiple local queries; bounds are not a production-scale
throughput claim.

## Freezing, staleness and citations

Full source fingerprints include all same-case VT rows, including opinions
omitted from a payload and changes to their time, status, results and references.
Other providers/foreign cases are excluded. The historical four-kind streaming
fingerprint walker stays separate; VT is an optional canonical suffix, preserving
no-VT nil/empty-reference normalization and cache parity. A VT update after a
plan refuses Start. Single preview keys and latest staleness also react to VT
updates. Single preparation rejects a changed before/after source fingerprint.

Single attempts retain bounded optional `frozen_vt` DTOs in the existing
`case_reviews.record_json` **before** dispatch. Old rows are not rewritten;
absent frozen data means not recorded/unavailable. Batch manifests freeze raw
local source records once, alongside primary members. `manifest?kind=enrichment`
pages IDs/ordinals only, with `primary_packet_seq:-1`; it never returns raw JSON.

Accepted model citation JSON is `{"kind":"enrichment","id":"original-stored-id"}`.
The model only sees V aliases. Upsert preserves an enrichment's original ID while
replacing live content, so citations **must** use review/run context:

* `GET /api/cases/{id}/enrich/case-review/{review}/virustotal/{enrichment}`
* `GET /api/cases/{id}/enrich/case-review/batches/{run}/virustotal/{enrichment}`

Both inherit the ordinary authenticated analyst/session and request-source
protections. Unknown/wrong-case review/run/member, an unrecorded old single
attempt, or a non-citable invalid indicator returns 404. There is **no live
fallback**. The single route resolves only the exact attempted DTO; batch reads
resolve only the frozen manifest and frozen original events, not live Upserts.
The single ServeMux implementation uses a validated reference suffix to avoid
Go's ambiguity with the existing `batches/{run}/packets` route; the public URL
above is unchanged and other suffixes return 404.

### Flat local-only readback schema

```json
{
  "id": "original-enrichment-id",
  "provider": "virustotal",
  "indicator_type": "sha256",
  "indicator": "raw-lowercase-content-hash-local-only",
  "status": "found",
  "fetched_at": "2024-03-03T05:06:07Z",
  "verdicts_recorded": true,
  "malicious": 2,
  "suspicious": 0,
  "harmless": 1,
  "undetected": 3,
  "timeout": 1,
  "failure": 0,
  "type_unsupported": 0,
  "engines": 6,
  "source_event_ids": ["verified-original-event-id"],
  "omitted_refs": 0,
  "scope": "single_review_attempt_snapshot"
}
```

`status` is exactly `found|not_found|error|unusable`. `fetched_at` is the recorded
UTC RFC3339Nano time or **empty string**, never current/year-0001 time. If
`verdicts_recorded:false`, all eight optional numerical fields are omitted, not
zero-filled. `source_event_ids` is always an array, deduplicated and sorted, with
only verified same-snapshot links. Single DTO links are to included event
excerpts; batch local readback checks the full frozen run. At most 120 IDs are
returned, and `omitted_refs` counts additional verified references omitted by the
readback cap. `scope` is fixed `single_review_attempt_snapshot` or
`batch_run_snapshot`. No raw error/result/free text/URL/credential field is
returned. Raw hash is allowed in this authenticated local DTO, never outbound.

## Synthesis

Only structurally accepted, locally restored commentary is eligible. A cited V
record and necessary verified original event excerpts are read from the frozen
manifest and prepared in a new namespace, preserving numerical opinion/time
facts and typed claim kinds. V-only commentary may anchor an external opinion
while its original event context is present; V does not become primary evidence.
Unresolvable/capped items are counted as synthesis omissions. Raw rejected
answers, arbitrary kind metadata and old packet aliases are never new model
input. Existing output limits, partial states, leases, cancellation/revocation
CAS, startup interruption and no-resend behavior remain in force.

## Synthetic fixture and verification boundary

Separate scratch helper (not a production endpoint or committed binary):
`/home/udalah/.hermes/cache/scratch/tf-review-vt-fixture/main.go`.
Its sibling go.mod uses module `tracefall/reviewvtfixture` and a local replace to
this worktree, so internal store packages are imported normally. It refuses
existing DB/evidence roots and non-absolute/outside-scratch paths. It creates only
synthetic records/files and calls no VT/model endpoint or real evidence reader.

```sh
cd /home/udalah/.hermes/cache/scratch/tf-review-vt-fixture
GOCACHE=/home/udalah/.hermes/cache/scratch/gocache go run -mod=mod . \
 /home/udalah/.hermes/cache/scratch/NEW-disposable-vt/fixture.db \
 /home/udalah/.hermes/cache/scratch/NEW-disposable-vt/evidence
```

The executed helper verified 6 events, 6 stored opinions and one complete
raw-record/observation/source provenance chain per event, case
`11111111-aaaa-4111-8111-111111111111`. It includes flagged/clean/not-found/error/
unusable and unknown-time states; canaries `VT_FORBIDDEN_*` are only untrusted VT
prose and must not enter captured model requests. Case egress stays none. Start
ordinary `cmd/tracefall` with that disposable DB, an isolated data directory and
explicit fake LLM configuration; use the existing preview/ack/start UI. No debug
or production seeding endpoint exists. Use fresh paths for each run; never point
this helper at an existing case database.

Backend tests exercise synthetic request capture, frozen Upsert readback,
source staleness, typed V synthesis and budget relevance.

Observed assertion REDs (then GREEN with the same selectors) included:
`go test ./internal/narrative -run TestReviewVTStoredOpinion` (missing V facts),
`-run TestReviewVTSynthesisExternalCitation` (V-only item omitted),
`go test ./internal/store -run TestReviewVTStreamed` (unchanged VT fingerprint),
`-run TestReviewVTOversized` (oversized raw ID accepted),
`go test ./internal/api -run 'TestCaseReviewVTFrozen|TestReviewBatchesVTContext'`
(missing stored context), `-run TestReviewBatchesVTDistinct` (missing distinct
plan fields), and `-run TestReviewVTPreparation` (cancelled preparation ignored).
Additional RED/GREEN slices covered trivial hashes, algorithm/field mismatches,
VT byte-budget omission, duplicate opinion IDs, and the empty-case 422 regression.
All commands used the explicit scratch GOCACHE and `-count=1`.

Final scoped race verification (not a full suite):

```sh
GOCACHE=/home/udalah/.hermes/cache/scratch/gocache TRACEFALL_VT_API_KEY= \
 go test -race -p 1 ./internal/narrative ./internal/store ./internal/api \
 -run 'Review|Narrative|VirusTotalCandidates' -count=1 -timeout 15m
```

Execution passed: narrative 34.146s, store 24.246s, API 263.644s. Separate
VirusTotal-client/egress package tests also passed with the live-key variable
empty. Build/vet/diff checks are recorded in the delivery summary.

Integrated embedded-UI,
actual CLI/browser restart, full-suite and independent review are separate
parent verification gates. No live provider/evidence analytical-quality claim is
made by these synthetic checks.
