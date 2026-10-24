# Optional parsed-case batch review: backend API

This is separate from the existing single-packet `enrich/case-review` and legacy
`enrich/narrative` Summary. It never promotes a finding, changes severity, or
writes a report appendix. The browser workflow is available inside the existing AI Case Review card: open **Parsed-case batch review**, configure a bounded budget, build and inspect a local plan, then explicitly start it. Actual tests, RED evidence and
limitations are in [the backend verification record](ai-case-review-batches-verification.md).

**Reviewed means that a bounded model request succeeded and returned commentary
passing the existing structural validator. It does not mean semantic accuracy,
image completeness, or a human-reviewed forensic conclusion.** All counts refer
to normalized primary event representatives, not every recollection in the
observation/provenance tables. Chunk order is selection order, not chronology.

Stored VirusTotal context is attached alongside verified original event excerpts in relevant packets and synthesis, never deferred to a VT-only packet or fetched automatically. See [the VT contract](ai-review-virustotal-context.md) for frozen citation routes, numerical validation, privacy-v2 and distinct VT coverage.

## Endpoints

Let `B = /api/cases/{case_id}/enrich/case-review/batches`.
Every endpoint inherits central session/role, request-source, CSRF and case
existence checks. All API routes require analyst privilege in authenticated
mode; administration/deletion retains its existing privilege boundary. In local
no-auth mode use a loopback Host. Every write needs `X-Tracefall-Client` and must
not have a foreign Origin or cross-site Fetch-Site. Authenticated browser writes
also need the existing CSRF cookie/header pair. Use JSON request bodies.

| Method / path | Request | Response |
|---|---|---|
| `GET B` | none | `200 Plan`, the latest **created plan**, including live progress; before any plan: `{"latest":null,"defaults":Budget}` |
| `POST B/plan` | `{}` for defaults, or `{"budget":Budget}` with **all** budget fields | `201 Plan`; local only, zero provider calls, even when configured |
| `GET B/history?offset=0&limit=20` | limit 1..100 | `200 {plans:Plan[],total,offset,limit,has_more}`, newest first, live counters |
| `GET B/{run_id}` | none | `200 Plan`; explicit unknown/wrong-case run is 404 |
| `POST B/{run_id}/start` | `{"plan_key":"exact returned key","acknowledge":true}` | `202 Plan`; external providers require acknowledgement and current pseudonymized egress; local providers need neither external acknowledgement nor raised egress |
| `POST B/{run_id}/cancel` | `{}` | `204`; cancels in-flight context and durably prevents a cancelled run becoming succeeded; already delivered bytes cannot be recalled |
| `GET B/{run_id}/packets?after=-1&limit=20` | zero-based sequence cursor; limit 1..100 | `200 {packets:Packet[],after,limit}`; continue after the last returned `seq`, until a short/empty page |
| `GET B/{run_id}/packets/{seq}/payload` | none | `200 {payload:Payload,privacy:Privacy,attempted:bool,state}`; both frozen pre-send inspection and exact attempted readback; 404 if that budget-disabled packet has no prepared payload |
| `GET B/{run_id}/manifest?kind=event&offset=0&limit=60` | kind `event`, `finding`, `correlation`, `source`, `enrichment`; limit 1..60 | `200 {members:[{kind,member_id,ordinal,primary_packet_seq}],total,offset,limit,has_more}`; original same-case IDs, **not** raw member JSON; source/enrichment members have primary_packet_seq -1 |

Packet pages include bounded payloads/results as well as metadata. They are not
a source-file export. They never return the locally frozen raw manifest JSON.
The payload endpoint is the authoritative exact-text readback. `attempted:false`
is not a transmission receipt; `attempted:true` records durable admission before
entering Chatter, not proof of delivery, billing, or provider execution.

Errors: malformed budgets/pagination 400; policy/acknowledgement 403; unknown
case/run/payload 404; local preparation deadline 408; changed plan/provider,
already-running case or unavailable provider lease 409; empty input, no packets
within budget, privacy refusal or local planning cap 422; unconfigured provider
at start 501. Unexpected database failures remain generic 500 responses. The
existing shared JSON decoder remains in use; it does not enforce Content-Type or
reject unknown JSON members. Request-source/CSRF checks are still mandatory.

## Budget schema

| Field | Default | Accepted hard range / meaning |
|---|---:|---|
| `requests` | 8 | 1..8; includes at most one synthesis |
| `input_bytes` | 1280000 | 4096..1280000; combined UTF-8 system + user text across admitted requests, excluding transport JSON/header overhead |
| `output_bytes` | 131072 | 1024..131072; combined retained raw answer bytes plus serialized validated sentence arrays |
| `per_request_seconds` | 120 | 1..120; cancellable Chatter context deadline |
| `overall_seconds` | 900 | 1..900; run deadline starting at admitted start |
| `concurrency` | 1 | must be 1; sequential calls within this run |
| `retries` | 0 | must be 0; no automatic retry, especially after uncertain delivery |
| `synthesis` | true | reserve one request and a full 160000-byte synthesis input allowance before admitting initial packets |

No dollar/token estimates are invented. Provider token usage is retained only
when reported; zero/unknown fields are omitted. These are local admission,
retention and deadline ceilings, **not** uniform provider-side computation or
charge limits. The existing hardened API/Codex transports have their own output
bounds; a response exceeding this run's remaining local allowance is failed and
locally truncated or its validated commentary is withheld. It does not earn
reviewed-event coverage.

Initial packets are admitted in deterministic order until the request or input
allowance cannot admit the next packet. Remaining manifest packets stay
unreviewed. Input allowance for synthesis is reserved, not secretly added later.
Output/time left after the initial requests may still prevent synthesis; that
is visible partial work, not a completed whole-case review.

## Plan schema

All non-optional fields are always emitted. IDs, fingerprints and keys are opaque
strings; numbers below are integers.

- Identity/binding: `id`, `case_id`, `created_at` (RFC3339Nano), `plan_key`,
  `source_fingerprint`, `provider_binding`, `privacy_contract` (currently
  `parsed-review-privacy-v1`), `scope` (`bounded_batched_parsed_snapshot`).
- Provider/policy **at planning**: `destination`, `model`, `local` (bool),
  `egress_level`. `provider_binding` is an opaque local configuration generation,
  not account identity or a credential. It changes on managed provider/account
  changes and restart. Existing integration status remains the provider setup UI.
- Admission: `budget:Budget`, `acknowledged` (external acknowledgement recorded
  at start, otherwise false), optional `requested_by`, `started_at`, `finished_at`.
- State: `state`, `reason`, `input_incomplete` (bool). Run states are `planned`,
  `running`, `succeeded`, `partial`, `failed`, `cancelled`, `interrupted`.
  Cancelled and interrupted delivery is not safe to resend automatically.
- Catalog/selection: `eligible_events`, `planned_events`, `total_batches`,
  `enabled_batches`, `initial_input_bytes`, `findings_included`,
  `findings_omitted`, `correlations_included`, `correlations_omitted`.
- `snapshot:{fingerprint,events,findings,correlations,sources,source_parse_gaps,
  bytes,coverage:Coverage}`. `bytes` is locally serialized snapshot JSON size,
  not a payload/billing estimate. The privacy dictionary is **not** serialized
  into API responses.
- `progress:Progress` (below).
- Final reduction: `synthesis_state` (initially empty; then `ready`, `sending`,
  `succeeded`, `failed`, `cancelled`, `omitted` or `disabled`),
  `synthesis_omitted_sentences`, `unsynthesized_batches`. The last counter counts
  successful initial batches not fully represented, or all successful initial
  batches if synthesis was not produced. It is not an additional event count.

`GET` reads the frozen plan and persisted progress, not a live case allocation.
It does **not** recalculate current source staleness. Starting re-streams a
consistent current fingerprint and refuses changed input, policy, privacy
contract or provider configuration before any provider request. A run reviews
its frozen snapshot even if later case work changes the current case. Do not
label an old plan "current whole case". History exposes older manifests/results;
there is no resume/retry endpoint. After restart create and explicitly approve
a new plan rather than starting a pre-restart configuration-bound plan.

### Progress and count semantics

`Progress` fields:

```
succeeded, failed, cancelled, interrupted,
unreviewed, ready, sending,
primary_reviewed_events, distinct_successful_events,
requests_attempted, input_bytes_admitted, output_bytes_retained
```

- `eligible_events` counts every normalized event in manifest membership.
- `planned_events` counts primary membership in budget-enabled event packets,
  not event contexts repeated in claim packets.
- `primary_reviewed_events` is SQL membership in **successful initial event
  packets**. `distinct_successful_events` is the distinct same-case manifest
  event-ID union in successful initial packets, including claim contexts. A
  failed/cancelled/interrupted packet never contributes. Synthesis never adds
  reviewed-event coverage. Neither counter is inferred from snippets/prose.
- State counts concern initial packets only. `ready` is a subset of
  `unreviewed`, not another disjoint count to add. `sending` is a durable attempt
  awaiting its result. On cancellation unsent prepared packets are cancelled;
  ordinary budget/failed-run leftovers are unreviewed.
- `requests_attempted` and admitted input include synthesis when attempted.
  Admission is persisted before provider entry; delivery can remain uncertain.
- All-time catalog status counts are independent of the first-60 source sample.
  `snapshot.coverage.sources_imported`, `sources_failed`, `sources_unsupported`,
  `sources_not_imported` are mutually exclusive classifications. The imported
  and failed status classifications take precedence over supported=false,
  matching the existing review rule. Unknown statuses are never uploaded as
  free text. `parse_coverage_not_recorded` and `snapshot.source_parse_gaps`
  disclose absent diagnostics / unmapped, failed, capped diagnostics.

Source parse gaps, omitted claims or supporting excerpts, prohibited command
omissions, budget exhaustion, failed requests and dropped synthesis items cause
partial work. Even `succeeded` only means successful bounded parsed-snapshot
requests with no recorded gap in this contract; it never proves image coverage.

## Packet, payload, privacy and commentary schemas

`Packet` fields:

```
seq, kind, offset, state, namespace, primary_events,
event_ids, finding_ids, correlation_ids,
payload:Payload, privacy:Privacy, coverage:Coverage,
output_bytes_retained, rejected,
attempted_at?, raw_answer?, sentences?, reasons?, actual_model?,
prompt_tokens?, completion_tokens?, error?, omitted_source_batches?
```

Kinds: `event`, `finding`, `correlation`, `synthesis`. Initial metadata sequences
are contiguous, starting at zero. Synthesis, when prepared, has `seq` equal to
`plan.total_batches`; `total_batches` itself excludes that optional final call.
Offsets are zero-based membership ordinals within their kind. Event chunks have
60 primary records; claim chunks have 20 claims plus up to 60 primary excerpts.
Sources are a bounded contextual sample, not independent provider packets.

Packet states: `unreviewed`, `ready`, `sending`, `succeeded`, `failed`, `cancelled`,
`interrupted`. `namespace` explicitly scopes all batch-local tokens and citation
aliases. Never merge equal-looking `USER_1`, `E1`, `A1` or `S1` across namespaces.
Accepted sentence text is locally restored, and citation IDs are original IDs.
Synthesis re-prepares a new namespace from validated, restored commentary plus
original same-case primary excerpts. It never copies raw rejected model output
into a prompt. `omitted_source_batches` lists initial packet sequences whose
commentary items were dropped from synthesis.

`Payload = {system,user,sha256,destination,model,sent_at}`. `sha256` is lowercase
SHA-256 of UTF-8 `system + NUL + user`, independently inspectable before/after
attempt. `sent_at` is empty before admission, not proof of provider delivery.
`Privacy = {contract,status,payload_bytes,requires_separate_permission}`; checked
receipts have status `checked` and requires_separate_permission true. Unprepared
metadata has empty/zero fields, **not** a checked privacy receipt.

`sentences` contains `{kind?,text,cites:[{kind,id}]}`. The optional sentence kind
is Review commentary metadata: `observation`, `possible_conflict`, `hypothesis`,
`gap`, `next_check`, or `unclassified`. It is distinct from both packet kinds and
citation kinds. New untyped responses are explicitly unclassified; historical
rows without it remain unchanged. Synthesis carries canonical kinds with original
primary references and normalizes unknown/absent metadata to unclassified; it
must not present commentary as evidence or promote hypotheses/conflicts to
established observations. See [claim types](ai-review-claim-types.md) for the
plain-text protocol and semantic limits. Cite kinds are `event`, `finding`,
`correlation`, `coverage`. Coverage ID `selection` means the packet coverage;
other coverage IDs refer to original source metadata. Missing same-case primary
references are never repaired into a different case. `reasons` maps validation
rejection categories to counts. `raw_answer` is untrusted provider output;
render it as text, never HTML, never evidence, never a new prompt. Model/usage
fields are reported metadata, not semantic validation.

`Coverage` is the existing ReviewCoverage shape:

```
scope, events_total, events_included, events_omitted,
findings_total, findings_included, findings_omitted,
correlations_total, correlations_included, correlations_omitted,
sources_total, sources_imported, sources_failed, sources_unsupported,
sources_not_imported, sources_included, sources_omitted,
undated_total, missing_supporting_refs, supporting_refs_omitted,
unflagged_included, command_lines_omitted, parse_coverage_not_recorded
```

Inside a packet it describes that packet's bounded inputs; do not sum repeated
context/source counts across packets. In `snapshot.coverage` it is used only for
whole-catalog totals, source statuses, undated and absent-parse diagnostics;
selection/included/omitted fields there are zero/not applicable. Use Plan and
Progress for reviewed coverage. Known omitted claim references are counted as
`supporting_refs_omitted`, not falsely described as missing primary evidence.

## Snapshot, resources and persistence

Planning keyset-pages all eligible events, current findings/correlations and
active source files by ID inside one SQLite transaction. It fingerprints and
persists every manifest member before constructing bounded provider packets.
That includes unflagged events, tied timestamps and undated records. It does not
load `ListEvents`, `ListSourceFiles` or `CaseNames` on this path. Shape-recognized
identities from all allowlisted snapshot values are learned under the same
bounded dictionary, including identities appearing only in another packet's
profile/UNC/URL/email context. Recognizable credentials are removed before name
learning. Unknown privacy cannot be promised by these pattern guards.

Local caps refuse a plan explicitly, with zero provider calls: 1000000 total
manifest records, 256 MiB serialized snapshot, 128 KiB raw normalized row before
Go scanning, 1 MiB serialized row, 16384 names, 2 MiB total dictionary names,
1024 bytes per identity, and 10000 distinct claim references per prepared claim
packet. The raw-row preflight is conservative across the case's source tables,
including retained rows not selected by current-analysis filtering. Planning has
a 60-second context and uses the existing shared heavy-operation gate. Each
provider packet is at most 160000 combined system/user bytes.

Remaining O(case-size) work is **time and disk**, not a hidden case-sized Go
slice: raw-size preflight, consistent snapshot scan/hash, frozen member writes,
and metadata for all possible initial packets. Each approved local plan retains
its own frozen normalized records in the case DB; these may contain sensitive
original fields locally, separate from sanitized outbound packets. Repeated
plans consume additional local disk. No secure erasure of backups is promised.
A process killed during unreturned local planning can leave provisional
case-owned rows; case deletion still removes them. There is no automatic model
resume and no automatic resend after uncertain delivery.

SQLite still has one connection. A consistent scan can temporarily delay other
DB work, including the case-access check preceding policy changes. The new run
manager does not hold a global preparation mutex or a mutex across a network
call. Revocation cancels active external batch contexts before waiting for the
legacy single-review preparation mutex, and blocks new external dispatch during
the policy transition. It cannot recall already delivered bytes. Local provider
runs retain the existing policy exception.

Legacy single-review status now streams its original fingerprint contract rather
than constructing a full case input. A bounded 32-entry metadata cache uses
SQLite local change count + data_version; any database write conservatively
invalidates it. Thus unchanged status polling does not reconstruct the snapshot.
The first/invalidation scan remains O(case-size) time, bounded-page memory. The
legacy explicit single-packet preview/start preparation and Summary path retain
their old contracts and are not themselves advertised as large-case preparation.

Tables `review_batch_runs`, `review_batch_members`, `review_batch_packets` are
case-owned, deletion-audited, and created backward-safely. Every INSERT names its
columns. Attempt/result transitions are conditional on packet/run state. Startup
marks sending attempts and running runs `interrupted`; prior payloads/results
remain inspectable and are never automatically resent. Completed batch work is
kept even when a later packet fails or synthesis cannot run.

## Synthetic flow for UI integration

1. On a disposable configured fake-provider server create a synthetic case and
   upload/import a ZIP with 181 distinct undated shell-history lines. No real
   evidence, live provider, personal Codex home or VT credential is needed.
2. `POST B/plan {}`. Assert fake request count is zero. Show eligible/planned,
   total/enabled batches, claims omitted, whole-catalog source gaps, budgets and
   separate privacy receipts. Inspect ready packet payloads via `/payload`.
3. For an external fake provider explicitly set case egress to pseudonymized,
   create a **new** plan under that policy, and require acknowledgement tied to
   that exact plan key. No-egress/no-ack/wrong-key/provider-changed/source-changed
   starts must refuse without sending. A policy change is not a privacy receipt.
4. `POST B/{id}/start {plan_key,acknowledge}`. Poll that run, not only latest if
   another local plan was created. Page metadata/manifest as needed. Preserve
   already successful results when later work is partial/cancelled/failed.
5. With the default budget this synthetic case produces four initial requests
   and one synthesis. Independently hash every captured system-NUL-user request
   and compare payload readback. Reviewed distinct/primary counts are 181, not
   increased by synthesis or repeated contexts.
6. Create another plan, start a blocking fake request, kill the scratch binary,
   restart with the same scratch DB/data. The run/attempt are interrupted; request
   count must not increase. Read the previous successful manifest/payload again.
   A fresh approved plan is required for new work; no Resume/Retry button exists.
7. Delete the synthetic case using the existing endpoint (HTTP 200 with
   deleted_case_id), verify readbacks are 404, then stop and probe both disposable
   ports. Browser/UI screenshots and responsive UX remain the UI workstream.
