# Batch-review backend verification record

Scope: backend, schema, API, Go tests and documentation on the isolated
`feat/case-review-batches` worktree based on `783b637`. No browser assets/scripts,
user case/server, personal CLI authorization, live provider, VT or remote write
was used. API/field contract: [ai-case-review-batches.md](ai-case-review-batches.md).

## Follow-up review blockers: observed RED → GREEN

The resumed backend fix pass preserved the staged implementation and used
vertical test-first slices (one assertion-failing RED, minimal fix, then GREEN):

| New exact test | Observed compiled assertion RED | Fix / GREEN |
|---|---|---|
| api `TestReviewBatchesPolicyRevocationSerializesOutcomeObservation` | `context=context canceled durable_packet=succeeded` after real `SetEgressLevel` revocation between the first Err observation and packet CAS | Observe context and persist under the same short admission mutex used by explicit cancel, revocation and deletion. The test deterministically admits the old interleaving only when that mutex is absent; with serialization, admission wins before revocation. PASS. |
| api `TestReviewBatchesDeadlineAtOutcomeAdmissionWithholdsCommentary` | expired context persisted packet `succeeded` with validated sentences | An expired overall deadline yields packet `failed`, removes validated commentary/coverage and retains only the already-bounded raw answer. Not user cancellation. PASS. |
| api `TestReviewBatchesDeadlineAtFinalBoundaryIsPartial` | final reason incorrectly reported generic synthesis omission rather than overall time exhaustion | Recheck context under final admission lock; persist `partial` with `overall time budget exhausted`, including the last-packet/synthesis boundary. Explicit cancellation remains cancelled. PASS. |
| store `TestReviewBatchesLegacyFingerprintReferenceNormalization` | `empty` subtest canonical hash `bc830de46203f9f28132440616d64577c5c5f0ad2d551c86c6fd189ec0825939` differed from streamed `ac16c1d21d9125244af9357d10f5a3518dbd61c415594b5548f22744f059745c` | Copy supporting references with `append([]string(nil), refs...)` before sorting, exactly matching canonicalReview. Nil, empty, sorted and shuffled cases, both scan and cache, PASS. |
| api `TestReviewBatchesProviderBindingIsNotAddressAndRevisionOnly` | binding derived solely from reusable process address and revision | Use a crypto-random UUID generation for each shared provider manager, plus revision. Stable unchanged binding and provider replacement regression PASS. No actual restart collision was claimed. |

Final scoped race command shown below was rerun after all Go edits: api PASS
(82.295s), store PASS (22.194s), narrative PASS (12.385s). `go build ./...` and
`go vet ./...` both exited 0. Diff whitespace and gofmt checks passed. Added-line
security/sample-name scans found no matches. The first draft of the outcome test
used the wrong sentence type name; that compile failure was corrected and was
**not** counted as RED.

Boundary review included all batch manager lock/cancel callers (start, dispatch,
policy revocation, explicit cancel, deletion and worker cleanup), finalization,
packet/run store CAS, synthesis and the legacy status/fingerprint caller. No lock
is held for Chat/network or validation. Durable cancellation still permits only
a cancelled late-packet write; interrupted/deleted runs cannot be revived.
Deadline admission is local, not a provider-side computation or billing limit.
The existing UTF-8/output-cap and restart/deletion tests remained green.

The real-binary/browser/large-case records below are earlier checks, not rerun by
this follow-up fix pass. No full suite or UI/browser files were changed or run.
No scratch server was started in this pass. Steps 6/7 and live services remain
out of scope.

## Observed assertion-failing REDs

These were real compiled test runs before the corresponding behavior was made
GREEN, not missing-symbol/compiler-error substitutes. Representative captured
failures (run each named test with `go test PACKAGE -run '^NAME$' -count=1`):

| Package / test suffix | Observed RED |
|---|---|
| api `TestReviewBatchesPlanAccountsBeyondLegacyCap` | plan route was 404; no multi-packet local plan |
| api `TestReviewBatchesStartPersistsExactAttempt` | start route wanted 202, got 404 |
| api `TestReviewBatchesDistinctCoverageAndBudgetPartial` | missing manifest-derived `progress` |
| api `TestReviewBatchesWholeCatalogFailureOutsideSample` | source catalog was 0 instead of including the source outside the first-60 sample |
| api `TestReviewBatchesRevocationCancelsActiveRequest` | revoked active run remained running |
| api `TestReviewBatchesRevocationDoesNotWaitForLegacyPreparationLock` | active batch cancellation waited for the legacy preparation mutex |
| api `TestReviewBatchesCancelIsDurableAndCannotBeRevived` | cancellation response left durable state running |
| api `TestReviewBatchesDeletionCancelsAndErasesActiveManifest` | case deletion left the active transport uncancelled |
| api `TestReviewBatchesProviderReplacementInvalidatesPlan` | same-metadata provider replacement accepted the old plan |
| api `TestReviewBatchesSynthesisKeepsPrimaryReferences` | one initial call but no required bounded synthesis |
| api `TestReviewBatchesClaimContextOmissionIsNotMissingEvidence` | available-but-capped references were called missing; then omitted context was absent from the top-level plan |
| api `TestReviewBatchesShapeOnlyNamesAreLearnedAcrossPackets` | profile-only synthetic identity leaked into a separate finding packet |
| api `TestReviewBatchesLegacyStreamingFingerprintParity` | zero-value stub hash/count differed from the historical canonical fingerprint |
| api `TestReviewBatchesLegacyPollingDoesNotReallocateSnapshot` | unchanged polling made 6852 allocations, over the 1500 bound |
| api `TestReviewBatchesOutputAllowanceIncludesValidatedOutput` | 825 raw + 1951 validated bytes were retained against a 1024-byte allowance |
| api `TestReviewBatchesResponseTruncationRetainsValidBoundedUTF8` | mid-rune truncation read back as 1026 bytes against a 1024-byte cap |
| api `TestReviewBatchesOverallBudgetExpiryIsPartialNotSuccess` | time-budget exhaustion was cancelled instead of partial |
| api `TestReviewBatchesPayloadAndManifestRoutesAreCaseIsolated` | frozen payload readback route was 404 |
| api `TestReviewBatchesPriorPlansRemainDiscoverable` | paged prior-plan history was 404 |
| store `TestReviewBatchesRestartInterruptsWithoutResend` | reopening left uncertain delivery running instead of interrupted |
| store `TestDeleteCase_EveryCaseOwnedTableIsEmptiedOrDocumented` | seeded new case-owned tables caused a foreign-key deletion failure |
| narrative `TestReviewBatchFinalCombinedSizeIncludesAddedInstructions` | final expanded system+user packet over the cap was accepted by the zero-value stub |

Fixture/harness mistakes were not counted as feature REDs: an initial event
fixture lacked collection provenance, a catalog fixture reused an empty SHA,
and the HTTP probe initially expected the wrong existing deletion status.
Additional regression tests exercise already-implemented branches: all invalid
hard-budget fields, synthesis byte reservation, no-egress/no-ack/stale-input/
wrong-key refusal, same-case citations and stable namespaced identity remapping,
failed-request zero reviewed coverage, unchanged core findings, insertion-order
fingerprint determinism, tied/undated records and atomic oversized-row refusal.

## Final scoped Go checks

All commands used:

```
GOCACHE=/home/udalah/.hermes/cache/scratch/gocache
```

The final run after the UTF-8 and combined-packet-size checks was:

```
go test -race -short ./internal/api ./internal/store ./internal/narrative \
  -run '^(TestReviewBatches|TestCaseReview_|TestReview|TestDeleteCase_EveryCaseOwnedTableIsEmptiedOrDocumented)' \
  -count=1 -timeout=8m
```

Result: api PASS (74.448s), store PASS (13.719s), narrative PASS (12.317s).
`-short` deliberately skips the separate large synthetic case exercise, not the
concurrent cancellation/revocation/persistence checks.

```
go test ./internal/api -run '^TestReviewBatchesLargeSnapshotHasBoundedHeap$' \
  -count=1 -v -timeout=5m
```

Result: PASS, package 12.344s. Actual logged preparation measurement:

```
events=12002 frozen_json_bytes=102183063 initial_packets=7 total_batches=201
baseline_heap=1895872 peak_heap=8960176 elapsed=6.190540158s
```

The fixture inserts records in reverse identity order, mostly unflagged and
undated, with a large non-allowlisted Extra value. It creates the fixture in
small writes rather than constructing a case-sized test slice. Snapshot
fingerprint is re-streamed and compared; Go heap is sampled during planning.
This is synthetic evidence for bounded-page retention, not a production-case
capacity guarantee or a claim that disk/time is constant.

```
go test -short ./internal/api -run '^Test(Narrative|ChatGPT|CaseReview)' \
  -count=1 -timeout=5m
go test ./internal/enrich/llm ./internal/narrative -count=1 -timeout=5m
```

Results: api PASS (49.946s); llm PASS (2.122s); narrative PASS (0.720s).
The broader scoped api/store/narrative `TestReviewBatches|TestCaseReview_|TestReview|TestDeleteCase_`
normal run also passed during development. Build, vet and whitespace checks
were exercised with `go build ./...`, `go vet ./...`, `git diff --check`.

## Actual compiled binary, synthetic provider, real restart

Built `bin/backend-check/tracefall` from this worktree. The ignored local driver
`bin/backend-check/probe.py` starts only disposable loopback servers, strips
inherited TRACEFALL configuration, supplies a dummy API key and an explicit
synthetic provider, and uses fresh isolated integration storage. It imports a
real synthetic ZIP through the API/parser; it does not seed API results or SQL
case rows. Output is saved at `bin/backend-check/probe-results.json`.

The final driver run returned:

```
passed: true
parsed_events: 181
primary_reviewed_events: 181
distinct_successful_events: 181
initial_batches: 4
synthesis_calls: 1
restart_state: interrupted
sending_packet_after_restart: interrupted
requests_before_restart: 6
requests_after_restart: 6
deletion_http: 200
source_checks: foreign Origin and Host refused
ports_closed: true
```

Four initial request hashes and the dynamic synthesis hash were independently
computed from captured wire messages and compared with exact payload readback:

```
368f9667cc7ca6b6274c3ef9f9e03d7c78d3ebb477b3982a61665ef8def8c1e9
63b38b706ca0b2d1cf1ae3de0db6401e39a1fe8348b0aced042100f4782e108c
8c0097958aa52ce778d5094d5e4df23e674b2cf8674b37ef7e491207748302fb
1f058455fdd41c73ac941b525272527dff1c435491b340c58f2aa94c744534ca
d5edee5c6b5e8e2fb753f3c37773007cc6f72e8f094f252642c10846537fa2b5
```

The sixth request was a separately approved run killed while in flight. Restart
made no seventh request. The first successful run's manifest, commentary and
exact payload remained readable. Case deletion then removed readback access.
The driver checked its final server/provider ports (38297, 44349) closed.

Harness corrections: this binary uses flags directly, **not** a `serve`
subcommand; a premature `serve --help` invocation started an empty scratch
server on the default port and was timed out. Port 8080 was subsequently probed
closed. The raw request-source test must use `rawNoAuthRouter`, because
`dashboardLike` intentionally replaces request headers. Existing case deletion
returns HTTP 200, not 204. Those corrections did not touch the user's server,
case, credentials or production repository.

## Backend-only checkpoint limitations

The later parent-integration record below supersedes only the explicitly repeated gates. Other limitations remain.

- No full repository suite on this branch; parent integration must run it.
- No browser/UI changes, DOM behavior, responsive layout or screenshots verified.
- No live-provider account access, terms, retention, model quality or forensic
  accuracy verified. Fake model commentary is transport/validation test data.
- No user/production case was opened or transmitted. No real provider, personal
  Codex authorization, VT lookup, remote API write or push was used.
- No raw-image completeness, autonomous retrieval/tools, automatic restart
  resend/resume/retry, typed analyst review or report appendix is implemented.
- Local output limits are not provider computation/charge limits. Structural
  validation is not a truth check. Regex/dictionary privacy is risk reduction,
  not a guarantee of identifying unknown secrets or all sensitive semantics.
- Planning has explicit row/dictionary/record/byte/deadline caps. The million-row
  and dictionary-cap extremes were not load-tested; the measured large exercise
  is the logged synthetic case, not a production capacity certification.
- Snapshot/fingerprint/manifest metadata are O(case-size) disk/time. SQLite's
  single connection can delay other DB work. Legacy explicit single-packet
  preview/start and Summary preparation are not claimed to be streaming.
- Crash during an unreturned local plan can leave provisional case-owned rows
  until case deletion; no provider work is launched from such a plan. Repeated
  retained plans consume additional local disk.
- Polling batch status reads frozen metadata and live progress; it does not
  promise current-source freshness. Start performs the streaming stale check.
  Managed provider/account changes and restart invalidate planned consent;
  manually replacing credential files outside managed configuration is not a
  supported configuration workflow or verified account-change detector.

## Parent integration verification

Backend and UI were cherry-picked into main as `c4ccf41` and `2dc7090`.
The parent reran the integrated scoped race suite:

```
go test -race -short ./internal/api ./internal/store ./internal/narrative \
 -run '^(TestReviewBatches|TestCaseReview|TestReview|TestUI_|TestDeleteCase_EveryCaseOwnedTableIsEmptiedOrDocumented)' \
 -count=1 -timeout 8m
```

PASS: api 94.389s, store 23.984s, narrative 12.467s. Build, vet, JS syntax and diff checks also passed.

`tests/case-review-batches.browser.cjs` now defaults to **embedded assets** and
compares the binary-served app.js/style.css bytes with the integrated source.
Worktree route overrides require the explicit `TRACEFALL_TEST_ROUTE_ASSETS=1`.
The parent built `bin/tracefall-batch-review` and ran the browser test without
that override. The actual upload/import produced 181 synthetic events, four
initial provider calls and one synthesis; primary/distinct successful event
counts remained 181. Planning sent zero model calls. Exact captured payloads
and hashes matched readback. A one-request/no-synthesis budget yielded 60
primary reviewed events and three unreviewed packets, with partial status.
Actual cancellation, retained history selection, packet coverage/event citations,
external-policy/no-ack UI controls, focus/details/payload scroll, changed consent,
untrusted raw-answer escaping, and late-response isolation passed. Desktop and
390px screenshots were inspected; no horizontal overflow was observed.
Artifacts: `/home/udalah/.hermes/cache/scratch/batch-parent-integrated-final-2/`.

The parent also ran the rebuilt integrated binary through the independent
synthetic HTTP probe: 181 events, four initial plus one synthesis; an additional
blocked request was interrupted by killing/restarting the server. The persisted
run/packet became interrupted and provider calls stayed six before/after, with
no automatic resend. Prior exact payload remained readable, case deletion
removed readbacks, foreign Origin/Host were refused, and ports 34023/33843 were
verified closed. Probe record:
`/home/udalah/.hermes/cache/scratch/batch-parent-integrated-probe/probe-results.json`.

Legacy `tests/external-ux.browser.cjs`, `tests/case-review.browser.cjs` and
`tests/case-review-ui.browser.cjs` also passed against the freshly integrated
embedded-assets binary using the required empty/synthetic provider modes.
Scratch regression ports were 18483/18484, not the user's server.

A full repository suite and independent post-fix source review are separate final
gates, not established by these targeted/browser checks. No real case, real
provider, VT result input, analyst-decision/report workflow, or accuracy claim
was exercised. Budget limits can deliberately leave most of a large snapshot
unreviewed; new plans are separate approvals, not automatic continuation.
