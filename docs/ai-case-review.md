# Optional bounded AI Case Review

AI Summary and AI Case Review are **different operations** in a case's Outside services tab.

- **AI Summary** keeps its existing `/enrich/narrative` contract, selection, output and Appendix E. It summarizes selected deterministic findings and their cited events. It is not an independent review of the case.
- **AI Case Review** makes **one bounded request** over selected existing parsed case data, including unflagged observations. It can run with zero findings when parsed events exist. Its output is optional commentary, not a new finding or evidence. It never changes deterministic findings or severity and is not inserted into Summary or the report appendix. Reports do not include this separate commentary in this phase.
- **Exhaustive all-case/batch review is unavailable.** There is no autonomous retrieval, tool use, multi-batch coverage, restart/resume pipeline, analyst accept/reject workflow, or raw-image coverage claim. Even when all currently parsed events fit, unparsed/acquisition/image coverage is not established.

## Selection and privacy contract

Evidence selection, privacy preparation and transmission permission are three independent stages. A selected packet is not a permission grant. A successful local privacy check is not permission either: the case policy and explicit external-request acknowledgement still apply. Provider login never changes either stage. The UI shows all three separately, and preview is available locally even while external case egress is blocked.

The server builds the packet. Client-supplied facts, IDs or retrieval instructions are not accepted.

Caps: **25 findings, 25 correlations, 120 normalized events, 60 source coverage records, 160000 bytes for system plus user text**. Oversized text is refused before sending, rather than silently shortened. Finding title/description and normalized event fields also use the existing per-field text limits. Coverage gives total/included/omitted counts separately for findings, correlations, events and source coverage, plus missing and available-but-omitted supporting references. These are record-selection counts, not a percentage of forensic truth or image completeness.

Findings use deterministic severity/time/ID selection; correlations and coverage use ID ordering. At most half the event budget initially goes to the selected findings'/correlations' primary referenced events. The remaining budget round-robins sorted acquisition/source/artifact/event-type/host/time-knownness strata, in ID order within each stratum. Selection reasons distinguish primary references, referenced strata, unflagged strata and acquisition/established-host context. This is deterministic sampling, not a representative statistical sample or a guarantee that every source participates when the budget is exhausted.

Unknown hosts are acquisition-scoped (an absent acquisition is scoped to the individual event); they are never treated as one case-wide machine. No temporal context join is made. ID ordering is a deterministic tie-break, **not evidence of temporal ordering**. Unknown timestamps remain undated; tied timestamps establish no sequence. A small fixed allowlist classifies time bases including memory snapshots. Unrecognized basis prose is not transmitted. Snapshot time does not establish execution time.

Opaque F/E/C/K references identify findings/events/correlations/coverage in each payload; A/S aliases identify primary acquisitions/sources. Real IDs stay on the server. Provenance is explicitly the **primary observation only**, not a census of every deduplicated recollection. K1 holds selection coverage; source coverage records contain numeric read/mapped/unmapped/undated/failed/capped facts and whether parser caveat notes exist. Absent parse coverage is **not recorded**, never complete. Omitted source coverage and missing supporting references are explicit limitations.

Case names, analyst material, evidence filenames, server source paths, file bodies, SQL/cookie fields and raw parser errors are excluded. Bounded normalized command lines are included after positional-secret redaction, pseudonymization and leak checks, so unflagged command evidence remains useful. Recognizable SQL/cookie bodies in command fields are conservatively omitted and counted, never passed through as command context. Strictly shaped original partial/local time readings are included as recorded text, not established UTC instants. Global imported/failed/unsupported/not-imported source totals cover the whole catalog even when per-source coverage records are sampled. Only the existing small normalized Extra allowlist (`logon_type`, `outcome`, `action`) is used, with an independent fixed classification of `timestamp_basis`. Generated finding/correlation prose is bounded and pseudonymized; recognizable SQL/cookie bodies copied into that prose cause refusal rather than attempted semantic SQL redaction. Recognized request-body command forms (curl/wget data/cookie options and PowerShell Body), data URIs and private-key blocks are also omitted in commands or refused in other allowed prose/classifications. Source import status is a fixed classification; unknown text is not transmitted. These conservative guards can exclude benign commands. This defense-in-depth pattern is not a general content classifier.

The existing convergent case dictionary, command-semantic positional-password redactor and per-value pseudonym leak gates are reused. Review applies `cmdsem.Redact` to generated prose before pseudonymization; this does not change legacy Summary. Review-specific preparation removes URL userinfo, query strings and fragments before tokenization/truncation, including URLs with unknown credential parameter names. Short access/refresh/session-token and AWS credential assignments/flags are irreversibly redacted rather than retained in the reversible name dictionary. Classifications are checked as values too; known forbidden bodies cannot bypass the guard through event/artifact types. The shared pseudonymizer replaces known/recognized identifiers, strips recognized secrets and refuses detected leaks. Pseudonymized does not mean anonymous; time/process/activity shape still travels. Input remains untrusted data, not instructions. The existing hardened Codex and OpenAI-compatible `llm.Chatter` transports are reused without adding tools or egress modes.

External destinations still require case `pseudonymized` permission and explicit acknowledgement for **each request**. Local providers retain their existing distinction and need no external acknowledgement. Provider login, selection, status and preview never initiate a case-data model request. The provider is leased through completion/cancellation, so Settings cannot replace it during the operation. Preview keys also bind the current case egress level and versioned privacy contract. Changing the level requires a new preview. The worker checks current permission again immediately before invoking the provider. Lowering egress below pseudonymized cancels an active external Case Review using its transport context (including retries). Cancellation cannot recall bytes already delivered, cannot force a remote provider to erase data, and is not proof of zero transmission. Local review and legacy Summary/VT retain their existing behavior.

## API

Under `/api/cases/{id}/enrich/case-review`:

| Method/path | Effect |
|---|---|
| `GET /` | Read configuration, current source fingerprint, in-memory run status and latest separately persisted review; no model call. |
| `GET /preview` | Build the local inspectable `system`, `user`, exact payload `sha256`, coverage, source fingerprint, destination/model, egress/locality, `preview_key` and a local `privacy` receipt; no model call. |
| `POST /` | Body `{ "acknowledge": true, "preview_key": "..." }`; rebuild and compare the preview key, then start one background model request (`202`). |
| `POST /cancel` | Cancel this case's review (`204`); retain the request record and any failure/cancellation outcome. |
| `GET /payload` | Read the latest attempted request's exact system/user strings and payload hash, independently of Summary. |

The preview key binds payload hash, full source fingerprint, provider kind, destination/model, local/external distinction, case egress level and privacy-contract version. It is not a new authorization mechanism. A changed/missing preview or duplicate start is `409`; egress/ack refusal is `403`; unconfigured provider is `501`; empty input, pseudonymization refusal or byte-cap refusal is `422`. Refusal sends nothing and creates no request row.

The exact hash is SHA-256 of `system + NUL + user`, not the serialized HTTP envelope. A `case_reviews` row retains the versioned privacy receipt (contract, checked status, actual combined payload bytes and separate-permission requirement). Older rows without a receipt remain not recorded; no retrospective claim of checking is made. The row is written **before** invoking the provider, then updated with the exact raw answer, accepted sentences/rejection reasons, usage if supplied, and error/cancellation outcome. The initial row records an attempted request, not proof the destination received it. If the process stops, its unfinished row says running-or-interrupted; no automatic resend happens. Run state itself is in memory.

The locally computed source fingerprint includes current events, findings, correlations and active source/parse-coverage records, including omitted records, rather than only finding IDs. Changes mark stored commentary stale. The packet and source selection are bounded, but local preparation/status currently materialize case data: **RAM and fingerprint work remain O(case size)**. This phase does not claim streaming/local-memory scalability.

## Output and UI

Accepted lines require actual packet references, issued entity tokens and permitted number runs; unsupported references/unknown tokens/numbers/schema are rejected, not repaired. An anchored sentence can still be semantically false. **Validation does not prove truth, contradiction, completeness or model accuracy.** The model is asked to label hypotheses/investigative leads and to avoid unsupported order/identity claims; these semantic requirements still need examiner review.

Outside services has independent Summary and Case Review cards. Review shows separate evidence-selection, privacy-preparation and transmission-permission stages alongside caps, partial scope, provider/notice and an explicit pre-send preview. Missing/mismatched privacy receipts or changed preview context disable Start and invalidate previous acknowledgement. Privacy checks are pattern-based and never an anonymity guarantee. Start requires the current preview, and acknowledgement when external. Polling preserves same-provider/same-input preview, acknowledgement, focus and exact-payload panels; a changed provider/policy or source fingerprint invalidates consent/preview. After a request, actual persisted coverage and staleness are visible. Event/finding citations use existing drill-down; correlation and coverage citations open their current case record/recorded selection coverage, with missing references shown as unavailable, never fabricated. Current source/correlation details can differ from a stale review and are labelled accordingly.

## Synthetic verification recipe

Use an isolated scratch directory and disposable ports, **not the user's server, case, credentials or real OpenAI/VT**. Assets are embedded, so rebuild after JS/CSS edits. Example commands (run provider/server in separate managed terminal processes and stop them afterwards):

```sh
GOCACHE="$SCRATCH/gocache" go build -o "$SCRATCH/tracefall-review" ./cmd/tracefall
python3 tests/case-review-provider.py "$SCRATCH/review-provider" 18480
env -i PATH=/usr/bin:/bin HOME="$SCRATCH/review-home" TMPDIR="$SCRATCH" \
 TRACEFALL_LLM_PROVIDER=openai-compatible \
 TRACEFALL_LLM_API_KEY=synthetic-review-only \
 TRACEFALL_LLM_MODEL=synthetic-review-test \
 TRACEFALL_LLM_BASE_URL=http://127.0.0.1:18480 \
 "$SCRATCH/tracefall-review" -port 18479 -db "$SCRATCH/review.db" -data-dir "$SCRATCH/review-data"
PLAYWRIGHT_MODULE=/path/to/playwright node tests/case-review.browser.cjs http://127.0.0.1:18479 "$SCRATCH/review-browser"
PLAYWRIGHT_MODULE=/path/to/playwright node tests/case-review-ui.browser.cjs http://127.0.0.1:18479
```

The actual browser flow uploads/imports a synthetic history ZIP, leaves findings empty, previews/starts a real backend request to the **fake provider**, checks persisted output, sources and desktop/mobile layout, and writes screenshots plus the disposable case ID. The UI-only fixture exercises external consent/polling/provider/input changes, missing-receipt refusal, privacy checked under blocked egress, and correlation/missing-reference states with **zero model sends**. The upload fixture includes short synthetic URL/environment secrets and recognizable bodies; inspect the exact captured outbound request, not only the DOM. Tests with a synthetic external destination exercise the non-local policy path separately from this loopback browser flow. Inspect screenshots, not just DOM assertions. Provider request records permit independent payload/hash/leak inspection. Restart the disposable server, read the saved case ID's latest review and confirm no new provider request before asserting persistence.

Focused Go checks include `TestReview_*`, `TestCaseReview_*`, `TestDeleteCase_*` and the existing Narrative/ChatGPT/VT/UI regressions, including `-race`. Do not infer real-service access or forensic accuracy from synthetic outputs. No full-suite, real-provider accuracy, all-case batch pipeline, or large-case memory validation is established by this recipe.
