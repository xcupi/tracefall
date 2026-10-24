# AI Review commentary claim types

This is the Review-only `review-output-v1` contract for single-packet Case Review,
initial batch packets and dynamic synthesis. It classifies **model commentary**,
not evidence, deterministic findings, severity, or analyst decisions. Legacy AI
Summary retains its original prompt, validator semantics and report appendix.
Case Review commentary is not added to reports by this change.

## Provider protocol

The model is asked for at most 12 plain-text items, one per line:

```text
observation | A command is recorded. [E1]
possible_conflict | The recorded context may conflict with the rule claim. [F1, E1]
hypothesis | The command may warrant further investigation. [E1]
gap | Execution evidence is missing from this selection. [E1, K1]
next_check | Examine execution telemetry for this command. [E1]
unclassified | The record warrants examiner review. [E1]
```

These are illustrative protocol examples, not conclusions about any actual case.

| Kind | Intended meaning, not a verified conclusion |
|---|---|
| `observation` | What the supplied records show; a recorded command does not establish execution or success. |
| `possible_conflict` | A possible conflict, not a proven contradiction. No automatic reconciliation of detector claims. |
| `hypothesis` | Unconfirmed interpretation, never implicitly an established observation. |
| `gap` | Missing evidence or context, not evidence of absence. |
| `next_check` | A recommendation, not an action already taken. No tool or retrieval is invoked. |
| `unclassified` | Conservative abstention; also the explicit fallback for new untyped output. |

The first ASCII `|` separates the kind from text. Whitespace around it is trimmed;
kind values are exact, lowercase snake-case. Bullets retain existing tolerance.
Only a known prefix is removed; an unknown, empty or forged explicit prefix drops
the whole line and increments `reasons["unknown review claim kind"]` and `rejected`.
Further pipes inside the body remain text (for example a recorded shell pipeline).
A plain line with no separator remains compatible and gets `unclassified`, even
if its prose says “observation”, “hypothesis” or “proves success”. There is no
keyword classifier or semantic promotion.

After prefix removal the existing citation, bracket, issued-token, numeric-run,
URL, sentence-length and item-count checks still apply to the body. Empty bodies
and invalid references are rejected, not repaired. Validation preserves accepted
text subject to the existing whitespace/bullet/citation handling and local name
restoration. Citation aliases resolve to original same-case IDs; claim type never
changes a citation or supplies a new one. A type does not bypass validation.

## JSON and persistence

The existing `narrative.Sentence` adds `Kind string` with `json:"kind,omitempty"`:

```json
{
  "kind": "hypothesis",
  "text": "The command may warrant further investigation.",
  "cites": [{"kind": "event", "id": "original-same-case-event-id"}]
}
```

Sentence `kind` is distinct from `cites[].kind` (`event`, `finding`, `correlation`,
`coverage`) and batch packet `kind` (`event`, `finding`, `correlation`, `synthesis`).
The existing sentence JSON storage/readback carries it without schema/table
changes. Earlier successful packets retain their types when a later packet
fails, cancellation occurs, or a budget leaves the run partial. Failed/cancelled
responses do not become usable commentary merely because they contain a label.

Old stored rows without `kind` remain readable with an empty Go field and retain
absent JSON metadata. They are not backfilled or silently rewritten. Consumers
must treat missing/unknown metadata as unclassified, never observation. Summary
continues to omit sentence `kind`; it does not parse the Review prefix.

## Synthesis and limits

Only successful validated, locally restored commentary enters synthesis, with
original primary references resolved against the frozen same-case snapshot.
Preparation constructs a fresh token/citation namespace, preserving distinct
packet identities. Each included commentary line is explicitly marked:

```text
commentary_only | kind=hypothesis | Re-pseudonymized commentary. [E1]
```

Canonical metadata is preserved. Unknown or absent legacy metadata becomes the
fixed `unclassified` value before interpolation; arbitrary metadata is never
copied into the prompt. Raw rejected answers remain excluded. Existing omission
counts and byte/privacy gates apply to these complete lines, including type
metadata. The synthesis prompt says commentary is not evidence, preserves
uncertainty/disagreement, forbids implicit promotion of hypotheses/possible
conflicts and does not instruct automatic reconciliation.

The output-contract marker is in the exact system payload, not a new database
column. Prompt edits naturally change payload SHA-256 and preview/plan binding;
source fingerprints still identify source data, not model output. Input caps use
actual system-plus-user UTF-8 bytes, including prompts and category metadata.
Output budgets include serialized sentence JSON, so `kind` costs bytes too.
Consent, privacy receipts, frozen snapshots/provider binding, cancellation,
restart interruption/no-resend, and transport clients remain unchanged.

**Structural validation does not verify truth**, including a model-supplied
`observation`. It does not prove contradiction, execution, success, identity,
completeness or model accuracy, nor enforce every semantic instruction above.
A provider may mislabel or overstate a claim; examiner review is still necessary.
Synthetic tests prove protocol/workflow preservation, not real-model analytical
quality. No live provider, user case, VirusTotal, stored-VT-input feature, analyst
acceptance workflow or report appendix is authorized or implemented here.

## UI and integrated verification

The same grouped renderer is used for single-packet Review, initial batch
packets and synthesis. Each nonempty category shows its count, category-specific
caution and original actionable citations. Missing/unknown stored metadata is
shown under **Unclassified / not type-checked**, not retrospectively inferred
from text. Styling is neutral, not detector severity. Legacy Summary remains a
flat list and does not use the Review grouping renderer.

The parent reran integrated review/summary/UI/store race checks after merging:
API 135.196s, narrative 12.164s, store 30.523s, all PASS. Build, vet and JS syntax
checks also passed. The built `bin/tracefall-claim-types` was exercised with:

```sh
TRACEFALL_TEST_TYPED_CLAIMS=1 PLAYWRIGHT_MODULE=/path/to/playwright \
 node tests/case-review-batches.browser.cjs /absolute/tracefall-claim-types "$SCRATCH/claims-typed"
PLAYWRIGHT_MODULE=/path/to/playwright \
 node tests/review-claim-types.browser.cjs "$SCRATCH/claims-fixtures"
```

Without an asset override, the browser harness compared the binary-served assets
with integrated source and exercised a real synthetic provider: 181 imported
events, four initial requests plus one synthesis, five grouped kinds in packet
and synthesis output, exact captured payload/hash readback, partial budget,
cancel, external no-send controls and existing state-preservation checks.
The typed mode also started an actual single Review through its UI, checked five
persisted categories and exact wire payload/hash, and opened the hypothesis
citation's original event. Desktop/390px screenshots were inspected. Separate
zero-write UI fixtures covered missing/unknown legacy kinds, no prefix inference,
HTML escaping, unchanged Summary and packet-specific coverage references. The
untyped provider mode also passed as a compatibility control. The original
single-event drilldown locator was made explicit with `.first()` because typed
output legitimately contains several citations to the same event.

A separate integrated-binary HTTP restart probe used a synthetic hypothesis-only
provider. All five successful packet/synthesis items still had kind `hypothesis`
after an actual restart. An in-flight later run became interrupted, and provider
calls remained six before/after restart with no automatic resend. Exact payloads
and original primary coverage remained inspectable; deletion and request-source
checks passed; disposable ports were verified closed. These checks prove
transport/UI/persistence behavior, not model accuracy. Full-suite and independent
source review are separate final gates.
