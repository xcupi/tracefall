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
