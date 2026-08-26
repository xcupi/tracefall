# Analyst workflow (Phase 6)

Phase 6 ("Forensic Hardening & Analyst Workflow") adds a thin layer of
analyst-facing workflow state on top of Tracefall's deterministic
forensic engine: case metadata, notes, tags, finding/investigation
review status, an audit trail, and export. **None of this is forensic
evidence, and none of it is ever produced by the detection, correlation,
or investigation engines.** It exists specifically so a human
investigator has somewhere to record their own judgment without that
judgment ever being confused with, or capable of altering, what the
deterministic engine actually found.

## The core rule

> **Engine Assessment** (Severity, Confidence, the finding/investigation
> itself) is always deterministic, evidence-derived, and untouched by
> anything an analyst does.
>
> **Analyst Assessment** (review status, notes, tags) is always
> human-entered, optional, and layered on top -- never written back into
> a Finding or Investigation's own fields.

Concretely: `internal/model.Finding.Severity`/`Confidence` and
`internal/model.Investigation.Severity`/`Confidence`/`Score` are produced
exclusively by `internal/detect`, `internal/correlate`, and
`internal/investigate`. Nothing in `internal/api/workflow.go` (the
analyst-status/notes/tags code) has a code path back into those values.
`TestFindingStatus_NeverModifiesDeterministicResult` and
`TestAnalystStatus_DoesNotTouchFindingsTable`
(`internal/api/workflow_test.go`, `internal/store/workflow_test.go`)
verify this directly: setting a finding's status to `false_positive`
never changes its Severity/Confidence, at the API layer and the storage
layer respectively.

The dashboard keeps this distinction visually explicit wherever a
finding/investigation is shown: a "Deterministic Assessment" block
(severity, confidence, score, rationale -- read-only) and a separate
"Analyst Assessment" block (status, notes, tags -- editable) never
share a badge or a color scale.

## Why finding/correlation/investigation IDs had to become stable

Findings and Correlations are wiped and rebuilt from scratch on every
`/analyze` call (`internal/store.Store.ReplaceAnalysis`). Before Phase 6,
their IDs were random (`uuid.NewString()`), so the SAME real-world
finding got a brand-new ID on every re-analysis -- even a no-op
re-analysis that changed nothing about the evidence. Any analyst status,
note, or tag keyed by that ID would have been silently orphaned the
moment someone clicked "Re-run analysis" again.

Phase 6 fixed this at the source: `internal/detect.Run` and
`internal/correlate.Run` now assign IDs via `internal/model.StableID`, a
deterministic content hash (case ID + rule ID/type + sorted supporting
event IDs). `internal/investigate`'s Investigation IDs were already
stable (Phase 5), built from the same finding IDs -- so this fix also
transitively stabilizes investigation identity across re-analysis.
`TestRun_FindingIDsAreStableAcrossReanalysis` and
`TestRun_CorrelationIDsAreStableAcrossReanalysis`
(`internal/detect`/`internal/correlate`) lock this in directly; the
end-to-end proof is `TestAnalystStatus_SurvivesReanalysis`
(`internal/api/workflow_test.go`), which sets a finding's status,
re-analyzes unchanged evidence through the real HTTP API, and confirms
the status is still attached to the (unchanged) finding ID afterward.

An ID only changes when the finding/correlation/investigation it
identifies is genuinely different -- different supporting events, a
different rule, different case. That's correct: it really is a different
finding then, and analyst status attached to the old one legitimately
becomes orphaned (still queryable, no longer attached to anything live)
rather than silently migrated to whatever superficially resembles it.

## Case-level workflow: two independent status concepts

`model.Case` carries two status-like fields, deliberately never
conflated:

| Field | Values | Who sets it | Meaning |
|---|---|---|---|
| `Status` | `created` / `ingested` / `analyzed` | The engine, automatically | Does the case's current evidence have up-to-date analysis? |
| `CaseStatus` | `open` / `investigating` / `contained` / `closed` | An analyst, explicitly | Where is the human investigator in handling this case? |

A case can be `analyzed` (engine ran successfully) while `CaseStatus` is
still `open` (nobody's looked at it yet), or `ingested` (evidence just
changed, stale) while `CaseStatus` is `closed` (someone added evidence to
an already-closed case -- allowed, but it doesn't reopen the case
automatically; that's still an analyst decision).

`Priority` (`low`/`medium`/`high`/`critical`) is a third, independent,
purely-descriptive field an analyst sets -- nothing reads it to make a
decision.

## Notes

A `Note` (`internal/model.Note`) is free-text, attachable to a case,
collection, source file, event, finding, or investigation
(`model.Target*` constants). Every note's content is exactly what an
analyst typed -- Tracefall never generates one.

**Notes and evidence deletion.** Deleting the entity a note is attached
to does **not** delete the note. A note on a source file that later gets
deleted, or on a finding that no longer recurs after a re-analysis,
becomes an "orphaned" note -- still stored, still listed in a full-case
export, just attached to an ID that no longer resolves to a live object.
This is deliberate: a note is part of the investigation's own history
("I checked this file on the 3rd, it looked clean") and destroying it
because the file was later removed would erase exactly the record of
having checked it. The **one** exception is deleting the whole case,
which removes every record belonging to it, notes included -- there's no
partial state left to annotate once the case itself is gone.
(`TestNotes_SurviveTargetDeletion`, `TestNotes_DeletedWithCase` in
`internal/store/workflow_test.go`.)

## Tags

`Tag` is a lightweight label (`internal/model.CommonTags` offers a
predefined set as UI suggestions: `phishing`, `persistence`,
`credential-access`, `lateral-movement`, `suspicious`, `false-positive`,
`requires-review` -- but any string an analyst types is equally valid).
Tags are **never** auto-applied from ATT&CK technique, severity, or
category -- only an explicit analyst action creates one.

## Finding / Investigation review status

Separate vocabularies, matching how each actually progresses:

- Finding: `new` / `reviewing` / `confirmed` / `dismissed` / `false_positive`
- Investigation: `open` / `investigating` / `confirmed` / `dismissed` / `closed`

Both are stored in one shared `analyst_status` table
(`case_id, target_type, target_id, status, note, updated_at`), one row
per target (upserted on status change, not append-only -- the note field
here is a short one-line explanation of *why* the status changed; use the
Notes feature above for a longer running commentary). This table is
completely separate from `findings`/`correlations`, specifically so
`ReplaceAnalysis` never touches it.

## Audit log

Append-only, one row per recorded action
(`internal/model.AuditEvent`/`Audit*` action constants): case created,
evidence discovered/imported/deleted, analysis started/completed/failed,
finding/investigation status changed, note added, tag added/removed,
export. Never records raw evidence content or secrets -- only that an
action of a given kind happened, when, to what, and a short summary.

**Actor identity is not authoritative.** Every event's `actor` field is
currently `"local-user"` -- Tracefall has no authentication in this
phase (see `docs/security.md`), so there is genuinely no way to
attribute an action to a specific human. Do not treat this field as
proof of who did something; it exists to make the audit trail's shape
correct in advance of real authentication, not to provide non-repudiation
today.

**Audit writes are best-effort.** `Service.audit` swallows any error from
writing the audit event rather than failing the primary action that
triggered it (e.g. a note saving successfully must not fail the whole
request just because the secondary audit-log insert failed). This is a
deliberate trade-off: audit logging is a secondary record of what
happened, never a gate on whether the primary action succeeds.

**Scope limitation:** the audit log is per-case (`audit_log.case_id`),
and `DeleteCase` removes it along with everything else belonging to that
case -- so a case's own deletion is not separately auditable in the
current design (there's nothing left to read the "case deleted" entry
back from). A global, cross-case audit log would be needed to capture
case-deletion events themselves; noted as a recommended next-phase item.

## Analysis state

Five states from Phase 6's spec, and how Tracefall represents each:

| State | How it's represented |
|---|---|
| Not Analyzed | `Case.Status == "created"` (no evidence) or `"ingested"` with `AnalyzedAt` zero (evidence present, never analyzed) |
| Analyzed | `Case.Status == "analyzed"` |
| Evidence Changed | `Case.Status == "ingested"` with `AnalyzedAt` **non-zero** (it WAS analyzed before; evidence changed since) -- the dashboard's stale banner uses exactly this distinction |
| Analysis In Progress | Not persisted -- `AnalyzeCase` is synchronous (detect/correlate/investigate are pure, in-memory, non-blocking-I/O functions; the only I/O is the final atomic write), so there is no meaningful window where the case sits in an intermediate DB state. The dashboard shows a transient "Analyzing..." button state client-side for the duration of the request. |
| Analysis Failed | Not persisted as a case status -- see below |

### Why "Analysis Failed" isn't a persisted case status

`AnalyzeCase` computes findings/correlations in memory first, then
writes everything (`ClearAnalysis` + `SaveFindings` + `SaveCorrelations`
+ mark analyzed) in **one atomic transaction**
(`Store.ReplaceAnalysis`). If that transaction fails for any reason (disk
error, etc.), it rolls back completely -- the case's `Status`/
`AnalyzedAt`/findings/correlations are left in EXACTLY the state they
were in before the attempt. This is a direct fix for a real bug: the
pre-Phase-6 code ran `ClearAnalysis`, `SaveFindings`, `SaveCorrelations`,
and `UpdateCaseStatus` as four **separate** transactions, so a failure
between the first and the rest wiped the case's valid prior results with
nothing to replace them.

Given that guarantee, "the current evidence set has not been
successfully analyzed" is already fully and correctly conveyed by the
combination of the failed HTTP response (the caller learns immediately)
and the case's persisted state simply still reflecting whatever the last
*successful* analysis was (or "never analyzed," if there wasn't one).
Adding a fifth persisted case status for this would be redundant with
information the existing two fields (`Status`, `AnalyzedAt`) already
carry correctly, so Phase 6 chose not to. `internal/store.Store.ReplaceAnalysis`'s
doc comment and `TestReplaceAnalysis_SetsAnalyzedAt` cover this.

## Exports

Four export types (`internal/api/export.go`), all read-only,
deterministic (same data always serializes the same way), and containing
**no raw evidence and no secrets** -- only the same normalized
records the rest of the API already returns:

1. **Case JSON** (`GET /cases/{id}/export`) -- case metadata, collections,
   source files, findings, correlations, investigations, ATT&CK
   coverage, analyst statuses, notes, tags, audit log. Deliberately
   excludes the full event timeline (that's export #3's job -- a case's
   event count can be large, and duplicating it here would make every
   case export unnecessarily heavy).
2. **Investigation JSON** (`GET /cases/{id}/investigations/{id}/export`)
   -- identical shape to the investigation detail endpoint (already
   resolves every event/finding/correlation/technique reference inline).
3. **Timeline CSV** (`GET /cases/{id}/export/timeline.csv`) -- every
   event, one row each, fixed column order.
4. **Findings CSV** (`GET /cases/{id}/export/findings.csv`) -- every
   finding, enriched with its current analyst status/note (defaulting to
   `new`/empty if never set).

## Case/evidence isolation

Notes, tags, analyst status, and the audit log all live in tables shared
across every case (keyed by `case_id`), not one table per case --
`TestCaseIsolation_NotesTagsAuditDoNotLeakAcrossCases` and
`TestCaseIsolation_EvidenceDeletionScopedToOwningCase`
(`internal/api/security_test.go`) confirm one case's workflow data and
evidence-deletion actions are never visible through, or able to affect,
another case's endpoints -- including the specific case where two cases
happen to hold byte-identical evidence (a duplicate KAPE package
legitimately collected for two different investigations).
