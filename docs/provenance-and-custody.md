# Provenance and chain of custody

This document describes what Tracefall can and cannot prove about where
its conclusions came from.

**Terminology matters here.** Tracefall records *technical provenance*:
which stored object produced which other stored object, and whether the
bytes it read still hash the way they did when it first read them. That
is not the same as legal chain of custody, and this document does not
claim it is. See [What this does not prove](#what-this-does-not-prove).

---

## The chain

```
Evidence  →  Collection  →  Source file  →  Parser  →  Event
                                                         ↓
              Export  ←  Investigation  ←  Finding  ←────┘
```

Almost all of this existed before Phase 11 and is **reused**, not
reimplemented. Phase 11 added the two missing links, exposed the chain
as a chain, and made the evidence re-checkable.

| Link | Mechanism | Status |
|---|---|---|
| Case → Collection | `Collection.CaseID` | pre-existing |
| Collection → Source file | `SourceFile.CollectionID` | pre-existing |
| Source file → Event | `Event.SourceFileID`, `CollectionID`, `Parser`, `ArtifactType`, `SourceReference` | pre-existing |
| Event → each observation | `EventObservation` — one row per collection an event was seen in | pre-existing |
| Event → raw record | `Event.RawEvidenceID` → `RawEvidence` | pre-existing |
| Finding → Events | `Finding.SupportingEvents` | pre-existing |
| Investigation → everything | `Investigation.FindingIDs` / `EventIDs` / `CollectionIDs` / `SourceFileIDs` | pre-existing |
| **Finding → Analysis run** | `Finding.AnalysisRunID` → `analysis_runs` | **new in Phase 11** |
| **Anything → Tool build** | `internal/version` | **new in Phase 11** |

Every link is a stable ID. No provenance anywhere depends on a row
number, an array index, or a UI position.

### Reading the chain

| Question | Endpoint |
|---|---|
| What is this case built from? | `GET /api/cases/{id}/provenance` |
| Why does this finding exist, and on what evidence? | `GET /api/cases/{id}/findings/{findingID}/provenance` |
| What did this source file produce? | `GET /api/cases/{id}/sources/{sourceFileID}/provenance` |
| Where did this event come from? | `GET /api/cases/{id}/events/{eventID}` (pre-existing, extended) |
| Has this evidence changed? | `POST /api/cases/{id}/evidence/{collectionID}/verify-integrity` |

---

## Evidence identity: two hashes, two jobs

Unchanged from Phase 10A, and deliberately so.

| Field | Algorithm | Purpose |
|---|---|---|
| `archive_hash` | SHA-256 | **Deduplication identity.** What the duplicate-evidence check compares. |
| `integrity_sha512` | SHA-512 | **Integrity attestation.** What verification re-computes. |

SHA-512 did not replace SHA-256, and duplicate detection is untouched.
Full details of what is hashed for each source type are in
[evidence-integrity.md](evidence-integrity.md).

### Timestamps are labelled for what they are

A collection's timestamp is `imported_at` — when **Tracefall received**
the evidence. It is never called an acquisition time, because Tracefall
did not acquire the evidence and has no way to know when it was
collected from the source machine. No provenance response contains an
`acquisition_time`, `acquired_at` or `collected_at` field, and a test
asserts their absence.

---

## Integrity verification

**Verify Integrity** recomputes a collection's SHA-512 and compares it
with the digest recorded at ingestion.

It uses the **same functions** Phase 10A used to record the digest — not
an equivalent reimplementation. A verifier that canonicalized even
slightly differently would report a mismatch on unchanged evidence,
which is worse than not verifying at all.

| Source type | What is re-hashed |
|---|---|
| Uploaded archive | The received bytes, still on disk as uploaded — **not** the extraction directory |
| Segmented AD1 | Every segment's raw bytes, concatenated in segment order — **not** extracted or decompressed content |
| Local directory | `relpath + NUL + contents + NUL` per file in `WalkDir` lexical order — no mtime, inode, permissions or absolute path |

### Three outcomes, not two

| Status | Meaning |
|---|---|
| `verified` | The evidence hashes exactly as it did at ingestion. |
| `mismatch` | The evidence is readable but hashes differently. **This is a finding about the evidence, not an error in Tracefall.** |
| `unavailable` | Verification could not run — no digest was recorded, or the evidence is no longer reachable. |

`unavailable` is deliberately distinct from `mismatch`. **Not knowing is
not the same as knowing it changed**, and collapsing the two would let a
missing file read as tampering.

Both digests are returned complete (128 characters). Truncation is a
display choice; the API never truncates, and the UI's compact form
always carries the full value in its copy control and its "Show full"
expansion.

### Verification is read-only

It never modifies evidence, source files, collection rows, hashes,
events, findings or investigations, and never re-imports or re-analyzes.
A test snapshots the entire case as JSON before and after repeated
verification and fails on any difference.

**The recorded digest is never rewritten.** It is the historical fact
being checked; "verifying" by overwriting it would destroy the thing
under test. Verification appends one audit entry stating the outcome —
that entry is a record of the *analyst's action*, not a change to the
evidence.

---

## Analysis runs

Before Phase 11 a finding could be traced to its evidence but not to the
*analysis* that produced it. Re-analysis replaces every finding
atomically, so "was this from the run I read last week?" had no answer.

An `analysis_runs` row records each execution: id, start, completion,
status, tool version, and the counts produced. Findings carry
`analysis_run_id`.

- **Re-analysis is distinguishable.** A second run gets a new id, and
  findings are attributed to it.
- **Superseded runs are kept.** Their findings are gone — analysis
  replaces them, exactly as before — but the record that the run
  happened, when, and on which build outlives its output.
- **A finished run is immutable.** `FinishAnalysisRun` updates only a
  run still marked `running`, so a completed run cannot be reopened or
  rewritten.
- **A run that died mid-way stays `running`** with a nil completion
  time, rather than being silently promoted to `failed`.
- **Recording is best-effort.** If the run row cannot be written,
  analysis still proceeds and its findings carry no run id — the same
  honest "unavailable" state a legacy finding has, rather than a
  dangling reference.

Analysis behaviour itself is unchanged. Runs are a record *of* the
process, not a new lifecycle around it, and `analysis_run_id` is set
after detection and is not an input to any rule, severity, confidence or
StableID.

---

## Audit trail

The audit log predates this phase. Phase 11 extended its vocabulary with
`integrity_verified` rather than building a second log.

**Append-only from the application's perspective.** The store exposes
only `CreateAuditEvent`; there is no update or per-row delete path, and
no route accepts a mutation of an audit entry. Tests assert both: that
ordinary operations leave every historical entry byte-identical, and
that `PUT`/`PATCH`/`DELETE`/`POST` against an audit entry are not
handled.

### Actor is not identity

Every entry records `local-user`. Tracefall has **no authentication**,
so there is no way to attribute an action to a specific human. This
field must not be treated as an authoritative identity — not for access
control, and not for non-repudiation. Nothing invents a named analyst.

### Deletion and the audit trail

| Action | Effect on provenance |
|---|---|
| Delete a **source file** | Soft delete. The row is retained with `deleted_at`; provenance reports it as **Deleted** rather than omitting it. Events observed elsewhere survive and have their provenance re-pointed to a surviving observation. The deletion is audited. |
| Delete a **case** | Hard delete of everything scoped to that case, **including its audit log and analysis runs**. |

The second row is pre-existing behaviour, documented here rather than
changed. It is a real limitation: deleting a case destroys the record of
what was done to it. Within a live case, deleting evidence never erases
the audit entry describing that deletion.

---

## Legacy data

Rows written by earlier builds do not carry provenance that did not
exist yet. Tracefall reports that honestly and **never backfills**:

| Missing | Reported as |
|---|---|
| `analysis_run_id` on a finding | *Legacy — provenance unavailable* |
| `integrity_sha512` on a collection | Verification returns `unavailable` with a reason |
| `imported_at` on a source file | *Not recorded* |

Backfilling would mean inventing a run that was never recorded, or
computing a digest now and presenting it as an attestation about the
past. Both are fabrication. Migration tests assert that a pre-Phase-11
database gains the new schema while its existing findings stay
unattributed and **zero** runs are invented.

---

## Export provenance

The case JSON export is **additive** — every pre-existing field keeps its
name, type and position, and a regression test asserts that. It now also
carries:

- `tool_version` — the build that produced the export
- `analysis_runs` — the case's run history, so each finding's
  `analysis_run_id` resolves within the same document

Evidence hashes are **not** duplicated into new fields: `collections`
already carries `archive_hash` and `integrity_sha512` for every
collection, and a second copy could disagree with the first. A test
asserts the exported digest equals what verification computes.

---

## What this does not prove

Being precise about the limits is part of the point.

- **This is not legal chain of custody.** Tracefall records technical
  provenance between stored objects. It does not establish who handled
  the evidence, under what authority, or with what continuity of
  possession — and an audit log does not create those facts.
- **There is no authenticated actor.** Without authentication, `actor`
  records that *something* acted, not *who*.
- **Integrity is not a signature.** A recorded digest proves two reads
  saw the same bytes. It is not timestamped by a third party, is stored
  in the same database as everything else, and would not detect an
  attacker who altered the evidence *and* the recorded digest together.
- **Verification says nothing about before ingestion.** It compares
  against what Tracefall first saw. Whether that already differed from
  what was collected is outside what Tracefall can know.
- **A `mismatch` names no cause.** It says the bytes changed, not who
  changed them or why. Ordinary causes — a file re-copied, a directory
  edited — produce the same result as tampering.
- **Deleting a case destroys its audit trail**, as described above.
- **Investigations are recomputed, not stored**, so they have no
  identity that persists across analyses; their provenance is that of
  the findings they group.
