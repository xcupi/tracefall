# Investigation assessment layer

`internal/investigate` (Phase 5) is Tracefall's investigation-level
assessment layer. It sits above `internal/detect` and `internal/correlate`,
never below or beside them: it takes their already-computed,
already-persisted output (`Finding`, `Correlation`) plus the case's
`Event`s, and groups, categorizes, scores, and narrates them into a small
number of evidence-backed "investigations" — the story an analyst would
otherwise have to reconstruct by hand from a dozen separate findings.

Like detect and correlate, this package is a pure, deterministic function
of its input: no network calls, no LLM, no randomness. Running `Run`
twice on the same findings/correlations/events always produces the same
investigations, in the same order. It never rewrites or hides a Finding —
every Finding in an analyzed case is referenced by exactly one
Investigation, and the individual Findings/Correlations endpoints are
completely unaffected by this package's existence.

## Why investigations are never persisted

`Service.Investigations`/`Investigation` (`internal/api/service.go`) call
`investigate.Run` at read time against whatever `Finding`/`Correlation`
rows are currently in the database — the same "compute on read from
existing store queries" pattern `CaseSummary` and `AttackSummary` already
use, with no new table and no migration. This has one very deliberate
consequence: deleting evidence and re-running analysis can never leave a
stale investigation behind. There is no cache to invalidate — the next
`GET /cases/{id}/investigations` simply recomputes from the current
`Finding`/`Correlation` rows, which `AnalyzeCase` already keeps
authoritative (it clears and resaves both atomically). Investigation
generation is cheap enough for this to be free in practice: a union-find
pass over at most a few hundred events, per request.

## The `Investigation` model

Defined in `internal/model/investigation.go`. Every field beyond the
narrative/score/rationale is either a scalar summary (severity,
confidence, category, time range, hosts, users) or a list of **references**
into already-existing case data — `EventIDs`, `FindingIDs`,
`CorrelationIDs`, `Techniques`, `CollectionIDs`, `SourceFileIDs` — never a
copy of the underlying record. Resolve them through the exact same
endpoints the Timeline/Findings/Activity Chains tabs already use
(`GET .../events/{id}`, `GET .../findings/{id}`); the investigation detail
endpoint (below) does this resolution automatically for convenience.

`Investigation.ID` is **not** a random UUID — see "Stable IDs" below.

## Grouping: `internal/investigate/group.go`

Investigations are connected components of a graph whose nodes are
events and whose edges are:

- two events that are both in the same Finding's `SupportingEvents`, and
- two events that are both in the same *mergeworthy* Correlation's
  `EventIDs`.

A connected component is promoted to an Investigation only if it contains
at least one Finding — a cluster of correlated events with no Finding
attached is correlation context, not a risk-assessed story.

**"Mergeworthy" deliberately excludes `temporal` correlations.**
`internal/correlate`'s own doc comment describes `temporal` as "the
weakest, most general correlation type: it asserts these events happened
close together, nothing about causation" — exactly the "same host, same
time window" signal the task this package was built for explicitly
prohibits using to group investigations. Without this exclusion, a burst
of entirely unrelated low-severity findings that merely occurred within
the same 10-minute window on one host — ordinary benign administrative
activity is a real, verified example of this (see "False-positive
validation" below) — would get merged into one artificially inflated
"multi-stage" investigation. `process_chain`, `entity`, and the three
narrative chain types (`activity_chain`, `credential_chain`,
`service_chain`) all remain mergeworthy: each is backed by a specific,
named heuristic beyond mere timing.

## Categorization: `internal/investigate/category.go`

A fixed, small set of seven analyst-level categories (not one per
detection rule — there are 15 rules):

| Category | When assigned |
|---|---|
| `multi_stage_attack` | Evidence spans 3+ of {execution, persistence, credential, network} |
| `credential_attack` | Only credential-related findings (brute force, explicit creds, privileged/remote logon) |
| `service_persistence` | Persistence evidence backed by a `service_install` event specifically |
| `persistence` | Any other persistence evidence (Run key, scheduled task, Winlogon/IFEO/AppInit_DLLs) |
| `suspicious_network` | Network evidence without an accompanying execution facet |
| `script_based_attack` | Execution evidence involving a scripting interpreter |
| `suspicious_execution` | Any other execution evidence (also the fallback default) |

Every rule ID from `internal/detect/rules.go`'s `All()` is mapped to one
or more coarse **facets** (execution, script-interpreter, persistence,
service, credential, network) in `ruleFacets`; categorization is a fixed
decision tree over the union of a group's facets, documented in full in
`categorize`'s doc comment.

## Risk scoring: `internal/investigate/score.go`

A fixed, documented, additive point system — never ML, never an LLM.
**Each factor is checked at most once per investigation** (a boolean "is
this facet/property present in the group", not "how many findings have
it"), which is what keeps several findings that all stem from the same
underlying event from inflating the score multiple times over.

| Factor | Points |
|---|---|
| Base: highest finding severity (low/medium/high/critical) | 15 / 30 / 50 / 70 |
| Execution facet present | +5 |
| Scripting-interpreter facet present | +5 |
| Persistence facet present | +10 |
| Credential facet present | +5 |
| Network facet present | +5 |
| A genuine multi-step chain correlation present | +15 |
| ...else any (mergeworthy) correlation present | +5 |
| Spans 3+ ATT&CK tactics *(only if independently corroborated — see below)* | +10 |
| Spans 2 ATT&CK tactics *(same gate)* | +5 |
| Corroborated by 2+ independent artifact types | +5 |
| Independently observed across 2+ evidence collections | +5 |

Score is clipped to [0, 100] and mapped to severity: **critical** ≥ 70,
**high** ≥ 50, **medium** ≥ 25, else **low**.

**Base points and thresholds are calibrated together** so that a
finding's own severity, taken entirely alone with zero corroboration,
maps to that *same* Investigation severity — matching the worked example
"a suspicious PowerShell command may be Severity: HIGH, Confidence:
MEDIUM": a standalone high-severity finding stays high-severity at the
investigation level; only its *confidence* reflects the lack of
corroboration. Corroborating factors then provide headroom to escalate a
*lower*-severity finding upward, never to invent severity from nothing.

**Facet bonuses are deliberately modest** relative to the base-severity
points: a single finding-cluster commonly satisfies several rules/facets
from one or two underlying events (e.g. one encoded PowerShell command
that's also a suspicious parent/child pattern and also makes a network
connection) — that's the *same* evidence looked at from several rules'
angles, not several independent pieces of evidence. Facet presence alone
must never be able to carry a case across two full severity bands; real
escalation to critical comes from the corroboration factors (a real
correlation, multiple artifact types, multiple evidence collections)
stacking on top.

**Tactic diversity is gated behind genuine corroboration**
(`hasAnyCorr || distinctArtifact >= 2 || distinctCollect >= 2`) —
otherwise "spans 3 tactics" can be entirely an artifact of one or two
events each matching several rules that each map to a different tactic
(Execution + Defense Evasion + Command and Control from a single
encoded-PowerShell-then-network pair), which is the same evidence counted
from multiple angles, not genuinely diverse evidence. This was found and
fixed during Phase 5's own browser verification (see "Known issues found
and fixed" below).

**Cross-collection scoring only counts genuinely independent evidence.**
A single real-world event re-observed in two collections is still *one*
`Event` row with *one* (first-observation) `CollectionID` — Tracefall's
deduplication (`Event.ComputeDedupHash`) guarantees this by construction
— so the cross-collection bonus can only fire when the group actually
contains distinct, independently-sourced events, never merely because
the same artifact was collected twice.

## Confidence: `internal/investigate/confidence.go`

Computed **entirely independently of Severity/Score** — confidence is
not derived from how bad a finding looks, only from evidence quality and
corroboration strength:

1. Start from the group's own best-reported `Finding.Confidence` (low=1,
   medium=2, high=3).
2. +2 if a genuine multi-step chain correlation backs the group, +1 for
   any weaker mergeworthy correlation (entity/process-chain) instead.
3. +1 if corroborated by 2+ independent artifact types.
4. +1 if independently observed across 2+ evidence collections.

Combined ≥ 5 → **high**; ≥ 2 → **medium**; else **low**. This reproduces
both of the task's worked examples exactly: a standalone medium-confidence
finding with nothing else (combined = 2) → medium; a chain-correlated,
multi-artifact investigation (combined ≥ 6) → high.

## Narrative: `internal/investigate/narrative.go`

A deterministic, template-generated prose summary, built by walking the
group's events **in timestamp order** and emitting one clause per
notable event type (logon, process create/spawn, persistence, network,
DNS, credential use), joined into sentences. It never speculates about
intent — no "the attacker", only "the activity" / "the process" / "the
observed execution" — and every clause is derived directly from a real
event's fields.

An earlier version of this function preferred a chain correlation's own
step ordering over plain chronological order, on the theory that the
chain's ordering is authoritative. **Phase 5's own browser verification
caught two real bugs this produced** (see below), and the fix was to
simplify to always-chronological ordering — a chain correlation's steps
are themselves already chronological by construction
(`internal/correlate/activity_chain.go` and its credential/service-chain
counterparts all walk strictly forward in time), so plain timestamp order
reconstructs the identical narrative for chain events while staying
correct for every other event in the group too.

## ATT&CK view: `internal/api/service.go`'s `buildAttackBreakdown`

Each `InvestigationDetail` response includes an `attack_breakdown`:
Tactic → Techniques → supporting Finding IDs → supporting Event IDs,
scoped to that one investigation (compare the case-wide `AttackSummary`,
which is the same shape at case scope). A technique is only ever
attached because a finding within *this* investigation actually carries
it — `internal/attck` remains the single source of truth for technique
metadata; this only groups IDs findings already reference.

## Stable IDs

`Investigation.ID` is a SHA-256 hash of the case ID plus the sorted set
of Finding IDs it groups (`internal/investigate/util.go`'s `stableID`),
**not** a random UUID. Because investigations are recomputed on every
read, a random ID would make `GET .../investigations/{id}` unable to find
what an earlier `GET .../investigations` just listed. The ID changes only
when the investigation's actual finding membership changes (evidence
added/removed and reanalyzed) — which is correct: it genuinely is a
different grouping then.

## Known issues found and fixed during this phase's own verification

Live browser verification (not just unit tests) caught three real bugs,
each fixed and covered by a regression test:

1. **Temporal correlations over-merging benign activity.** Before the
   `mergeworthy` exclusion above, Phase 4's benign Scenario G (ordinary
   RDP logon, privileged logon, mapped-drive credentials, standard
   software install, standard scheduled task/service) merged into one
   artificial "Multi-Stage Attack" investigation scoring CRITICAL, purely
   because everything happened within one 10-minute temporal cluster on
   one host. Fixed by excluding `temporal` from grouping; verified
   Scenario G now produces only LOW/MEDIUM investigations (see
   `TestInvestigations_BenignScenarioG_NoSevereFalsePositive` and the
   live browser check).
2. **Narrative ordering.** A non-chain event timestamped *before* a
   chain's steps was narrated *after* them (because chain events were
   emitted first, non-chain events appended afterward), producing claims
   like "...a network connection was observed. the process explorer.exe
   was subsequently observed executing" about a process that actually ran
   first. Fixed by always ordering the narrative chronologically (see
   `TestBuildNarrative_ChronologicalEvenWithUnrelatedLaterMergedEvent`).
3. **Continuation phrasing across an interleaved clause.** A logon event
   interleaved between a parent process's own clause and its child's
   caused the child to be phrased as a continuation of the *logon*
   sentence ("...a successful logon for user jdoe, which spawned
   winword.exe"), wrongly implying the logon spawned the process. Fixed
   by resetting the "last process" continuation tracker on every
   non-process-create clause (see
   `TestBuildNarrative_ContinuationNotAcrossInterveningClause`).

## Adding a new category or scoring factor

1. New rule IDs need an entry in `category.go`'s `ruleFacets` — an
   unmapped rule contributes no facet (falls through to the default
   category) rather than erroring, so this is a silent gap to watch for,
   not a crash.
2. New scoring factors: add a named constant in `score.go` with a comment
   explaining the reasoning (see the existing factors for the pattern),
   and make sure it's a boolean "present in the group" check, not
   something that scales with the number of findings — see "each factor
   checked at most once" above.
3. Add tests in `internal/investigate/investigate_test.go` covering the
   trigger case, a case that must *not* fire, and — for anything
   touching severity — the exact score/threshold boundary.
