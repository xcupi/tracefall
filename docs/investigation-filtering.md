# Investigation filtering, date ranges, and severity transparency

This covers the Timeline, Findings and Investigations tabs: how to narrow
them, and how to read a finding's severity.

---

## Filters

All three tabs share one filter component, so search, chips, keyboard
behaviour and counts work identically wherever you are.

| Tab | Search | Dropdowns | Date range |
|---|---|---|---|
| **Timeline** | Search events… | Severity, Category, Host, User, Process, ATT&CK, Collection\* | yes |
| **Findings** | Search findings… | Severity, Confidence, Host, User, ATT&CK, Rule, Collection\* | yes |
| **Investigations** | Search investigations… | Severity, Confidence, ATT&CK | no |

\* The Collection dropdown appears only when a case has more than one
evidence collection — there is nothing to filter between otherwise.

Dropdown values are derived from the data the tab actually loaded, so a
dropdown only ever offers values that are present. A dropdown with more
than **10** options grows a type-ahead search inside it, and the popover
shows `3 of 27 selected` so the count is never hidden by the compact
trigger label.

### Multi-select semantics

- Within one dropdown, values combine with **OR** — selecting `High` and
  `Critical` shows findings that are either.
- Across dropdowns, filters combine with **AND** — `High` + `Registry`
  shows only high-severity registry findings.
- Search combines with **AND** on top of everything.
- Every active filter appears as a removable chip. Chips remove one
  value; **Clear all** removes everything.

### Severity and ATT&CK on the Timeline

An *event* has no severity — severity belongs to a Finding. Filtering the
Timeline by severity or ATT&CK therefore shows events that are **cited by
a finding** of that severity or technique. This is why an event can
disappear from a severity-filtered Timeline while remaining in the
unfiltered one: nothing found it noteworthy.

### Search

Case-insensitive substring matching, client-side over data the tab has
already loaded. There is **no API call per keystroke**; the 120 ms
debounce exists only to avoid re-rendering a large table on every
character.

| Tab | Searched fields |
|---|---|
| Timeline | host, user, process, process path, parent process, parent path, event type, command line, file path, registry path, network source/destination, provider, artifact type, parser, event ID, and the ATT&CK techniques of any finding citing the event |
| Findings | title, description, rule ID, severity, confidence, ATT&CK techniques |
| Investigations | title, summary, severity, confidence, ATT&CK techniques, hosts, users |

Each row's searchable text is built once and cached on the object as a
non-enumerable property, so a 100,000-event timeline pays that cost on
the first keystroke only.

### Clear filters

**Clear all** resets search, every dropdown, the date range, and the
chips. It never touches the underlying evidence — it is a view control.

### Counts

Headings always read `filtered of total`:

```
Unified timeline (7 of 51 events)
Findings (4 of 45)
Investigations (3 of 15)
```

The right-hand number is the case total; the left is what the current
filters show. They are never conflated.

### Filter state and tab switching

Filter selections, the search term and the date range are carried across
a tab switch, **scoped to the case**. Returning to the Timeline restores
both your filters and your scroll position, so you land where you left
off in a list that still matches what you were looking at.

Switching to a *different case* resets them. A date range set while
triaging one case must never silently pre-filter another.

---

## Date range

The Date range control offers a native calendar picker plus a time field
for each end, an explicit timezone note, Clear, and Apply.

### Timezone

**Timestamps are displayed and filtered in UTC.** The picker shows your
browser's current offset (e.g. `UTC+07:00 (browser local)`) so it is
never ambiguous which clock a typed time refers to, and the Timeline
column header reads `Time (UTC)`.

### Boundary semantics — both ends inclusive

For **events**, an event is shown when:

```
from <= event.timestamp <= to
```

Both bounds are **inclusive**. An event exactly on either boundary is
inside the range. Either bound may be left empty for an open-ended range.

For **findings**, which span `first_seen`..`last_seen`, the filter is an
**overlap** test:

```
finding.last_seen >= from   AND   finding.first_seen <= to
```

A finding is shown when any part of its span falls inside the window,
including when it merely touches a boundary. A finding that entirely
precedes or entirely follows the window is excluded.

Verified boundary behaviour:

| Case | Result |
|---|---|
| Event exactly at `from` / at `to` | shown |
| Event one second outside either end | hidden |
| `from` only / `to` only | open-ended, as expected |
| `from` == `to` | only that exact instant matches |
| Inverted range (`to` < `from`) | matches nothing; no error |
| Finding span overlapping either end, or containing the range | shown |
| Finding span entirely before/after | hidden |

---

## Severity

### Severity is rule-driven, not scored

A Finding's severity and confidence are decided by the **detection rule
that produced it**, from concrete conditions in the evidence. There is no
points model at the finding level and no configurable matrix.

Most rules have a **baseline** level and a set of **escalating
conditions**. A registry Run key is `low` on its own — ordinary software
writes Run keys constantly — and becomes `high` when its target sits in a
user-writable directory. That is the entire mechanism: a rule states what
would raise it, and the evidence either meets it or does not.

Only one rule asserts **critical**: `execution-persistence-temporal`,
which requires two independent behaviours linked by a shared target
within a bounded time window. That is a materially stronger claim than
either observation alone, which is why nothing else reaches it.

### The matrix

`GET /api/severity-model` publishes the live matrix for every registered
rule — baseline severity/confidence, maximum, escalating conditions, the
basis for the level, and ATT&CK mappings. It is generated from
`internal/detect.Catalog()`, and a test fails the build if a rule is
added without an entry, if an entry outlives its rule, or if a rule
assigns a level outside its documented band.

| Rule | Baseline | Max | Escalates when |
|---|---|---|---|
| `execution-persistence-temporal` | critical / high | — | (fixed) |
| `brute-force-then-success` | high / high | — | (fixed) |
| `office-spawns-powershell` | high / medium | — | (fixed) |
| `office-spawns-script-interpreter` | high / medium | — | (fixed) |
| `suspicious-process-chain` | high / medium | — | (fixed) |
| `powershell-encoded-command` | medium / medium | high | ≥2 suspicious indicators in one command |
| `registry-persistence-extended` | medium / low | high / medium | value data in a user-writable path |
| `network-after-execution` | medium / low | high / medium | executing image in a user-writable path |
| `new-registry-run-key` | low / low | high / medium | Run key target user-writable |
| `new-scheduled-task` | low / low | high / medium | action is a LOLBin, or path user-writable |
| `suspicious-parent-child-lineage` | low / low | high / medium | child is a LOLBin, or path user-writable |
| `service-persistence` | low / low | high / medium | image path user-writable, or a LOLBin |
| `privileged-logon-observed` | low / low | high / medium | same account has other auth anomalies |
| `explicit-credential-use` | low / low | medium / medium | invoking process is a LOLBin |
| `remote-logon-observed` | low / low | — | (fixed) |

### "Why this severity?"

Expanding a finding shows the reasoning. Every statement comes from one
of exactly two sources:

1. **The rule's declared reasoning** — what it detects, why its baseline
   is what it is, and what would raise it.
2. **Facts counted from that finding's own supporting events** — how
   many, over what timespan, from which artifact types and collections,
   touching which hosts and accounts, mapped to which techniques.

Nothing else. There is no factor that says a finding is "probably"
anything, because the data to support such a claim does not exist. If a
finding sits above its rule's baseline the panel says so and names the
conditions that could have raised it — the rule does not record *which*
one fired, so the honest statement lists the candidates rather than
picking one.

**Corroboration is counted, never assumed.** Two events of the same
artifact type in one collection are not corroboration. An event log and a
registry hive describing the same behaviour are, because they were
collected and written independently — and the panel names them.

### Confidence

Confidence describes evidence *quality*, separately from severity. A
suspicious PowerShell command can be high severity and medium confidence
at once: serious if real, but a single artifact saying so.

Investigations compute confidence with a documented additive model
(`internal/investigate/confidence.go`), starting from the best supporting
finding's confidence and adjusting for corroboration. Investigations also
carry a 0–100 risk score with an itemized rationale
(`internal/investigate/score.go`) — both predate this phase and are
unchanged.

### Why the matrix is not runtime-configurable

Findings are **recomputed from scratch on every re-analysis**. A
runtime-editable severity table would therefore silently rewrite the
severity of historical findings the next time a case was analyzed — an
analyst could change a dropdown and, without any further action, alter
what past evidence appeared to show. That is not a trade-off worth
making for a forensic tool, so the model is fixed in the build and
published read-only for inspection instead.

Changing severity is a code change, reviewed and versioned, and it
applies on the next analysis run.

---

## Artifact priority is not finding severity

These are different judgements and must never be read as the same thing.

| | Artifact priority | Finding severity |
|---|---|---|
| Question | "How important is this evidence to inspect?" | "How serious is this observed finding?" |
| Applies to | A file in an evidence collection | A detection result |
| Values | Critical / High / Medium / Low / Unknown | Critical / High / Medium / Low |
| Source | `internal/artifacts` (Phase 9A) | The detection rule |
| Independent of | Whether a parser exists | — |

A raw Prefetch file is **HIGH artifact priority** and **unsupported** —
valuable evidence Tracefall cannot currently read. That is not a finding
and has no severity. They are styled differently in the UI (priority as
an outline badge, severity as a filled one) so they are not confused at a
glance.

---

## Limitations

- Filtering is client-side over data the tab has loaded. Every tab loads
  its full dataset, so a case far beyond 100,000 events would want
  server-side filtering; measured client-side filtering at 100,000 events
  is 219 ms on the first keystroke and 32 ms after.
- The Timeline renders all matching rows. The evidence-selection screen
  caps its render at 400 rows; the Timeline does not, because a filtered
  timeline is normally the thing you want to read in full.
- A finding's explanation names the escalating conditions its rule
  *could* have applied, not the one that actually fired — rules do not
  record which condition matched.
- Investigations have no date-range filter; they are grouped from
  findings that already carry their own time spans.
