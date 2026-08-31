# Scale, pagination and navigation

Phase 10B is about one problem: a real forensic image holds thousands of
files, and a real case holds thousands of records. This document
describes how Tracefall presents them — what is paginated where, how
selection stays correct across pages, and how the application is
navigated.

---

## Pagination

### One component, four screens

There is a single pagination implementation, shared by Evidence,
Timeline, Findings and Investigations. Four screens needing the same
control is how four subtly different controls get written — one that
clamps an out-of-range page and one that blanks, one that resets on
filter and one that does not — so the behaviour is defined once.

| Screen | Default | Options | Paginated by |
|---|---|---|---|
| Evidence | 100 | 25, 50, 100, 250 | **Server** |
| Timeline | 50 | 25, 50, 100, 250 | Client |
| Findings | 50 | 25, 50, 100 | Client |
| Investigations | 50 | 25, 50, 100 | Client |

### The rule that shapes everything

**A page is a view, never a filter on what exists.** Every pager states
the true total of matching records (`Showing 1–100 of 7,074 files`), so
a page boundary is never mistaken for the end of the evidence.

### Behaviour

- **Changing a filter, a search, or the page size returns to page 1.**
  Staying on page 40 of a result that now has three pages shows an empty
  screen and reads as "no matches".
- **Pagination never resets filter state.** Only the reverse direction is
  wired. Paging through a filtered Timeline keeps the filter.
- **First/Previous are disabled on page 1; Next/Last on the final page.**
- **A page past the end returns empty, not the last page.** Clamping
  would answer a different question than the one asked: a caller that
  believed it was reading page 90 would be reading page 3. The totals
  are still returned so the client can correct itself.
- **Ordering is deterministic.** Paging slices an already-ordered set. A
  non-deterministic order would show one record twice and skip another —
  for evidence selection that is a correctness bug, not a cosmetic one.

### Accessibility

The pager is a `<nav>` with an `aria-live` summary. Its controls are
`<button>`s, not links, because they change a view rather than a
location — a screen reader announcing "link" for something that does not
navigate is a lie. Disabled boundaries use the real `disabled`
attribute, and the page-size control is a labelled `<select>`.

---

## Server-side evidence filtering

`GET /api/cases/{id}/evidence/{collectionID}/files`

Query parameters:

| Parameter | Meaning |
|---|---|
| `page`, `page_size` | Pagination. `page_size` is an allow-list (25/50/100/250) |
| `q` | Free-text, case-insensitive, over filename, path, artifact labels and parser |
| `family` | Artifact family — repeatable |
| `priority` | Forensic priority — repeatable |
| `status` | Supported / unsupported / imported / duplicate / failed — repeatable |

Response:

```json
{
  "items": [ ... ],
  "page": 1, "page_size": 100, "total": 7074, "total_pages": 71,
  "collection_total": 7074,
  "selectable_total": 2101,
  "families": [...], "priorities": [...], "statuses": [...]
}
```

**Filter semantics are Phase 9A's, unchanged:** values *within* one
multi-select are OR'd; separate filters are AND'd. An empty selection
means "no constraint", not "match nothing".

`collection_total` is the collection's size regardless of the filter, so
the UI can say "120 matching of 7,074 files". `selectable_total` is how
many *matching* files could actually be imported — stated separately so
"7,074 matching" is never mistaken for "7,074 importable".

The vocabularies describe the **whole collection**, never the current
page. A dropdown that shrank as you paged would be unusable, and a
filter must not remove its own escape route.

### Why this filters in Go rather than in SQL

Artifact family, forensic priority and supported/unsupported are **not
stored columns**. They are derived at read time from the capability
registry, which is what guarantees the triage view can never drift from
what the running binary can parse (see
[evidence-triage.md](evidence-triage.md)). Pushing them into SQL would
mean persisting a classification, and a persisted classification goes
stale the moment a parser is added.

So a collection's rows are loaded, classified, filtered and paged on the
server. The database read is local and bounded to one collection; what
crosses the network is one page. That trade — a local scan to keep
classification live — is deliberate, and is why the Phase 9A invariant
survives Phase 10B.

A `(collection_id, path)` index supports the query's `WHERE` and
`ORDER BY` together, so the rows come back already ordered rather than
being sorted on every page request.

### Discovery responses are bounded

Discovering a collection returns the **first page** of the catalog plus
`source_files_total` and `source_files_page_size`. A 7,074-file
discovery response is ~67 KB instead of ~4 MB. Coverage still summarizes
the whole catalog — a coverage summary of page 1 would be actively
misleading.

---

## Selection semantics

This is forensic evidence selection, so the model is explicit.

**Selection is a set of stable source-file IDs**, held in the page's
state and never in the DOM. A checkbox is a *view* of the set, not the
set itself. That is what makes paginated selection safe.

### The three actions

| Action | Scope |
|---|---|
| **Select recommended** | High/critical-priority importable evidence, across the whole catalog (Phase 9A, preserved) |
| **Select page** | Only the selectable files on the page currently shown |
| **Select all matching** | Every importable file matching the current search and filters — resolved by the server |
| **Clear selection** | The entire selection, not merely the current page |

"Select recommended" is additive and filter-independent, so it
deliberately does **not** set the bulk-selection marker described below:
it makes no claim about "everything matching the current filter", and
warning that it went stale when the filter changed would be a warning
about something that was never true.

"Select all matching" calls
`GET /api/cases/{id}/evidence/{collectionID}/files/ids` with the current
filter. The server returns the stable IDs of every matching file that
can actually be imported. It can never quietly mean "the first 100": the
server returns the whole match set, and the count shown is the length of
what was added.

Only *selectable* files are returned — a selection including
already-imported or unsupported files would show a count the import
could never honor.

### The two modes are described differently, on purpose

> **250 file(s) selected** · 250 on this page

> **1,050 matching file(s) selected** · every file matching the current
> search and filters

"100 selected" and "7,074 selected" must never look the same to someone
about to press Import.

### Selection survives

Page navigation, page-size changes, searching, filtering, and returning
to a previous page. Files selected on page 1 are still selected — and
still imported — after paging to page 40.

### Changing the filter after "select all matching"

A bulk selection records the filter it was made under. If the filter
later changes, the selection no longer describes what is on screen, and
the UI says so explicitly rather than silently importing files outside
the current filter:

> **Filters changed since "Select all matching"**
> 1,050 file(s) are still selected from the earlier filter. Importing now
> would include files outside the filter currently on screen.
> [Re-select all matching (N)] [Clear selection]

The recompute is **explicit**. The selection still holds exactly the IDs
chosen earlier; the investigator decides whether that is still what they
want.

The alternative design — storing the filter and re-evaluating it at
import time — was rejected. It would let the imported set differ from
the set the investigator was looking at when they chose it.

### Import safety

Import validation is server-side and per-ID. Every submitted ID is
checked to belong to this case *and* this collection, to be undeleted,
and to still be `discovered`; anything else is skipped with a stated
reason rather than imported. IDs from another case are skipped, not
honored.

The submitted list is also de-duplicated server-side. A selection
assembled across many pages can legitimately contain the same ID twice;
importing it twice was already prevented, but the count shown would have
disagreed with the work done.

---

## Evidence presentation

### The table

Columns: checkbox, Filename, Artifact type, Priority, Size, Status,
Details.

**The Path column was removed.** It was by far the widest column and
forced the whole table into horizontal scrolling, while being the one
field nobody reads in full at a glance. Nothing forensic was traded away
to make the table fit — the path is present three ways:

1. truncated under the filename,
2. in full in the `title` attribute (hover),
3. in full, untruncated, in the expandable **Details** row.

The details row also carries artifact type and family, parser, forensic
priority, status, size, SHA-256, the container's embedded hash, source
collection, event count, and the support reason.

### Responsive presentation

**Breakpoint: 900px.**

Above it, the evidence table and a permanent sidebar column. At or below
it, records become **cards** and the sidebar becomes an off-canvas panel
behind a menu button. A seven-column table at 480px can only be made to
fit by shrinking the type past readability or by scrolling sideways;
neither is acceptable for evidence an investigator has to select
accurately.

Both presentations are always in the DOM and CSS picks one, so resizing
the window never needs a re-render — and the checkbox state cannot
disagree between them, because the selection lives in JS, not in markup.

The same 900px boundary switches both layout and navigation, so they
change together rather than at two confusing widths.

### Badges never split

`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`, `SUPPORTED`,
`UNSUPPORTED`, `DUPLICATE` and `FAILED` are single tokens. A badge
rendered as `CRITICA / L` or `SUPPORT / ED` reads as a different, wrong
value at a glance.

`.badge` and `.tech-chip` set `white-space: nowrap` with
`word-break: normal` and `overflow-wrap: normal` — the latter two
because a container using `overflow-wrap: anywhere` (the path cells)
would otherwise override the first. The containing cells are given
enough width separately; this is **not** solved by letting the page
scroll sideways.

Priority badges remain styled apart from finding-severity badges. They
are different judgements and must never be read as the same thing.

---

## Navigation

### The sidebar

The horizontal tab strip is replaced by an application sidebar:

```
CASE                SYSTEM
  Overview            All Cases
  Evidence
  Timeline
  Findings
  Investigations
  Activity Chains
  ATT&CK
  Audit History
```

Items are real `<a href>` links — they do change location (the hash
route), so middle-click and open-in-new-tab keep working. The active
item is marked three ways (background, text colour, and a left rule) so
it does not depend on colour alone, and carries `aria-current="page"`.

`CASE_NAV` is the single definition of order, labels and route keys; the
sidebar renders from it and the active-item marker reads from it, so the
two cannot disagree.

### Overview is a destination

The panels that used to sit permanently above the tab strip — analyst
notes, the investigations preview, evidence collections, and the
analysis action — are now the **Overview** view. They were several
screens of scrolling in front of every other tab; as a destination they
cost nothing to reach and nothing to scroll past.

The **case header** stays mounted above every view. Case name,
description, ID, status, priority, created and last-analyzed are visible
from everywhere — an investigator must never have to remember which case
they are reading. It is two rows by design (identity and actions above,
metadata below), and both wrap rather than overflow. Nothing is hidden
at any width: case status and priority are forensic context, not
decoration.

### Small viewports

Below 900px the sidebar becomes an off-canvas panel:

- a labelled menu button with a live `aria-expanded`,
- focus moves into the panel when it opens and back to the button when it
  closes,
- Escape closes it,
- a scrim click closes it,
- choosing a destination closes it — a menu that stayed open over the
  content it just navigated to would hide the answer,
- main content reclaims the full width,
- no horizontal page overflow at any tested width.

The `transform` animation is skipped under `prefers-reduced-motion`.

### Scroll behaviour

Phase 8's behaviour is preserved. Switching views replaces only the
content region, leaving the sidebar and case header mounted, and each
view's scroll offset is remembered and restored. There is one main
scroll area — the sidebar is `position: sticky` on desktop rather than a
competing scroll container.

---

## What is *not* server-paginated, and why

Timeline, Findings and Investigations are paginated **in the browser**.
The DOM holds one page (50 rows, not 7,350), which is what makes those
views fast to open and to scan. But the API still returns the full set
for the case.

This was deliberate. Those screens carry Phase 9B's filtering — ATT&CK
technique, severity, confidence, host, user, process, rule, and date
range with its specific boundary semantics — and several of those
filters resolve *through* a record's supporting events rather than from
a column. Moving them server-side is a substantially larger change with
real risk to filtering semantics the previous phase established and
tested. Section 9–11 of the Phase 10B specification require that these
views stop rendering everything into the DOM, which client-side
pagination achieves.

The cost is measured and stated rather than hidden:

| Endpoint | Records | Response |
|---|---|---|
| `/timeline` | 7,350 events | ~6.9 MB |
| `/findings` | 1,050 findings | ~1.0 MB |
| `/investigations` | 1,050 investigations | ~1.0 MB |
| `/evidence/{id}/files?page_size=100` | 100 of 7,074 | **~64 KB** |

Server-side pagination for the three record views is the natural next
step, and would follow the pattern `internal/api/evidencequery.go`
already establishes.
