# Forensic event search and the timeline

This document states exactly what the forensic timeline searches, what it
does not search, and why. An examiner may have to describe their own
search in a report; "I searched Tracefall" is not a description, and the
point of this page is that it can be replaced with a precise one.

Introduced in Phase 14. It concerns the **event** layer only — see
[Layers](#layers) below for what that means and what it deliberately
excludes.

## Layers

Tracefall keeps five things apart, and conflating any two of them
misrepresents the evidence:

```
AD1 / KAPE package        the thing that was collected
  └─ Evidence collection  one import of it, hashed and attested
      └─ Source file      one artifact inside it
          └─ Event        one normalized observation a parser read out
              └─ Finding       a detection rule's conclusion about events
                  └─ Investigation   an analytical grouping of findings
```

The forensic timeline is the **Event** row of that list. It is not the
Findings page.

The distinction is load-bearing rather than tidy-minded:

- **Most events will never be cited by a finding.** A browser visit to a
  research forum, a file created in a temp directory, a shortcut to a
  spreadsheet — these are facts about the machine whether or not any rule
  cares about them. Before Phase 14 the only events reachable through the
  UI were the ones a detection had already selected, which meant an
  analyst could only find what Tracefall had already decided was
  interesting.
- **An empty "Finding" column is not a negative result.** It says no
  current detection has associated one. It says nothing about whether the
  event matters. The UI wording is "No related finding" for exactly this
  reason.
- **Nothing in the search path creates a finding or an investigation.**
  Importing evidence produces events and nothing else.

Where a relationship does exist, the timeline shows it as a **link** —
event → finding → investigation — so crossing a layer boundary is
something the analyst does deliberately and can always see they have
done.

## What free-text search covers

The search box with **Any field** selected matches a case-insensitive
substring against these normalized event columns:

| Column | What it holds |
| --- | --- |
| `host` | the machine the event was observed on |
| `user` | the account |
| `event_type` | the normalized event type constant |
| `artifact_type` | the artifact class constant |
| `parser` | the parser name@version that produced the event |
| `provider` | the Windows event provider/channel, where applicable |
| `process_name`, `process_path` | the process |
| `parent_process`, `parent_process_path` | its parent |
| `command_line` | the command line, where the artifact records one |
| `file_path` | the file the event concerns |
| `registry_path` | the registry key, where applicable |
| `network_source`, `network_dest` | connection endpoints, and the URL host for browser evidence |

and these named keys inside an event's extra metadata:

| Key | What it holds |
| --- | --- |
| `url` | the requested resource (browser history, browser cache) |
| `page_title` | the title of a visited page |
| `original_path` | a deleted file's path *before* deletion (Recycle Bin `$I`) |
| `original_name` | a deleted file's name before deletion |
| `target_path` | what a shortcut or Jump List entry points at |
| `file_name` | the filename an NTFS or USN record names |
| `application` | the application a Jump List belongs to |
| `executable_name` | the executable a Prefetch record names |
| `content_type` | a cached response's MIME type |

Extra metadata is read with `json_extract` on those **named** keys. It is
never a blind match against the whole JSON blob: a blind match would hit
key names, numeric internals and every field a future parser adds, so an
analyst could not state what their own search had covered.

`internal/store/eventquery.go` holds these two lists as data, and
`TestSearchSemantics_FreeTextSearchesExactlyTheDocumented*` fails if this
table and that code ever disagree.

### A term that names a moment also searches that moment

If the term parses as a date or a timestamp, it additionally matches
events **inside the window that term names** — OR'd with the field match
above, so a term that is both text and a date still finds the text.

The window is the **precision of what was typed**:

| Term | Matches |
| --- | --- |
| `2021-04-29` | that whole local day |
| `2021-04-29 18:17` | that local minute |
| `2021-04-29 18:17:38` | that local second |
| `2021-04-29T18:17:38Z` | that second, at the offset given |

Interpreted in the **display timezone**, like every other time input —
so the search agrees with the timestamps rendered beside it. See
[Dates and timezones](#dates-and-timezones).

This exists because it was missing. Every field the text predicate reads
is a string, and no string field contains a timestamp, so searching a
real case for `2021-04-29 18:17:38` returned **zero events** for a
Chromium History visit that was present and correctly stored at exactly
that instant. The evidence was reachable only through the date picker.
Answering "no events" for evidence that exists is a retrieval failure,
not a true statement, and pasting a timestamp out of a report is the
most natural way an analyst looks for one.

Note the asymmetry with the date *filter*: the filter takes a calendar
range and is the right tool for "show me this day". This is for the
analyst who already knows the moment.

### One documented exception: numeric event IDs

If the search term is **entirely digits**, it additionally matches the
`event_id` column exactly. This is the one numeric field free text
reaches, and it is there because a Windows Event ID (`4624`, `4625`) is a
forensic identifier analysts genuinely search by. A term containing any
non-digit can never be diverted into a numeric comparison.

## What free-text search does NOT cover

Deliberately excluded, each for a reason:

- **`dedup_hash` and any other hash.** A hash is hex, and hex collides
  with ordinary terms by accident. A search that returned an event
  because its hash happened to contain "cafe" would be worse than no
  result.
- **`id`, `case_id`, `collection_id`, `source_file_id`,
  `raw_evidence_id`.** Internal row keys. An analyst typing `a1b2` wants
  a filename or a URL fragment, not a UUID that contains it.
- **`source_reference`, `confidence`, `pid`, `ppid`.** Plumbing and bare
  numbers with no free-text meaning.

The **timestamp column is not matched as text** either — a substring
search against a stored timestamp string would be a fragile way to ask a
question about time. A term naming a moment is resolved to a time
window instead, as described above.

None of these is searchable through any parameter. If you need to reach a
specific event by id, use its provenance URL directly.

## Field-scoped search

The selector next to the search box aims the term at one field instead of
all of them. Each option maps to an API parameter of the same name:

| Option | Parameter | Searches |
| --- | --- | --- |
| Any field | `q` | everything in the two tables above |
| Filename | `filename` | `process_name`, `parent_process`, and the `file_name` / `original_name` / `executable_name` keys |
| Path | `path` | `file_path`, `process_path`, `parent_process_path`, `registry_path`, and the `original_path` / `target_path` keys |
| URL | `url` | the `url` key |
| Domain / host | `domain` | `network_dest` — where both browser parsers put the URL's host and winevent puts a connection destination |
| IP address | `ip` | `network_source` and `network_dest` |
| Command line | `command_line` | `command_line` |
| Deleted original path | `original_path` | the `original_path` / `original_name` keys |

Filename is narrower than Path on purpose: an analyst who knows a file's
name and not where it lived should not have to wade through every event
whose *directory* happens to contain the string.

**Domain and IP read `network_dest` rather than re-parsing the URL.** The
browser parsers already normalized the host into that column at parse
time; guessing at it again here would be a second, worse implementation
of something the evidence already answers.

## Matching rules

- **Case-insensitive** for ASCII, which is what SQLite's `LIKE` provides
  and what the table above promises. Searching `PAYLOAD.EXE`,
  `payload.exe` and `Payload.exe` returns the same events.
- **Substring, not word.** `quarterly` matches
  `quarterly-figures.xlsx`. This is deliberate: forensic values are paths,
  URLs and filenames, not prose, and word-boundary matching would fail on
  most of them.
- **Wildcards are literal.** `%` and `_` are `LIKE` metacharacters and are
  escaped before the query is built, so `a_b` matches a literal
  underscore and not "a, any character, b". Windows paths are full of
  underscores and backslashes; treating them as operators would silently
  widen a search.
- **Every value is a bound parameter.** Nothing an analyst types is ever
  concatenated into SQL. Column names and sort directions come from fixed
  allow-lists in `internal/store/eventquery.go`.

## Filters

| Filter | Values |
| --- | --- |
| Artifact | the `model.Artifact*` constants present in this case |
| Event type | the `model.Event*` constants present in this case |
| Host, User, Process | the distinct values present in this case |
| Collection | the evidence collections in this case |
| Date range | see [Dates and timezones](#dates-and-timezones) |
| Severity, ATT&CK | **finding-derived** — see below |

Values **within** one filter are OR'd; separate filters are AND'd. An
empty selection is "no constraint", never "match nothing".

Every dropdown is built from the values the case's events actually carry,
so a filter can never offer a choice that returns nothing. An artifact
whose parser produces no events — `$LogFile`, for instance — correctly
never appears.

### Severity and ATT&CK are properties of findings, not events

These two filters reach across the layer boundary, and are named after
the finding on purpose. An event has no severity and no technique of its
own; those are conclusions a detection rule drew. Selecting one narrows
the timeline to the minority of events some detection has spoken about,
which is a legitimate question — "show me what the rules flagged, in
timeline context" — as long as it is not mistaken for a property of the
evidence.

Both resolve through the findings table under the same
`currentAnalysisFilter` every other results query uses, so an invalidated
analysis run can never bring events back into a filtered timeline.

## Dates and timezones

Stored timestamps are **UTC instants and are never rewritten**. The
display timezone is a presentation preference held in `app_settings`;
nothing reads it to decide what to store, how to order, or what to
analyze. See [`internal/api/settings.go`](../internal/api/settings.go).

A **calendar date, though, is not an instant.** "29 April 2021" names a
different 24 hours in Jakarta than it does in UTC. So:

- A date typed into the timeline is read as a wall-clock reading **in the
  configured display timezone** — the same zone every timestamp on screen
  is rendered in.
- It is converted to the pair of UTC instants that bracket that local
  day, and only instants cross into the database.
- The response reports which instants it actually queried, and the UI
  shows them. A conversion the analyst cannot see is a conversion they
  cannot check.

Worked example, with the display timezone set to `Asia/Jakarta` (UTC+7):

```
analyst selects   2021-04-29
queried window    2021-04-28T17:00:00Z .. 2021-04-29T16:59:59.999999999Z
```

An event stored at `2021-04-29T18:17:38Z` is `2021-04-30 01:17:38` in
Jakarta, so it belongs to **30 April** for that analyst and does not
appear under 29 April. That is correct, and it is the off-by-one an
examiner would otherwise carry into a report.

Notes:

- Day boundaries are computed with calendar arithmetic, not by adding 24
  hours. A local day is 23 or 25 hours long across a daylight-saving
  transition, and a fixed offset would clip or duplicate an hour of
  evidence once a year.
- Bounds are **inclusive at both ends**.
- A date that cannot be parsed is a `400` with the reason, never a
  silently dropped filter — showing an analyst the whole case while they
  believe they are looking at one day is the worse failure by far.
- An `RFC3339` value with its own offset is accepted as-is, for API
  callers that want to be explicit rather than depend on the server's
  display setting.
- Changing the display timezone changes only rendering. It never
  invalidates an analysis and never alters a stored timestamp — see
  `TestPhase14_ChangingTimezoneNeverAltersStoredTimestamps`.

## Ordering and pagination

- Ordering is **`timestamp`, then `id`**, in the same direction. Both
  directions are total orders, so paging is a partition: every matching
  event appears on exactly one page.
- The tie-breaker is not decoration. With `ORDER BY timestamp` alone, a
  set of events sharing one timestamp comes back in a different order
  depending on which index SQLite chooses — and which index it chooses
  varies with the data, with `ANALYZE` statistics, and across SQLite
  versions. `TestSearchSemantics_OrderIsIndependentOfTheQueryPlan`
  demonstrates the divergence directly.
- Page sizes are a fixed allow-list: **10, 25, 50, 100**, default 10. An
  out-of-range size falls back to the default rather than being honoured,
  so an unbounded response cannot be requested.
- A bad page number clamps to page 1. A page past the end returns an
  **empty page**, not the last page: the caller asked for page 90 of 6
  and is told there is nothing there, rather than being silently shown
  something else.
- Every response carries the **true total** of matching events, counted
  with the same `WHERE` clause. A page is a view, never a filter on what
  exists.
- The response also carries `total_in_case`, so the UI can tell "no
  events match your filters" apart from "this case has no events" — two
  situations that send an analyst to entirely different next steps.

## Performance

Filtering, searching, ordering and paging all happen in SQLite. The
browser receives one page.

Measured on a 200,000-event case (single case, mixed artifacts):

| Query | Time |
| --- | --- |
| Unfiltered first page | 23 ms |
| Page 5,000 (deep offset) | 22 ms |
| Event-type filter | 5 ms |
| One-day range | 13 ms |
| Artifact filter | 146 ms |
| Combined day + artifact + free text | 79 ms |
| Free text, common term | 254 ms |
| Free text, rare term (worst case) | 1.2–1.9 s |
| Filter vocabulary (facets) | 416 ms |
| *Previous behaviour: read the whole case* | *4.0 s, before the browser filtered anything* |

Free text is the slow case and inherently so: a substring search cannot
use an index, in any database. Two things keep it acceptable — the search
box is debounced rather than fired per keystroke, and any other filter
applied alongside it cuts the scanned set first (the combined query above
is 79 ms). This is a deliberate trade: correctness over speed, because a
search that silently failed to match a backslash in a Windows path would
be worse than a slow one.

### Indexes

Phase 14 **replaced** one index and added none:

- `idx_events_case_ts` → `idx_events_case_ts_id` `(case_id, timestamp,
  id)`. The old index is a strict prefix of the new one, so it was
  dropped. Import speed is unchanged (200,000 events insert in ~5.8 s
  either way), and deep paging went from 155 ms to 22 ms.

Indexing the filter columns was measured and **rejected**: four such
indexes raised the cost of importing 200,000 events from 5.3 s to 9.1 s —
a 73% tax on an operation analysts run repeatedly with real evidence — to
save roughly 700 ms on one that happens when a tab opens. The filter
vocabulary is built from a single pass instead
(`Store.EventFacets`).

## Provenance

Every timeline row opens to the full chain, using the existing provenance
model — there is no second one:

```
Event → raw evidence record → source file → evidence collection → AD1 / package
```

plus every collection the event was independently observed in
(deduplicated events can have more than one), the parser and version that
produced it, the source reference within the file, the collection's
SHA-256/SHA-512 integrity attestation, and whether the artifact recorded
a timestamp at all.

The detail view also carries the links **upward** — related findings,
their investigations, and any correlation the event participates in.
All three are routinely empty, and empty means "nothing has been
concluded from this yet", not "nothing to see".

## Which parsers actually reach this layer

Having a parser is not the same as producing searchable events. Verified
by importing each artifact through the normal ingestion path:

| Artifact | Events? |
| --- | --- |
| Chromium History | ✅ `browser_visit` |
| Firefox History (`places.sqlite`) | ✅ `browser_visit` |
| Prefetch | ✅ `prefetch_execution` |
| Windows LNK | ✅ `lnk_target_created` / `_modified` / `_accessed` |
| Recycle Bin `$I` | ✅ `recyclebin_deletion` |
| NTFS `$MFT` | ✅ `filesystem_created` / `_modified` / `_changed` / `_accessed` |
| NTFS `$UsnJrnl` | ✅ `usnjrnl_create` / `_delete` / `_modify` / `_rename` / `_metadata_change` |
| Jump Lists | ✅ `jumplist_entry_access`, `jumplist_target_metadata` |
| Firefox cache2 | ✅ `browser_cache_entry` |
| Firefox cache1 (legacy) | ✅ `browser_cache_entry` |
| Chromium blockfile (legacy) | ✅ `browser_cache_entry` |
| **NTFS `$LogFile`** | ❌ **by design** |
| **Chromium Simple Cache** | ❌ **by design** |
| **Browser cache containers and index files** | ❌ **by design** |
| **Recycle Bin `$R`** | ❌ **by design** |

The four that produce no events are not gaps in this layer, and none of
them was "fixed" by inventing an event:

- **`$LogFile`** — a `LOG_RECORD_HEADER` carries no timestamp anywhere in
  the structure. Placing a record on a timeline would mean borrowing a
  time from somewhere else and presenting it as when the operation
  happened. The parser records validated structure (restart areas, LSN
  ranges, transaction ids, operation distribution) as raw evidence
  instead.
- **Chromium Simple Cache entries** — this format records no fetch time.
  The URL, headers and response metadata are stored as raw evidence
  against the source file and are visible under Evidence; they are simply
  not points on a clock. This is specific to the Simple Cache: the older
  Chromium *blockfile* generation does record times, and its entries do
  reach the timeline.
- **Cache containers / index files** — a container is not a cached
  response. Claiming otherwise would report an index as web activity.
- **Recycle Bin `$R`** — the deleted file's *content*. Its metadata,
  including the deletion time, comes from the paired `$I`, which is on
  the timeline.

In each case the evidence is still imported, hashed, attested and
inspectable through the Evidence view. The timeline's empty state says so
explicitly, so an analyst does not read "no events" as "nothing was
found".

## Authorization

The search endpoints are registered on the same router as everything
else, so `withSecurity` applies to them automatically — authentication,
CSRF, role checks and audit logging are not re-implemented here, and a
route added later is protected by default rather than by remembering to
protect it.

Every query is scoped to one case, and a query with no case is refused by
the store outright rather than defended against at each call site. An
event id from one case is not readable through another case's URL.

Tracefall's authorization model is role-based, not per-case: any
authenticated analyst may open any case. Phase 14 does not change that,
and does not weaken it — the guarantee it adds is that case scoping is
enforced in the query layer, so no filter combination can return another
case's events.

## API

```
GET /api/cases/{id}/events           one page of matching events
GET /api/cases/{id}/events/facets    the filter vocabulary for this case
GET /api/cases/{id}/events/{eventID} one event's full provenance and links
```

Parameters for `/events`:

| Parameter | Repeatable | Meaning |
| --- | --- | --- |
| `q` | no | free text, as documented above |
| `filename`, `path`, `url`, `domain`, `ip`, `command_line`, `original_path` | no | field-scoped terms |
| `artifact_type`, `event_type`, `host`, `user`, `process`, `collection` | yes | OR-sets |
| `severity`, `technique` | yes | finding-derived OR-sets |
| `date` | no | one local calendar day |
| `from`, `to` | no | local date, local date-time, or RFC3339 instant |
| `sort` | no | `asc` for oldest-first; default newest-first |
| `page`, `page_size` | no | `page_size` ∈ {10, 25, 50, 100}, default 10 |
