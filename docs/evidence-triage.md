# Evidence triage (Phase 9A)

Adding evidence to a case has always been four steps:

```
Discover → Select → Import → Analyze
```

Phase 9A did not change that. It changed what an investigator can *see*
during **Select**, and what they are told during **Import**.

The problem it solves is scale. A KAPE ZIP or an AD1 logical image holds
thousands of files, of which a handful are evidence Tracefall can act
on. Before this phase the selection screen was one flat table of every
file, with an artifact type only for the files a parser recognized.
Everything else — a Prefetch file, `$MFT`, a browser cache entry, a font
— was an anonymous row with a blank type. There was no way to find the
six registry hives inside seven thousand files, and no way to know that
nine hundred Prefetch files were being ignored.

---

## The capability registry

[`internal/artifacts`](../internal/artifacts/artifacts.go) is the single
authoritative answer to "what is this file, and how much should I care?"
Both the backend and the dashboard read it; neither restates it.

It keeps two things deliberately separate:

| | Source of truth | Changes when |
|---|---|---|
| **Support** — can Tracefall parse this? | Derived at runtime from `ingest.Registry()` | A parser is added or removed |
| **Priority** — how much forensic value does this artifact class carry? | A fixed table in the same package | Forensic judgement changes |

**Priority is independent of support.** A raw `.pf` Prefetch file is
HIGH priority and unsupported. That combination is not a contradiction
and is not hidden — it is the most useful thing the screen can tell an
investigator, because it says what Tracefall is *not* looking at.

### Supported artifact types

Derived from the live parser registry, so this table cannot drift from
what the binary can actually parse:

| Artifact type | Label | Family | Priority | Parser |
|---|---|---|---|---|
| `windows_event_log` | Windows Event Log (EVTX) | Event Log | **Critical** | `evtx@1`, `evtxcsv@1` |
| `registry_hive` | Windows Registry Hive | Registry | **Critical** | `registry@1` |
| `registry_run_key` | Registry (RECmd export) | Registry | High | `recmd@1` |
| `scheduled_task` | Scheduled Task XML | Scheduled Task | High | `scheduledtasks@1` |
| `prefetch` | Prefetch (PECmd export) | Prefetch | High | `pecmd@1` |

An artifact type produced by a parser but missing from the metadata
table still works — it falls back to a derived label, family "Other" and
MEDIUM priority. A forgotten entry degrades the display; it never breaks
discovery.

### Recognized but unsupported

These are matched by path/filename only. Discovery walks every file in a
collection, so it must stay cheap: files are not opened for this
classification. (Content sniffing is reserved for parsers that actually
claim a file — see `parsers.ContentDetector`.)

| Class | Priority | Why it is not parsed |
|---|---|---|
| Prefetch (raw `.pf`) | High | No raw Prefetch parser. Run PECmd and add its CSV output. |
| Amcache hive | High | Hive format is read, but there is no Amcache-specific extraction. |
| SRUM database | High | No ESE database parser. |
| NTFS `$MFT` / `$LogFile` / `$UsnJrnl` | High | No NTFS filesystem parser. |
| PowerShell console history | High | No `ConsoleHost_history` parser. Script-block events from EVTX *are* parsed. |
| Memory images (`pagefile.sys`, `memory.dmp`, …) | High | No memory analysis. |
| ShellBags / `UsrClass.dat` | Medium | Hive is read; no ShellBags extraction. |
| Browser history | Medium | No SQLite/ESE browser parser. |
| Event Log (legacy `.evt`) | Medium | Only the modern EVTX format is parsed. |
| CSV (unrecognized tool output) | Medium | Does not match any EZ Tools output naming convention. |
| Application log (`.log`) | Low | Format is application-specific. |
| XML (not a Scheduled Task) | Low | Only Task Scheduler XML under a `Tasks` directory is parsed. |
| Windows Error Report (`.wer`) | Low | No WER parser. |
| Documentation / notes | Low | Not forensic evidence. |

Anything matching no rule is classified **Unrecognized / Unknown
priority**, with a reason saying so. Nothing is guessed.

`GET /api/capabilities` returns all of the above, plus the filter
vocabularies the dashboard builds its dropdowns from — so a new family
or priority added in Go appears in the UI with no frontend change.

---

## Six states, and why they are different

| State | Meaning |
|---|---|
| **Supported** | A parser exists. The file can become evidence. |
| **Unsupported** | No parser. Cataloged, visible, with a reason. **Not an error.** |
| **Not imported** | Supported and selectable, awaiting the investigator's choice. |
| **Imported** | Selected, parsed, and now evidence. |
| **Duplicate** | Byte-identical to another file in the same collection. |
| **Parse error** | Supported, selected — and it *failed*. |

**Unsupported and Parse error are never conflated.** An unsupported file
is one Tracefall was never able to read. A parse error is evidence that
*should* have been readable and was not, which is itself a finding about
the evidence. The UI, the API and the tests all keep them apart.

---

## Coverage

Every discovery result and collection detail carries a `coverage` object,
counted from the real catalog — never estimated:

```
7,300 files discovered
  300 Supported     7,000 Unsupported     0 Duplicates
```

plus a per-artifact-type breakdown, ordered most-valuable-first:

| Artifact type | Priority | Files | Supported |
|---|---|---|---|
| Windows Event Log (EVTX) | Critical | 150 | 150 |
| Windows Registry Hive | Critical | 150 | 150 |
| Prefetch (raw .pf) | High | 1,400 | 0 |
| Browser history | Medium | 1,400 | 0 |
| Log file | Low | 1,400 | 0 |

---

## Search and filters

A compact toolbar replaces the old three-button control strip.

**Search** matches, case-insensitively and by substring: filename, path,
artifact type label, family label, raw artifact type, and parser.

**Filters** are multi-select dropdowns over Artifact type (family),
Priority and Status. They combine with AND, appear as removable chips,
and clear individually or all at once. They reuse the same filter
component as the Timeline and Findings bars, so type-ahead search inside
a dropdown, the selected/total counts and the keyboard behaviour are
identical to what an investigator already knows.

Two behaviours are load-bearing:

- **Selection is not the DOM.** Selected file IDs live in a `Set`.
  Filtering, searching and re-rendering never lose a selection. When
  selected files are filtered out of view the counts say so explicitly:
  `8 selected (8 not currently shown)`.
- **"Select all shown" means the filtered view.** Filtering to Registry
  and pressing it selects exactly those files — never the whole catalog.
  Acting on hidden rows would be the most dangerous thing this screen
  could do.

**Select recommended** selects high/critical-priority files that are
actually importable. An unsupported file is never recommended, because
selecting it would do nothing. Nothing is ever imported automatically.

### Rendering large catalogs

At most **400 rows** are rendered at once. The count line always states
the true total, and narrowing the filter reveals anything beyond the cap
— the cap keeps the first render of an unfiltered 7,000-file catalog
cheap, it does not hide evidence. Selection and "Select all shown" apply
to *all* matching files, not just the rendered ones.

No virtualization library was added: with filtering in place, measured
search and filter latency on a 7,300-file catalog is 1–3 ms, so
virtualization would be complexity without benefit.

---

## Import progress

`POST /api/cases/{id}/evidence/{collectionID}/import/start` returns a
job ID; `GET /api/cases/{id}/import-jobs/{jobID}` reports progress. The
original synchronous `…/import` route is unchanged.

### Phases

These are the phases that *actually exist* in `Service.importEvidence`.
No stage is reported that does not correspond to code that runs:

| Phase | Work |
|---|---|
| `preparing` | Resolving the selection |
| `parsing` | Parse every selected file (phase 1) |
| `enriching` | Resolve hosts across the whole batch (phase 2) |
| `persisting` | Deduplicate and save (phase 3) |
| `finalizing` | Recompute counts, update case status, audit |
| `complete` / `failed` | Terminal |

### No fake progress

Percent is derived from **units of real work**: each selected file
contributes exactly two units, one when parsed and one when persisted. A
file that fails to parse consumes both, because it is equally finished.
There is no case where the bar advances without work having happened.

When the total is not yet known, `percent` is `-1` and the UI shows an
**indeterminate** indicator rather than inventing a number. The bar is
capped at 99% until the job is genuinely done, because a bar sitting at
100% while work continues is the same lie as a fake one.

### Why job state is in memory

The store opens SQLite with `SetMaxOpenConns(1)`. A running import holds
that single connection for long stretches, so a status poll **must not**
touch the database or it would block behind the very work it reports on.
Job records are therefore in-memory and process-lifetime only. Losing
them on restart costs nothing: whether the import committed is recorded
in the database, where it belongs.

### Duplicate and concurrent imports

One import may run per collection at a time. A second start returns
**409**. That makes the dashboard's disabled Import button a real
guarantee rather than a client-side courtesy — a double-click, a second
browser tab, or a replayed request all hit the same guard.

### What is never published

`current_file` is the path **relative to the evidence root**. Absolute
server paths, temp directories and internal identifiers are never sent
to the browser.

---

## Parse errors

Each failure is reported structurally, not as a raw error string:

| Field | Notes |
|---|---|
| `path`, `filename` | Relative to the evidence root |
| `artifact_type`, `parser` | What it was cataloged as |
| `stage` | `extract` (materializing an AD1 entry) or `parse` |
| `category` | `corrupt_or_truncated`, `unreadable`, `limit_exceeded`, `unsupported_format`, `internal_error` |
| `message` | Sanitized, human-readable |
| `partial_events` | Whether any events were persisted before it failed |

Categories are derived from the sentinel errors the readers already
define (`evtx.ErrCorrupt`, `regf.ErrNotHive`, `ad1.ErrLimitExceeded`, …),
so classification tracks what the code returns rather than matching on
message text. Raw errors are never passed through — a parser error can
embed the absolute path it was reading.

`partial_events` is always `false` today, because import parses every
file completely before persisting anything. It is reported explicitly
rather than left to be assumed: "did this file half-land in my evidence?"
is a question an investigator must never have to guess at.

---

## AD1 specifics

An AD1 image is cataloged without extracting anything; a selected entry's
bytes are materialized only at import time. Coverage therefore shows the
whole image immediately, and an investigator can filter to
`Supported + High priority + Registry` and select six files out of seven
thousand without Tracefall ever touching the other 7,994.

All Phase 7 protections are unchanged: read-only source, entry-name
validation, traversal protection, decompression limits, metadata/entry
limits, case isolation and duplicate handling. Phase 9A added no code to
`internal/ad1`.

**Limitation:** AD1 entries carry Tracefall's own SHA-256 only after
import, because computing it during discovery would mean decompressing
every entry. Until then the catalog shows the hash AD1 itself reported,
clearly labelled as unverified.

---

## Adding a parser later

1. Implement `parsers.ArtifactParser` (optionally `ContentDetector`).
2. Register it in `ingest.Registry()`.
3. Add one entry to `supportedTypeInfo` in `internal/artifacts` with the
   label, family and priority.
4. If a matching entry exists in `unsupportedRules`, remove it — the
   artifact is now supported.

Support flips automatically because it is derived from the registry.
Nothing in the frontend changes: the dashboard renders whatever the
capability endpoint reports.
