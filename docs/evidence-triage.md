# Evidence triage

Adding evidence to a case has always been four steps:

```
Discover → Select → Import → Analyze
```

Phase 9A did not change that. It changed what an investigator can *see*
during **Select**, and what they are told during **Import**. Phase 10A
then added upload progress, three new parsers, and honest handling of
artifacts that record no timestamp. Phase 10B made **Select** scale:
server-side filtering and pagination, and an explicit selection model —
see [scale-and-navigation.md](scale-and-navigation.md).

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

| Artifact type | Label | Family | Priority | Parser(s) |
|---|---|---|---|---|
| `windows_event_log` | Windows Event Log (EVTX) | Event Log | **Critical** | `evtx@1`, `evtxcsv@1` |
| `registry_hive` | Windows Registry Hive | Registry | **Critical** | `registry@1` |
| `powershell_history` | PowerShell console history | PowerShell | High | `pshistory@1` |
| `prefetch` | Prefetch | Prefetch | High | `prefetch@1`, `pecmd@1` |
| `registry_run_key` | Registry (RECmd export) | Registry | High | `recmd@1` |
| `scheduled_task` | Scheduled Task XML | Scheduled Task | High | `scheduledtasks@1` |
| `browser_history` | Browser history (Chromium / Firefox) | Browser | Medium | `browserhistory@1` |

Several artifact types are produced by more than one parser — raw EVTX
and EvtxECmd CSV both yield `windows_event_log`; raw `.pf` and PECmd CSV
both yield `prefetch`. That is deliberate: the same execution reported by
either source describes **one** event, not two. `GET /api/capabilities`
names a single representative parser per type; the full set is in
`ingest.Registry()`.

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
| Amcache hive | High | Hive format is read, but there is no Amcache-specific extraction. |
| SRUM database | High | No ESE database parser. |
| NTFS `$MFT` / `$LogFile` / `$UsnJrnl` | High | No NTFS filesystem parser. |
| Memory images (`pagefile.sys`, `memory.dmp`, …) | High | No memory analysis. |
| ShellBags / `UsrClass.dat` | Medium | Hive is read; no ShellBags extraction. |
| Browser data (other formats) | Medium | Only Chromium `History` and Firefox `places.sqlite` are parsed. Edge Legacy/IE `WebCacheV01.dat` is an ESE database; cookie and cache stores are not parsed. |
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

Since Phase 10B the search and the filters are applied **on the server**,
and the dropdown options are vocabularies the server derives from the
whole collection — so an option list never shrinks as you page, and the
counts beside each option describe the catalog rather than the page.

One behaviour is load-bearing and unchanged since Phase 9A:

- **Selection is not the DOM.** Selected file IDs live in a `Set`.
  Filtering, searching, paging and re-rendering never lose a selection.

**Select recommended** selects high/critical-priority files that are
actually importable, across the whole catalog. An unsupported file is
never recommended, because selecting it would do nothing. Nothing is
ever imported automatically.

The other selection actions — **Select page**, **Select all matching**
and **Clear selection** — and the rules that keep a selection correct
across pages are described in
[scale-and-navigation.md](scale-and-navigation.md).

### Rendering large catalogs

Superseded by Phase 10B. The selection screen no longer renders a capped
slice of a client-held catalog: the catalog stays on the server and the
browser receives one page at a time, filtered server-side.

See [scale-and-navigation.md](scale-and-navigation.md) for pagination
semantics, the selection model (select-page vs select-all-matching), the
server-side filter API, and the responsive evidence presentation.

---

## Upload progress

An evidence package can be gigabytes. Before Phase 10A the browser sent
it with `fetch`, which reports nothing until the whole body has been
transmitted — so a large upload looked indistinguishable from a hung
one.

Uploads now go through `XMLHttpRequest` purely for its
`upload.onprogress` event, which reports bytes actually sent. The
progress shown is that number and nothing else:

| Stage | Indicator | Source of the number |
|---|---|---|
| Uploading | Determinate `%` + `sent / total` | `XHR.upload.onprogress` — real transmitted bytes |
| Inspecting | **Indeterminate** | Server is hashing and identifying the package; no byte count exists to report |

The transition matters: once the last byte is sent, the browser has no
further information, so the bar switches to an indeterminate indicator
with the note *"Hashing and identifying the uploaded evidence…"* rather
than sitting at 100% while the server is still working, or animating a
number nothing is measuring. This is the same rule the import job
follows — see "No fake progress" below.

The upload control is disabled for the duration, so the same package
cannot be submitted twice by an impatient second click. Existing upload
validation and error reporting are unchanged: a non-archive still fails
with its specific message (e.g. *"Not a valid zip archive: zip: not a
valid zip file"*), not a generic one.

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

## Phase 10A parsers: exactly what is supported

Three artifact classes moved from "recognized but unsupported" to
supported. Each is stated here in terms of the **formats actually
parsed**, because claiming broader support than the code delivers is the
one failure mode a capability registry exists to prevent.

### Raw Prefetch (`prefetch@1`)

Reads the SCCA format directly, so PECmd is no longer required.

| Version | Windows | Supported |
|---|---|---|
| 17 | XP / 2003 | Yes — 1 retained run time |
| 23 | Vista / 7 | Yes — 1 retained run time |
| 26 | 8.1 | Yes — up to 8 retained run times |
| 30 | 10 (early) | Yes — up to 8 retained run times |
| 31 | 10 / 11 (later) | Yes — up to 8 retained run times |

**MAM-compressed Prefetch is not decompressed.** Windows 10 and 11 store
`.pf` files wrapped in a `MAM\x04` LZXPRESS Huffman container. Tracefall
detects this and reports it as a specific, named condition
(`prefetch.ErrCompressed`) rather than a generic parse failure — the UI
says the file is compressed and names the format, instead of "the file
could not be parsed". Decompression is not implemented; a compressed
`.pf` produces no events.

One event is emitted **per recorded execution**, not per file. A
Windows 8+ Prefetch file retains up to eight execution times, and each is
a distinct observed run: collapsing them would discard seven real
observations. Empty run-time slots are dropped and duplicate times are
deduplicated, so a file retaining three runs yields three events, not
eight. A file with no usable run time yields **no events** — the file's
own mtime is when it was collected, not when the program ran, and is
never substituted.

Detection is by SCCA/MAM signature (`parsers.ContentDetector`), so a
Prefetch file under a non-`.pf` name is still recognized, and a `.pf`
that is not Prefetch is still rejected.

### PowerShell console history (`pshistory@1`)

Parses `ConsoleHost_history.txt`, written by PSReadLine: one accepted
command line per line, in order.

Encodings handled: UTF-8, UTF-8 with BOM, UTF-16LE/BE with BOM, and
UTF-16LE/BE **without** a BOM. The BOM-less UTF-16 case needs a
structural check that must run *before* the UTF-8 check, because
BOM-less UTF-16LE ASCII is byte-for-byte valid UTF-8 (`NUL` is a legal
UTF-8 byte) — testing UTF-8 first silently accepts it and turns every
command into NUL-separated mojibake. The encoding actually used is
recorded in `Extra["text_encoding"]`.

Two limitations, both structural to the artifact:

- **No timestamps exist.** PSReadLine records none — not per command,
  not per session. These events carry a **zero timestamp**, marked
  `Extra["timestamp_known"] = "false"` with the reason in
  `timestamp_basis`. The file's modification time is deliberately *not*
  used: that is when the file was last written or collected, never when
  a particular command ran, and presenting it as an execution time would
  fabricate evidence. See "Events with no timestamp" below.
- **Execution is not proven.** PSReadLine writes a line when it is
  *accepted at the prompt*. That does not prove the command ran, or
  succeeded. The event type is `powershell_history_command` — named for
  what the evidence supports — and confidence is 0.5, reflecting the
  timing and execution uncertainty, not doubt about the command text
  (which is recorded exactly as written).

`DetectContent` deliberately returns **false**. A console history is
plain text with no signature; claiming any text file that "looks like
commands" is a PowerShell history would misclassify every script, log
and note in a collection. Recognition is by filename only, and that
limit is stated rather than papered over with a guess.

### Browser history (`browserhistory@1`)

Two schemas, both real SQLite databases, both identified **by their
tables** rather than by filename:

| Browser family | File | Tables read | Epoch |
|---|---|---|---|
| Chromium (Chrome, Edge, Brave, Opera, Vivaldi) | `History` | `urls`, `visits` | microseconds since 1601-01-01 UTC |
| Firefox | `places.sqlite` | `moz_places`, `moz_historyvisits` | microseconds since 1970-01-01 UTC |

Nothing else is claimed. Cookies, cache, downloads, form history and
Edge Legacy/IE `WebCacheV01.dat` (an ESE database, not SQLite) are not
parsed, and the registry says so explicitly rather than advertising
generic "browser history" support.

**The evidence is copied before it is opened.** A browser history file
is a live SQLite database, and opening it with a SQLite driver — even
read-only — can cause the engine to checkpoint and *delete* a hot `-wal`
sidecar, changing the evidence on disk. The parser copies the database
together with its `-wal`, `-shm` and `-journal` sidecars into a scratch
directory and opens the copy; the originals are never opened by SQLite.
A regression test hashes the evidence before and after parsing and fails
if the digest changes. See [evidence-integrity.md](evidence-integrity.md).

Visit timestamps come from the database's own visit records. Filesystem
timestamps are never used as visit times. A database whose tables match
neither schema is reported as `ErrUnknownSchema`, and a file that is not
SQLite at all as `ErrNotSQLite` — both surfaced as named conditions, not
generic failures.

---

## Events with no timestamp

Most artifacts record when something happened. PowerShell console
history does not, and its events therefore carry a zero timestamp by
design. This is handled consistently rather than hidden:

- **In the timeline**, the time column renders *No timestamp* in muted
  italics, with the parser's own stated reason as a tooltip. It never
  renders the zero time as a date — `0001-01-01` is a date that was
  never in the evidence, and showing it would be exactly the fabrication
  the parser refused to commit.
- **In a collection's event time range**, undated events are excluded
  from the range and **counted separately** ("+ N event(s) with no
  timestamp"). Including them would report the evidence as spanning from
  year 1 to the present. Counting them means they are excluded from the
  range without being silently dropped from the summary.
- **In storage**, the timestamp stays zero. Excluding these events from
  a displayed range must never become a reason to stamp them with a
  substitute time.
- **In deduplication**, a zero timestamp causes `CommandLine` to be
  included in the dedup hash, so N distinct timestamp-less commands keep
  N distinct identities instead of collapsing into one.

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

The Phase 10A readers define their own sentinels so their failures are
specific rather than generic. Each maps to a message that tells the
investigator whether the *evidence* or the *tool* is the limit:

| Sentinel | Category | What the investigator is told |
|---|---|---|
| `prefetch.ErrCompressed` | `unsupported_format` | It is a MAM-compressed Win10/11 Prefetch file; Tracefall does not decompress it. Decompress first, or use PECmd output. |
| `prefetch.ErrUnsupportedVersion` | `unsupported_format` | The Prefetch format version is not read. |
| `prefetch.ErrNotPrefetch` | `unsupported_format` | Cataloged as Prefetch, but is not a Prefetch file. |
| `browserhistory.ErrUnknownSchema` | `unsupported_format` | It is SQLite, but not a browser history schema Tracefall reads. |
| `browserhistory.ErrNotSQLite` | `unsupported_format` | Cataloged as browser history, but is not a SQLite database. |
| `pshistory.ErrEncoding` | `corrupt_or_truncated` | Not readable as UTF-8 or UTF-16 text. |
| `prefetch.ErrCorrupt` | `corrupt_or_truncated` | Corrupt, truncated, or structurally invalid. |
| `prefetch.ErrLimitExceeded`, `pshistory.ErrTooLarge`, `browserhistory.ErrTooLarge` | `limit_exceeded` | The file exceeds a safety limit. |

The distinction the compressed-Prefetch message draws is the point of
the whole table: *"the evidence is fine, the tool is the limit"* is a
different fact from *"this file is damaged"*, and an investigator must
not have to guess which one they are looking at.

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
