# Evidence triage

## SQL Server core text and instance evidence

| Artifact | Coverage |
|---|---|
| SQL Server ERRORLOG / numbered rotations | Recognizable SQL text; local clock readings remain unconverted |
| SQL Server Agent OUT / numbered rotations | Agent text messages, not complete job execution history |
| SOFTWARE SQL instance mapping, Setup, Parameters | Recorded configuration, not observed execution |
| MSSQL / SQL Agent Application events | Provider-and-channel gated normalization through native EVTX and CSV |

See [SQL Server forensics](sql-server-forensics.md) for formats, identity and timestamp semantics, source references and verification limits. Binary `.xel`, `.sqlaudit`, `.trc` and database transaction logs are **not parsed by this core phase**. An arbitrary ERRORLOG filename is not enough to claim support.


A browser upload can run the complete default workflow automatically:

```
Upload → Discover → Import all supported files → Analyze → Review results
```

Automatic import is enabled by default and can be disabled before upload to
keep the manual review workflow. Unsupported files are never imported;
the discovery coverage summary and per-file reasons remain visible in
either mode. The automatic workflow uses the same stable file IDs,
background import job, progress/cancellation handling, and analysis engine
as the manual path. Analysis runs only after a non-empty import selection
finishes without cancellation. Parse failures are reported separately
from unsupported evidence.

The manual workflow remains:

```
Discover → Select → Import → Analyze
```

It is useful when an investigator wants to review and choose specific
files before parsing. Phase 9A improved what an investigator can see
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
— was an anonymous row with a blank type. (All but the font are parsed
today; the point stands for whatever is not.) There was no way to find the
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

**Priority is independent of support.** An LSASS process dump is
CRITICAL and unsupported; a Chromium `data_0` rankings file is LOW and
unsupported. That combination is not a contradiction and is not hidden —
an unsupported CRITICAL row is the most useful thing this screen can
say, because it names what Tracefall is *not* looking at.

LOW is never assigned because a parser is missing. It means the artifact
is auxiliary, indirect, redundant, or has limited standalone value, and
every LOW row has to justify itself on those grounds.

### The four levels

| Level | Means |
|---|---|
| **CRITICAL** | Can contain highly significant evidence of compromise, execution, persistence, credentials, or core system activity. |
| **HIGH** | Highly valuable for reconstructing user and system activity and building an attack timeline. |
| **MEDIUM** | Commonly provides useful supporting evidence or important context, but rarely carries an investigation alone. |
| **LOW** | Auxiliary, indirect, redundant, or of limited standalone value. |

`UNKNOWN` is **not a fifth level**. It is the absence of a
classification, used only for a file that matched no rule at all, and it
is deliberately not folded into LOW: *"we do not know what this is"* and
*"we know what this is and it is of limited value"* are different
statements, and an investigator triaging seven thousand files needs to
tell them apart. It sorts last and is never recommended.

**Every classification carries a rationale.** Each entry states in one
clause why it sits at its level — visible in the Notes column, on the
badge's tooltip, and in the file's detail panel. A rationale may argue
only from forensic value: none of them may mention whether a parser
exists, and a test enforces that.

### Supported artifact types

Derived from the live parser registry, so this table cannot drift from
what the binary can actually parse:

| Artifact type | Label | Family | Priority | Parser(s) |
|---|---|---|---|---|
| `windows_event_log` | Windows Event Log (EVTX) | Event Log | **Critical** | `evtx@1`, `evtxcsv@1` |
| `registry_hive` | Windows Registry Hive | Registry | **Critical** | `registry@1` |
| `powershell_history` | PowerShell console history | PowerShell | High | `pshistory@1` |
| `bash_history` | Bash history | Shell | High | `bashhistory@1` |
| `wtmp` | Login records (wtmp) | Log | High | `wtmp@1` |
| `auth_log` | Authentication log (auth.log) | Log | High | `authlog@1` |
| `syslog` | System log (syslog) | Log | High | `syslog@1` |
| `web_access_log` | Web server access log | Log | High | `webaccess@1` |
| `iis_w3c_log` | IIS web log (W3C) | Log | High | `iislog@1` |
| `cryptnet_url_cache` | CryptoAPI URL cache (CryptnetUrlCache) | Execution | High | `cryptneturl@1` |
| `defender_cmd_log` | Defender command-line log (MpCmdRun.log) | Execution | High | `defendercmd@1` |
| `defender_detection_history` | Defender detection history | Log | High | `defenderhistory@1` |
| `wmi_repository` | WMI repository configuration | Execution | Critical | `wmirepository@1` (admitted bundle) |
| `defender_mplog` | Defender antimalware support log (MPLog / MPDetection) | Log | High | `defendermplog@1` |
| `srum_db` | System Resource Usage Monitor (SRUM) | Execution | High | `srum@1` |
| `webcache_db` | IE / Edge Legacy web cache (WebCache) | Browser | Medium | `webcache@1` |
| `package_log` | Package log (dpkg) | Log | Medium | `packagelog@1` |
| `network_capture` | Network capture (pcap) | Network | High | `netcapture@1` |
| `journal` | Systemd journal | Log | Medium | `journal@1` |
| `prefetch` | Prefetch | Prefetch | High | `prefetch@1`, `pecmd@1` |
| `registry_run_key` | Registry (RECmd export) | Registry | High | `recmd@1` |
| `scheduled_task` | Scheduled Task XML | Scheduled Task | High | `scheduledtasks@1` |
| `browser_history` | Browser history (Chromium / Firefox) | Browser | Medium | `browserhistory@1` |
| `browser_cache` | Browser cache entry (Chromium Simple Cache / blockfile, Firefox cache2 / cache1) | Browser | Medium | `browsercache@1` |
| `browser_cache_index` | Browser cache index/container (Chromium blockfile index, Firefox `_CACHE_MAP_`) | Browser | Low | `browsercacheindex@1` |
| `ntfs_mft` | NTFS `$MFT` | File system | High | `mft@1` |
| `ntfs_usnjrnl` | NTFS `$UsnJrnl` change journal | File system | High | `usnjrnl@1` |
| `ntfs_logfile` | NTFS `$LogFile` transaction log | File system | Medium | `logfile@1` |
| `windows_lnk` | Windows LNK shortcut | File system | **High** | `lnk@1` |
| `recycle_bin_metadata` | Windows Recycle Bin `$I` metadata | File system | **High** | `recyclebin@1` |
| `recycle_bin_content` | Recycle Bin recovered content (`$R`) | File system | Medium | `recyclebincontent@1` |
| `jumplist_automatic` | Windows Jump List (Automatic Destinations) | Execution Artifact | **High** | `jumplist@1` |
| `jumplist_custom` | Windows Jump List (Custom Destinations) | Execution Artifact | **High** | `jumplistcustom@1` |

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
| Process memory dump (LSASS or similar) | **Critical** | No memory analysis. Cataloged and hashed only. |
| WMI repository companions (`INDEX.BTR`, `MAPPING1/2/3.MAP`) | High | Not standalone parsers; admitted and hashed with their `OBJECTS.DATA` entry point. |
| Memory image, full capture (`hiberfil.sys`, `memory.dmp`) | **Critical** | No memory analysis. |
| Event Log, legacy `.evt` | **Critical** | Only the modern EVTX format is parsed. |
| SRUM database | High | Only a file named `SRUDB.dat` that is not an ESE database lands here; a real one is read (see SRUM below). |
| PowerShell transcript | High | No transcript parser; console history *is* parsed. |
| USB / device install log (SetupAPI) | High | No SetupAPI log parser. |
| Antimalware detection log | High | Only `MPLog-*.log` and `MPDetection-*.log` are read, and only their detection and blocked-process lines (see below). Other Defender text logs are not read. Binary `DetectionHistory` has a separate strict modern-subset parser. |
| Web server log (IIS / W3C) | High | No web server log parser. |
| Page / swap file | High | No memory analysis. |
| Windows Search index (`Windows.edb`) | Medium | An ESE database. The ESE reader opens it; the Windows Search tables are not interpreted, and no real `Windows.edb` was available to validate an interpretation against. |
| Thumbnail cache | Medium | No thumbcache parser. |
| RDP bitmap cache | Medium | No RDP bitmap cache parser. |
| Event trace log (`.etl`) | Medium | No ETL parser. |
| Hosts / network configuration file | Medium | Static configuration is not parsed. |
| Host firewall log | Medium | No firewall log parser. |
| Crash dump | Medium | No memory analysis. |
| NTFS metadata files (`$Secure`, `$Bitmap`, `$Boot`, …) | Medium | The `$MFT`, `$UsnJrnl` and `$LogFile` *are* parsed; these other system files are not. |
| IE / Edge Legacy web cache (`WebCacheV01.dat`) | Medium | Only a file of that name that is not an ESE database, or the old `index.dat`, lands here; a real WebCache is read (see below). |
| Browser cookie store | Medium | No cookie-store parser. Cookies are never extracted. |
| Chromium blockfile auxiliary file | Low | `data_0`: rankings. Use times, but no cache key. |
| Chromium blockfile payload file | Low | `data_2` / `data_3`: stream payloads. Metadata is in `data_1`. |
| Chromium cached response body | Low | `f_######`: a body, with no key, time or headers. |
| Browser cache hash index | Low | Simple Cache `index`/`the-real-index` and cache2 `index` store key *hashes*. |
| Browser cache journal/state | Low | Journals, locks, temporary indexes: a cache's own bookkeeping. |
| Browser cache unsupported format | Medium | A recognized cache structure in a version this build does not decode. |
| Browser cache unknown | Low | In a cache directory; structural detection identified nothing. |
| Event Log (legacy `.evt`) | Medium | Only the modern EVTX format is parsed. |
| CSV (unrecognized tool output) | Medium | Does not match any EZ Tools output naming convention. |
| Application log (`.log`) | Low | Format is application-specific. |
| XML (not a Scheduled Task) | Low | Only Task Scheduler XML under a `Tasks` directory is parsed. |
| Windows Error Report (`.wer`) | Low | No WER parser. |
| Documentation / notes | Low | Not forensic evidence. |

**Amcache and Windows Timeline moved off this list.** Both are parsed as
of Phase 16 — `Amcache.hve` by the registry parser (which already claims
the hive by its REGF signature) and `ActivitiesCache.db` by
`internal/parsers/activitiescache`. Before that they were classified
*supported* while producing no events, which is the least useful
combination for an analyst.

**SRUM is read, and the other ESE databases are not interpreted.** Tracefall has an ESE reader (`internal/ese`, see "ESE databases" below). `SRUDB.dat` has a parser on top of it. `WebCacheV01.dat` and `Windows.edb` are also ESE and the reader opens them, but nothing interprets their tables yet, so they stay in this table.

### ShellBags and UserAssist are no longer in this table

Both were listed here as recognized-but-unparsed. They are now
extracted from `NTUSER.DAT` and `UsrClass.dat` by the hive parser, and
produce their own event and artifact types -- so the row that said
"no ShellBags extraction" has been removed rather than left to go stale.

The hive FILE is still classified as a Windows Registry Hive, which is
what it is. What changed is that the structures inside it now become
events an analyst can filter, search and trace. See
[windows-artifacts.md](windows-artifacts.md) for what each of them
proves, and for the per-user MRU structures in the same hive that are
still not read.

Anything matching no rule is classified **Unrecognized / Unknown
priority**, with a reason saying so. Nothing is guessed.

### Browser cache: what it proves, and what it does not

Browser cache support is the one capability where the *limits* matter
more than the coverage, so they are stated on every record rather than
left in this document.

**Six structures are read, and only six.** Four hold cache entries; two
are containers that describe a cache and hold no cache keys at all.

| Structure | Read | Timeline events | Times the format records |
|---|---|---|---|
| Chromium **Simple Cache** entry files (`<hash>_0`) | Yes | **None** | none — the entry file stores no time |
| Chromium **blockfile** `data_1` entry records | Yes | Yes | `creation_time` (per entry) |
| Chromium **blockfile** `index` | Yes, as a **container** | **None** | cache `create_time` (per cache) |
| Firefox **cache2** entry files (v1–3) | Yes | Yes | `lastFetched`, `lastModified` |
| Firefox **cache1** `_CACHE_00{1,2,3}_` records | Yes | Yes | `lastFetched`, `lastModified`, `expirationTime` |
| Firefox **cache1** `_CACHE_MAP_` | Yes, as a **container** | **None** | none |

The blockfile and cache1 formats are **legacy** generations, tagged
`cache_generation: legacy` on every record — a superseded cache format
on a modern system is itself worth noticing. Blockfile is not merely
historical: `GPUCache`, older Chrome/Edge profiles and Chromium-embedder
applications still write it, and it is the *only* Chromium cache
generation whose entries carry their own timestamp.

Firefox cache1 is the only format read that records an **HTTP request
method**. No other cache stores one, and no other format's records
carry an `http_method` field.

**Explicitly NOT read, and reported as such rather than guessed at:**

| Structure | Why |
|---|---|
| Chromium `f_######` external files | Cached response **bodies**. No key, no time, no headers. The `data_1` entry that owns one names it by address. |
| Simple Cache `index`, `index-dir/the-real-index` | Key **hashes**, not keys. It does record a last-used time per hash, but joining that to an entry means reading a file other than the one being imported — see below. |
| Firefox cache2 `index` | SHA-1 key hashes only; strictly weaker than the entry files already parsed. |
| blockfile `data_0` (rankings) | 36-byte LRU nodes: times, but no cache key. A time that cannot be attributed to a resource is not evidence of one. |
| blockfile `data_2` / `data_3` | 1 KiB and 4 KiB stream payloads. Entry records live only in the 256-byte block file. |
| Cookie stores, `WebCacheV01.dat` | Out of scope. Cookies are never extracted from any browser. |

### Shortcuts and Recycle Bin metadata

Both are parsed natively, and both are read for what they actually say —
which is less than they are commonly assumed to say.

**Windows LNK shortcut** — `internal/shelllink`, parser `lnk@1`.

Shortcut metadata can preserve the referenced target path, volume
information and target timestamps even when the target is no longer
present. **LNK metadata alone does not prove execution.**

Read: the 76-byte `ShellLinkHeader` (validated by its size and the fixed
`00021401-…-46` class identifier), `LinkFlags`, `FileAttributes`, the
target's creation/access/write `FILETIME`s, target size, `ShowCommand`;
`LinkInfo` (local base path, common path suffix, drive type, volume
serial and label, network share); the `LinkTargetIDList`; the five
`StringData` values in whichever of ANSI or Unicode `LinkFlags`
declares; and the `TrackerDataBlock`'s machine ID.

Each recorded timestamp becomes its own event — `lnk_target_created`,
`lnk_target_modified`, `lnk_target_accessed` — carrying a
`timestamp_meaning` that says it describes the **target file** as the
shortcut recorded it. A shortcut with no target timestamps produces
structured evidence and **no timeline events**; its own file mtime is
never substituted.

Where a shortcut carries more than one path representation, both are
kept: `link_info_path` and `id_list_path` sit alongside `target_path`,
because a disagreement between them is itself forensically interesting.

*Limitation:* shell items are decoded for their documented, version-stable
fields — root-folder GUIDs, volume names, and a file entry's ANSI primary
name, size, DOS timestamp and attributes. The `0xBEEF0004` extension
block's long name is **not** decoded: its offsets vary by Windows version,
and a wrong path that looks authoritative is worse than a short one.

**Windows Recycle Bin `$I` metadata** — `internal/recyclebin`, parser
`recyclebin@1`.

Recycle Bin metadata records the deleted file's original path, size and
deletion time. **The `$R` file contains the deleted content when it is
still available.**

Both record versions are read — version 1 (Vista–8.1, a fixed
260-character path field) and version 2 (Windows 10+, length-prefixed).
A record declaring any other version is refused by name rather than
decoded with a layout that may not apply.

The single event is `recyclebin_deletion`, labelled **"Recycle Bin
deletion time"**. It is not a write time, not a creation time, and not
evidence that anything ran.

Where the paired `$R` file was collected beside the `$I` record, the
pairing is reported as an observation about the **collection** —
`paired_r_file_status: present in this collection`, with its size. Where
it was not, the record names the file that *would* pair and says it is
absent. The `$R` file is never opened.

### Jump Lists

Two containers, read by two parsers, because they are two formats
carrying different evidence:

| | Automatic Destinations | Custom Destinations |
|---|---|---|
| Container | OLE compound file (`internal/olecf`) | concatenated shell links |
| Streams | one numbered stream per shortcut, plus `DestList` | none |
| Jump List's own timestamps | **yes** — last-recorded access per entry | **no** |
| Access count, MRU order, pinning | yes | no |
| Artifact | `jumplist_automatic` | `jumplist_custom` |

Embedded shortcuts are decoded by `internal/shelllink` — the same parser
that reads standalone `.lnk` files. Nothing about the shell link format
is reimplemented.

#### Two timestamps, never merged

| Event type | Timestamp means |
|---|---|
| `jumplist_entry_access` | The **Jump List's own** last-recorded access, from the DestList: when the application last recorded reaching the item. |
| `jumplist_target_metadata` | A **target file** timestamp carried by the embedded shortcut — its creation, write or access time. A property of the file, not a use of it. |

Every event carries a `timestamp_meaning` saying which it is. A Jump List
entry shows that an **application holds a reference to a target**; it is
**not proof of execution** — Windows records items opened, saved,
previewed, or merely reached through a file dialog. No event populates
`ProcessName` or `CommandLine`, and a shortcut's arguments are recorded
as `shortcut_arguments`, never as a command line that ran.

#### Application attribution

A Jump List is named for a 16-hex-digit AppID: a one-way hash of the
application's path. It can only be **looked up**, never reversed, so the
table in `internal/jumplist/appid.go` is deliberately small — identifiers
that are stable across installations because they derive from fixed
system paths. An AppID outside it resolves to nothing and is reported as
`Unknown application (AppID <id>)`, with the raw identifier always kept:
that identifier is the only lead an analyst has, and hiding it behind
"unknown" would discard it. A renamed file carrying no AppID at all is
reported differently again — absent is not the same as unresolved.

#### Provenance

Every event traces back through the whole chain:

```
Jump List file → AppID/application → OLE stream (name + directory index)
   → embedded shortcut (offset, byte length) → target path → event
```

`jumplist_stream`, `jumplist_stream_directory_index`,
`embedded_link_offset` and `embedded_link_bytes` record exactly where
inside the artifact each shortcut was found.

#### Failure is contained

One malformed embedded shortcut costs that entry, not the file — the
others parse, and the damaged entry is still reported with whatever its
DestList row supplied. An unreadable or unsupported-version DestList
loses the ordering and access times while leaving every shortcut
readable. A DestList row whose stream is missing is reported as evidence
in its own right.

#### Detection

Custom Destinations is content-detectable: a shell link header is 20
fixed bytes, and a custom list places its first one *after* a small
header rather than at offset zero — which is also what separates it from
a standalone `.lnk`. So a **renamed Custom Destinations list is still
found**.

Automatic Destinations is **not** content-detected, deliberately. Its
container is the OLE compound file format, shared with pre-2007 Office
documents, MSI packages and `Thumbs.db`, and nothing in the first 512
bytes tells them apart — what distinguishes a Jump List is a `DestList`
stream beside numbered shortcut streams, visible only after walking the
container's allocation tables, which discovery does not do. Claiming
every compound file by content would classify every old `.doc` in a
collection as a Jump List and then report each as a parse failure. The
extension is claimed instead, and a file wearing it without the content
is refused at parse time.

*Limitations:* the DestList's four droid GUIDs (link-tracking volume and
object identifiers) are read as opaque values and not resolved to
volumes or MAC addresses. DestList versions 1, 3 and 4 are decoded; any
other version is reported and its rows skipped, leaving the shortcuts
intact. The Custom Destinations category header is recorded as a byte
count but not decoded into category names. Shell items inside embedded
shortcuts carry the same `0xBEEF0004` limitation as standalone `.lnk`
files.

#### The `$R` half: recovered content

A deletion is two files, and Tracefall now reads both:

| | `$I` — metadata | `$R` — content |
|---|---|---|
| Artifact | `recycle_bin_metadata` (High) | `recycle_bin_content` (Medium) |
| Parser | `recyclebin@1` | `recyclebincontent@1` |
| Carries | original path, name, size, deletion time, version, SID | the deleted file's bytes, and nothing else |
| Detection | structural (version + FILETIME + path shape) | name + location, then validated by resolving the pair |
| Timeline | one `recyclebin_deletion` event | **none** |

**Every identifying fact on a `$R` record is borrowed, and says so.**
A `$R` file has no header, no timestamp and no path; its own name is an
identifier, *not* the deleted file's name. So the record separates the
two sources explicitly:

```
content   { status, recovered_size, sha256, measured_from: "$RA1B2C3.docx" }
metadata  { resolved, source: "$IA1B2C3.docx", original_path,
            original_name, original_size, deletion_time, record_version }
```

The hash is SHA-256 over the bytes actually read, streamed so a large
deleted file is never held in memory. The evidence model's own
`SourceFile.SHA256` — computed for every collected file at discovery —
covers the same bytes independently.

**Why `$R` produces no timeline event.** The deletion already has one,
emitted by the `$I` parser from the timestamp the `$I` record actually
carries. A `$R` file records no time of its own, and borrowing the
`$I`'s to place a second row at the same moment would put one deletion
on the timeline twice. Recovered content is an attribute of a deletion,
not a separate moment in it.

**Every pairing outcome is reported distinctly**, and none is a parse
failure — each is a true finding about the evidence:

| `pairing_status` | Meaning |
|---|---|
| `resolved` | The `$I` was found and parsed; its facts appear, attributed to it. |
| `orphan` | No `$I` was collected. Content is hashed; path, name and deletion time are `null` — never guessed from the `$R` filename. |
| `invalid` | The `$I` is present but is not a readable record. Distinct from absent. |

Content status is separate again: `recovered` (read through and hashed),
`unreadable` (**no hash is produced** — a digest over a partial read
identifies nothing), or `not_read_size_limit` above 2 GiB, where the size
is recorded and the bytes are left alone.

**A size mismatch preserves both numbers.** `original_size` is what the
system recorded at deletion; `recovered_size` is what the collection
holds. When they differ, both are kept unchanged and a warning says so —
the difference is a fact about the evidence, not an error to correct.

*Limitations:* the content is hashed and measured, never copied,
carved or interpreted — Tracefall does not identify file types, extract
text, or scan recovered content. Above 2 GiB it is not hashed at all.
A `$R` file outside a Recycle Bin directory is not claimed, because
nothing distinguishes it from any other file.

#### Detection is structural for both

Neither parser claims a filename. A `.lnk` extension is not evidence that
a file is a shortcut, and a `$I` prefix is not evidence that a file is a
metadata record — and claiming either by name would classify a
mislabelled file as supported and then report a *parse failure* where the
honest answer is "this is not that artifact". A file that resembles
either and fails validation stays unsupported.

#### Not every file in a cache is a cache entry

A browser cache is a small filesystem of its own. Alongside the entry
records it holds rankings, payload blocks, indexes, journals, lock files
and raw bodies — none of which are parseable into forensic records, and
none of which are broken evidence. **An unsupported cache file is not a
failed one.**

Triage therefore classifies each kind separately, with its own label,
its own priority, and a one-line note:

| Class | Supported | Priority | Note |
|---|---|---|---|
| Browser cache entry | yes | Medium | — |
| Browser cache container/index | yes | Medium | parsed for the cache's own metadata; **not an event source** |
| Chromium blockfile auxiliary file (`data_0`) | no | Low | ranking/index data is not independently parsed |
| Chromium blockfile payload file (`data_2`/`data_3`) | no | Low | metadata is in the associated `data_1` entry records |
| Chromium cached response body (`f_######`) | no | Low | metadata is in the associated `data_1` entry record |
| Browser cache hash index | no | Low | names no URL; the entry files it points at are parsed |
| Browser cache journal/state | no | Low | no independently parsed cache-entry metadata |
| Browser cache unsupported format | no | **Medium** | recognized structure, unsupported version/variant |
| Browser cache unknown | no | Low | format could not be identified |

Two things that follow from this table are load-bearing:

**Priority follows what the file could yield.** An auxiliary or
bookkeeping file is LOW because it holds no independently useful
metadata by design. An unsupported *variant* is MEDIUM because it is a
structure Tracefall reads, in a version it does not — it may still hold
recoverable data, and an analyst should see it.

**"Supported" keeps meaning "can be parsed into forensic records."**
Recognizing a file never makes it supported, and never raises the
supported count. Containers are the one qualified case: they are
genuinely parsed, so they are genuinely supported, and they carry a Note
saying they are not where the cached resources are.

#### Classification is structural

Discovery reads each file's leading bytes. When no parser claims one, it
asks what the bytes *are* before falling back to anything else:

```
parser claims it?          -> supported artifact type
bytes identify it?         -> recognition class (rankings / payload / variant)
exact format-defined name? -> cached body, journal/state
path rule?                 -> hash index, and the generic fallback
```

A file named `data_0` that is structurally an entry file is parsed as
one; a file named `data_1` that is structurally a rankings file is not.
Names are consulted only where a format defines an exact filename and
writes no signature — cached bodies (`f_######`), bookkeeping files, and
the Firefox cache1 block files — and never outside a cache directory.
The generic *"format could not be identified"* message is reached only
when structural detection settles nothing.

#### One file in, one file read

Tracefall ties every event to the hash of the file it came from. The
readers therefore never follow a cache address into a sibling file: a
`data_1` entry whose HTTP headers live in `data_2`, or whose key is
stored externally, is emitted with the **address recorded as a warning**
and the missing field left empty. Nothing is inferred from a file the
case did not import.

In practice this costs little — stream 0 (the response headers) is small
and is normally allocated in the same 256-byte block file as the entry —
and it is why Simple Cache entries still carry no timestamp even though
the Simple Cache *index* records last-used times.

#### Detection

Structural in every case but one. Blockfile files carry magic
`0xC103CAC3` (index) and `0xC104CAC3` (data); cache2 is validated
through its trailing metadata offset; Simple Cache has its own magic;
`_CACHE_MAP_` is validated by version word plus header coherence.

The exception is the Firefox cache1 **block files**. Their first 4096
bytes are an allocation bitmap — no magic, no version, no fixed shape —
so nothing in the 512-byte sniff window identifies them. They are
claimed by their three exact, format-defined names (`_CACHE_001_`,
`_CACHE_002_`, `_CACHE_003_` — never `_CACHE_004_`, never
`_CACHE_001_.bak`) and then validated structurally while parsing.

#### Four outcomes, kept distinct

An analyst must be able to tell these apart, and the pipeline does:

| Outcome | What it looks like |
|---|---|
| **Supported entry file** | `browser_cache`, imported, events on the timeline |
| **Container/index file** | `browser_cache_index`, imported, structured evidence, **no events** |
| **Unsupported/unknown** | Not supported, with a reason naming the structure and what *is* parsed |
| **Corrupt** | A parse failure, attributed to that file, isolating it from its neighbours |
| **Valid but empty** | A **successful import** with a parse report saying zero entries were recovered — never a parse failure |

Every multi-entry file also emits a `browsercache:parse-report` record
carrying blocks scanned, entries emitted, and entries skipped by reason
(evicted, doomed, no recoverable key). "This cache held no live entries"
and "this file could not be read" are different findings.

#### What a cached object proves

**A cached object proves the browser received and stored a response.**
It does *not* prove the user navigated to the URL, viewed it, clicked
it, downloaded it, or ran it — a page's subresources, prefetch hints,
advertising and tracking pixels all land in the cache without anyone
choosing them. Every cache record carries an explicit `evidence_meaning`
field saying exactly that, and cache events carry a confidence of
**0.7**, below browser history's 1.0.

Consequences of that boundary, all enforced by tests:

- **No fabricated timestamps.** A Chromium Simple Cache entry produces
  structured evidence and *no timeline event*. A blockfile or cache1
  record whose recorded time is absent or implausible is **not emitted
  as an entry at all** rather than emitted with a zero time. The file's
  mtime is never substituted.
- **No invented actor.** Cache entries carry no user and no process. A
  path may name a Windows profile directory; that is recorded as
  `user_profile_path`, which is a path, not an authenticated identity.
- **No recycled records.** Blockfile entries in the *evicted* or
  *doomed* state are counted in the parse report but never emitted:
  their fields are being reused and may no longer describe the key.
- **No verdict.** A suspicious-looking cached URL raises no finding on
  its own.
- **No secrets.** `Cookie`, `Set-Cookie`, `Authorization` and the other
  authentication headers are redacted before anything is persisted, in
  every format.
- **No bodies.** Only metadata is read, in every format. Every record
  says so in `cached_body`.
- **Read-only.** Original files are opened for reading and never
  modified; SHA-256/SHA-512 integrity is unaffected.

Entry files are **medium** priority and containers **low**, so neither
is in the recommended set — one real cache holds tens of thousands of
files, and sweeping them into "Select recommended" would bury the six
registry hives that selection exists to surface.

Where the same host appears in *both* browser history and browser
cache, the correlation engine emits a `web_resource` correlation
([`internal/correlate/web_resource.go`](../internal/correlate/web_resource.go)).
It is a link between two independent sources, not a finding: it carries
no severity and describes a benign CDN exactly as it describes anything
else.

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

**MAM-compressed Prefetch is read natively.** Windows 10 and 11 store
`.pf` files wrapped in a `MAM` LZXPRESS Huffman container. Tracefall
decompresses these itself (`internal/lzxpress`) and hands the result to
the same SCCA parser an uncompressed file uses, so identical content
produces identical events either way. There is one parser and one
normalization path, not two, and no external tool is involved: PECmd,
PowerShell and .NET are not runtime dependencies.

Decompression is an in-memory parser step. The evidence on disk is never
modified or rewritten, and the file's SHA-256 and provenance continue to
describe the bytes **as collected**, not the decompressed intermediate.
Events carry `prefetch_container`, `prefetch_compressed_bytes` and
`prefetch_uncompressed_bytes` so the container is visible as
chain-of-custody detail — it is not a signal, and nothing in detection,
correlation or scoring treats a compressed file differently from an
uncompressed one.

Two conditions still fail, and are distinguished from each other:

| Condition | Sentinel | Meaning |
|---|---|---|
| Container declares a method other than LZXPRESS Huffman | `prefetch.ErrUnsupportedCompression` | A capability gap. |
| Container is LZXPRESS Huffman but the stream will not decode | `prefetch.ErrDecompress` | The evidence is damaged. |

The decompressor is validated against real Windows 10 evidence rather
than only against its own fixtures — see `TestDecompress_RealWindowsCorpus`,
which decodes an entire host's Prefetch directory and requires every
result to carry a valid `SCCA` signature.

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


### Bash history (`bashhistory@1`)

Parses `.bash_history`: one accepted command per line, in order. Blank
lines are skipped; line references count them, so a reference opens to
the same line an examiner sees.

Timestamps are present only when the shell ran with `HISTTIMEFORMAT`,
which writes a `#<epoch>` line before each command. When that line is
present the event takes its time from it (`timestamp_known = "true"`).
When it is absent, which is the default, the event is **undated** and the
file's modification time is not used. The Insider image's root history
has no epoch lines, so all 95 of its commands are undated.

A command typed twice is two events. Undated events are identified by
command text and line number together; see "Events with no timestamp".

### Login records (`wtmp@1`)

Parses `/var/log/wtmp`, a sequence of fixed 384-byte utmp records (glibc
x86-64 layout). Emitted: `session_start` (USER_PROCESS), `session_end`
(DEAD_PROCESS) and `system_boot` (BOOT_TIME). RUN_LVL, INIT_PROCESS,
LOGIN_PROCESS, NEW_TIME, OLD_TIME and ACCOUNTING records are bookkeeping
and produce no event.

Limitations, stated rather than hidden:

- A file whose size is not a multiple of 384 is rejected whole, not read
  partially, because a truncated record cannot be trusted.
- A logout record carries the terminal and PID but not the user. Its
  `user` is empty; pair it with the login by `terminal`.
- Only `wtmp` is claimed. `btmp` (failed logins) uses the same layout with
  different meaning, so it is not parsed by this parser.
- The file is in file order, not time order. Rotations and clock changes
  break time order, so each event keeps its own timestamp.

### Authentication log (`authlog@1`)

Parses `/var/log/auth.log` and its plain numbered rotations (`auth.log.1`).
Compressed rotations (`.gz`) are not claimed.

Emitted: `su` successes and failures (`privilege_switch`, outcome in
`Extra`), `sudo` commands (`sudo_command`, the authorised command, not a
confirmed execution), and `sshd` accepted and failed logons (`logon_success`
and `logon_failure`, with the source address). PAM session open/close lines
and CRON, systemd and polkit noise produce no event: they repeat the action
lines above or describe nothing an examiner acts on.

**Timestamps are partial on purpose.** Each line gives only `Mon DD HH:MM:SS`,
with no year, and the year is not in the file. These events therefore have a
zero `Timestamp`. The month, day and time are kept exactly as written in
`Extra["timestamp_partial"]`, so filtering by time of day works (the usual
question, for example "what happened at 11:26?") and the file's line order is
preserved. The year is deliberately **not** inferred, and the file's
modification time is not used to fill it in: mtime is when the file was last
written, not when a line was logged, and it can be changed.

On the Insider image this gives 6 successful `su` (all `Mar 20 11:26:22-23`,
target `postgres`, invoked by `root`) and 4 `sudo` commands. The `su` target
is `postgres`; the invoking account is `root`, so this line alone does not
show which person was behind the session.

**Account and group changes.** `useradd`, `userdel`, `usermod`, `groupadd`,
`groupdel`, `gpasswd`, `passwd` and `chpasswd` lines become `account_change`
events. `Extra["action"]` is one of `user_created`, `user_deleted`,
`user_modified`, `group_created`, `group_deleted`, `group_member_added`,
`group_member_removed`, `password_changed`, `password_locked` or
`password_unlocked`; `object_type`, `object_name` and, where the line has
them, `uid`, `gid`, `home`, `shell` and `member` complete it. The log records
that the system applied the change, not who asked for it, so the event's
`User` is empty and `actor_known` says why. The shadow-group twin of a group
line repeats the line before it and is not emitted. A failed password change
("new password not accepted") is not a change and is not emitted.

**Relative time.** A year-less stamp still orders the lines of one file and
measures the distance between them. Each event also carries
`Extra["partial_ordinal"]` (seconds from 1 January 00:00:00 of an unspecified
year) and `Extra["partial_calendar"]` (`leap` when the file holds a "Feb 29",
otherwise `common`). The rules `brute-force-then-success-sequence` and the
sequence credential chain use only these. They never produce a date, never
compare two files (rotations may cover different years), and never bridge a
New Year (a stamp that goes backwards while the line number goes forward).

Limitations, stated rather than hidden:

- A full timestamp is available only from another source, for example the
  correlation of an event with a dated artifact. Nothing here supplies one.
- `secure` (the Red Hat name for the same log) is not claimed: the name is too
  common to claim on its own.
- `auth.log.1` on the Insider image holds only CRON, realmd, systemd, polkit
  and gdm lines, so it correctly produces zero events. The count is verified
  against an independent pass over the raw file.
- Compressed rotations are not parsed.


### System log (`syslog@1`)

Parses `/var/log/syslog` and its plain numbered rotations (`syslog.1`).
Compressed rotations (`.gz`) are not claimed.

Only one kind of line is emitted: a cron job starting, in the form
`(user) CMD (command)`. It becomes a `scheduled_job_run` event with the
account, the command text (wrapper parentheses removed, inner ones kept),
and the cron PID. cron records that it started the job, not its result, and
the event says so.

Everything else in a system log is left uninterpreted. That includes USB
attachment: on the Insider image the only USB device in the log is a VMware
virtual mouse, and a rule that matched "usb" would have reported it as
removable media. Lines with no program name are skipped.

Partial timestamps, as in auth.log: no year, the month, day and time kept as
written in `Extra["timestamp_partial"]`, and the year not inferred.

On the Insider image, `syslog` gives 105 jobs (70 + 1 `debian-sa1`, 23
`sessionclean`, 11 `run-parts`) and `syslog.1` gives 785. Both match an
independent count of the raw files. `installer/syslog`, a BusyBox installer
log, is also detected by name and correctly yields zero events, since it has
no cron lines.

**Daemon log and service messages.** `daemon.log` and its rotations are read
in the same format. A fixed allow-list of MySQL messages becomes
`service_message` events, from the programs `mysqld`, `mysqld_safe`,
`mysqlcheck`, `debian-start` and `mysql` only:

| `Extra["category"]` | Matches |
|---|---|
| `database_insecure_account` | "root accounts without password" |
| `database_integrity` | corrupt or crashed tables, "not shut down normally", crash recovery |
| `database_error` | `[ERROR]` lines and `ERROR:` start-up errors |
| `database_lifecycle` | start, "ended", shutdown complete, ready for connections |

Each event keeps the message, the program and a `meaning` that says what the
line does and does not show. The list is short on purpose: a line that is not
on it proves nothing about what happened. The same words from a different
program are not claimed. `messages` is not claimed (name too common), and
`kern.log`, `user.log`, `debug`, `udev` and `dmesg` are not parsed.

mysqld stamps its own messages with a `YYMMDD HH:MM:SS` date. That text is
kept verbatim in `Extra["embedded_stamp"]`. It is the server's own clock; it is
not used to date the syslog stamp or any other line.

Not done: systemd unit start and stop, kernel, NetworkManager and DHCP events.
The journal (`/var/log/journal`) is not on this image, so it cannot be
validated here and is not parsed.


### Systemd journal (`journal@1`)

Parses systemd journal files: `*.journal` by name, and any file whose first
bytes carry the journal signature. That second rule also claims the
set-aside copies journald makes after corruption (`*.journal~`), which read
correctly.

Every entry becomes a `journal_entry` event with its **real UTC timestamp**.
This is the one Linux log in the set that carries the year, so these events
are dated and need no partial-timestamp handling.

Exclusions: entries from `sshd`, `sudo`, `su`, and `cron` are not emitted,
because the auth.log and syslog parsers already emit those actions. Excluded
counts are reported.

Kept fields are a fixed set: the message, the host, the command and
executable, the PID, the UID, the boot id, the systemd unit, the transport,
the syslog identifier and the priority. Other fields are read past. Messages
longer than 4096 characters are truncated and say so.

Limitations, stated rather than hidden:

- Only LZ4-compressed objects are decoded (the dependency is
  `github.com/pierrec/lz4/v4`). XZ and ZSTD objects are counted as
  unsupported in the statistics, not guessed.
- A message that is not valid text is kept with replacement characters.
- Volume: a journal holds far more entries than the text logs. The lab's 86
  AzurePot journals contain 904,601 entries. Most of them are auditd records,
  and an execution is spread over several of them (SYSCALL, EXECVE, CWD, PATH,
  PROCTITLE), so the parser groups them. See "Audit execution grouping".

Validation: every entry of every file on the AzurePot image (86 files) was
compared against `journalctl`, with the same realtime, process, PID and
message. All 86 files match. On the MrGamer image, six non-empty journal
files (76,762 events) match the same way, and the imported database holds
exactly 76,762 distinct events.

The MrGamer image's `system.journal` is zero bytes in its inode, with a
deletion time. It is reported as failed, not as empty; that status is a known
wart.

### Audit execution grouping (journal)

auditd writes one execution as several records, and journald stores each
one as a separate entry. They share an `_AUDIT_ID`. The parser groups records
with the same serial inside a file:

- a group whose SYSCALL record is `execve` (59) or `execveat` (322) becomes a
  single `process_create` event. The command line comes from the EXECVE
  record (chunked `a0[0]`/`a0[1]` arguments are rejoined, bare-hex arguments
  are decoded), the directory from CWD, the touched files from PATH, and the
  title from PROCTITLE when there is no EXECVE record;
- any other group (logins, credential records) stays one event per record,
  so nothing is merged away;
- groups from sshd, sudo, su and cron are excluded as before.

Each execution keeps its PID, PPID, process name, executable, uid, auid,
syscall, success, exit, argument count, cwd, paths (at most 20 are listed, the
count is kept), the audit serial and the record count. Commands longer than
8192 characters are cut and marked.

Validation, against journalctl on all 86 AzurePot files: 171,270 executions
(from 173,332 audit groups), 2,982 plain events, 1,419 excluded, and 881
non-text messages matched by key. Every execution's time, PID, process name
and, where the arguments can be rebuilt from journalctl, its full command line
match.

Limitations, stated rather than hidden:

- The command line joins argv with spaces. An argument that itself contains a
  space (for example `sh -c "a b"`) is shown joined, so the boundary between
  arguments is not recoverable from the text. The raw EXECVE record is kept
  verbatim in the raw evidence, so the original boundaries remain available.
- Executions whose arguments are bare hex or chunked are not compared
  character by character in the test; they are compared on time, PID and
  process name only.
- The syscall rule is architecture-aware: x86_64 (59, 322), i386 and 32-bit
  processes on a 64-bit kernel (11, 358), and aarch64 (221, 281). Only x86_64
  appears in the lab's AzurePot journals, so the 32-bit and aarch64 rows are
  covered by unit tests built from the kernel's syscall numbers, not by real
  samples. A mismatch there is a known unvalidated area.
- Other kernel syscalls in the same journals are kept as plain entries, not
  turned into events of their own. One example is a `finit_module` (kernel
  module load, syscall 313) by `modprobe` as root, which stays visible as a
  journal entry for analysts to read.

Not done: the journal's own integrity hashes are not verified by this parser.
`journalctl --verify` is the reference used in validation.

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

## Registry hives copied while Windows was running (transaction logs)

A hive copied from a running system is usually not cleanly written: its base
block has two different sequence numbers (offsets 4 and 8; the second is the last
transaction finished, the first the last one begun). The changes it is missing are
in `HIVE.LOG1` and `HIVE.LOG2` beside it. Without them the registry shown is older
than the machine was, and a run key or service added in the last minutes before
collection can be absent.

Tracefall replays those logs in memory (`regf.OpenWithLogs`). No file is written,
the evidence is read as it is, and the replayed state exists only while the hive
is read. The logs are found beside the hive whatever the case of their names.

What is replayed: logs of the Windows 8.1 and later format (file type 6, entries
signed `HvLE`). Every entry is checked before it is used: the two Marvin32
hashes, a size that is a multiple of 512 inside the file, a hive-bins size that is
a multiple of 4096, page references wholly inside the entry and the hive, and the
expected sequence number. The first entry that fails ends the chain; what follows
is stale remnant of an earlier use of the file, which is normal.

Every record from such a hive carries `hive_state` and `hive_recovery` in
`Extra`, and the parse coverage carries a note unless the hive was fully
replayed. A clean hive carries neither.

| `hive_state` | Meaning |
|---|---|
| `replayed` | The log chain covers every transaction the primary file had begun. Records reflect the logged state. |
| `replayed_partial` | Logged changes were applied, but the log ends before the transaction the primary file had begun. Changes of that transaction are not covered. |
| `not_recoverable` | The hive is dirty and the logs cannot be applied safely. The hive is read as the primary file is, and the registry changes of the gap are missing. |
| `no_logs` | The hive is dirty and no log was found beside it. |

**Where this is stricter than the reference implementation.** yarp, and probably
Windows, apply a log whose first entry is newer than the primary file's finished
transaction even when transactions lie between them. Tracefall does not: a log
must start at or before the transaction the primary file had begun, and a second
log must start right after the first one's last entry. On a live collection the
primary file is often copied earlier than its logs; applying the later pages
without the transactions in between yields a hive that never existed. The reason
names the sequence numbers (for example, a primary that finished 586 with a log
starting at 617).

Validation:

- `NewDirtyHive1` from yarp's test set ships with `RecoveredHive_Windows10`, the
  hive Windows wrote after recovering the same files. The replayed hive bins data
  are byte-identical to it (4 entries, both logs), and `NewDirtyHive2` applies
  only the second log, as the reference does.
- On a real Windows 10 live collection, DEFAULT (sequence 118 to 124) and SECURITY
  (to 122) replay to bytes identical to yarp's result. SYSTEM (primary 586, log
  from 617) and SOFTWARE (primary 1629, logs from 1738) are refused for the gap.
- The Marvin32 implementation matches yarp's on pinned vectors.

Limits:

- The older log format (file types 1 and 2, with a dirty vector; Windows 8 and
  earlier) is not replayed. It is named in the reason.
- A hive whose base block checksum is wrong is not replayed.
- Only the hive's key tree is replayed; deleted keys and values in slack are not
  examined here.
- An entry larger than 128 MiB, a log larger than 256 MiB, or more than 512 MiB of
  entries is refused.

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
- **In deduplication**, a zero timestamp causes `CommandLine` *and* the
  source reference (line or record number) to be included in the dedup
  hash. Identical text on two different lines is two events: the Insider
  image's root history had `ls` eleven times, and before the line
  reference was included 25 of its 95 lines collapsed into 70 events.
  Re-importing the same file yields the same line numbers, so the same
  artifact still deduplicates across collections.

---

## Credential evidence (Windows SAM)

Tracefall extracts Windows **local account** records from a SAM hive:
the account name, its RID, its account-control flags, its stored logon
and password timestamps, and its **NTLM password hash**. Full detail is
in [windows-artifacts.md](windows-artifacts.md#windows-sam); what triage
needs to know is here.

**Tracefall does not crack passwords.** There is no wordlist, no brute
force, and no integration with Hashcat, John the Ripper or anything
comparable. The hash is the evidence and the hash is where it stops.

**An NTLM hash is not the plaintext password.** It is a one-way function
of one and it is not reversible. A report must say "the account's stored
NTLM hash is X", never "the password is X".

**A SAM hash is credential evidence, not malicious activity.** Every
Windows machine has local accounts and most of them have password
hashes. Tracefall raises **no finding** and starts **no investigation**
because a hash exists, and SAM events are kept out of the correlation
engine — an account record is not an execution, a logon or a persistence
mechanism.

**Collect SYSTEM with SAM.** The hash is wrapped under the machine boot
key, which lives in the SYSTEM hive and not in the SAM. Without SYSTEM,
every account is still reported — name, RID, flags, every timestamp —
with its hash marked `encrypted_system_hive_missing` and the reason
stated on the event. That is a different statement from "this account has
no password", and Tracefall never conflates the two.

The key is derived **once per collection**, before any file in an import
is parsed, and the SYSTEM hive does not have to be selected for import —
being catalogued in the same collection is enough. Every account event
records which file supplied the key (`boot_key_source`), its hash, and
which control set it came from.

**"Encrypted" is not "not available".** An encrypted hash is material
that is present in the evidence and needs a key; a missing hash is an
account that stores none. Those are different findings with different
next steps, so they never render alike:

| State | What it means | What you do |
| --- | --- | --- |
| `decoded` | the hash was recovered | nothing; it is in the event |
| `not_stored` | the account stores no NT hash | nothing to recover |
| `encrypted_system_hive_missing` | hash present, no SYSTEM hive | collect `Windows\System32\config\SYSTEM` |
| `encrypted_system_hive_unusable` | hash present, SYSTEM hive will not do | it is damaged, or from another machine |
| `encrypted_data_unavailable` | hash present, its bytes are unreadable | the SAM record is damaged |
| `unsupported` | hash present, wrapping not decoded by this build | reported, never guessed |

**Anything it cannot decode safely, it reports.** A SAM structure in a
format this build does not read, a record that is truncated, or a boot
key that fails the domain-key checksum all produce an explicit status
and a sentence — never a guessed value. Specifically, an account that
stores no NT hash is reported as `not_stored`; the constant
`31d6cfe0d16ae931b73c59d7e0c089c0` that some tools print in that
position is the hash of the empty string, a convention rather than a
reading, and Tracefall does not emit it.

**Where the hash appears.** In the event's own detail view only, in a
labelled panel, displayed truncated with a reveal control and a Copy
button that copies the complete value. It is not in the timeline row,
not in the Detail column, and not in the free-text search index.

## Recognized is not parsed

Three classes of file are now catalogued as **what they are** and
explicitly not parsed. Nothing is extracted from any of them — no event,
no timestamp, no URL, no hash — and none of them is counted as a parser
failure, because nothing failed:

| Artifact | What it is |
| --- | --- |
| `unsupported_browser_artifact` | A browser database that is not history: cookies, saved logins, favicons, autofill, media state, quota bookkeeping |
| `registry_transaction_log` | A hive's `.LOG1`/`.LOG2` companion |
| `browser_cache_body`, `browser_cache_payload`, … | A cached response body and the cache's own bookkeeping files |

### Why detection was narrowed

Classification used to be far too broad, and the cost was a page of parse
errors about evidence that was perfectly intact. In one real image:

- **25 SQLite databases** from browser profiles were catalogued as
  "Browser history (Chromium / Firefox)" and failed with *"not a browser
  history schema"*. A browser profile holds a dozen databases and exactly
  one of them is history. Content detection accepted **any** SQLite file,
  so Cookies, Favicons, Login Data, Web Data, Media History, Top Sites,
  Shortcuts, Network Action Predictor, QuotaManager, Reporting and NEL,
  Safe Browsing Cookies — and `wpndatabase.db` and `queue.sqlite3` from
  outside any browser — were all claimed as history.
- **20 registry transaction logs** were catalogued as "Windows Registry
  Hive" and failed with *"this is a registry transaction log, not a
  hive"*. A transaction log **is** a REGF file and carries the same
  signature; the base block's file-type field at offset 28 is what
  separates them, and it sits inside the 512-byte window discovery
  already reads.
- **7 application-compatibility databases** (`AgGlGlobalHistory.db`,
  `ResPriHMStaticDb.ebd` and siblings) were catalogued as "Prefetch"
  because they share the MAM compression container. MAM is a general
  Windows compression wrapper, not a Prefetch format.

Browser history and Windows Timeline are now claimed by **name**,
confirmed against the bytes. The honest cost is that a *renamed* history
or Timeline database is no longer detected — but the previous behaviour
did not detect renamed history either. It claimed everything and let the
parser sort it out at import, turning a classification question into a
page of errors.

Hives and Prefetch keep content detection, because both have a structure
that actually proves what they are.

### A renamed hive is still a hive

Cataloging identifies a file by **name and content**, and both ingestion
paths — a walked directory or ZIP, and an AD1 image — make that decision
in one shared place (`ingest.MatchParser`). An AD1 previously matched on
the filename alone, so a hive renamed inside a triage image was
catalogued unsupported and never importable, while the same file in a
folder was recognized fine. Reading a bounded 512-byte prefix of each
entry costs about **0.6 seconds over a 7,000-entry, 720 MB image** —
measured, not estimated — and finds them.

### A file named SAM is not a SAM

A filename is a hint, never a verdict. A parser whose `Detect` matches
on a name must confirm it against the file's first bytes
(`parsers.ContentConfirmer`), so a text file called `SAM`, `SYSTEM` or
`NTUSER.DAT` is reported as **unrecognized** rather than claimed as a
hive and then failed at import. The old behaviour told an analyst their
hive was corrupt when no hive was ever there. A genuinely renamed hive
is still found — by content, which is what content detection is for.

---

## Parse errors

An import can leave a file in one of several states, and they are not the
same problem. Three of them mean the **evidence is intact**:

| State | Meaning | Is the evidence damaged? |
| --- | --- | --- |
| `unsupported_format` | Tracefall does not read this artifact | No |
| `unsupported_compression` | The artifact is supported and present; its container's compression is not implemented | No |
| `misclassified` | The file is not the artifact it was cataloged as | No |
| `empty` | The file has no content | No — there is nothing to parse |
| `corrupt_or_truncated` | The evidence itself is damaged | **Yes** |
| `limit_exceeded` | A safety ceiling stopped the parse | No |
| `unreadable` | Could not be read from storage | Unknown |
| `internal_error` | Tracefall failed unexpectedly | No |

The UI names the state on every row and explains what it means for the
evidence, because "parse error" told an analyst nothing about which of
these they were looking at.

An artifact that is correctly identified as unsupported never reaches a
parser at all, so it is never counted as a failure — it is catalogued as
recognized-and-unsupported and does not appear in this list.

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
| `prefetch.ErrUnsupportedCompression` | `unsupported_format` | The MAM container uses a compression method Tracefall does not implement. |
| `prefetch.ErrDecompress` | `corrupt_or_truncated` | The MAM container is LZXPRESS Huffman, but the compressed stream is truncated or corrupt. |
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

## Connection and media evidence

Two artifact classes added in Phase 20 sit outside the execution/registry
families and are worth a triage note each. Full detail is in
[windows-artifacts.md](windows-artifacts.md).

### FileZilla server entries

`recentservers.xml` and `sitemanager.xml` name a remote host, port,
protocol and username an FTP client on this machine was configured for —
often the only record on disk of where data was staged or sent.

**They record no time.** The events carry none, and the file's mtime is
not substituted. On a timeline these appear under "No timestamp", which
is what the artifact supports.

**A stored password is never extracted.** The value is not read out of
the source file at all; only `password_present` and the storage encoding
are recorded. As with the SAM, the useful fact is that a saved FTP
credential exists in this profile — the secret is not needed to state it.

**An entry is not a connection.** `recentservers.xml` says a connection
was *attempted* from this profile. The Site Manager says only that a site
was *saved*. Neither says anything succeeded.

### Image metadata and embedded location

Every JPEG in a collection is catalogued and its EXIF read, without
decoding the picture. Two events come out of one image: the metadata, and
— only when a full coordinate is present — the location.

**A coordinate is not a sighting.** It is a position the file *carries*.
Metadata travels with a copied file and can be edited or fabricated, so
this places the writer's claimed position, not necessarily a device or a
person.

**The country is derived, not observed.** It comes from an offline
point-in-polygon test against a bundled boundary dataset, performed by
Tracefall. The UI keeps observed and derived under separate headings for
exactly this reason, and every GPS event names the dataset and version
that produced its answer.

**Check the coordinate's precision before relying on it.** Many devices
store rounded positions. A coordinate written as whole degrees locates a
point to within about 111 km, and the event says so — a country
determination made from one inherits that uncertainty.

**Neither raises a finding.** An FTP server entry, a coordinate and a
country are observations. Nothing here is treated as a detection.

**Located photos are plotted on the case's Photo Map**, where the image
itself can be viewed and traced back to its evidence record — see
[photo-map.md](photo-map.md). Images without a coordinate never appear
there at a guessed position.

---

## Adding a parser later

1. Implement `parsers.ArtifactParser` (optionally `ContentDetector`, and
   `PathScopedDetector` if that detector is broad enough to need a path
   scope).
2. Register it in `ingest.Registry()`.
3. Add one entry to `supportedTypeInfo` in `internal/artifacts` with the
   label, family and priority.
4. If a matching entry exists in `unsupportedRules`, remove it — the
   artifact is now supported.

Support flips automatically because it is derived from the registry.
Nothing in the frontend changes: the dashboard renders whatever the
capability endpoint reports.


### Web server access log (`webaccess@1`)

Parses Apache-style access logs in Common and Combined Log Format. It claims
`access.log`, `access_log`, `*-access.log`, `other_vhosts_access.log` and
numbered plain rotations by name, and any file whose whole first line has the
layout (address, bracketed date with an offset, quoted request, status), so a
renamed log is still found while no other text is mistaken for one.
Compressed rotations are not claimed.

One `web_request` event per matching line, with the client address as the
network source, the logged user, and in `Extra`: `method`, `uri` (exactly as
logged), `protocol`, `request_line`, `status`, `bytes`, `referrer`,
`user_agent` and `log_utc_offset`. Anything the server appended after the user
agent (a request id, the time taken) is kept as text in `trailing_fields`.
The timestamp carries a UTC offset, so the event has a real UTC time.

Limitations:

- A line shows what was asked and what status came back. It does not show what
  the application did. A request that looks like an attack is an attempt; a
  200 does not prove it worked and a 404 does not prove it failed.
- The URL is stored raw. Decoding and classification happen in the rule
  `web-attack-indicators`, so the evidence is never altered.
- Lines of another layout are skipped and counted in `unparsed_lines` on the
  first event. The Apache error log is a different format and is not parsed.
- The host name is not in the log. It is filled in from the collection like
  other host-less artifacts, and left empty when that is ambiguous.
- A rule reads every request of a case, so memory grows with the size of the
  logs. The parser limit is 256 MiB per file.

### IIS web log (`iislog@1`)

Parses IIS W3C extended logs. It claims `u_ex*.log`, `u_in*.log` and `u_nc*.log`
by name, and any file whose `#Fields:` directive names `cs-uri-stem` and
`sc-status`, so a renamed log is still found while the Windows Firewall log and
other W3C-format files are not. FTP site logs (`FTPSVC*`) and HTTP.sys error
logs (`HTTPERR`) share the folder and are not claimed.

One `web_request` event per request line, with the client address (`c-ip`) as
the network source, `cs-username` as the user and, in `Extra`: `method`, `uri`
(stem and query, as logged), `uri_stem`, `uri_query`, `status`, `substatus`,
`win32_status`, `bytes`, `request_bytes`, `time_taken_ms`, `server_ip`,
`server_port`, `site`, `server_name`, `host_header`, `protocol`, `user_agent`,
`referrer` and `x_forwarded_for` when the log records it. The columns are named
by the log's own `#Fields:` line, which may change part-way through a file, so
nothing depends on column order. The existing rule `web-attack-indicators` reads
these events with no change.

Limitations:

- A line shows what was asked and the status IIS returned. It does not show what
  the application did: a 200 on an uploaded script proves the script was served,
  not what it ran.
- Times are UTC. Microsoft documents this for the W3C format; a single log file
  cannot confirm it. A row with no `date` or no `time` column is undated and is
  never given a date from the header or the file name.
- The user agent and query are stored as logged. IIS writes a space as `+`, and
  a literal `+` is not distinguishable, so neither is decoded. The cookie column
  is not copied into the event (it can hold session tokens); the untouched line
  is kept as raw evidence.
- A row that arrives before any `#Fields:` line, a row whose column count
  disagrees with the line in force, a row cut off while IIS was writing it, and a
  line longer than 64 KiB are counted in `unparsed_lines` on the first event and
  never guessed at.
- Behind a load balancer `c-ip` is the balancer. `x_forwarded_for` is shown when
  logged but is a header the client controls.

### CryptoAPI URL cache (`cryptneturl@1`)

Reads `CryptnetUrlCache\MetaData\<hash>` entries (system profile and per user).
Windows writes one for every URL it retrieves while validating a certificate
(revocation lists, OCSP, trust lists), and `certutil -urlcache -f` writes one for
a file it downloads, together with the file itself in `Content\<hash>`.

One `crypto_url_retrieval` event per entry, dated by the last-download FILETIME,
with `url`, `url_host`, `file_size`, `etag`, `last_modified_header` (the
response's Last-Modified), `cache_profile` and, from the sibling Content file,
`content_present`, `content_size_matches`, `content_magic` (pe, zip, 7z, rar, cab,
der, elf, pdf, text, unknown), `content_sha256`. The layout is the published one
(urlSize at 12, FILETIME at 16 and 88, ETag size at 100, file size at 112, then
URL and ETag in UTF-16LE); an entry whose parts do not account for the whole file
is marked `layout_verified: false`.

The rule `cryptnet-executable-retrieval` reports an entry only when the cached
object is an executable (high), an archive or ELF (medium), or the URL ends like a
program or script and the object is not there to examine (medium, low confidence).
Certificate traffic (DER, CAB, empty) is never reported.

Limitations:

- An entry shows that a URL was retrieved and when. It does not name the program
  that asked. In a normal system almost every entry is Windows itself.
- The ETag and Last-Modified are the server's headers, not the file's own times.
- Only the first 116 bytes of the header and the URL and ETag are interpreted; the
  rest of the header is not documented and is not read.
- Entries that Windows has already removed from the cache are not recoverable here.

Validated on 53 entries of a real Windows 10 collection: all 53 cached object
sizes equal the recorded `fileSize`, all layouts account for the whole file, and
the host tally, content kinds and time range equal a separate pass over the raw
bytes. That collection contains only certificate traffic, so no true positive was
available; the rule is tested on constructed entries.

### Defender command-line log (`defendercmd@1`)

Reads `MpCmdRun.log` (UTF-16LE with a byte order mark; also the rotated
`MpCmdRun-<date>.log`). One `defender_command` event per run, with
`command_line`, `executable`, `verb` (the first argument), `download_url` and
`download_path` when `-url` and `-path` are present, `timestamp_local` and
`end_local` (ISO, no zone), `error_lines` (up to three lines that say error or
failed) and `line_number`.

The times are the machine's local time and carry no zone, so a run has no instant.
When the collection's SYSTEM hive records the zone, `timestamp_utc` is derived
with that one fixed offset and `timestamp_utc_basis` names the hive and says that
daylight-saving changes are not applied. Only English day and month names are
read; any other time is kept as written in `timestamp_text`.

The rule `defender-mpcmdrun-misuse` reports `-DownloadFile` (high; MpCmdRun.exe is
a signed Microsoft binary that will fetch a file) and `-RemoveDefinitions -All`
(medium).

Limitations:

- The log records the command, not that a download succeeded or what happened to
  the file.
- Only MpCmdRun.log is read here. The support logs (MPLog, MPDetection) have their own
  reader, below.
- Validated on a real log of 16 runs (verbs, error runs, start times and the
  absence of any instant equal a separate pass over the raw bytes); it contains
  only signature updates, so the rule is tested on constructed runs.

### Defender antimalware telemetry (Operational log 1116-1119 and `defendermplog@1`)

Three event types, shared by two sources of the same engine:

- `antimalware_detection`: Defender Operational EventID **1116**, and the
  support log's `DETECTIONEVENT` line.
- `antimalware_action`: Operational **1117**, **1118** (failed), **1119** (failed,
  critical).
- `antimalware_process_blocked`: the support log's `Process creation blocked:`
  line.

Operational records (provider and channel `Microsoft-Windows-Windows Defender` and
`.../Operational`, both required) keep the recorded fields in `Extra`:
`threat_name`, `threat_id`, `severity_name/id`, `category_name/id`,
`detection_id`, `detection_time_recorded`, `detection_user`, `resource`,
`resource_kind` (`command_line` for a `CmdLine:` path, `file` for `file:`, else
`other`), `action_name/id`, `error_code`, `error_description`,
`remediation_user`, `process_name_recorded`, `source_name`. The resource goes
through `cmdsem.Redact`, is capped at 2 KiB, and never enters `CommandLine` or
`FilePath` of the event: a CmdLine resource is a command-line string, not a file
and not a process start. `detection_id` is carried so several records of one
detection are counted once by the rule; the records themselves stay separate
events (the EVTX record id is part of their identity). Defender 5007 (configuration change) is mapped only for security-relevant settings, and
5004 and 1013 are mapped as configuration/history records (see
[evtx-coverage.md](evtx-coverage.md)); every other Defender ID (scan and update records,
1000-1002, 1150/1151) stays unmapped on purpose.

The support log reader streams the file (UTF-16LE/BE with or without a BOM, or
UTF-8) with caps: 1 GiB scanned, 32K characters per line, 100000 events. Past a
cap the rest is counted and written to the parse coverage notes. It reads only
the two line kinds above and says in its coverage note that all other lines are
skipped by design. Each event carries `line_number` and `byte_offset` of the
record for citation. `Process creation blocked` keeps `process_name`,
`process_id`, `parent_pid`, `reason_code` and the two `ProcessCreationTime`
tokens exactly as written, plus a separately labelled FILETIME reading
(`*_utc_derived`). The line prefix time has no zone: it is kept in
`timestamp_local`, the event is undated, and nothing is converted. PIDs are
neither set as the event's PID/PPID nor joined across hosts. The rule
`av-threat-detected` reports detection groups (per host and threat label, with
record and detection-ID counts kept apart and the two sources never added) and
blocked creations (per host) with the engine's recorded severity.

Limitations:

- A detection is the engine's record under its own label; it does not show the
  resource ran. An action of Remove with error code 0 describes the engine's
  action, not a completed transfer or command, and not removal or recovery of a
  payload.
- 1118 and 1119 share the 1117 template in the provider manifest; no real record of
  either was read, so their layout is not verified. 1015 (behavior detection) and
  5001 (protection disabled) are not mapped: no real record to ground their fields.
- The EvtxECmd CSV path maps these IDs only when it carries the same field names;
  this was not verified. Use the raw EVTX.
- `DetectionHistory` binary files have a separate [strict modern-subset parser](defender-detection-history.md).
- Verified on real Operational logs and support logs of two hosts: the per-ID
  record counts and the blocked-line counts equal an independent decode.

### ESE databases (`internal/ese`)

A reader for Extensible Storage Engine databases (`.edb`, `.dat`, `.dit`): the
Windows Search index, SRUM, WebCache, the Active Directory database, BITS on
Windows 10. It reads only. It never writes, repairs or replays a log.

What it reads: format version 0x620; 2, 4, 8, 16 and 32 KiB pages; the catalog
(with its shadow copy used when the primary is unreadable); B+trees including
shared key prefixes; fixed, variable and tagged columns; multi-values; long
values stored in the long value tree, reassembled from their segments; 7-bit
and XPRESS column compression; text by code page (UTF-16 or single byte); JET
date-times and FILETIMEs; and tables derived from a template table.

What it reports rather than hides:

- A record the engine has marked deleted but not yet reclaimed is returned with
  `Defunct` set and counted apart from live records. Those records are evidence
  of rows that existed; they are not live rows, and a parser chooses which it
  wants.
- An entry that cannot be taken apart (a record shorter than its own header, a
  key whose shared prefix is missing) is counted as unreadable and not returned.
  The engine leaves small stubs of deleted records behind; those are counted
  separately from stubs of live ones.
- The database state from the header (clean or dirty shutdown) and whether the
  header's own checksum holds. A dirty database was copied while in use; its
  newest changes are still in the transaction log (`.log`), which is not read.
- A value that cannot be decoded (a long value whose segments do not add up to
  its stated size, a compressed value that is not valid) fails that one value
  and leaves the rest of the row.

What it does not do:

- XPRESS9 and XPRESS10 column compression is refused with that reason. Encrypted
  columns are not decrypted. Secondary indexes are not used: tables are read in
  primary key order.
- Page checksums are not verified, so a page damaged in place is read as it is.
  The structure checks (bounds, loops, sizes) are what stand between a damaged
  page and wrong output; they refuse, they do not repair.
- The earlier format versions, and streaming (`.stm`) files, are refused.
- It does not replay the transaction log, so a dirty database is read as the
  database file holds it.

Validation. The reader was compared with two independent implementations,
`libesedb` (through `pyesedb`) and `dissect.esedb`, on four databases of a real
Windows 10 collection: `SRUDB.dat`, `WebCacheV01.dat`, `CacheStorage.edb` and
`IndexedDB.edb` (75 tables, 6,078 readable records of which 6,000 are live).
For every table the number of live records equals libesedb's; the bytes of every
fixed and variable column of every readable record equal dissect's; and the
decoded value of every tagged column outside the engine's own system tables
equals dissect's (text with its terminating NULs removed). The test is
`TestRealDatabases`, gated on `TRACEFALL_REAL_ESE_DIR`, with each file pinned by
SHA-256 and a SHA-256 of the expected content per table taken from the other
readers.

Where the references disagree: libesedb returns 8 bytes for 34 long binary cells
(33 in WebCache, 1 in IndexedDB) where dissect and this reader return the whole
value (the first, 8,082 bytes). libesedb also fills a null fixed column with
`0x2a` bytes where the other two report null. This reader follows dissect in
both; neither point was adjudicated further.

What the real samples do not exercise: that collection has no compressed column,
no multi-valued column and no two-value column. Those paths are tested on
databases built by `internal/ese/esegen` from the documented format, and the
XPRESS vectors were produced by an independent encoder and decoded back by
dissect before being used. A compressed or multi-valued column in a real
database is therefore less proven than the rest. Windows Search (`Windows.edb`)
uses both heavily.

### System Resource Usage Monitor (`srum@1`)

Reads `SRUDB.dat`. About once an hour Windows writes what each application and
service used since the last write. A row shows that an application was running
and what it used in the interval ending at the row's time; it does not show what
the application did, and the interval is not the moment of any action.

Four tables are interpreted, by the provider GUIDs that name them:

| Table | Event | Fields |
|---|---|---|
| `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` | `srum_app_usage` | CPU cycles, foreground time, context switches, bytes and operations read and written, foreground and background |
| `{973F5D5C-1D90-4944-BE8E-24B94231A174}` | `srum_network_usage` | bytes sent and received, interface (type, LUID), L2 profile |
| `{DD6636C4-8929-4683-974E-22C046A43763}` | `srum_network_connection` | connect start (FILETIME), seconds connected, interface, L2 profile |
| `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}` | `srum_push_notification` | notification type, payload size, network type |

Applications and users appear in the rows as numbers. `SruDbIdMapTable` names
them: a path, a service, a package or a SID. A number the map does not hold, or
holds with an empty value, is shown as a number with `app_resolved: false` and is
never given a name. A path of the form `!!name!time!n` is a program SRUM could
not tie to a file; only the name is taken from it and the text is kept as
written. A user is a SID only when its map entry is of the SID type and the bytes
form a well-formed SID.

The timestamp is the JET date-time in the record (UTC). A value outside
1995..2100 is not used: the event is undated and the stored bytes are kept in
`timestamp_raw`.

Limitations:

- The other tables are counted and named in the parse notes, not interpreted. In
  the validation sample these are the two timeline tables (`{5C8CF1C7-7257-4F13-B223-970EF5939312}`,
  1,484 records, and `{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}`, 42) and the energy
  tables, which were empty.
- Deleted records still in the file are not emitted; their number is in the notes.
- The SRU log files are not read. A database copied from a running system can
  lack its newest records, and the notes and every event say when the database
  was not cleanly shut down.
- Application names are as SRUM stored them (NT device paths such as
  `\device\harddiskvolume3\...`); they are not mapped to drive letters.
- Network profile ids are not resolved to network names.

Validation. On the `SRUDB.dat` of a real Windows 10 collection (SHA-256 pinned in
`TestParse_RealSRUDB`, set `TRACEFALL_REAL_SRUDB`), the parser emitted 780 events
(657 application, 114 network usage, 4 connectivity, 5 push). Counts, distinct
applications and users, resolved and unresolved ids, the time range
(2023-07-12T06:19:00Z to 2023-07-14T10:37:00Z) and the sums of cycles, foreground
time, bytes sent (5,801,645,464) and received (1,125,681,198), push payload and
connected seconds all equal a separate pass with dissect and Python. In the same
file 1,526 records in two uninterpreted tables and 23 deleted records were
counted in the notes. There is no rule over SRUM yet; the sample came from an
ordinary system and holds no case a rule could be checked against.

### IE / Edge Legacy WebCache (`webcache@1`)

Reads `WebCacheV01.dat` (and `WebCacheV24.dat`), an ESE database. `Containers`
names the containers and each has a table `Container_<id>`.

| Container | Event | What a record is |
|---|---|---|
| `History`, `MSHist<period>` | `browser_visit` | one URL with its last access time and an access count |
| `Content` | `browser_cache_entry` | one cache entry: URL, file name, size, times, HTTP status line and content type |

A history record is **not** one visit: a URL visited five times is one record
with `access_count: 5` and the time of the last access. The event time is that
`AccessedTime`. `record_kind` says what the record is: `url`, or `daily_host` for
the daily history's host summaries (`:Host: example.com`), whose text is the
host and not a URL. The user is the name before the `@` in the record, or for
cache entries the profile in the container's directory.

The history `ModifiedTime` is not used as a time. In the validation sample it
differs from the access time by exactly three hours, which is a local-time
reading, so it is kept as stored in `modified_time_raw`. For cache entries
`ModifiedTime` is kept as `modified_time`.

Not read:

- **Cookie containers**, by design, as for every browser in Tracefall. The
  number of cookie records is in the parse notes.
- Every other container (DOM storage, background transfer, ...) is counted and
  named in the notes ("container DOMStore (id 4): 1 records not interpreted").
- Request headers, and response headers beyond the status line and content type:
  they can carry cookies and tokens. The raw record kept with an event omits them.
- Deleted records still in the file are not emitted; their number is noted.
- A cache entry shows that a copy was held. It does not show that the user chose
  to load it, and the cached body is not read.

A WebCache without a `Containers` table (the system profile's in the sample) is
valid and yields no events, with a note saying so. A `WebCacheV01.dat` that is
not an ESE database, and the old `index.dat`, are not read.

Validation. On the `WebCacheV01.dat` of a real Windows 10 collection (SHA-256
pinned in `TestParse_RealWebCache`, set `TRACEFALL_REAL_WEBCACHE`) the parser
emitted 79 events: 62 URL records, 2 daily-host records and 15 cache entries.
Per container the record count, access-count total, file-size total and the
first and last access time (to the microsecond), the 9 distinct hosts, the one
user, the status lines and content types of the 13 cached responses that carry
HTTP headers all equal a separate pass with dissect and Python. The other 6
records (DOM storage and background transfer) are in the notes. That database
was copied after a dirty shutdown, and the notes say so; changes still in its
transaction log are not in it. No rule reads these events beyond the existing
browser ones.

### WMI repository configuration (`wmirepository@1`)

`OBJECTS.DATA` is the single entry point for a Win7+ repository bundle. Import
admits `INDEX.BTR` and present `MAPPING1.MAP` / `MAPPING2.MAP` / `MAPPING3.MAP`
from source-catalog rows in the exact same collection and evidence-relative
parent directory. Original member names select roles; explicit stored paths
are transported into the isolated Go parser worker, so renamed storage does
not become a sibling-file guess. Each member retains its own source ID and
SHA-256 in authorized raw provenance. Missing, ambiguous, unsafe, incoherent
or unsupported bundles fail explicitly and atomically, not as successful zero
observations. Mapping/index companions are not independently parsed objects.
Linux reads and bundle extraction resolve the operator-admitted root boundary
(including a symlinked data-directory prefix), then reopen its resolved path and
all evidence-relative components with `O_NOFOLLOW`. Links beneath that boundary
are never followed. Filesystem admission on other platforms currently fails
closed. Directory discovery retains nonregular/link entries as explicit
unsupported inventory rows without reading, sniffing or hashing their targets.

The reader enumerates active indexed namespace hash IDs, not guessed namespace
names, for `__EventFilter`, `__FilterToConsumerBinding`,
`CommandLineEventConsumer`, `ActiveScriptEventConsumer`,
`NTEventLogEventConsumer`, `LogFileEventConsumer` and `SMTPEventConsumer`.
Namespace literals are not resolved in this version. Only validated dense,
packed inherited layouts and supported scalar/array CIM values are decoded;
unknown types/layouts and dynamic instances are explicit failures. Deleted
object carving, XP/core instances and arbitrary classes are not implemented.
Counts, tree cycles/depth, record extents and values have bounded guards.
The full snapshot additionally permits at most 4,096 schema-record reads and
32 MiB of schema-record bytes across all namespace/class layouts, including
repeated inheritance reads. Exceeding either guard is an explicit unsupported
source, not a partial success. No recognized namespace or no selected schema
also fails explicitly; a recognized selected schema with no indexed instances
may report a measured zero.

Every object yields an undated `wmi_configuration_snapshot`. Repository
FILETIME ticks are retained as raw metadata, never invented firing or process
execution times. Presence distinguishes explicit, supplying-class default and
uninitialized properties, with exact native identities, raw slots and physical
state/slot/value/default spans. Bundle file hashes permit re-verification.

Default events, reports and local LLM previews contain structural class/hash
identities and fixed caveats, not arbitrary property names, queries, commands,
scripts, SIDs, hosts or key values. Explicit authorized raw provenance retains
native properties and bytes. Quoted-string local, escaped, namespace-qualified
and multi-key references have tested exact-literal resolution. The grammar also
parses absolute-host forms, but production lacks recorded host identity for
those references: even `\\.\` stays visibly unresolved rather than guessing a
host. String key values currently require exact case; case variants can remain
unresolved. Unsupported, missing or ambiguous endpoints remain visible. Persisted
`wmi_configuration_context` correlations recheck case, collection, host,
repository and exact native class targets. They are navigable same-producer
configuration associations, never execution edges or independent corroboration,
and do not merge or score investigations. Configuration alone produces no
malicious verdict, actor or authorization claim.

Event dedup includes native object, complete repository content state and object
record digest; identical recollection adds observations while changed bundle
state remains distinct. Unlike a standalone artifact, equal `OBJECTS.DATA`
bytes alone cannot establish a duplicate: different index/map state is retained.
Source hashes remain literal per-file hashes, never relabeled bundle digests.
Existing cases require a fresh import to acquire these new observations.

### Not read yet

- **BITS** (`qmgr.db` and `qmgr*.dat`). The Windows 10 database is an ESE file and
  the ESE reader opens it, but there was no real `qmgr.db` to validate an
  interpretation of its tables against, so none was written.
- **Windows Firewall log** (`pfirewall.log`). No real sample was available.

### Package log (`packagelog@1`)

Parses `dpkg.log` and its numbered plain rotations. One `package_change` event
for each `install`, `upgrade`, `remove` and `purge` line, with `package`,
`architecture` (when the name carries one), `version_before`, `version_after`
and `action`. The `status`, `configure`, `trigproc` and `startup` lines are the
steps of a transaction and are not emitted.

dpkg writes local time and does not record the zone. The zone is not assumed,
so the event's `Timestamp` stays zero and the date is kept as written in
`Extra["timestamp_local"]`. The date has a year, so it can be compared with
dated artifacts once the host's zone is established. The event proves the
package database changed. It does not show that anything in the package ran, or
who asked. `apt/history.log` and `apt/term.log` are not parsed.

### Network capture (`netcapture@1`)

Reads classic pcap (both byte orders, microsecond and nanosecond) and pcapng,
by extension (`.pcap`, `.pcapng`, `.cap`) confirmed by the magic number, and
also under any name by magic number. Link types: Ethernet, Linux cooked v1 and
v2, raw IP, BSD loopback. Others are counted in `capture_summary`. The file is
read as a stream; every table has a limit and a limit that was reached is
written into `capture_summary.limits_reached`.

Events:

- `network_connection`: one per conversation (client, server, server port,
  protocol) with packets and bytes each way. `application` (`rdp`, `http`,
  `tls`, `dns`, `ntp`) is set only when the bytes parsed as that protocol. A
  port number alone appears as `service_hint` and proves nothing. A second
  event per Remote Desktop connection of at least 20 packets, with its client
  port (`session=true`), which is what a Windows logon event naming the same
  port refers to. The Remote Desktop cookie is the user name the client sent,
  not an authenticated identity.
- `dns_query`: DNS, mDNS and LLMNR lookups with answers. A response with no
  query in the capture is marked `query_in_capture=false`.
- `web_request`: one per HTTP transaction with method, URI, host, status,
  user agent, and for a response seen whole, `response_sha256`, `response_size`
  and `file_signature` (by magic number, not extension). A body is never
  stored. A body that was not seen whole has no hash (`reassembly=incomplete`).
  A 206 response is a byte range, marked `partial_content`, and its hash will
  not match the object's.
- `clock_observation`: an NTP packet or an HTTP `Date` header with the capture
  time of the packet that carried it. Input to the clock-offset model.
- `capture_summary`: span, counts, undecodable packets, limits reached.

**Time.** Every timestamp is the clock of the machine that captured. It is not
the clock of any host in the capture and nothing here corrects it. A TCP
four-tuple reused by a new connection (a SYN with a different sequence number)
is a new connection.

**Not shown.** Encrypted payloads (TLS, the inside of a Remote Desktop
session). What a host did with bytes that reached it. A capture shows only
what crossed the interface it was taken on.

## Static payload inspection (`internal/payload`)

Used to name what an HTTP object is. Magic number, SHA-256 and, for PE files,
sections with entropy, imports, exports, signature directory and appended data,
and network, path, registry and command strings. Static only: nothing is
executed, no hash is looked up anywhere, and Authenticode is not verified. An
indicator is a property common in malware, never a verdict.


## SQL Server Audit and Extended Events

| Artifact | Status | Evidence limits |
|---|---|---|
| `.xel` | Optional configured offline external reader | Linux offline fixture verified; selected captured events only; no all-query/completeness claim |
| `.sqlaudit` | Experimental **NOT-VERIFIED**, default refused | Genuine audit fixture and independent field reference still required |
| `.sqlaudit.csv` | **PARTIAL** explicit `fn_get_audit_file` export | Different evidence form, not binary equivalence; original/export method required |
| `.xel.xml`, `.xel.jsonl` | **PARTIAL** explicit XE exports | Recorded fields only; export selection/truncation can omit evidence |

Native configuration, source-only helper, protocol, resource and licensing gates:
[optional offline XE reader](../tools/mssql-xe-reader/README.md). These artifact
names are recognized even when the runtime is absent: attempting native import
then fails visibly, never silently falls back to text or claims native support.

Audit CSV must have exact `event_time` and `action_id` columns; optional columns
use documented `sys.fn_get_audit_file` names (including `succeeded`, `session_id`,
`server_instance_name`, principals/SIDs, database/schema/object, `statement`,
client fields, `sequence_number`, `audit_file_offset`). Header names are not
guessed or mapped from arbitrary CSV. Audit `event_time` is documented UTC;
outer XE timestamp is retained separately. Zone-less XE export timestamps stay
undated/local. No filesystem time or examiner timezone is substituted.

XE XML accepts `<event name="..." timestamp="...">` records with named
`data/value` and `action/value` children, standalone or under `Events` /
`RingBufferTarget`. Declared `truncated="1"` or `"true"` is rejected rather than
reported as complete. JSONL has one object per record with `name`, `timestamp`,
`fields` and `actions` maps, using the same documented XE names and scalar values
(e.g. `session_id`, `client_pid`, `client_hostname`, `client_app_name`,
`client_connection_id`, `attach_activity_id`, `sql_text`). The export contract is
explicit, not arbitrary vendor JSON recognition. Raw XML records, CSV row bytes
and JSONL lines remain independently accessible; summary text does not copy SQL
statement/credential text. Unknown fields survive in raw and `sql_field_*`.

For non-login audit actions, `succeeded` means **permission_check_allowed/denied**,
not completed execution, transaction commit, query result, or OS effects.
Documented login actions LGIS/LGIF retain login semantics. Missing/invalid outcome
stays unknown. Packed integer action IDs retain raw value and a separately decoded
little-endian four-byte action code; audit buffer offsets are never XE event
byte offsets. Statements/additional-information sequence fragments remain
separate records with an incomplete/not-reconstructed note; no blind assembly.

SQL session IDs are **not Windows PIDs**. Remote client PID/hostname/IP/application
are client claims, never host attribution or the sqlservr PID. Normalization uses
`sql_instance`, `sql_session_id`, `sql_client_pid`, `sql_client_hostname`,
`sql_client_ip`, `sql_statement`, `sql_action`, `sql_outcome`,
`sql_outcome_basis`, `sql_client_connection_id`, `sql_activity_id`,
`sql_activity_sequence`, `sql_server_pid` only when recorded. Evidence form,
raw record hash and per-file ordinal/span prevent tied observations collapsing;
collection IDs and sandbox notes do not split genuine recollections. Old cases
need a fresh import; lost rows cannot be recovered by rehashing old events.

Export caps: 16 MiB input, 1 MiB record/line, 10,000 records. Native reader caps
are documented beside its source. Corrupt, capped, incomplete-protocol or missing
reader imports fail the source visibly, not “empty evidence.” Successful sources
carry persistent parser coverage caveats even with zero events, visible in source
details, provenance and reports. No events is not evidence of no activity:
Audit/XE selection, predicates, sampling, loss modes, queue/dispatch delay,
rollover/deletion and missing acquisitions constrain every conclusion.

References: [audit records](https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-records),
[fn_get_audit_file](https://learn.microsoft.com/en-us/sql/relational-databases/system-functions/sys-fn-get-audit-file-transact-sql),
[XE targets](https://learn.microsoft.com/en-us/sql/relational-databases/extended-events/targets-for-extended-events-in-sql-server),
[Read-SqlXEvent](https://learn.microsoft.com/en-us/powershell/module/sqlserver/read-sqlxevent).
