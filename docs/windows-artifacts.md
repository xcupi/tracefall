# Windows user and execution artifacts

What Tracefall reads out of each Windows artifact, and — the part that
matters more — **what each artifact actually proves**.

Windows user-activity artifacts are mostly circumstantial. They record
that the system *noticed* something, which is not the same as recording
that something *happened*, and a tool that flattens that difference will
help an examiner state more than their evidence supports. This page is
the reference for where each artifact sits on that scale.

See [forensic-search.md](forensic-search.md) for how these events are
searched, and [evidence-triage.md](evidence-triage.md) for how the
source files are classified.

## Evidentiary strength at a glance

Every artifact below is genuine evidence. They are not equally strong,
and the difference is not about parser quality — it is about what the
format itself records.

| Artifact | What it establishes | Strength as execution evidence |
| --- | --- | --- |
| **EVTX Security 4688** | The kernel created a process, with its command line and parent | **Direct.** The OS recorded the event as it happened |
| **EVTX Sysmon 1** | Same, from an independent source | **Direct** |
| **Prefetch** | Windows prefetched an executable, with run count and up to 8 run times | **Strong.** The OS records this as a consequence of execution |
| **UserAssist** | Explorer counted this item being launched *through the shell* | **Circumstantial, user-attributed.** Only shell launches |
| **LNK** | A shortcut exists and names a target | **Weak.** A shortcut can exist having never been used |
| **Jump List** | An application registered this target | **Weak-to-moderate.** Registration, not execution |
| **ShellBags** | Explorer recorded a folder in its namespace | **Not execution evidence at all.** Navigation |
| **PSReadLine history** | A command was accepted at a PowerShell prompt | **Moderate for the command, none for time.** No timestamps |
| **Amcache** | Windows catalogued a binary, with its path, SHA-1, size and publisher | **Not execution evidence.** Cataloguing happens on install and inventory too |
| **Windows Timeline** | The Activities provider logged an app or document as active | **Circumstantial.** Focus reporting, and rows can sync from another device |
| **RecentDocs** | Explorer listed a document as recently opened | **User-interaction evidence.** Not execution |
| **RunMRU** | A command was typed into the Run dialog and accepted | **Intent, user-attributed.** Not proof it ran |
| **OpenSavePidlMRU** | A file was chosen in an Open or Save dialog | **User-interaction evidence.** Not execution |
| **TypedPaths** | A path was typed into the Explorer address bar | **Weak.** What was typed, not what was opened |
| **MUICache** | The shell cached an application's display name | **Presence only.** Enumerating a folder is enough to create one |
| **Browser download** | The browser retrieved a resource to a local path | **Arrival, not use.** Downloaded ≠ opened ≠ executed |
| **Browser history** | The browser recorded a navigation | **Circumstantial.** Redirects and prefetch are recorded too |
| **Browser cache** | A response was stored by the browser | **Weakest of the web artifacts.** Presence in cache, not viewing |
| **Windows SAM** | A local account exists, with its RID, flags, timestamps and stored NTLM hash | **Not execution evidence and not activity.** An account record: identity and credential evidence |
| **Registry transaction log** | A hive's `.LOG1`/`.LOG2` companion was collected | **Recognized, not parsed.** Records collection completeness, nothing more |
| **Browser database (not parsed)** | A browser profile holds this database — cookies, logins, favicons, autofill | **Recognized, not parsed.** Presence only; no value is read from it |
| **FileZilla server entry** | An FTP client held this host, port, protocol and username | **Configuration, not activity, and no time at all.** `recentservers.xml` says a connection was *attempted* from this profile; the Site Manager says only that a site was saved |
| **Image metadata (EXIF)** | The file contains these values | **File content, not an event.** Written by a camera *or* by any editor downstream |
| **Image location (EXIF GPS)** | The file records this coordinate | **File content.** The image was *carrying* a position, which is not the same as anyone having been there |

The rule the codebase follows: an event's **type**, its
**`evidence_meaning`** and its **`timestamp_meaning`** must each be true
of the artifact alone, without assuming corroboration.

---

## UserAssist

**Source.** `NTUSER.DAT`, under
`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`.
Read by `internal/userassist`, driven from `internal/parsers/registry`.

**Supported versions.** Two record layouts, distinguished by length —
there is no version field in the record:

| Bytes | Era |
| --- | --- |
| 16 | Windows 2000 / XP / 2003 ("version 3") |
| 72 | Windows Vista / 7 / 8 / 10 / 11 ("version 5") |

Any other length is reported as `ErrUnknownLayout` — an *unsupported
structure*, deliberately distinct from corruption.

**Detection.** Content-based. The hive is identified by its REGF
signature, and the UserAssist key is matched on its full **shape**
(`…\UserAssist\{GUID}\Count`, with a real braced GUID), not on the
substring "UserAssist" appearing somewhere in a path. A key that merely
resembles one is not decoded.

**Fields extracted.** Stored (ROT13) value name and its decoded form,
resolved known-folder path where the prefix is documented, subkey GUID
and its meaning, record version, session id, run count (raw and
interpreted), focus count and focus time (version 5), last-execution
FILETIME, record size.

**Timestamp semantics.** The event time is the record's last-execution
FILETIME, in UTC, meaning *"when Explorer last updated this entry"*. A
zero or implausible FILETIME yields **no timestamp at all** — the event
still carries its run count, and `timestamp_basis` says why there is no
time. Neither the key's last-write time nor the file's mtime is ever
substituted.

**Forensic interpretation.** `EventUserAssistActivity` —
*"UserAssist recorded activity"*. It is **not** a process-creation
record. `ProcessName` and `CommandLine` are deliberately left empty; the
launched item goes in `FilePath`.

**Limitations and false negatives.** Only shell-initiated launches are
counted — a program run from a script, a service, a scheduled task or a
command prompt leaves **no entry**, so absence proves nothing. The
counter is a tally Explorer maintains, not a log: it can be reset, and
an entry outlives the program it names.

**False positives.** Low. The risk is not spurious entries but
*over-reading* real ones as execution at a precise moment.

**Version 3 run counts.** The XP-era counter starts at 5. `run_count` is
the interpreted number of launches; `run_count_raw` is exactly what the
record holds. Both are reported, because the adjustment is a documented
convention rather than something the record states. A counter below 5
cannot be a launch tally and is reported unadjusted with a warning
rather than being wrapped by subtraction.

**Unknown GUIDs.** Left unnamed, exactly as Jump List AppIDs are.
`userassist_guid_meaning` says so explicitly rather than being blank.

**Produces events:** yes. **Directly supports findings:** no rule added —
see [Findings](#findings) below.

---

## ShellBags

**Source.** The `BagMRU` tree in `NTUSER.DAT`
(`Software\Microsoft\Windows\Shell\BagMRU`, and the `ShellNoRoam`
variant) and in `UsrClass.dat`
(`Local Settings\Software\Microsoft\Windows\Shell\BagMRU`). Read by
`internal/shellbag`.

**Supported structures.** Root/known-folder items (`0x1F`), volume items
(`0x2F`), file and directory entries (`0x30`–`0x3F`), network locations
(`0x40`–`0x4F`), URI items (`0x60`–`0x6F`), and the `0xBEEF0004`
extension block that carries the long name and the created/accessed
readings. Extension block versions 3 and 7–9 are handled.

A well-formed item of an undecoded type is reported as
`shell_item_kind: unknown` **with its raw type byte** — a coverage gap,
explicitly distinguished from corruption. Extension blocks with any
other signature are skipped by their own length rather than guessed at.

**Long-name location.** Located *structurally*, not from a
version-to-offset table: the published offset tables for later block
versions disagree with one another, and an offset wrong by two bytes
does not fail loudly — it yields a plausible but **wrong** filename. The
reader instead scans two-byte-aligned positions after the fixed header
for the first NUL-terminated UTF-16 string that terminates near the
block's end and contains no control characters. When nothing qualifies,
the item keeps its short name and says so.

**Fields extracted.** Reconstructed path (assembled across tree levels),
item kind, raw type byte, long and short names, CLSID and its documented
meaning, file size, file attributes (raw and decoded), `$MFT` file
reference (version 7+), the item's byte offset and size, and the tree
depth.

**Timestamp semantics — the subtlest part of this artifact.** Two
unrelated kinds of time appear, and Tracefall keeps them apart:

1. **The BagMRU key's last-write time.** A real FILETIME in UTC. This
   *is* the event's timestamp, and it means "Explorer last updated this
   node of the tree".
2. **The shell item's own DOS date fields** (modified, created,
   accessed). FAT-style: two-second granularity, written in the **local
   time of the machine**, with **no timezone stored anywhere**.

The DOS fields are therefore returned as **wall-clock readings**, in a
type that cannot be confused with an instant, and are exposed as
`shell_item_modified_local` and friends alongside a note saying exactly
that. They are never used as the event's timestamp: converting them
would require a timezone the artifact does not record.

**Forensic interpretation.** `EventShellBagNavigation` — *"Explorer
recorded this shell location"*. It is **not** evidence that a file was
opened, and **not** evidence that anything was executed. `ProcessName`
and `CommandLine` are left empty.

**Limitations.** A reconstructed path can be partial where an ancestor
item did not decode; confidence is 0.9 for this reason. Bags survive the
deletion of the folders they describe, which is a strength for the
investigator and a reason never to read one as "this folder exists now".

**Produces events:** yes. **Directly supports findings:** no.

---

### Reconstructing the hierarchy

A ShellBags entry means little on its own. What it establishes is **where
a folder sat**, and that is a statement about its ancestors — so the
chain is what carries the evidence, and every level of it has to survive.

Three decoding gaps used to break that chain, all found against a real
Windows 10 `UsrClass.dat`:

- **Folder GUIDs were not read.** "This PC\Pictures", "Downloads" and
  "Documents" are recorded as delegate items (type `0x2E`) carrying a
  folder GUID and no name. They decoded to an empty name, and an empty
  level was then **dropped from the path entirely** — so
  `This PC\Pictures\Contact` was reported as `This PC\Contact`, which
  asserts a parent-child relationship the registry does not record. An
  incomplete path is a limitation; a collapsed one is wrong.
- **Portable-device folders were not read.** A phone attached over MTP
  records its contents as property-store items (type `0x00`) with no
  documented name field, so an entire device subtree decoded to nothing.
- **Long names were located by scanning**, which prepended two junk
  characters to 25 of 35 real folder names — `usr` read as `ᑱÆusr`,
  `System32` as `迍)System32`.

#### What each level's name is worth

| Source | Meaning |
| --- | --- |
| `decoded from the item's documented name field` | Read from a documented offset. The strongest claim. |
| `recovered structurally` | The item has no documented name field. The name is the first string the item's own **length table validates**, and every validated string is preserved alongside it (`shell_item_recovered_strings`) so the reading can be checked. |
| the GUID itself | A folder GUID with no documented name. Reported AS the GUID, never guessed. |
| `(undecoded)` | The level exists and its name could not be read. It stays in the path as a placeholder. |

`path_complete` says which of these a path contains, and
`path_limitation` states what is still known when it does not: the level
**order** comes from the registry hierarchy and remains evidence even
where a name does not.

Every event also carries `parent_name`, `parent_path`, `shellbag_node`
and `parent_registry_key`, so a source folder can be read off the
evidence rather than inferred from a leaf. The relationship is recorded
by the registry, not derived — `parent_relationship` says so explicitly.

None of this changes what ShellBags MEAN: Explorer recorded a folder.
Not that a file was opened, not that anything ran.

---

## PowerShell history (PSReadLine)

**Source.** `ConsoleHost_history.txt`, written by the PSReadLine module.
Read by `internal/parsers/pshistory`. **Unchanged in this phase** — it
was already correct, and the phase's rules describe what it already
does.

**Timestamp semantics.** PSReadLine records **no timestamps** — not per
command, not per session. Events therefore carry a **zero timestamp**
and say so. The file's own modification time is deliberately not used:
that is when the file was last written or collected, not when any
command ran.

**Forensic interpretation.** `EventPowerShellHistoryCommand` — a command
was *entered and accepted at a prompt*. PSReadLine writes the line when
it is accepted, so it records neither that the command succeeded nor,
strictly, that it ran to completion.

**Produces events:** yes. **Directly supports findings:** existing rules
may cite these events; none was added in this phase.

---

## Windows Event Logs (EVTX)

**Source.** Raw `.evtx` binary logs, read natively by `internal/evtx`,
and EvtxECmd CSV exports. Both normalize through the single shared table
in `internal/parsers/winevent`, so the same real-world record produces
identical fields whichever way it was collected — which is what keeps
deduplication and every detection rule consistent across sources.

**Event IDs normalized.** Security 4624, 4625, **4634**, **4647**, 4648,
4672, 4688, 4768, 4769, 4776; PowerShell 4103 and 4104; System 7045
(Service Control Manager); Sysmon 1, 3, 11, 12/13 and 22.

**4634 and 4647 are new in this phase.** Both map to `EventLogoff` and
close a session that 4624 opened — without them, "who was at this
machine, and for how long" is open-ended. They stay distinguishable via
`logoff_kind`: 4647 records the user *asking* to log off; 4634 records
the session *ending*, which can happen without the user's involvement.
`logon_id` is carried on both so a session can be bounded against its
4624.

**Defensive parsing.** The reader validates the file signature, chunk
structure, record structure and bounds. A malformed record does not
reject the file: valid records are kept and the bad one is reported. The
container itself being invalid is a different answer from a record being
unreadable.

**Forensic interpretation.** 4688 and Sysmon 1 are **direct execution
evidence** — the OS recorded the process being created, with its command
line and parent. This is the strongest execution evidence in this
document, and the reason a UserAssist entry must not be dressed up to
look like one.

**Produces events:** yes. **Directly supports findings:** yes — the
existing detection rules are built on these.

---

## Prefetch

**Source.** `.pf` files. Read by `internal/prefetch` /
`internal/parsers/prefetchraw`. **Unchanged in this phase.**

**Supported versions.** SCCA 17, 23, 26, 30 and 31, in both the plain and
the **MAM-compressed** container. LZXPRESS Huffman decompression is
implemented natively (`internal/lzxpress`, no external dependency), so
Windows 10/11 Prefetch is read from the original evidence rather than
being reported as unsupported. A MAM container declaring some other
compression method is reported as an unsupported *compression method* —
not as a corrupt file.

**Fields extracted.** Executable name, prefetch hash, run count, up to
eight last-run times, referenced filenames, and volume device path,
serial and creation time.

**Forensic interpretation.** Windows prefetched the executable. Strong
execution evidence, though the run count and the retained run times are
a rolling window rather than a complete history.

**Produces events:** yes. **Directly supports findings:** yes.

---

## LNK shortcuts

**Source.** Shell links, read by `internal/shelllink`. **Unchanged in
this phase** — audited and found correct.

**Detection.** Content-based: `HeaderSize == 0x4C` and the shell link
CLSID. Never the `.lnk` extension.

**Fields extracted.** Target path, the three target timestamps, target
size and attributes, volume serial and label, drive type, arguments,
working directory, icon location, and tracker machine id.

**Forensic interpretation.** A shortcut *contains target metadata*. Its
existence is **not** evidence the target was executed, and the parser's
event types (`lnk_target_created` / `_modified` / `_accessed`) name the
target's own timestamps rather than any action on the shortcut. Embedded
targets and command lines are data only: nothing is resolved through the
Windows shell and nothing is executed.

**Produces events:** yes. **Directly supports findings:** no rule keys
on LNK alone.

---

## Jump Lists

**Source.** `*.automaticDestinations-ms` (an OLE compound file holding
numbered LNK streams plus a `DestList`) and `*.customDestinations-ms`.
Read by `internal/jumplist` on top of `internal/olecf`, reusing the LNK
parser for embedded shell links. **Unchanged in this phase** — audited
and found correct.

**Analyst-visible fields.** Application identity (AppID and, where
documented, its meaning), the destination target, per-entry access
timestamps from the DestList, entry access counts, the source file and
full provenance. Individual entries are separate events, so an analyst
can inspect them one by one.

**Forensic interpretation.** An application *registered* this target. A
Jump List entry is **not** proof the file was opened at a moment in
time. Unknown AppIDs are left unresolved rather than guessed.

**Produces events:** yes. **Directly supports findings:** no.

---

## Amcache

**Source.** `Amcache.hve`, under `Root\InventoryApplicationFile`,
`Root\InventoryApplication` and (older builds) `Root\File`. Read by
`internal/amcache`, driven from `internal/parsers/registry`.

**Why it lives in the registry parser.** `Amcache.hve` is a REGF hive,
so the hive parser claims it by content detection. Before Phase 16 that
meant it was classified **supported** and produced **nothing** — the
worst combination for an analyst. A separate parser could not have
reached it; discovery assigns one parser per file.

**Supported layouts.**

| Tree | Era | Value names |
| --- | --- | --- |
| `Root\InventoryApplicationFile` | Windows 10 / 11 | Named (`LowerCaseLongPath`, `FileId`, `Publisher`) |
| `Root\InventoryApplication` | Windows 10 / 11 | Named — describes an installed *program*, not one binary |
| `Root\File\{VolumeGUID}\{FileID}` | Windows 8 / 8.1 | **Numbered** (`0`, `1`, `15`, `101`…) |

**Fields extracted.** Application name and full path, SHA-1, file size,
publisher, product name, version, ProgramId, PE link date, install date,
inventory source, volume GUID.

The Windows 8 numbered values are decoded only where their meaning is
settled (`0` product, `1` company, `6` size, `c` description, `15` path,
`100` ProgramId, `101` SHA-1). **Every other number is preserved under
its own name** rather than given a label the code cannot justify.

**SHA-1 handling.** Windows stores it as `"0000"` plus the 40-character
digest. The padding is stripped **only** when the remainder is exactly
40 hex characters; anything else is preserved raw, flagged with a
warning, and never reported as a hash.

**Timestamp semantics.** The event time is the **registry key's
last-write time**. It is *not* an execution time — older guidance that
treated it as one was mistaken, and `timestamp_meaning` says so on every
event. `LinkDate` is the PE header's compile time: it describes the
binary, not this machine, and is trivially forgeable.

**Forensic meaning.** Windows catalogues a binary on **installation,
during inventory scans, and on execution alike**. An entry is
application-presence evidence with unusually strong identifying metadata
— a path and a SHA-1 that survive deletion of the binary. It is not a
process-creation record.

**Limitations.** The event that caused an entry is not recorded, so the
entry cannot be attributed to execution, installation or a scan.
Amcache is machine-wide: it carries no user attribution.

**Events / findings.** Produces `amcache_application` events. Supports
no finding rule on its own.

---

## Windows Timeline (ActivitiesCache)

**Source.** `ActivitiesCache.db`, a SQLite database under
`ConnectedDevicesPlatform`. Read by `internal/parsers/activitiescache`.

**Detection.** The SQLite signature, then a **schema check**: the
database must carry an `Activity` (or `SmartLookup_Activity` /
`ActivityOperation`) table. A SQLite file merely *named*
`ActivitiesCache.db` is reported as **not this artifact** — distinct
from "this artifact is broken".

**Fields extracted.** Activity id, application identity (from the
`AppId` JSON array, keeping the win32 path and the package AUMID
separately), activity type, display text, description, content URI,
activation URI, start/end times, last-modified times, platform device id.

**Timestamp semantics.** The event time is the activity's **start
time**. Where none is recorded it falls back to `LastModifiedTime`,
*saying which was used*; where neither exists the event carries no
timestamp and `timestamp_basis` explains why. The file's mtime is never
substituted.

**ActivityType.** Microsoft never documented this column. Only the
values independent research agrees on are named (2, 3, 5, 6, 10, 11, 12,
15, 16); anything else is reported as its **raw number**.

**Forensic meaning.** The Activities provider logged an application or
document as active. It is a shell component reporting focus, several
layers above the kernel event that creates a process — so an activity
row is not a process-creation record. Rows can also arrive by
**synchronization from another device** on the same account, which is
why `platform_device_id` is preserved and `device_note` states that an
activity need not have happened on this machine.

**Limitations.** No process id, no command line, no parent. A malformed
JSON payload is flagged and the row kept, not discarded.

**Events / findings.** Produces `activity_recorded` events. No finding
rule.

---

## Explorer MRU artifacts

Five per-user structures Explorer maintains, all read from a hive the
registry parser already claims, and all sharing one awkward property
that every event states explicitly:

> **The key's last-write time dates the KEY, and a key holds many
> entries — so it dates only the most recent one.** An older entry in
> the same key was added at some earlier, unrecorded time.

| Artifact | Key | What it records |
| --- | --- | --- |
| **RecentDocs** | `…\Explorer\RecentDocs` (and `.ext` subkeys) | Documents opened through the shell |
| **RunMRU** | `…\Explorer\RunMRU` | Commands typed into the Run dialog |
| **TypedPaths** | `…\Explorer\TypedPaths` | Paths typed into the address bar |
| **OpenSavePidlMRU** | `…\Explorer\ComDlg32\OpenSavePidlMRU` | Files chosen in Open/Save dialogs |
| **MUICache** | `…\Shell\MuiCache` (UsrClass or NTUSER) | Application display names the shell cached |

**MRU ordering.** `MRUListEx` (little-endian int32 indices, `0xFFFFFFFF`
terminated) and the older `MRUList` (letters) are both decoded, and each
event reports its `mru_position` — 0 being most recent.

**Shell items are decoded once.** OpenSavePidlMRU and the shell-item
tail of a RecentDocs value both use `internal/shellbag`, the same
decoder ShellBags uses. There is no second shell-item implementation.

**Field placement.** RunMRU puts the typed text in `CommandLine` —
honest, it *is* a command line the user typed — and leaves
`ProcessName` **empty**, because no process is recorded. None of the
other four sets either field.

**Forensic meaning, per artifact.**

- **RecentDocs** — the document was opened through the shell. Not a
  process-creation record, and the document need not still exist.
- **RunMRU** — the command was *typed and accepted*. Not evidence it
  executed successfully.
- **TypedPaths** — what was *typed*. Not that the path was opened, not
  that it existed, certainly not that anything was executed.
- **OpenSavePidlMRU** — a file was *chosen in a dialog*. For a Save
  dialog it need not have existed beforehand.
- **MUICache** — the shell caches a display name when it merely
  *enumerates* an executable; browsing a folder is enough. Presence
  evidence only.

**Events / findings.** `recent_document`, `run_mru_command`,
`typed_path`, `opensave_mru`, `muicache_entry`. No finding rules.

---

## Prefetch: what MAM is, and is not

A Prefetch file may be stored plain (SCCA signature at offset 4) or
wrapped in a **MAM** container. Tracefall reads both, including the
variant whose format byte sets the CRC flag and therefore has a 12-byte
header rather than 8. Getting that header length wrong feeds four bytes
of CRC to the decompressor as though they were compressed data, which
fails looking like a corrupt stream rather than a misread header — seven
files in one real image, each decoding correctly to *exactly* its
declared byte count once the header was read properly.

**MAM is not a Prefetch format.** It is a general Windows compression
container, and the application-compatibility databases that live in the
very same directory — `AgGlGlobalHistory.db`, `AgCx_SC4.db`,
`ResPriHMStaticDb.ebd` and their siblings — use it too. Classifying a
file as Prefetch because it carries the MAM tag catalogued seven of those
as Prefetch and then reported an unsupported compression method for files
that were never Prefetch. Content detection therefore requires the SCCA
signature; a compressed Prefetch file is recognized by its `.pf` name,
confirmed against the container tag, and what is inside is checked after
decompression — the only place it can be.

Four outcomes, kept distinct:

| Outcome | State |
| --- | --- |
| Valid Prefetch, parsed | events emitted |
| Valid Prefetch, container compression not implemented | `unsupported_compression` — the artifact is present |
| Not a Prefetch file | `misclassified` — the file is intact |
| Malformed or truncated Prefetch | `corrupt_or_truncated` |

---

## Windows SAM

`%SystemRoot%\System32\config\SAM` is the machine's **local account
database**. Tracefall reads the accounts out of it: the name, the RID,
the account-control flags, the stored logon and password timestamps, and
— when the SYSTEM hive was collected alongside it — the account's stored
**NTLM password hash**.

### What Tracefall does and does not do

**It does** decode the account records and the stored hash.

**It does not crack passwords.** There is no wordlist, no brute force,
no GPU anything, and no integration with Hashcat, John the Ripper or any
comparable tool. The hash is the evidence and the hash is where it stops.

**An NTLM hash is not a password.** It is a one-way function of one, and
it is not reversible. Two things follow that matter in a report:

- Writing "the user's password was `ecf5…`" is wrong. The password is
  unknown. What is known is the hash of it.
- The hash is still *useful* evidence — it identifies an account's
  credential, it can be compared against a hash seen elsewhere, and a
  change to it is a password change — without anyone ever learning the
  password.

**A SAM hash is not, by itself, suspicious.** Every Windows machine has
these records. Tracefall therefore raises **no finding** for their
existence; see [Findings](#findings).

### Why the SYSTEM hive is required for the hash

The SAM does not contain the key its hashes are wrapped under.

A stored NT hash is wrapped twice: once under a key derived from the
account's RID, and once under the domain **Password Encryption Key**,
which is itself wrapped under the machine's **boot key** (the "SysKey").
The boot key is not in the SAM at all — it is split across the *class
names* of four keys in the SYSTEM hive:

```
HKLM\SYSTEM\ControlSet00N\Control\Lsa\{JD, Skew1, GBG, Data}
```

Those keys hold no values. The eight hex digits each contributes live in
the key's class name, a field almost nothing else in the registry uses.

So: **collect SYSTEM with SAM.** With both, Tracefall decodes the hash.
With only the SAM, it reports every account — name, RID, flags, all the
timestamps — and marks each hash `encrypted_system_hive_missing`, saying
in the event itself what is missing and why. That is a different
statement from "this account has no password", and the two are never
conflated.

### Where the key comes from: the collection, not the directory

The boot key is derived **once per evidence collection**, before any file
in an import is parsed, from a SYSTEM hive catalogued in that same
collection. The file that supplied it is recorded on every account event
(`boot_key_source`, `boot_key_source_sha256`, `boot_key_control_set`), so
a decoded hash always names the second piece of evidence it stands on.

Two consequences worth knowing:

- **The SYSTEM hive does not have to be selected for import.** If it is
  in the collection's catalog, it can supply the key. Importing the SAM
  alone still yields decoded hashes.
- **Candidates are verified by content.** A renamed SYSTEM hive is found;
  a file merely *called* SYSTEM is not trusted, and a decoy named SYSTEM
  does not stop the real one elsewhere in the collection from being used.

This is deliberately **not** a filesystem scan next to the SAM. That was
the first implementation and it was wrong for AD1 images: AD1 entries are
materialized one at a time immediately before each is parsed, so at the
moment the SAM was parsed the SYSTEM hive beside it in the image had not
been written yet. On real evidence the gap was 6.2 seconds — SAM
extracted at 23:54:08, SYSTEM at 23:54:14 — and every hash came back
"encrypted, no SYSTEM hive" while the SYSTEM hive sat in the very same
collection. Deriving the key at collection scope removes the race by
construction.

### Structures decoded

| Path | What is read |
| --- | --- |
| `SAM\Domains\Account` → `F` | The wrapped Password Encryption Key, at offset `0x68`. Revision 1 (RC4/MD5) and revision 2 (AES) are both decoded |
| `SAM\Domains\Account\Users\<RID>` | One key per account, named as the RID in uppercase hex |
| …`\<RID>` → `V` | Variable-length record: a table of (offset, length) pairs, then the account name, full name, comment and the wrapped hashes from `0xCC` |
| …`\<RID>` → `F` | Fixed 80-byte record: last logon, password last set, account expiry, last incorrect password, the RID, account-control flags and the logon counters |
| `SAM\Domains\Account\Users\Names\<name>` | The name index. The RID is in the default value's **type** field, not its data |
| `SYSTEM\Select` → `Current` | Which control set is live — read, never assumed to be 001 |
| `SYSTEM\ControlSet00N\Control\Lsa\{JD,Skew1,GBG,Data}` | The boot key, in the four **class names** |

Both hash wrappings a real machine produces are read: the **AES** form
(Windows 10 1607 and later) and the **RC4/MD5** form (earlier releases).

### Fields extracted

| Field | Notes |
| --- | --- |
| `account_name`, `rid` | From the account's own `V` record; the Names index is only a fallback |
| `ntlm_hash` | 32 hex characters, **only** when it could actually be decoded |
| `ntlm_hash_status` | see the state table below |
| `ntlm_hash_unavailable_reason` | A sentence, whenever the status is not `decoded` |
| `boot_key_status`, `boot_key_source`, `boot_key_source_sha256`, `boot_key_control_set` | The cryptographic dependency: which SYSTEM hive supplied the key, or why none did |
| `account_control`, `account_control_flags`, `account_disabled` | Decoded names plus the raw word, so nothing is lost |
| `last_logon`, `password_last_set`, `last_incorrect_password`, `account_expires` | Each with its own `_meaning` |
| `logon_count`, `failed_logon_count` | |
| `account_full_name`, `account_comment` | When present |
| `registry_last_write` | Metadata **about the record**, labelled as such |

### Hash states, and why "not available" is not one of them

An encrypted hash is **not** a missing hash. The material is in the
evidence; what is missing is a key. Saying "not available" for both was
wrong — it told an analyst the same thing about an account with no
password and about an account whose hash needed one more file to read,
and those call for different next steps.

| Status | Meaning | What the UI shows |
| --- | --- | --- |
| `decoded` | The NT hash was decoded | the 32-character hash |
| `not_stored` | The record stores no NT hash — normally, no password is set | "No hash stored for this account" |
| `encrypted_system_hive_missing` | The hash **is present** and encrypted; no SYSTEM hive was available | "Encrypted — SYSTEM hive required" |
| `encrypted_system_hive_unusable` | The hash **is present**; a SYSTEM hive was found but could not supply a usable key | "Encrypted — SYSTEM hive could not be used" |
| `encrypted_data_unavailable` | The hash **is present** and its bytes could not be read out of the record | "Encrypted — hash material could not be read" |
| `unsupported` | The hash **is present** in a wrapping this build does not decode | "Encrypted — unsupported format" |

Every encrypted state also sets `ntlm_hash_present_but_encrypted`, so no
consumer can mistake one for an account that has no hash.

The `_missing` / `_unusable` split matters because the remedy differs:
one says *collect the SYSTEM hive*, the other says *the SYSTEM hive you
collected will not do* — it is truncated, corrupt, carries no SysKey
class names, or belongs to a different machine.

### Three refusals worth stating

**No hash is invented.** An account whose record stores no NT hash is
reported as `not_stored`. Some tools print
`31d6cfe0d16ae931b73c59d7e0c089c0` there — that is the NTLM hash of the
*empty string*, a convention rather than a value read from the hive.
Tracefall does not emit it, and says so in the event.

**No timestamp is invented.** A SAM account record carries no time of its
own, so **the event has none**. Neither the hive's nor the file's
modification time is substituted; those describe the file, not the
account. The account's own timestamps travel as labelled fields.

**No wrong hash is preferred to no hash.** The RC4 domain-key record
carries a checksum, and a boot key that fails it is rejected rather than
used to produce plausible-looking garbage for every account — a SYSTEM
hive from a *different machine* is caught here and reported as
`encrypted_system_hive_unusable`. A hive whose structures cannot be
decoded safely reports that, field by field. A truncated or corrupt
SYSTEM hive can never produce a hash that is not the real one.

### Where the hash is, and is not

Credential material is shown in exactly one place: the **event's own
detail view**, in a labelled panel, displayed truncated with a reveal
control and a Copy button that always copies the complete 32 characters.

It is deliberately **not** in the timeline row, **not** in the Detail
column, and **not** in the free-text search index — search reads a named
allowlist of fields (`internal/store/eventquery.go`) and the hash is not
one of them, so it cannot be surfaced by guessing it into the search box
or leaked into a URL.

---

## FileZilla connection evidence

FileZilla stores connection records as XML in
`%APPDATA%\FileZilla\`. Two files matter, and they are different
claims:

| File | Root container | What an entry means |
| --- | --- | --- |
| `recentservers.xml` | `<RecentServers>` | The client wrote this when a connection was started from the Quickconnect bar. A connection to this host was **attempted** from this profile |
| `sitemanager.xml` | `<Servers>` | A site the user **saved**. It may never have been connected to |

Tracefall keeps them apart with a `filezilla_section` field, and each
gets its own `evidence_meaning` wording. Merging them would let "saved a
site" read as "connected to a server".

### Neither file records a time

There is no per-entry timestamp anywhere in the format. The events
therefore carry **no event time**, and say so in `timestamp_basis`. The
file's own mtime dates the most recent change to the whole list — not
any individual entry — so substituting it would put a fabricated instant
on the timeline.

### Detection

`<FileZilla3>` is not enough on its own. FileZilla writes its settings
(`filezilla.xml`), window layout (`layout.xml`) and certificate store
(`trustedcerts.xml`) under the same root element, and none of those is
connection evidence. Identity requires the root **and** one of the two
connection containers, which is what keeps `filezilla.xml` out of this
parser.

The filename is a hint, never proof: a name match is re-checked against
the bytes (`ConfirmContent`), and a genuine connection file found under
any other name is still claimed (`DetectContent`).

### Addresses are classified, never resolved

The `<Host>` literal is parsed, and the result is reported as `ipv4`,
`ipv6`, `hostname`, `absent` or `malformed`. Tracefall performs no DNS.
When the host is a hostname, the event says so explicitly in
`ipv4_availability` rather than leaving an analyst to infer it from a
missing field — and notes that a name's address today is not necessarily
what it resolved to when the entry was written.

### Passwords

FileZilla can store a password (`<Pass>`) or a private key
(`<Keyfile>`). **The value is never read out of the source file.**
`internal/filezilla` does not carry it out of the decoder, so nothing
downstream can leak what it never received. What is recorded:

```
password_present: true
password_storage: base64
```

The presence of a stored FTP password in a user profile is the
forensically useful fact. The secret itself is not needed to state it.

---

## Image metadata (EXIF) and embedded location

### What is read, and what is not

A JPEG is marker segments followed by entropy-coded pixel data.
Everything Tracefall needs — the EXIF APP1 segment and the frame header
with the image's dimensions — is in the marker segments, so parsing
**stops at the start-of-scan marker**. The picture is never decoded. An
8 MB photograph costs about 140 µs and a few kilobytes of I/O.

### What an EXIF record asserts

That the software which wrote the file recorded these values. EXIF is
ordinary file content: a camera writes it, and so does every editor,
exporter, messaging app and forger downstream. Make and Model name the
device that **claimed** to produce the image — not proof of which device
did, and nothing at all about who owned it.

When `Software` names an editor rather than a camera, the event says so:
the values below it passed through, and possibly were changed by, that
software.

### Timestamps

EXIF holds several times with genuinely different meanings, and each
keeps its own label rather than being collapsed into one "image time":

| Tag | Meaning |
| --- | --- |
| `DateTimeOriginal` | When the exposure was recorded — when the photograph was taken |
| `DateTimeDigitized` | When the image was digitized (equal to the above for a digital camera; the scan time for a scan) |
| `DateTime` | ModifyDate: when the writing software last saved the file |
| `GPSDateStamp` + `GPSTimeStamp` | The GPS fix time |

Two rules the code enforces:

* **A filesystem mtime is never substituted.** The parser does not read
  one. A file's mtime describes the file as it was collected, which is a
  different fact about a different object.
* **`DateTimeOriginal` is never called a file creation time.**

Most EXIF times carry **no timezone** — they are wall-clock readings
from the writing device's clock. Where EXIF 2.31's `OffsetTime` tags are
present the zone is applied and reported; where they are absent, that
absence is stated on the event rather than a zone being assumed. The one
exception is the GPS fix time, which is UTC by specification.

### GPS: observed, then derived

The event separates the two, and the UI renders them under separate
headings:

```
OBSERVED  GPSLatitude  [16/1, 0/1, 0/1]  GPSLatitudeRef  S
          16° 0' 0" S
DERIVED   -16
          degrees + minutes/60 + seconds/3600, signed by the hemisphere ref
```

The three RATIONAL components are kept unconverted alongside every
derived decimal, so a conversion can always be checked against what the
file actually said.

A coordinate is decoded only when **both** a full component triple and a
valid hemisphere reference are present. A latitude with no
`GPSLatitudeRef` is ambiguous by a whole sign, and guessing one would
put a position on the wrong side of the equator. A GPS block holding
only `GPSVersionID` — very common — is reported as present and not
decoded, never as a position at 0,0.

### Coordinate precision is computed, not assumed

The finest unit the stored components actually resolve is derived from
the components themselves and reported:

| Stored | Granularity | Locates a point within |
| --- | --- | --- |
| `16/1 0/1 0/1` | degree | ~111 km |
| `17/1 55/1 28/1` | arcsecond | ~31 m |
| `34/1 12/1 152/10` | sub-second | finer than 31 m |

A coordinate written as whole degrees names a degree and nothing finer.
Reporting the derived decimal without this would make a ±55 km position
look like a ±1 m one — and any country determination made from it
inherits the same uncertainty.

### Country is derived, and says so

The country on a GPS event is **not in the image**. It is an offline
point-in-polygon test Tracefall performs against a bundled boundary
dataset — see [`internal/geo/DATASET.md`](../internal/geo/DATASET.md)
for the source, version, license, hashes and the command that
regenerates it. There is no network call, no DNS, and no third-party
geocoder: a forensic conclusion must be reproducible from the same build
months later.

Every GPS event carries `geolocation_method`, `geolocation_dataset`,
`geolocation_dataset_version`, `geolocation_dataset_source` and
`geolocation_dataset_license` alongside the country, plus a
`country_confidence` of `inside` or `near_boundary` and the distance to
the boundary. A coordinate the dataset attributes to no country is
reported as `country: unavailable` with the reason — never the nearest
landmass.

### Seeing them on a map

Images with a coordinate are plotted on the case's **Photo Map**, with
the actual image viewable from each marker — see
[photo-map.md](photo-map.md). The map is a second view of the same
`image_gps` events; it creates no records of its own, and the country it
shows is derived there exactly as it is here.

### Detection, and why cached images are left alone

Images are detected **by content only**: an extension is not evidence,
and a renamed JPEG is still a JPEG. That makes it the broadest detector
in the registry, which is a problem inside a browser cache — a Chromium
cache holds hundreds of cached response bodies that really are JPEGs (84
on one real image). Those are already correctly catalogued as
browser-cache evidence, and claiming them as standalone images both lost
that context and emptied the cache picture.

So the image parser scopes itself out of cache directories via
`parsers.PathScopedDetector`. A cached image stays catalogued as the
cache entry it is, which is the more specific and more useful
classification: a picture that arrived over HTTP through a named browser
profile, not a file someone put on the disk.

---

## Browser downloads

**Source.** The **same database as history** for both browsers —
Chromium's `downloads` / `downloads_url_chains` tables, and Firefox's
`moz_annos` download annotations (or the legacy `moz_downloads` table).
Read by `internal/parsers/browserhistory`, which already claims the file.

**Fields extracted.** URL, target path, filename, referrer, MIME type,
start and end times, total and received bytes, state, danger type, and
the browser's own "opened from the downloads UI" flag.

**URL selection.** Where Chromium records a redirect chain, the **last**
entry is used: that is where the bytes actually came from. The chain's
first entry is what the user clicked.

**Schema variation.** Chromium's `downloads` schema has grown across
many versions, so each optional column is included only when
`pragma_table_info` shows it present. The column list is built in a
**fixed order** and scanned in the same order — an earlier version of
this code ranged over a map to build it, which silently returned *zero*
downloads because Go randomizes map iteration.

**Timestamp semantics.** The event time is the download's **start**
time; where only an end time exists that is used and `timestamp_meaning`
says so. A download with neither carries no timestamp.

**Forensic meaning.** The browser retrieved a resource to a local path.
**Downloaded is not opened, and not executed.** The `opened` flag is a
*browser* flag about its own downloads UI: false does not mean the file
was never opened, and true is not evidence of execution. Corroboration
from Prefetch, Amcache or a process-creation record is what establishes
those.

**Events / findings.** Produces `browser_download` events, carrying
`model.ArtifactBrowserDownload` — deliberately a **different artifact
type from browser history**, so "this file arrived" can never read as
"this page was viewed". No finding rule.

---

## Findings

**No detection rule was added in this phase**, and that is a deliberate
outcome rather than an omission.

The rule the phase set is that a finding requires a meaningful,
deterministic, explainable condition. "A UserAssist entry exists", "a
ShellBag exists", "a PowerShell command exists" or "a local account has
an NTLM hash" are none of those — they are *evidence*, present in
essentially every real Windows image, and turning them into findings
would bury the findings that mean something.

The SAM case is the sharpest example. Every Windows machine has local
accounts and most of them have password hashes. A rule that fired on
that would fire on every image ever collected, which is the definition
of a useless alert. SAM events are also kept out of the correlation
engine's inputs: an account record is not an execution, a logon or a
persistence mechanism, and letting it join a chain would manufacture a
story out of a machine simply having users.

These events participate fully in the layers above them:

- They are **searchable** in the forensic timeline by artifact, event
  type, date, path and free text.
- They can be **cited by existing rules** wherever those rules key on
  fields these events populate.
- They enter **correlation** through the normal event pipeline, so an
  executable seen in Prefetch, UserAssist, an LNK and a 4688 record
  contributes four independent observations rather than one merged
  claim. Tracefall deliberately does **not** invent a correlation score
  simply because several artifacts mention the same name.

---

## Resource limits

Every parser here is bounded against hostile evidence. The limits that
bind in practice:

| Limit | Value | Where |
| --- | --- | --- |
| Hive file size | 512 MiB | `regf.DefaultLimits` |
| Keys walked per hive | 500,000 | `regf.DefaultLimits` |
| Values per key | 4,096 | `regf.DefaultLimits` |
| Hive key depth | 32 | `regf.DefaultLimits` |
| Value data | 1 MiB | `regf.DefaultLimits` |
| UserAssist name | 4 KiB | `userassist.DefaultLimits` |
| UserAssist entries | 20,000 | `userassist.DefaultLimits` |
| BagMRU depth | 64 | `shellbag.DefaultLimits` |
| Shell items per BagMRU level | 512 | `shellbag.DefaultLimits` |
| Shell item size | 64 KiB | `shellbag.DefaultLimits` |
| Total bags | 50,000 | `shellbag.DefaultLimits` |
| SAM accounts | 100,000 | `sam` (`maxAccounts`) |
| Boot-key candidate hives opened | 64 | `registry` (`maxBootKeyCandidates`) |

The per-level shell-item bound is the one worth explaining: resolving
each child of a BagMRU level costs a key lookup that scans its siblings,
so an unbounded level is quadratic work an attacker controls. Measured
on a synthetic 2,000-sibling level, the bound took the parse from 5.8s
to 0.48s. Real BagMRU levels hold a handful of children.

The BagMRU walk is **iterative, not recursive** — depth is
attacker-controlled, and a bounded queue cannot overflow the stack
however the hive is shaped.

Measured on this build: 4,096 UserAssist entries parse in ~75 ms (~44
MiB allocated); a 200-level BagMRU chain terminates in ~8 ms.

SAM parsing is linear in the account count — enumeration uses
`regf.ChildKeys`, a single pass over the subkey list, rather than a
lookup per child. Measured on this build: 5 accounts in 0.36 ms, 500 in
20 ms, 5,000 in 141 ms — ten times the accounts for roughly seven times
the work.

---

## Not implemented

Deliberately out of scope, and listed so the boundary is visible rather
than assumed:

- **SECURITY hive secrets** — LSA secrets, cached domain credentials
  (MSCACHE/DCC2), machine account passwords. The SAM hive *is* now read
  (see [Windows SAM](#windows-sam)); the SECURITY hive is not.
- **A separate "Windows SYSTEM" artifact type.** The SYSTEM hive is
  already read as a registry hive and contributes the hostname and
  persistence evidence it holds. Giving the boot-key derivation its own
  artifact or event would manufacture an "activity" record out of a
  cryptographic step that is not activity at all — nothing happened on
  the machine when Tracefall read those four class names. The dependency
  is recorded where it belongs: on the SAM account event that relied on
  it.
- **Password recovery of any kind.** Tracefall extracts the stored hash
  and stops there. There is no wordlist, no brute force, no rule engine,
  and no integration with Hashcat, John the Ripper or anything like
  them. See [Windows SAM](#windows-sam).
- **Broad registry parsing.** The hive reader extracts a fixed, targeted
  set of locations. A SOFTWARE hive holds hundreds of thousands of keys,
  and emitting an event per key would bury an investigator.
- **Other ESE / JET databases.** Tracefall has an ESE reader (`internal/ese`)
  and reads **SRUM** (`SRUDB.dat`) with it. `WebCacheV01.dat` (Internet
  Explorer and Edge Legacy history and cache) is read too. `Windows.edb`, the
  BITS database and `ntds.dit` are opened by the reader but their tables are
  not interpreted.
  The reader's scope, validation and limits are in `docs/evidence-triage.md`,
  "ESE databases".
- **WMI repository**, **`$Secure` / `$Bitmap` / `$Quota` / `$ObjId` /
  `$Reparse`** — classified honestly as recognized but unparsed.
- **`Bags` view-settings subtree.** Tracefall reads `BagMRU`, which
  carries folder identity. The paired `Bags` tree holds view settings
  (icon size, column layout) and is not read.
- **Browser cookies.** Not parsed. The forensically useful part is the
  metadata (domain, creation, expiry, last access), but the same tables
  hold session tokens, and Tracefall has no mechanism for storing a
  field that must never be displayed or exported. Rather than parse the
  rows and rely on every future view remembering to redact them, the
  artifact is left unread and the limitation stated here.
- **`LastVisitedPidlMRU`.** The companion to `OpenSavePidlMRU`,
  recording which *application* last used a dialog in a given folder.
  Recognized in the code's key table but not yet extracted.
