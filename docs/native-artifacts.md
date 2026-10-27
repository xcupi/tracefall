# Native Windows Artifact Ingestion (Phase 9)

Tracefall reads two Windows artifacts in their **native binary form**, in
addition to the EZ Tools CSV exports it already consumed:

| Artifact | Package | Parser name | Artifact type |
|---|---|---|---|
| Windows Event Log (`.evtx`) | `internal/evtx` + `internal/parsers/evtx` | `evtx@1` | `windows_event_log` |
| Windows Registry hive (REGF) | `internal/regf` + `internal/parsers/registry` | `registry@1` | `registry_hive` |

Both are read-only, bounded, dependency-free, and feed the existing
pipeline unchanged:

```
Evidence → Discover → Select → Import → Parse → Event
        → Detect → Correlate → Investigate → ATT&CK
```

There is no parallel analysis engine, no second event model, and no
schema migration.

## Format references used

Both parsers were written against the **libyal** format specifications,
which are the de facto public documentation for these structures and are
themselves derived from long-running reverse-engineering projects with
corroborating implementations:

- **EVTX** — *Windows XML Event Log (EVTX) format*, libyal/libevtx.
  Used for: the 4096-byte file header (`ElfFile\0`, chunk counts, CRC32
  over bytes 0–119), the 512-byte chunk header (`ElfChnk\0`, record
  number/identifier ranges, free-space offset, the 64-entry common
  string offset array and 32-entry template pointer array), the event
  record header (`0x2a 0x2a 0x00 0x00`, size, record identifier,
  FILETIME, trailing size copy), and the BinXML token and value-type
  tables.
- **REGF** — *Windows NT Registry File (REGF) format*, libyal/libregf.
  Used for: the 512-byte base block (`regf`, sequence numbers, root key
  offset, hive bins data size, XOR-32 checksum), the `hbin` header, the
  signed cell-size convention (negative = allocated), the `nk`/`vk`
  record layouts, the `lf`/`lh`/`li`/`ri` subkey list variants, the
  `db` big-data record, and the REG_* value type codes.

Cross-checked against Eric Zimmerman's Registry/EvtxECmd behavior as
observed in the CSV output Tracefall already parses — in particular that
EvtxECmd's `Channel`, `EventId`, `ComputerName` and `PayloadData` fields
correspond exactly to BinXML `System/Channel`, `System/EventID`,
`System/Computer` and the `EventData` name/value pairs. That
correspondence is what makes cross-source deduplication (below) work.

No binary structure was inferred from sample files alone.

## Dependency decision: hand-written, no new dependencies

**No new Go dependency was added.** `go.mod` still has exactly two
direct requires (`google/uuid`, `modernc.org/sqlite`).

Candidates evaluated:

| Candidate | License | Maintained | Verdict |
|---|---|---|---|
| `0xrawsec/golang-evtx` | **GPL-3.0** | last push 2022-11 | **Rejected.** GPL-3.0 is a copyleft license Tracefall (which ships no license of its own) cannot absorb without relicensing the whole project. Nearly four years stale. |
| `Velocidex/evtx` | Apache-2.0 | active (2026-06) | **Rejected on footprint.** Genuinely good code from the Velociraptor project, but its module graph pulls ~24 modules including `github.com/mattn/go-sqlite3` — a **cgo** SQLite driver — plus `go-pe`, `pkcs7`, `kingpin` and `yaml`. Tracefall deliberately uses pure-Go `modernc.org/sqlite`; admitting a cgo SQLite driver into the graph works against the cross-platform, cgo-free build that choice exists to protect. |
| `libregf` / `libhivex` | LGPL / LGPL | active | **Rejected.** C libraries; would require cgo, ending the pure-Go build outright. |
| `joshuapare/hivekit` | **none** | 2026-03 | **Rejected.** No license at all (so: all rights reserved, not usable), 3 stars, and it is a read/**write** toolkit — writing to a hive is explicitly forbidden here. |

There is no maintained, permissively-licensed, pure-Go REGF library.

Hand-writing also matches the precedent already set by `internal/ad1`
(Phase 7), which parses AD1 forensic images directly against the
`fox-it/dissect.evidence` reference for the same reasons. And Tracefall
needs a *bounded subset* — System + EventData extraction, and a fixed
list of registry persistence locations — not full-fidelity BinXML or a
general registry API. A general-purpose library would carry far more
attack surface than the subset justifies, and none of the candidates
offer the hard allocation/record/depth ceilings this codebase applies to
every attacker-controlled input.

The cost is real and worth stating: two hand-written binary parsers are
code Tracefall now owns and must maintain, and they implement a subset,
not the whole format. See "Known limitations".

## EVTX: source-level coverage

Raw EVTX imports persist `SourceFile.parse_coverage` independently of events:
records read, mapped/unmapped, undated, failed records/chunks and a reached
record cap. A bounded provider/channel/Event-ID census records the first 512
distinct kinds and discloses records beyond that bound. This survives parser
worker serialization and imports producing zero timeline events. Source details,
provenance and the report expose it; imported does not mean every record was
analyzed. Older imports and parsers without diagnostics retain an unknown
coverage state, not a fabricated complete result. Reimport into a fresh case to
obtain diagnostics for historical evidence.

Mapped observations without a usable timestamp remain undated, with the missing
basis recorded; they are not silently discarded or dated from file metadata.
Unmapped records remain available in the original hashed evidence file, but are
not synthesized into semantically unsupported events.

## EVTX: what is parsed

`internal/evtx` reads the file header, iterates 65536-byte chunks, and
walks each chunk's event records. Each record's BinXML is resolved into
a flat structure:

- **System** — Provider, EventID, Version, Level, Task, Opcode,
  Keywords, TimeCreated, EventRecordID, Execution ProcessID/ThreadID,
  Channel, Computer, Security UserID, Correlation ActivityID.
- **EventData / UserData** — the name→value pairs, which is exactly the
  shape `EvtxECmd` flattens into its `PayloadData` columns.

BinXML support covers what real event records use: fragment headers,
open/close start element, close empty element, end element, attributes,
value text, template instances (including definitions resolved by
in-chunk offset, forward or backward), normal and optional
substitutions, character/entity references, CDATA, and end-of-stream.
Value types 0x00–0x15 plus 0x21 are decoded, including SIDs (rendered
`S-1-5-…`), FILETIME, GUID, hex integers, and the 0x81+ array variants
used by `Keywords`-style fields.

Templates are cached per chunk, so a 100k-record log resolves each
template once rather than per record.

## Registry: what is parsed

`internal/regf` validates the base block, then provides iterative,
bounded traversal from the root key. It handles `nk` records (ASCII and
UTF-16 names via `KEY_COMP_NAME`), `vk` records (including the
resident-data convention when the data size MSB is set, and `db`
big-data segment lists), and all four subkey list types (`lf`, `lh`,
`li`, and `ri`, which points at sub-lists).

Value data is decoded for REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ,
REG_DWORD (both endiannesses), REG_QWORD, and REG_BINARY; anything else
is preserved as bounded binary.

The hive is opened **read-only**. Nothing writes to it, no file is created or
changed when a transaction log (`.LOG1`/`.LOG2`) is replayed in memory, and the host operating
system's registry API is never involved — the file is parsed as bytes,
so this works identically on Linux.

## Normalization: one canonical mapping

The (channel, EventID, payload) → `model.Event` mapping lives in **one
place**: `internal/parsers/winevent`. Both the native `.evtx` parser and
the existing `EvtxECmd` CSV parser call it.

This is the same principle Phase 4 applied with `internal/parsers/regpersist`
(one persistence classifier shared by RECmd and Sysmon registry events),
and it is what makes cross-source determinism a property of the code
rather than of two switch statements happening to agree. Native registry
persistence extraction also calls `regpersist.Classify` — there is still
exactly one persistence classification table.

## Deduplication across sources

`model.Event.ComputeDedupHash` is **unchanged**. It hashes what happened
(event type, timestamp, host, user, process, PID/PPID, file path,
registry path, artifact type, Windows event ID, network destination) and
deliberately excludes where Tracefall heard about it.

Consequence, by design: the *same* Windows event record read from a
native `.evtx` and from an `EvtxECmd` CSV normalizes to the **same**
`DedupHash`, because both produce `ArtifactType = windows_event_log` and
identical normalized fields via `internal/parsers/winevent`. It
therefore collapses to **one** `Event` row with **two**
`EventObservation` rows — one per source file — so:

- findings and correlations do not double-count,
- both provenance chains are preserved and visible,
- deleting one source removes its observation, not the other's.

That is the existing evidence-deduplication semantic applied to a new
source, not a new mechanism.

Registry events from a native hive and from a RECmd CSV likewise share
`registry_run_key`-family event types and dedup normally when they
describe the same key/value at the same last-write time. They carry
different `ArtifactType` values (`registry_hive` vs
`registry_run_key`), so they are deliberately **not** collapsed: a hive
snapshot and a CSV export of that hive are the same underlying evidence,
but Tracefall treats artifact type as part of event identity, and
changing that would be a semantic change to every artifact, not just
these. Both remain visible on the timeline with independent provenance.

## Host attribution

EVTX `System/Computer` is a first-class host signal and is written
straight to `Event.Host` — no backfill needed, and it participates in
`ComputeDedupHash` normally.

The SYSTEM hive yields the hostname from
`ControlSet00N\Control\ComputerName\ComputerName\ComputerName`. It is
offered to Phase 7.1 host enrichment as a **collection-scoped** host
fact, used only to fill events that have no host of their own. It never
overwrites a host an event already carries, never votes, and is ignored
when a collection presents more than one candidate hostname. No hostname
is ever invented.

## Safety controls

Both parsers treat their input as hostile. Limits are explicit values
(`evtx.DefaultLimits`, `regf.DefaultLimits`), not scattered constants:

| Control | EVTX | Registry |
|---|---|---|
| Max file size | 1 GiB | 512 MiB |
| Max records / keys | 1,000,000 records | 500,000 keys |
| Max values per key | — | 4,096 |
| Max nesting depth | 64 BinXML elements | 32 key levels |
| Max name / value length | 64 KiB per value | 32 KiB name, 1 MiB data |
| Cycle detection | template resolution depth-capped | visited cell-offset set |
| Offset validation | every offset bounds-checked against its chunk | every offset bounds-checked against hive bins data |
| Allocation | one chunk (64 KiB) at a time | one cell at a time |

Neither parser writes, executes, resolves paths, opens sockets, or
shells out. Malformed input returns an error; it never panics, hangs, or
allocates unbounded memory — see the corruption tests.

## Partial recovery

**EVTX recovers per chunk, and says so.** A chunk whose header or CRC is
invalid, or whose records are malformed, is skipped; the records already
read from valid chunks are kept. The parser reports
`RecordsRecovered` and `ChunksFailed`, and the source file's event count
reflects only what was genuinely parsed. Tracefall never claims a file
parsed cleanly when it did not — a partially-recovered file surfaces the
chunk failure count in the event's `Extra` and in the import result.

This is the correct trade-off for event logs specifically: a truncated
`.evtx` (very common in real triage, since logs are copied while in use)
still contains thousands of intact, independently-framed records, and
discarding them would destroy real evidence. Records are self-delimiting
and CRC-covered per chunk, so "valid chunk" is a defensible boundary.

**Registry fails whole-file on a bad base block**, because a hive's
structure is a pointer graph rooted in that block — there is no
equivalent independent framing to fall back on. Individual unreadable
cells below the root are skipped and counted, not silently ignored.

## Known limitations

- BinXML **template resource** files (`.mui` message strings) are not
  read, so `Extra` carries raw substitution values rather than the
  rendered human-readable message string. EvtxECmd's `MapDescription`
  is richer here. Detection does not depend on rendered text.
- Only the event families Tracefall already has detection or timeline
  handling for are normalized into events (see
  `internal/parsers/winevent`). Records with any other EventID are read and
  then **skipped without being counted or reported**: the parser keeps a
  tally in a local variable that nothing uses yet. On a real Security log
  this is most of the volume (for example 4907 audit-policy changes), so an
  analyst currently cannot see how much was left out. Reporting that count
  is an open item.
- A log whose records all fail to decode produces zero events, and the
  `evtx_partial_parse` note is attached only to events, so it has nowhere to
  go in that case. Same open item.
- Registry emits events only for the targeted persistence locations plus
  the SYSTEM hostname — not one event per key, which would be noise.
- Deleted/unallocated registry cells are **not** recovered. Reading
  unallocated space means trusting offsets in freed structures, which
  conflicts with the safety posture above. This is a deliberate omission.
- Transaction logs (`.LOG1`/`.LOG2`) are replayed in memory when they sit beside
  the hive (see `docs/evidence-triage.md`); a disk image's extraction now copies
  them with the hive (`docs/disk-images.md`). A hive with no log beside it, or
  from an AD1 where the logs were not selected, may be older than the live
  registry; its replay state says `no_logs`.
- `SAM`/`SECURITY` hives are discovered and traversable, but no
  credential-material extraction is performed.
