# NTFS sources: what is read, what a row shows, how coverage is reported

Applies to `$MFT` (`ntfs_mft`), `$UsnJrnl:$J` (`ntfs_usnjrnl`) and `$LogFile`
(`ntfs_logfile`) collected as standalone files, for example by a KAPE triage
(`C/$MFT`, `C/$Extend/$J`, `C/$LogFile`) delivered as a folder, a ZIP upload, an
AD1 container or a disk image. Related: [bounded-ntfs-import.md](bounded-ntfs-import.md)
(streaming and budgets), [source-atomic-parser-import.md](source-atomic-parser-import.md)
(atomic persistence), [evidence-triage.md](evidence-triage.md) (triage overview).

Every number in this page was read from tool output in the session that wrote it
(the verification sections say how). Nothing here names a host, user, case or
sample; the real inputs were measured, not committed.

## Per source type

### `$MFT`

- **Read:** the table as an array of fixed-size slots (the record size is taken
  from the first coherent record). Per record: `$STANDARD_INFORMATION` times,
  `$FILE_NAME` (name, namespace, parent reference and sequence, times),
  `$DATA` size and residency, whether an `$ATTRIBUTE_LIST` exists, in-use and
  directory flags, base-record reference. Parent directories are resolved with a
  4096-entry LRU over the same file, accepted only when the parent's sequence
  matches; otherwise the path is marked incomplete.
- **Emitted:** up to four events per base record that has a name and at least one
  usable `$STANDARD_INFORMATION` time (created, modified, MFT-changed, accessed).
  `$FILE_NAME` times ride along as context (`fn_*`), they are not separate events.
- **Not emitted, and counted by class:** extension (non-base) records, records
  without a file name, records without a usable standard-information time.
  All-zero slots are skipped and are *not* part of `records_read`; they are
  counted separately as empty slots.
- **Free records** (flag "in use" clear) are emitted, labelled
  `allocation_state = not in use (record marked free)`, and counted
  (`free_mapped`). A free record is not a deletion instant.
- **Bounds:** the 8 GiB input ceiling, per-record and name bounds, the worker's
  and staging's 1 GiB budgets. There is **no event-count ceiling** on the import
  path (see "Legacy ceilings" below). A malformed slot, header, fixup, attribute
  or name fails the source; it is not skipped.
- **A row shows:** the filesystem's own record of a file. It does not show who
  acted, which process ran, or when a file was deleted. `$STANDARD_INFORMATION`
  times can be set by software (timestomping), so they are what the table says,
  not proof. Every event carries an `evidence_caveat` saying so.

### `$UsnJrnl:$J`

- **Read:** a sliding window over the stream; leading sparse zeros are skipped;
  record versions 2 and 3 are decoded (reason mask, source info, file and parent
  reference with sequence, USN, timestamp, attributes, name).
- **Emitted:** one event per record with a usable timestamp, typed by the most
  significant reason bit; the full reason mask travels as hex and flag names.
- **Not emitted, counted by class:** records of an undecoded version, records
  without a usable timestamp.
- **Non-record bytes:** nonzero 8-byte words that are not a record are counted
  (`non_record_bytes`, first offset). They are not called records and a source
  that has them is reported incomplete. Framing is regained only at a complete,
  bounded V2/V3 header with a valid name and a plausible time.
- **Fails (does not skip):** a recognisable record whose length, name bounds or
  UTF-16 are invalid, an unsupported version at a record boundary, and a file in
  which no coherent record exists.
- **A row shows:** that the volume recorded a change to a file *name* and which
  reasons it recorded. It does not show who or what made the change and it does
  not describe what the content became. Every event carries an `evidence_caveat`.

### `$LogFile`

- **Read:** restart areas, log pages and log records (LSN, transaction id,
  redo/undo operation codes, target attribute).
- **Emitted:** **no timeline events**, by design: a log record has no timestamp
  and describes a byte-level change, not a file operation. Per-record detail is
  stored as raw evidence (at most 5,000 records) and a summary record.
- **Coverage:** an explicit zero-event source: records decoded, records kept as
  detail. A `$LogFile` that does not decode fails and is shown as failed.

## What coverage records and where it is shown

`parse_coverage.ntfs` (model `NtfsCoverage`, only counters and offsets, never
evidence text) is stored with the source file and is read back by the files API,
the source details panel (`Parser coverage`), the report's coverage section and
its limitations:

| Field | Meaning |
|---|---|
| `records_read`, `mapped`, `unmapped`, `emitted_events` | existing counters; MFT: one mapped record yields up to 4 events |
| `unmapped_non_base`, `unmapped_no_name`, `unmapped_no_time` | MFT reason classes; they sum to `unmapped` |
| `unmapped_undated`, `unmapped_unsupported_version` | USN reason classes |
| `zero_slots` | MFT empty slots skipped (not in `records_read`) |
| `free_mapped` | MFT mapped records marked free |
| `attribute_list_records` | MFT mapped records whose attributes overflow (names/sizes may be incomplete) |
| `non_record_bytes`, `first_non_record_offset` | USN bytes not decoded as records |
| `log_records`, `log_records_retained` | `$LogFile` |
| `limit_reached` | reading stopped at a safety limit or cancellation |
| `failed`, `failure_class`, `failure_offset` | the source failed; class is one of `not_a_usn_journal`, `not_an_mft`, `not_a_logfile`, `corrupt`, `unsupported_version`, `limit`, `other` |

- A **failed** source keeps this record (the worker's coverage is persisted with
  the failed status; `emitted_events` is forced to 0 because nothing from a failed
  source is imported). The sentence is: *"FAILED, this source produced no events;
  it is not evidence of no activity"*, followed by the class and, when known, the
  byte offset. It appears in the files API, the source details and in **both** the
  report's coverage diagnostics and its limitations. If the worker died before it
  could report anything, the report says so ("NTFS coverage detail: not recorded").
- An import made before these fields existed has no `ntfs` object. It is shown as
  "NTFS coverage detail: not recorded", never as complete.
- The worker's coverage is checked before it is believed: the NTFS reason classes
  must add up to `unmapped`, no counter may be negative, a clean end of stream may
  not carry `failed`.
- The browser mirrors `NtfsSummary` (Go) sentence for sentence; a parity test
  runs both on the same fixtures.

## Legacy ceilings: which paths still apply them

`mft.DefaultMaxEvents` (200,000) and `usnjrnl.DefaultMaxEvents` (300,000) bound
only the legacy `Parser.Parse`. Evidence from the code (read this session):

- The only registry construction is `ingest.Registry()`; the only call of the
  legacy `Parse` for a registry parser is `ingest.runner.Run`, reached from
  `Service.ImportEvidence` only when the parser is **not** a `StreamingParser`
  (`internal/api/service.go`, the `streaming` branch precedes it). `mft.Parser`
  and `usnjrnl.Parser` implement `ParseStream`, so every import takes
  `stageStream` → `ingest.ParseFileStream` → isolated worker `ParseStream`.
- Folder, ZIP upload, AD1 and disk-image sources differ only before that point
  (discovery and, for AD1/disk image, extraction of the one selected entry);
  all then go through `ImportEvidence`. `import_segmented.go` admits only
  MSSQL logs in segments.
- Regression tests: a constructed KAPE-layout ZIP through upload, discovery, the
  isolated worker, staging and persistence imports 200,004 MFT events and 300,100
  USN events with no `limit_reached` (`TestNTFSTriageUploadIsNotCappedAtTheLegacyCeilings`);
  parser-level tests do the same for each stream.
- No ceiling remains on the import path, so there is no truncation to report. If
  a future change reintroduces one it must set `limit_reached`; the stream treats
  a limit as a failed source, never as a clean end.

## Diagnosis of the failed USN source (class b: not a journal)

The saved receipts showed one acquisition whose `$J` failed and imported 0
events. It was reproduced with the compiled server through `POST /ingest`, import
and the isolated worker on a copy of the input, then the bytes were examined:

- File size 39,306,306 bytes, of which 21,198,279 are zero. None of its 9,596
  4-KiB blocks is entirely zero. The first bytes are nonzero.
- The file contains 2,434 `FILE0` record signatures, every one at a file offset
  congruent to 2 modulo 1,024, spaced 1,024 bytes apart (except three gaps of
  525,312 bytes, one of 2,622,464 and one of 1,049,600): `$MFT`-style records
  at a 2-byte shift, from offset 2 up to offset 7,734,274 (the last signature);
  from that last signature to the end of the file are 31,572,032 bytes, in which
  nothing there decodes as a journal record; it was not further classified.
- Tracefall: `ntfs: not a USN change journal ($UsnJrnl:$J)`, 0 records read, 1
  failed, 37,720,058 nonzero bytes counted as non-record words from offset 0.
- Independent decoder (`dissect.ntfs` 3.16): its own reader raises
  `ValueError` and yields 0 records. An
  adapter that walks past failures finds exactly one 8-byte-aligned candidate
  (version 3, at offset 7,700,064, whose USN differs from its offset: a chance
  match inside table data) and 4,396,062 non-record words.
- Classification: **(b) a source that is not a USN journal**: the content of the
  file is not journal data, so it is not a reader defect and not a resource limit.
  Nothing was skipped, no bound was raised, no corruption check was weakened.
  What changed is that the failure is no longer silent: it keeps its class
  (`not_a_usn_journal`), its offset (0), its non-record byte count, and the
  "not evidence of no activity" sentence in the report. Whether the acquisition
  tool copied the wrong stream is not determinable from the file; the
  recommendation is to re-acquire `$UsnJrnl:$J` from the source and keep this file.
- A neutral fixture reproduces the layout (`$MFT`-style records at a 2-byte shift
  as a `$J`): `TestStreamCoverage_MFTShapedBytesInsteadOfAJournalIsAFailedSource`,
  `TestNTFSFailedSourcePersistsItsCoverage`.

## Verification performed

Second decoder: `dissect.ntfs` 3.16 in a venv, through two small adapters kept with
the verification notes (not in the repository): `oracle_mft.py` hands each
record-size slot of a standalone `$MFT` to `MftRecord.from_bytes` (a standalone
`$MFT` is not a volume); `oracle_usn.py` runs dissect's `UsnRecord` over the file
and steps 8 bytes past a failure so that the whole file is walked. Tracefall's
decode is compared by env-gated tests (`NTFS_ORACLE_*`, skipped when unset)
that print only counts.

| Source | Quantity | Tracefall | dissect |
|---|---|---|---|
| `$MFT` A | FILE slots / in-use / free | 1,029,960 / 842,599 / 187,361 | same |
| | mapped (free among them) | 992,602 (186,274) | same |
| | non-base / base without name or time | 35,378 / 1,980 | same |
| | events (created, modified, changed, accessed each) | 3,970,408 (992,602) | same |
| | min and max timestamp | equal | |
| | sample compared field by field | 2,500 records: 2,500 identical, 0 differing | |
| `$MFT` B | FILE slots / in-use / free | 744,270 / 594,079 / 150,191 | same |
| | mapped (free among them) | 706,407 (144,595) | same |
| | non-base / base without name or time | 36,850 / 1,013 | same |
| | events (modified is 706,386, the others 706,407) | 2,825,607 | same |
| | sample compared field by field | 2,506 records: 2,506 identical, 0 differing | |
| `$J` B | v2 records / v3 records | 308,095 / 0 | same |
| | first non-record offset | 33,894,400 | same |
| | non-record bytes | 4,296 (537 nonzero words) | 515 words with a nonzero first half; the 22-word difference is the counting unit, verified against the file |
| | min and max timestamp | equal | |
| | sample compared field by field | 2,505 records: 2,505 identical, 0 differing | |
| `$J` A | records | 0 (failed) | 0 from its reader; 1 chance candidate from the adapter |

Fields compared per sampled `$MFT` record: record number (slot), sequence,
in-use, directory, base flag, the four `$STANDARD_INFORMATION` times, the best
`$FILE_NAME` (name, namespace, parent reference, parent sequence, the four times)
and whether the record is mapped. Per sampled USN record: version, USN, reason
mask, source info, file attributes, timestamp, name, raw file reference, raw
parent reference. The samples are evenly spaced and include free records. The
counts for A and B `$MFT` also match the saved persisted-import receipts
(`records_read`, `mapped`, `unmapped`, events), and the B `$J` count matches its
receipt (308,095 records, 4,296 non-record bytes).

## End-to-end with the compiled binary

Real inputs (copies, laid out as `C/$MFT` and `C/$Extend/$J`) were uploaded with
`POST /ingest` to a fresh server (fresh port, scratch data directory),
discovered, imported through the isolated worker, and read back through the
API. Results, counts only:

- Host with the failed journal: `$MFT` imported 3,970,408 events (1,029,960
  read, 992,602 mapped, 37,358 unmapped); `$J` status `failed`, 0 events, its
  coverage stored with `failure_class = not_a_usn_journal`, `failure_offset = 0`,
  37,720,058 non-record bytes. The base binary (before this change) showed the
  same `$MFT` counters and a `failed` journal with **no coverage at all**.
- Other host: `$MFT` 2,825,607 events (744,270 read, 706,407 mapped, 37,863
  unmapped; 144,595 free among the mapped; 178 empty slots); `$J` 308,095
  events with 4,296 non-record bytes (first at offset 33,894,400).
- The timeline endpoint streamed 3,970,408 and 3,133,702 events (the sums of the
  imported events); after a server restart the files API read back the same
  statuses, event counts and coverage; the server was stopped and the port was
  confirmed closed. `report.html` generated for both cases (about 26 and 22
  minutes each for roughly four and three million events; a performance
  observation, not changed here).
- Findings and correlations are 0 on the full-size cases: `/analyze` on about
  four million events did not finish in 50 minutes and was aborted, so the full
  size findings were not compared. A before/after comparison was made on
  reduced copies (first 30 MiB of each `$MFT` plus the whole `$J`), base binary
  and new binary, analysis included: events 119,624 and 430,769 in both,
  findings 0 and 0 / 0 and 0, correlations 0 and 1 in both, statuses identical,
  existing coverage counters identical. Differences: (1) the new binary adds the
  `ntfs` object to every NTFS source and `emitted_events` to the `$J`
  coverage, and stores coverage for the failed `$J` (base: none); (2) the
  report gains the NTFS coverage sentences for each source, including the failed
  journal in its coverage section and limitations; (3) the list of USN rows in
  the host-2 report differs by 6 of about 310 rows against the base, and two
  base runs differ from each other by 8 rows, so that part is import-to-import
  variation among equally ranked rows, not a result of this change. A restart
  read back the same files, coverage, findings and correlations on the reduced
  copies.

## NOT verified

- Whether the input of the failed `$J` was mis-acquired or mislabelled: only the
  file's bytes were examined.
- `$MFT` records with an `$ATTRIBUTE_LIST`: names and sizes are flagged as
  possibly incomplete; extension-record attributes are not merged (unchanged).
- USN record version 4 and ReFS-style 128-bit references beyond what the V3
  decoder keeps; no real version-3 or version-4 journal was available (the real
  journal contained only version 2).
- `$LogFile`: no real `$LogFile` was available; behaviour is tested on generated
  logs only, and no operation is reconstructed from it.
- Equivalence of paths: path reconstruction for `$MFT` events was exercised by
  tests, but the resolved paths were not compared with the second decoder.
- AD1 and disk-image delivery of these files was traced in code, not run on real
  containers; multi-terabyte images and their hash/space checks are out of scope.
- Decoder agreement is for the two `$MFT` and the one readable `$J` available; it
  says nothing about other volumes, cluster sizes or Windows versions.
- The 1 GiB wire and staging budgets were not changed and not re-measured here;
  a source that exceeds them still fails as a limit.
