# Disk images: E01 / raw, partitions, NTFS

Status: implemented and tested against images written by independent
tools. **Not yet validated on a real Windows acquisition** (see
"Validation" and "Limits").

Add a disk image the same way as any other evidence: upload it, or give its
path. Tracefall recognises it from its contents, opens the container, finds
the partitions, reads the NTFS volumes, catalogs the artifacts that have a
parser, and imports them. From there detection, correlation and the report
run unchanged.

```
E01 / raw  ->  internal/image      container, per-chunk checksums, hash verification
           ->  internal/partition  MBR (+extended/logical), GPT (backup fallback)
           ->  internal/ntfsvol    NTFS read straight from bytes (no mount)
           ->  catalog -> import   existing parsers, detect, correlate, report
```

## What is supported

| Layer | Supported | Reported, not read |
|---|---|---|
| Container | raw/dd (single or split `.001 .002 ...`), E01 / EWF1 (EnCase, libewf), multi-segment E01 | Ex01 (EWF2), L01 logical evidence, VMDK/VHD/VHDX/AFF4 |
| Partitions | MBR, extended + logical, GPT (primary or backup), bare NTFS or ext volume with no table | dynamic disks (LDM) are named, not read |
| File system | NTFS (MFT, attribute lists, data runs, sparse, alternate data streams, deleted entries); ext2, ext3 and ext4, read-only (in-use directory tree, extents and block maps, holes, hard links, freed inodes that still map data); FAT12, FAT16, FAT32 and exFAT, read-only (in-use tree, long names, cluster chains, contiguous exFAT files) | NTFS-compressed and EFS-encrypted streams (reported), BitLocker (reported), ext inline data and encrypted ext files (reported), APFS and HFS+ (reported) |

"Reported" means the image report and the audit trail say so, and the
partition's contents are listed as **not part of the analysis**. Nothing is
silently skipped.

## Integrity

- Every E01 chunk is checked against its Adler-32/zlib checksum as it is
  read. A failure is an error, never wrong data.
- At discovery the whole image is decoded and hashed (MD5, SHA-1, SHA-256)
  and compared with the MD5/SHA-1 the acquisition tool stored. The outcome
  goes into the image report, the audit entry and the forensic report:
  *verified*, *MISMATCH*, or *no hash stored* (a raw image has none, and is
  never described as verified).
- The collection hash is SHA-256/SHA-512 of the **container file(s) as
  received**, in order, so duplicate detection and re-verification
  (`Verify integrity`) work like for any other evidence.
- An image that cannot be decoded to its end, or whose segments are
  incomplete, is refused with the reason (e.g. "segment 2 is missing") and
  leaves nothing behind. Recovering data from a damaged image is not done.

## What is cataloged

Only files that a registered parser claims by name, confirmed by content,
plus `$MFT`, `$LogFile` and the `$UsnJrnl:$J` stream. The image report states
per volume how many files were in use, how many were cataloged and how many
were not, so the omission is visible. Deleted MFT entries are counted
(`Deleted entries`) but not cataloged.

Catalog paths are `volN/<path in the volume>` where N is the partition
number, e.g. `vol1/Windows/System32/winevt/Logs/Security.evtx`.

## Where things are stored

- Local path: the image stays where it is. It is reopened at import time.
- Upload: stored as `upload.img` in the collection directory (single-file
  images only; a segmented E01 cannot arrive as one upload, give its path).
- `diskimage.json` in the collection directory is the discovery record.

## Validation

`testdata/images/gen.py` builds the fixtures with tools that are not
Tracefall: `ewfacquire` (libewf) writes the E01, `sgdisk`/`sfdisk` the
partition tables, `mkntfs` and the ntfs-3g driver the volume. The expected
contents (`manifest.json`) are read back from the **mounted** file system.
The tests compare every file of a 1,200-file volume byte-for-byte (SHA-256),
including heavily fragmented files that need an `$ATTRIBUTE_LIST`, a sparse
file, alternate data streams, Unicode names, a directory with 1,200 entries,
and a deleted file. They also cover corruption: flipped bits, truncation,
missing segments, damaged GPT, looping extended-partition chains and
random byte damage (no panics, no hangs).

## Limits (read before relying on it)

- **No real Windows image has been run through this.** mkntfs/ntfs-3g
  volumes exercise the format, but a Windows volume has structures they do
  not produce (compressed files, `$Extend` journals with data, reparse
  points, very large fragmented `$MFT`, VSS). Treat results from a real
  acquisition as unvalidated until one has been compared with another tool.
- Volume Shadow Copies are not read, so history held only in snapshots is
  absent.
- Deleted files are listed in the volume statistics only; they are not
  recovered into the case.
- The image is read twice at discovery (hash, then walk) and once more per
  import (walk). Fine for GB-scale images; for 500 GB expect minutes.
- Only artifacts that a parser exists for are examined. The disk is not
  searched for anything else (no carving, no keyword search).
- Container formats: EWF1 only. Segments over 2 GiB (EnCase overflow
  offsets) are detected and refused, not guessed.

## ext2/3/4

The ext reader (internal/ext4) is read-only. It lists every name reachable
from the root through in-use inodes, and reads file content through the extent
tree (ext4) or the block map (ext2 and ext3). Freed inodes that still map
data are listed as deleted files (see below), and metadata checksums are not
verified. A directory entry that points to a
free inode is not listed as in use, although debugfs dumps it. Its name is
used for the deleted file below, if the inode is still freed.

Checked two ways:

- Unit tests build images with the ext2/3/4 formatters from a source tree the
  test writes, so the expected content is the source, not the reader's output.
  Covered: 1 KiB and 4 KiB blocks, a 2 MiB file through the double-indirect
  block map, a 400-entry hashed directory, a hole, a hard link, a symlink, and
  deterministic corrupt and truncated images (no panic, and no wrong bytes
  returned as if they were right).
- On a real E01 with an ext4 partition, TestReal_ExtVolumeMatchesDebugfsRdump
  (set TRACEFALL_REAL_EXT4) compares the listing and every regular file's
  SHA-256 with debugfs rdump of the same partition. On the validation image:
  258,124 regular files, all content identical. debugfs also dumps one stale
  directory entry whose inode is free; the test accepts only that case, after
  checking that the inode is not in use.

Deleted files. A freed inode that is no longer reachable from the root, and
that still maps data, is listed with InUse false under /$OrphanFiles/. Its
name is the last name a directory still listed for that inode, or inode-N when
no name is left. Freed directories and freed inodes whose data map was cleared
on deletion are not listed. ext4 clears the extent tree of a deleted file, so
most freed inodes have no content left, and listing them would add names with
nothing behind them. The catalog never includes deleted files, the same as
NTFS: they are reported by the reader, not added to the evidence.

Checked against debugfs lsdel on the validation image: the two freed inodes it
lists are the two the reader lists, and their content equals debugfs dump.

## FAT12, FAT16, FAT32 and exFAT

The FAT reader (internal/fat) is read-only. It lists the in-use tree with long
names (LFN entries, checked against their short alias's checksum) and exFAT
names, follows FAT chains, and reads exFAT files with no FAT chain as a
contiguous run. Each volume's type comes from its layout (cluster count for
FAT12/16/32, the signature for exFAT). Deleted entries are not listed: FAT
frees a deleted file's chain, so its content is generally gone, and a name
alone is not catalogued. Damaged directory entries and chains are reported
as corrupt, and the walk continues.

Checked two ways. The fixtures are written by the reader's test code from a
known tree and then checked by the file system's own checker (fsck.fat and
fsck.exfat), which rejects a damaged image. Files are read back and compared
with the source; fragmented files are checked to be read through their chain.
The fixture writer is test code, and the checker validates its output; no real
FAT or exFAT image from the validation set has been read yet.

## Registry transaction logs extracted with their hive

A hive collected from a running system is usually missing its newest changes;
they are in `HIVE.LOG1`, `HIVE.LOG2` (or the older `HIVE.LOG`) beside it.
Replay (see `docs/evidence-triage.md`, "Registry hives copied while Windows was
running") only works when those files sit next to the extracted hive. From a disk
image, extraction used to copy only files a parser claims, so the logs stayed in
the image and the hive was read without them, silently.

Now, when a registry hive is extracted from a disk image, its logs are extracted
with it:

- **Which files.** The file name is the hive's name plus `.LOG1`, `.LOG2` or
  `.LOG`, in any case (the same rule `regf.SiblingLogs` uses, shared as
  `regf.IsCompanionLogName`); a regular, in-use file; **same directory of the same
  volume** as the hive. Nothing else is copied: not another hive's log, not the
  parent directory's (a `RegBack\SOFTWARE` does not take `config\SOFTWARE.LOG1`),
  not a same-named log on another partition, not a log whose hive is not in the
  catalog (such a file stays an ordinary unsupported entry).
- **Where.** Under the same evidence layout (`volN/<path>`), beside the hive, so
  `OpenReplayed` finds them. This covers every hive the registry parser claims
  (SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT, NTUSER.DAT, UsrClass.dat, Amcache.hve
  by content). The boot-key and time-zone helpers extract the SYSTEM hive through
  the same function, so they read the same replayed state as the parser.
- **How they are recorded.** Each log is hashed (SHA-256 of the logical stream) and
  the hash is stored on its catalog row. At discovery the row is labeled
  `companion_of` = the hive's catalog path (in the row's parse coverage, shown in
  source details and provenance; no schema change). The row keeps import status
  `unsupported`, event count 0 and no events: **a companion is not independent
  evidence.** It is counted in `coverage.companions` and in the catalog's
  unsupported total (no parser reads it alone) but it is not reported as an
  unextracted gap, and the triage view says what it is used for.
- **Status per hive.** The hive's parse coverage carries `hive_replay`:
  `state` (`clean`, `replayed`, `replayed_partial`, `not_recoverable`,
  `no_logs`), `reason`, `logs_applied`, and `companions` (path, size, SHA-256,
  `extracted` / `oversize` / `failed`). A dirty hive with no log in its
  directory is `no_logs` with the reason that the image holds none; a hive
  without logs in its directory is never "clean by assumption". Events of a hive
  that was not cleanly written keep carrying `hive_state` / `hive_recovery`; events
  of a clean hive stay unannotated, as before.
- **Limits.** Each log is capped at `regf.MaxLogFileBytes` (256 MiB, what the
  replay reader itself accepts); at most one log per suffix per hive. A log over
  the cap, or one that cannot be copied, is **not extracted** (any copy from an
  earlier run is removed), the hive is still parsed, and for a hive that is not
  clean the status, the coverage notes (so the hive is "incomplete") and the
  events' `hive_recovery` name the log and why. The index of log-like file names
  in an image stops at 200,000 entries; a `no_logs` reason then says a log may
  have gone unseen.
- **Re-import.** Extraction overwrites the same paths with the same bytes; no
  file or row is added, and no event identity changes (the dedup hash is
  untouched). A hive imported *before* this change was parsed without its logs; its
  stored events do not change. Use a fresh case to re-import it.

### Boundaries

- Only **disk images** (raw, E01, VHD, VHDX, VMDK) are covered. Folder, ZIP and
  KAPE-style directory ingests extract the whole tree, so a log is beside its hive
  already and `SiblingLogs` finds it. **AD1 containers are not covered:** they
  extract only the selected entries (`ad1Extractor.extract`), so a hive imported
  from an AD1 is still read without logs that were not selected. This is a known
  gap, not a decision.
- Logs are found in the image only by name beside the hive; a log renamed or moved
  elsewhere is not found. Deleted (not in-use) logs are not recovered.
- Replay rules are unchanged (Windows 8.1+ format, gap refused, first failing
  entry ends the chain). A log of the older format is extracted and hashed, and
  the state says it was not replayed.
- Verified with synthetic hives and logs on an NTFS volume written by independent
  tools (fixture `testdata/images/companions.dd.gz`). Replay of a real
  live-collected hive with its real logs through this path has **not** been
  verified.
