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
| File system | NTFS (MFT, attribute lists, data runs, sparse, alternate data streams, deleted entries); ext2, ext3 and ext4, read-only (in-use directory tree, extents and block maps, holes, hard links; symlinks and device nodes listed but not read as content) | NTFS-compressed and EFS-encrypted streams (reported), BitLocker (reported), ext inline data, encrypted ext files and meta_bg layouts (reported); FAT/exFAT/APFS (reported) |

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
tree (ext4) or the block map (ext2 and ext3). Deleted inodes are not listed,
and metadata checksums are not verified. A directory entry that points to a
free inode is not listed, although debugfs dumps it; that is the correct
behaviour for an in-use catalog.

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
