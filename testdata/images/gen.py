#!/usr/bin/env python3
"""Regenerates the disk-image fixtures in this directory.

The fixtures are NOT produced by Tracefall's own code. Every container and
file-system structure is written by an independent tool, so the Go readers
are tested against bytes they did not help create:

  NTFS volume      mkntfs + the ntfs-3g driver (mounted in user space)
  partition tables sgdisk (GPT) and sfdisk (MBR)
  E01 / EWF        ewfacquire from libewf (the reference implementation)

Needs: mkntfs, ntfs-3g, fusermount3, sgdisk, sfdisk, ewfacquire (+ewfinfo),
python3.  Everything is synthetic: names, contents and timestamps are
invented, and the registry/EVTX/prefetch samples are the synthetic ones
already in testdata/native_samples.

    python3 testdata/images/gen.py

writes into this directory:
    gpt.dd.gz  mbr.dd.gz        raw disks (gzip only to keep the repo small)
    gpt.E01                     E01 of the whole disk, deflate-compressed
    gpt-store.E01 .E02 .E03     E01 of the first 2 MiB, uncompressed and split
                                into 1 MiB segments (the only multi-segment case)
    manifest.json               what every image must contain (ground truth
                                taken from the MOUNTED file system, not from us)
"""
import gzip, hashlib, json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "..", "native_samples")
SECTOR = 512
VOL_BYTES = 24 * 1024 * 1024
PART_START = 2048 * SECTOR            # 1 MiB
DISK_BYTES = 28 * 1024 * 1024


def run(*a, **kw):
    kw.setdefault("check", True)
    return subprocess.run(a, **kw)


def pattern(n, seed):
    """Deterministic, offset-stamped data: a misplaced read cannot match."""
    out = bytearray()
    i = 0
    while len(out) < n:
        stamp = hashlib.sha256(b"%s:%d" % (seed.encode(), i)).hexdigest().encode() + (b"#%08d|" % i)
        out += (stamp * (4096 // len(stamp) + 1))[:4096]   # unique per 4 KiB block, still compressible
        i += 1
    return bytes(out[:n])


def sha(b):
    return hashlib.sha256(b).hexdigest()


def build_volume(tmp):
    img = os.path.join(tmp, "vol.img")
    mnt = os.path.join(tmp, "mnt")
    with open(img, "wb") as f:
        f.truncate(VOL_BYTES)
    run("mkntfs", "-F", "-Q", "-q", "-L", "TFIMG", "-s", "512", "-c", "4096", img, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.mkdir(mnt)
    run("ntfs-3g", "-o", "rw,streams_interface=windows", img, mnt)
    files = {}       # path -> bytes
    streams = {}     # "path:stream" -> bytes
    dirs = []
    deleted = []

    def put(path, data):
        full = os.path.join(mnt, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as f:
            f.write(data)
        files["/" + path] = data

    try:
        put("hello.txt", b"hello from a resident file\n")
        put("r\u00e9sum\u00e9_\u65e5\u672c\u8a9e.txt", "unicode name\n".encode())
        put("big.bin", pattern(1_500_000, "big"))
        put("Users/alice/Documents/notes.txt", b"alice's notes\n" * 40)

        # Real artifact samples placed where Windows keeps them, so the
        # same images exercise automatic artifact extraction later.
        place = {
            "Windows/System32/winevt/Logs/Security.evtx": "Security.evtx",
            "Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx": "Sysmon.evtx",
            "Windows/System32/config/SYSTEM": "SYSTEM",
            "Windows/System32/config/SOFTWARE": "SOFTWARE",
            "Users/alice/NTUSER.DAT": "NTUSER.DAT",
            "Windows/Prefetch/EDGE.EXE-11111111.pf": "EDGE.EXE-11111111.pf",
            "Windows/Prefetch/UPDATE.EXE-0BADF00D.pf": "UPDATE.EXE-0BADF00D.pf",
            "Users/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt": "ConsoleHost_history.txt",
        }
        for dest, src in place.items():
            put(dest, open(os.path.join(SAMPLES, src), "rb").read())

        # Alternate data streams.
        put("ads.txt", b"visible content\n")
        for name, data in {"secret": b"hidden stream payload\n", "Zone.Identifier": b"[ZoneTransfer]\nZoneId=3\n"}.items():
            with open(os.path.join(mnt, "ads.txt:" + name), "wb") as f:
                f.write(data)
            streams["/ads.txt:" + name] = data

        # A directory big enough to need $INDEX_ALLOCATION blocks.
        for i in range(1200):
            put("many/file_%04d_with_a_reasonably_long_name.txt" % i, b"%d\n" % i)

        # A sparse file: 3 MiB logical, data only at both ends.
        sp = os.path.join(mnt, "sparse.bin")
        with open(sp, "wb") as f:
            f.write(b"HEAD" * 1024)
            f.seek(3 * 1024 * 1024 - 4096)
            f.write(b"TAIL" * 1024)
        files["/sparse.bin"] = open(sp, "rb").read()

        # Heavily fragmented files. Eight files grown one cluster at a time
        # in round-robin, each fsynced, are interleaved on disk: every file
        # ends up with hundreds of extents, more than one MFT record can
        # describe, which makes NTFS add an $ATTRIBUTE_LIST. (Checked with
        # ntfsinfo: frag/f0.bin has ~340 runs and an ATTRIBUTE_LIST.)
        os.makedirs(os.path.join(mnt, "frag"))
        handles = [open(os.path.join(mnt, "frag", "f%d.bin" % i), "wb") for i in range(8)]
        bufs = [bytearray() for _ in handles]
        for blk in range(400):
            for i, h in enumerate(handles):
                stamp = hashlib.sha256(b"frag%d:%d" % (i, blk)).hexdigest().encode() + (b"#%08d|" % blk)
                chunk = (stamp * (4096 // len(stamp) + 1))[:4096]
                h.write(chunk); h.flush(); os.fsync(h.fileno())
                bufs[i] += chunk
        for h in handles:
            h.close()
        for i, b in enumerate(bufs):
            files["/frag/f%d.bin" % i] = bytes(b)

        # A deleted file: its MFT record stays, marked not-in-use.
        put("deleted/secret_plan.txt", b"this file is deleted before imaging\n")
        os.remove(os.path.join(mnt, "deleted/secret_plan.txt"))
        deleted.append("/deleted/secret_plan.txt")
        del files["/deleted/secret_plan.txt"]

        # Ground truth: read back through the mounted driver.
        for root, ds, fs in os.walk(mnt):
            for d in ds:
                dirs.append("/" + os.path.relpath(os.path.join(root, d), mnt))
        manifest_files = {}
        for p in files:
            data = open(os.path.join(mnt, p.lstrip("/")), "rb").read()
            manifest_files[p] = {"size": len(data), "sha256": sha(data)}
        manifest_streams = {k: {"size": len(v), "sha256": sha(v)} for k, v in streams.items()}
    finally:
        run("fusermount3", "-u", mnt)
    return img, {"files": manifest_files, "streams": manifest_streams, "dirs": sorted(set(dirs)), "deleted": deleted, "volume_label": "TFIMG"}


def raw_hashes(path):
    md5, sha1, s256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            md5.update(b); sha1.update(b); s256.update(b)
    return {"size": os.path.getsize(path), "md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": s256.hexdigest()}


def make_disk(tmp, vol, scheme):
    disk = os.path.join(tmp, scheme + ".dd")
    with open(disk, "wb") as f:
        f.truncate(DISK_BYTES)
    if scheme == "gpt":
        run("sgdisk", "-o", "-n", "1:2048:%d" % (2048 + VOL_BYTES // SECTOR - 1), "-t", "1:0700", "-c", "1:Basic data",
            "-n", "2:0:+2M", "-t", "2:8300", "-c", "2:Linux data", disk, stdout=subprocess.DEVNULL)
        offset = PART_START
    else:
        # primary NTFS (type 07), extended container with one logical
        script = "label: dos\nunit: sectors\n%d,%d,7\n,,5\n,2000,83\n" % (2048, VOL_BYTES // SECTOR)
        run("sfdisk", "-q", disk, input=script.encode(), stdout=subprocess.DEVNULL)
        offset = PART_START
    with open(vol, "rb") as v, open(disk, "r+b") as d:
        d.seek(offset)
        shutil.copyfileobj(v, d)
    return disk


def acquire(raw, base, compression, segment=None, ewf_format="encase6"):
    cmd = ["ewfacquire", "-u", "-t", base, "-C", "CASE-0001", "-D", "Tracefall synthetic fixture", "-e", "Fixture Examiner",
           "-E", "EV-001", "-N", "synthetic; contains no real data", "-m", "fixed", "-M", "physical",
           "-c", compression, "-f", ewf_format, "-d", "sha1", "-b", "64"]
    if segment:
        cmd += ["-S", segment]
    cmd.append(raw)
    run(*cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    tmp = tempfile.mkdtemp(prefix="tfimg")
    try:
        vol, truth = build_volume(tmp)
        out = {"volume": truth, "images": {}}
        for scheme in ("gpt", "mbr"):
            disk = make_disk(tmp, vol, scheme)
            out["images"][scheme] = raw_hashes(disk)
            with open(disk, "rb") as f, gzip.GzipFile(os.path.join(HERE, scheme + ".dd.gz"), "wb", compresslevel=9, mtime=0) as g:
                shutil.copyfileobj(f, g)
            if scheme == "gpt":
                # "stored" (uncompressed) chunks: a small prefix of the disk only,
                # so the repository does not carry a 28 MiB uncompressed image.
                small = os.path.join(tmp, "store.dd")
                with open(disk, "rb") as f, open(small, "wb") as g:
                    g.write(f.read(2 * 1024 * 1024))
                out["images"]["store"] = raw_hashes(small)
                for name, comp, seg, src in (("gpt", "deflate:fast", None, disk), ("gpt-store", "none", "1MiB", small)):
                    for old in os.listdir(HERE):
                        if old.startswith(name + ".") and old[len(name) + 1:len(name) + 2] in ("E",) :
                            os.remove(os.path.join(HERE, old))
                    acquire(src, os.path.join(HERE, name), comp, seg)
        with open(os.path.join(HERE, "manifest.json"), "w") as f:
            json.dump(out, f, indent=1, sort_keys=True)
            f.write("\n")
        print("wrote fixtures:", sorted(os.listdir(HERE)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
