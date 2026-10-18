package partition

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"hash/crc32"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtures = "../../testdata/images"

func rawDisk(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open(filepath.Join(fixtures, name+".dd.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func read(t *testing.T, b []byte) Table {
	t.Helper()
	tb, err := Read(bytes.NewReader(b), int64(len(b)), 512)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

func TestGPT_ReadsWhatSgdiskWrote(t *testing.T) {
	disk := rawDisk(t, "gpt")
	tb := read(t, disk)
	if tb.Scheme != SchemeGPT || len(tb.Partitions) != 2 {
		t.Fatalf("table = %+v", tb)
	}
	p1, p2 := tb.Partitions[0], tb.Partitions[1]
	if p1.Index != 1 || p1.StartLBA != 2048 || p1.SectorCount != 49152 || p1.StartByte != 2048*512 || p1.SizeBytes != 24*1024*1024 {
		t.Errorf("partition 1 geometry = %+v", p1)
	}
	if p1.Name != "Basic data" || p1.TypeID != "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" || p1.TypeName != "Microsoft basic data" {
		t.Errorf("partition 1 identity = %+v", p1)
	}
	if p2.Index != 2 || p2.SectorCount != 4096 || p2.StartLBA != 51200 || p2.TypeName != "Linux filesystem" || p2.Name != "Linux data" {
		t.Errorf("partition 2 = %+v", p2)
	}
	if tb.DiskGUID == "" || len(tb.Warnings) != 0 {
		t.Errorf("guid=%q warnings=%v", tb.DiskGUID, tb.Warnings)
	}
}

func TestMBR_ReadsPrimaryAndLogicalPartitions(t *testing.T) {
	tb := read(t, rawDisk(t, "mbr"))
	if tb.Scheme != SchemeMBR {
		t.Fatalf("scheme = %s", tb.Scheme)
	}
	if len(tb.Partitions) != 2 {
		t.Fatalf("partitions = %+v (the extended container itself is not a data partition)", tb.Partitions)
	}
	p1, p5 := tb.Partitions[0], tb.Partitions[1]
	if p1.Index != 1 || p1.StartLBA != 2048 || p1.SectorCount != 49152 || p1.TypeID != "07" {
		t.Errorf("primary = %+v", p1)
	}
	if p5.Index != 5 || !p5.Logical || p5.SectorCount != 2000 || p5.TypeID != "83" || p5.StartLBA <= p1.StartLBA+p1.SectorCount {
		t.Errorf("logical = %+v", p5)
	}
}

func TestProbe_IdentifiesTheFileSystemByItsBootSector(t *testing.T) {
	disk := rawDisk(t, "gpt")
	tb := read(t, disk)
	r := bytes.NewReader(disk)
	if got := Probe(r, tb.Partitions[0]); got != "ntfs" {
		t.Errorf("partition 1 = %q, want ntfs", got)
	}
	if got := Probe(r, tb.Partitions[1]); got != "unknown" {
		t.Errorf("blank partition 2 = %q, want unknown", got)
	}
	fve := make([]byte, 512)
	copy(fve[3:], "-FVE-FS-")
	if got := Probe(bytes.NewReader(fve), Partition{StartByte: 0, SizeBytes: 512}); got != "bitlocker" {
		t.Errorf("bitlocker volume reported as %q: an encrypted volume must never look empty", got)
	}
}

func TestBareVolumeWithoutAPartitionTable(t *testing.T) {
	disk := rawDisk(t, "gpt")
	vol := disk[2048*512 : 2048*512+49152*512]
	tb := read(t, vol)
	if tb.Scheme != SchemeNone || len(tb.Partitions) != 1 || tb.Partitions[0].FS != "ntfs" ||
		tb.Partitions[0].StartByte != 0 || tb.Partitions[0].SizeBytes != int64(len(vol)) {
		t.Errorf("a bare NTFS volume = %+v", tb)
	}
}

func TestGPT_UsesTheBackupWhenThePrimaryIsDamagedAndSaysSo(t *testing.T) {
	disk := rawDisk(t, "gpt")
	bad := append([]byte(nil), disk...)
	bad[512+30] ^= 0xff // inside the primary header, breaking its CRC
	tb := read(t, bad)
	if tb.Scheme != SchemeGPT || len(tb.Partitions) != 2 {
		t.Fatalf("backup GPT not used: %+v", tb)
	}
	if len(tb.Warnings) == 0 || !strings.Contains(strings.ToLower(strings.Join(tb.Warnings, " ")), "backup") {
		t.Errorf("silently used the backup table: warnings = %v", tb.Warnings)
	}
}

func TestGPT_DamagedEntriesAreNotTrusted(t *testing.T) {
	disk := rawDisk(t, "gpt")
	bad := append([]byte(nil), disk...)
	bad[1024+40] ^= 0xff // first partition entry's first LBA; primary entries CRC now wrong
	tb := read(t, bad)
	if len(tb.Partitions) != 2 || tb.Partitions[0].StartLBA != 2048 {
		t.Errorf("entries from a damaged table were used: %+v", tb.Partitions)
	}
	if len(tb.Warnings) == 0 {
		t.Error("no warning although the primary entry array failed its CRC")
	}
}

func TestGPT_WithBothTablesDamagedIsAnErrorNotAnEmptyDisk(t *testing.T) {
	disk := rawDisk(t, "gpt")
	bad := append([]byte(nil), disk...)
	bad[512+30] ^= 0xff
	bad[len(bad)-512+30] ^= 0xff
	if _, err := Read(bytes.NewReader(bad), int64(len(bad)), 512); err == nil {
		t.Error("a disk whose GPT is unreadable on both ends was reported as having no partitions")
	}
}

func TestGPT_EntryOutsideTheDiskIsRejectedWithAWarning(t *testing.T) {
	disk := append([]byte(nil), rawDisk(t, "gpt")...)
	// Rewrite partition 2 to end far beyond the disk, and fix both CRCs
	// so only the geometry is wrong.
	ent := disk[1024+128 : 1024+256]
	binary.LittleEndian.PutUint64(ent[32:], 1<<40)
	binary.LittleEndian.PutUint64(ent[40:], 1<<40+10)
	entries := disk[1024 : 1024+128*128]
	hdr := disk[512 : 512+92]
	binary.LittleEndian.PutUint32(hdr[88:], crc32.ChecksumIEEE(entries))
	binary.LittleEndian.PutUint32(hdr[16:], 0)
	binary.LittleEndian.PutUint32(hdr[16:], crc32.ChecksumIEEE(hdr))
	tb := read(t, disk)
	if len(tb.Partitions) != 1 || len(tb.Warnings) == 0 {
		t.Errorf("an out-of-range partition was accepted: %+v warnings=%v", tb.Partitions, tb.Warnings)
	}
}

func TestMBR_ExtendedChainLoopIsStopped(t *testing.T) {
	disk := append([]byte(nil), rawDisk(t, "mbr")...)
	// Find the EBR (first extended partition's start) and make its link
	// point back at itself.
	mbr := disk[:512]
	var extStart uint32
	for i := 0; i < 4; i++ {
		e := mbr[446+16*i : 446+16*i+16]
		if e[4] == 0x05 {
			extStart = binary.LittleEndian.Uint32(e[8:])
		}
	}
	if extStart == 0 {
		t.Fatal("fixture has no extended partition")
	}
	ebr := disk[int(extStart)*512 : int(extStart)*512+512]
	binary.LittleEndian.PutUint32(ebr[446+16+8:], 0) // next EBR = extStart + 0 = itself
	ebr[446+16+4] = 0x05
	binary.LittleEndian.PutUint32(ebr[446+16+12:], 10)
	tb := read(t, disk) // must terminate
	if len(tb.Warnings) == 0 {
		t.Errorf("a looping EBR chain produced no warning: %+v", tb)
	}
}

func TestRead_NeverPanicsOnGarbage(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	disk := rawDisk(t, "gpt")
	for i := 0; i < 300; i++ {
		b := append([]byte(nil), disk[:64*1024]...)
		for k := 0; k < 1+rng.Intn(20); k++ {
			b[rng.Intn(len(b))] = byte(rng.Intn(256))
		}
		Read(bytes.NewReader(b), int64(len(b)), 512)
	}
	junk := make([]byte, 4096)
	rng.Read(junk)
	if tb, err := Read(bytes.NewReader(junk), int64(len(junk)), 512); err == nil && len(tb.Partitions) != 0 {
		t.Errorf("random bytes yielded partitions: %+v", tb)
	}
	if _, err := Read(bytes.NewReader(nil), 0, 512); err == nil {
		t.Error("an empty disk was accepted")
	}
}

func TestPartitionReaderIsBoundedToItsPartition(t *testing.T) {
	disk := rawDisk(t, "gpt")
	tb := read(t, disk)
	sr := tb.Partitions[1].Reader(bytes.NewReader(disk))
	if sr.Size() != 4096*512 {
		t.Errorf("size = %d", sr.Size())
	}
	buf := make([]byte, 1000)
	if n, err := sr.ReadAt(buf, sr.Size()-10); n != 10 || err != io.EOF {
		t.Errorf("a read past the partition leaked bytes of the next area: n=%d err=%v", n, err)
	}
}
