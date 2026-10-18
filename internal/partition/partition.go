// Package partition reads MBR (with extended/logical partitions) and GPT
// partition tables, and identifies what is inside each partition.
//
// It reports what is on the disk and says so when something is wrong.
// A damaged primary GPT falls back to the backup copy and a warning is
// recorded; a table that is unreadable at both ends is an error, not an
// empty disk. Partitions that lie partly outside the image are clamped
// and flagged, and ones entirely outside are dropped and flagged.
package partition

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"unicode/utf16"
)

// Scheme names a partitioning scheme.
type Scheme string

const (
	SchemeNone Scheme = "none" // a bare volume, no table
	SchemeMBR  Scheme = "mbr"
	SchemeGPT  Scheme = "gpt"
)

var (
	// ErrNoTable means the disk has neither a partition table nor a
	// recognisable bare volume.
	ErrNoTable = errors.New("no partition table or recognisable volume found")
	// ErrBadGPT means a GPT is present but unreadable at both ends.
	ErrBadGPT = errors.New("the GUID partition table is damaged and its backup is unusable")
)

// Partition is one entry of a partition table.
type Partition struct {
	Index       int
	Scheme      Scheme
	TypeID      string // MBR type byte ("07") or GPT type GUID
	TypeName    string
	Name        string // GPT partition name
	Bootable    bool
	Logical     bool
	StartLBA    uint64
	SectorCount uint64
	StartByte   int64
	SizeBytes   int64
	SectorSize  int
	// FS is what the partition's first sectors say it holds: "ntfs",
	// "bitlocker", "exfat", "fat32", "fat", "ext", or "unknown". It comes
	// from the contents, not from the declared type.
	FS string
}

// Reader returns a view of exactly this partition's bytes.
func (p Partition) Reader(r io.ReaderAt) *io.SectionReader {
	return io.NewSectionReader(r, p.StartByte, p.SizeBytes)
}

// Table is a disk's partitioning.
type Table struct {
	Scheme     Scheme
	SectorSize int
	DiskGUID   string
	Partitions []Partition
	Warnings   []string
}

// Read parses the partition table of a disk of the given size.
func Read(r io.ReaderAt, size int64, sectorSize int) (Table, error) {
	if sectorSize < 512 || sectorSize&(sectorSize-1) != 0 {
		sectorSize = 512
	}
	if size < int64(sectorSize) {
		return Table{}, fmt.Errorf("%w: the disk is smaller than one sector", ErrNoTable)
	}
	ss := int64(sectorSize)
	sector0 := make([]byte, ss)
	if _, err := r.ReadAt(sector0, 0); err != nil {
		return Table{}, err
	}
	tb := Table{SectorSize: sectorSize}

	// A volume with no partition table: its boot sector also ends in
	// 55 AA, so it must be recognised before the MBR check.
	if fs := fsFromBootSector(sector0); fs != "" {
		tb.Scheme = SchemeNone
		tb.Partitions = []Partition{{Index: 1, Scheme: SchemeNone, TypeName: "bare volume", StartLBA: 0,
			SectorCount: uint64(size / ss), StartByte: 0, SizeBytes: size, SectorSize: sectorSize, FS: fs}}
		return tb, nil
	}

	protective := hasProtectiveEntry(sector0)
	primary := readSector(r, size, ss, 1)
	backup := readSector(r, size, ss, size/ss-1)
	if protective || bytes.HasPrefix(primary, []byte("EFI PART")) || bytes.HasPrefix(backup, []byte("EFI PART")) {
		return readGPT(r, size, sectorSize, tb)
	}
	if len(sector0) >= 512 && sector0[510] == 0x55 && sector0[widthSig] == 0xAA {
		return readMBR(r, size, sectorSize, sector0, tb)
	}
	return Table{}, ErrNoTable
}

const widthSig = 511

func readSector(r io.ReaderAt, size, ss, lba int64) []byte {
	if lba < 0 || (lba+1)*ss > size {
		return nil
	}
	b := make([]byte, ss)
	if _, err := r.ReadAt(b, lba*ss); err != nil {
		return nil
	}
	return b
}

func hasProtectiveEntry(s []byte) bool {
	if len(s) < 512 || s[510] != 0x55 || s[511] != 0xAA {
		return false
	}
	for i := 0; i < 4; i++ {
		if s[446+16*i+4] == 0xEE {
			return true
		}
	}
	return false
}

// fsFromBootSector identifies a volume from the first sector alone.
func fsFromBootSector(b []byte) string {
	if len(b) < 512 {
		return ""
	}
	switch {
	case string(b[3:11]) == "NTFS    ":
		return "ntfs"
	case string(b[3:11]) == "-FVE-FS-":
		return "bitlocker"
	case string(b[3:11]) == "EXFAT   ":
		return "exfat"
	case string(b[82:90]) == "FAT32   ":
		return "fat32"
	case string(b[54:62]) == "FAT16   " || string(b[54:62]) == "FAT12   ":
		return "fat"
	}
	return ""
}

// Probe reports the file system a partition holds, from its contents.
func Probe(r io.ReaderAt, p Partition) string {
	n := int64(2048)
	if p.SizeBytes < n {
		n = p.SizeBytes
	}
	if n <= 0 {
		return "unknown"
	}
	b := make([]byte, n)
	if got, _ := r.ReadAt(b, p.StartByte); int64(got) < n {
		b = b[:got]
	}
	if fs := fsFromBootSector(b); fs != "" {
		return fs
	}
	if len(b) >= 1082 && b[1080] == 0x53 && b[1081] == 0xEF {
		return "ext"
	}
	return "unknown"
}

// ---- GPT

type gptHeader struct {
	entriesLBA uint64
	numEntries uint32
	entrySize  uint32
	entriesCRC uint32
	first, end uint64
	guid       string
}

func parseGPTHeader(b []byte, wantSig bool) (gptHeader, error) {
	if len(b) < 92 || string(b[:8]) != "EFI PART" {
		return gptHeader{}, errors.New("no GPT signature")
	}
	hsize := binary.LittleEndian.Uint32(b[12:])
	if hsize < 92 || int(hsize) > len(b) {
		return gptHeader{}, errors.New("implausible header size")
	}
	tmp := append([]byte(nil), b[:hsize]...)
	stored := binary.LittleEndian.Uint32(tmp[16:])
	binary.LittleEndian.PutUint32(tmp[16:], 0)
	if crc32.ChecksumIEEE(tmp) != stored {
		return gptHeader{}, errors.New("header fails its CRC")
	}
	h := gptHeader{
		first:      binary.LittleEndian.Uint64(b[40:]),
		end:        binary.LittleEndian.Uint64(b[48:]),
		guid:       guidString(b[56:72]),
		entriesLBA: binary.LittleEndian.Uint64(b[72:]),
		numEntries: binary.LittleEndian.Uint32(b[80:]),
		entrySize:  binary.LittleEndian.Uint32(b[84:]),
		entriesCRC: binary.LittleEndian.Uint32(b[88:]),
	}
	if h.entrySize < 128 || h.entrySize > 4096 || h.entrySize%8 != 0 || h.numEntries == 0 || h.numEntries > 4096 ||
		uint64(h.entrySize)*uint64(h.numEntries) > 4<<20 {
		return gptHeader{}, errors.New("implausible entry array geometry")
	}
	return h, nil
}

func readGPT(r io.ReaderAt, size int64, sectorSize int, tb Table) (Table, error) {
	ss := int64(sectorSize)
	lastLBA := size/ss - 1
	tb.Scheme = SchemeGPT

	type attempt struct {
		name string
		lba  int64
	}
	var problems []string
	var parts []Partition
	used := ""
	for _, a := range []attempt{{"primary", 1}, {"backup", lastLBA}} {
		hb := readSector(r, size, ss, a.lba)
		h, err := parseGPTHeader(hb, true)
		if err != nil {
			problems = append(problems, fmt.Sprintf("the %s GPT header is unusable: %v", a.name, err))
			continue
		}
		arr := make([]byte, int(h.entrySize)*int(h.numEntries))
		if h.entriesLBA > uint64(size/ss) {
			problems = append(problems, fmt.Sprintf("the %s GPT entry array lies outside the disk", a.name))
			continue
		}
		if n, _ := r.ReadAt(arr, int64(h.entriesLBA)*ss); n < len(arr) {
			problems = append(problems, fmt.Sprintf("the %s GPT entry array is truncated", a.name))
			continue
		}
		if crc32.ChecksumIEEE(arr) != h.entriesCRC {
			problems = append(problems, fmt.Sprintf("the %s GPT entry array fails its CRC", a.name))
			continue
		}
		used, tb.DiskGUID = a.name, h.guid
		parts = gptPartitions(arr, h, size, sectorSize, &tb)
		break
	}
	if used == "" {
		return Table{}, fmt.Errorf("%w: %s", ErrBadGPT, strings.Join(problems, "; "))
	}
	tb.Warnings = append(tb.Warnings, problems...)
	if used == "backup" {
		tb.Warnings = append(tb.Warnings, "the partition table was read from the BACKUP GPT because the primary was damaged; the primary should be treated as evidence of tampering or corruption")
	}
	tb.Partitions = parts
	for i := range tb.Partitions {
		tb.Partitions[i].FS = Probe(r, tb.Partitions[i])
	}
	return tb, nil
}

func gptPartitions(arr []byte, h gptHeader, size int64, sectorSize int, tb *Table) []Partition {
	var out []Partition
	diskSectors := uint64(size / int64(sectorSize))
	for i := 0; i < int(h.numEntries); i++ {
		e := arr[i*int(h.entrySize) : (i+1)*int(h.entrySize)]
		if allZero(e[:16]) {
			continue
		}
		first := binary.LittleEndian.Uint64(e[32:])
		last := binary.LittleEndian.Uint64(e[40:])
		if last < first {
			tb.Warnings = append(tb.Warnings, fmt.Sprintf("GPT entry %d ends before it starts and was ignored", i+1))
			continue
		}
		if first >= diskSectors {
			tb.Warnings = append(tb.Warnings, fmt.Sprintf("GPT entry %d starts at sector %d, beyond the end of the image, and was ignored", i+1, first))
			continue
		}
		count := last - first + 1
		if first+count > diskSectors {
			count = diskSectors - first
			tb.Warnings = append(tb.Warnings, fmt.Sprintf("GPT entry %d extends beyond the end of the image (truncated acquisition?) and was clamped", i+1))
		}
		typeID := guidString(e[:16])
		out = append(out, Partition{
			Index: i + 1, Scheme: SchemeGPT, TypeID: typeID, TypeName: gptTypeName(typeID), Name: utf16Name(e[56:128]),
			Bootable: binary.LittleEndian.Uint64(e[48:])&4 != 0, StartLBA: first, SectorCount: count,
			StartByte: int64(first) * int64(sectorSize), SizeBytes: int64(count) * int64(sectorSize), SectorSize: sectorSize,
		})
	}
	return out
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func guidString(b []byte) string {
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		binary.LittleEndian.Uint32(b[0:]), binary.LittleEndian.Uint16(b[4:]), binary.LittleEndian.Uint16(b[6:]),
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func utf16Name(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

var gptTypes = map[string]string{
	"C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System",
	"E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft reserved",
	"EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft basic data",
	"DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows recovery",
	"E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D": "Windows Storage Spaces",
	"5808C8AA-7E8F-42E0-85D2-E1E90434CFB3": "Windows LDM metadata (dynamic disk)",
	"AF9B60A0-1431-4F62-BC68-3311714A69AD": "Windows LDM data (dynamic disk)",
	"0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux filesystem",
	"0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux swap",
	"E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
	"7C3457EF-0000-11AA-AA11-00306543ECAC": "Apple APFS",
	"48465300-0000-11AA-AA11-00306543ECAC": "Apple HFS+",
}

func gptTypeName(id string) string {
	if n, ok := gptTypes[id]; ok {
		return n
	}
	return "unknown type"
}

// ---- MBR

var mbrTypes = map[byte]string{
	0x01: "FAT12", 0x04: "FAT16", 0x06: "FAT16", 0x0E: "FAT16 (LBA)", 0x0B: "FAT32", 0x0C: "FAT32 (LBA)",
	0x07: "NTFS / exFAT / HPFS", 0x27: "Windows recovery (hidden NTFS)", 0x42: "Windows dynamic disk (LDM)",
	0x82: "Linux swap", 0x83: "Linux", 0x8E: "Linux LVM", 0xEE: "GPT protective", 0xAF: "Apple HFS",
	0xA5: "FreeBSD", 0xEF: "EFI System",
}

func isExtended(t byte) bool { return t == 0x05 || t == 0x0F || t == 0x85 || t == 0xC5 }

func readMBR(r io.ReaderAt, size int64, sectorSize int, s0 []byte, tb Table) (Table, error) {
	ss := int64(sectorSize)
	diskSectors := uint64(size / ss)
	tb.Scheme = SchemeMBR
	var extStart uint64
	extSeen := 0

	for i := 0; i < 4; i++ {
		e := s0[446+16*i : 446+16*i+16]
		if e[0] != 0x00 && e[0] != 0x80 {
			return Table{}, fmt.Errorf("%w: entry %d has an invalid status byte 0x%02X", ErrNoTable, i+1, e[0])
		}
	}
	for i := 0; i < 4; i++ {
		e := s0[446+16*i : 446+16*i+16]
		typ := e[4]
		start := uint64(binary.LittleEndian.Uint32(e[8:]))
		count := uint64(binary.LittleEndian.Uint32(e[12:]))
		if typ == 0 || count == 0 {
			continue
		}
		if isExtended(typ) {
			extSeen++
			if extSeen == 1 {
				extStart = start
			}
			continue
		}
		if p, ok := mbrPartition(i+1, e[0] == 0x80, false, typ, start, count, diskSectors, sectorSize, &tb); ok {
			tb.Partitions = append(tb.Partitions, p)
		}
	}
	if extSeen > 1 {
		tb.Warnings = append(tb.Warnings, "more than one extended partition is declared; only the first was followed")
	}
	if extStart != 0 {
		visited := map[uint64]bool{}
		ebrLBA := extStart
		for idx := 5; len(visited) < 128; idx++ {
			if visited[ebrLBA] {
				tb.Warnings = append(tb.Warnings, "the extended partition chain loops back on itself; the walk was stopped")
				break
			}
			visited[ebrLBA] = true
			b := readSector(r, size, ss, int64(ebrLBA))
			if b == nil || b[510] != 0x55 || b[511] != 0xAA {
				tb.Warnings = append(tb.Warnings, fmt.Sprintf("the extended boot record at sector %d is missing or invalid; the chain ends there", ebrLBA))
				break
			}
			e0, e1 := b[446:462], b[462:478]
			if t, c := e0[4], binary.LittleEndian.Uint32(e0[12:]); t != 0 && c != 0 {
				start := ebrLBA + uint64(binary.LittleEndian.Uint32(e0[8:]))
				if p, ok := mbrPartition(idx, e0[0] == 0x80, true, t, start, uint64(c), diskSectors, sectorSize, &tb); ok {
					tb.Partitions = append(tb.Partitions, p)
				}
			}
			if isExtended(e1[4]) && binary.LittleEndian.Uint32(e1[12:]) != 0 {
				ebrLBA = extStart + uint64(binary.LittleEndian.Uint32(e1[8:]))
				continue
			}
			break
		}
		if len(visited) >= 128 {
			tb.Warnings = append(tb.Warnings, "the extended partition chain is implausibly long and was cut at 128 entries")
		}
	}
	for i := range tb.Partitions {
		tb.Partitions[i].FS = Probe(r, tb.Partitions[i])
	}
	return tb, nil
}

func mbrPartition(idx int, boot, logical bool, typ byte, start, count, diskSectors uint64, sectorSize int, tb *Table) (Partition, bool) {
	if start >= diskSectors {
		tb.Warnings = append(tb.Warnings, fmt.Sprintf("partition %d starts at sector %d, beyond the end of the image, and was ignored", idx, start))
		return Partition{}, false
	}
	if start+count > diskSectors {
		count = diskSectors - start
		tb.Warnings = append(tb.Warnings, fmt.Sprintf("partition %d extends beyond the end of the image (truncated acquisition?) and was clamped", idx))
	}
	name, ok := mbrTypes[typ]
	if !ok {
		name = "unknown type"
	}
	return Partition{
		Index: idx, Scheme: SchemeMBR, TypeID: fmt.Sprintf("%02X", typ), TypeName: name, Bootable: boot, Logical: logical,
		StartLBA: start, SectorCount: count, StartByte: int64(start) * int64(sectorSize), SizeBytes: int64(count) * int64(sectorSize),
		SectorSize: sectorSize,
	}, true
}
