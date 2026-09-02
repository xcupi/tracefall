// Package mftgen builds synthetic NTFS $MFT tables in memory, for TEST
// FIXTURES ONLY.
//
// A real $MFT lists every file on a real machine, so one cannot be
// committed. This emits the same structures a real table uses -- FILE
// record headers, update sequence arrays with genuine fixups,
// $STANDARD_INFORMATION, $FILE_NAME and resident/non-resident $DATA --
// because a fixture that skipped them would not exercise the reader that
// has to handle them.
//
// It lives outside internal/ntfs so no production code can import an
// $MFT writer by accident.
package mftgen

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// RecordSize is the allocation size every record in a generated table
// uses. 1024 is what NTFS uses on essentially every real volume.
const RecordSize = 1024

// SectorSize is the fixup granularity.
const SectorSize = 512

// Namespaces, mirroring internal/ntfs.
const (
	NamespacePOSIX    = 0
	NamespaceWin32    = 1
	NamespaceDOS      = 2
	NamespaceWin32DOS = 3
)

// Times is one MACB set.
type Times struct {
	Created  time.Time
	Modified time.Time
	Changed  time.Time
	Accessed time.Time
}

// Name is one $FILE_NAME attribute to emit.
type Name struct {
	Name      string
	Namespace uint8
	ParentRef uint64
	ParentSeq uint16
	// Times defaults to the record's $SI times when zero.
	Times        Times
	LogicalSize  uint64
	PhysicalSize uint64
}

// File describes one FILE record to build.
type File struct {
	RecordNumber   uint64
	SequenceNumber uint16
	InUse          bool
	IsDirectory    bool
	HardLinks      uint16
	// BaseRecordRef marks this as an extension of another record.
	BaseRecordRef uint64

	// OmitStandardInformation builds a record with no $SI attribute.
	OmitStandardInformation bool
	SI                      Times

	Names []Name

	// Data controls the unnamed $DATA attribute.
	//   nil                  -> no $DATA at all (as for a directory)
	//   ResidentData         -> content stored inside the record
	//   NonResidentData      -> sizes only, as a real large file
	ResidentData    []byte
	NonResidentData *NonResident

	// WithAttributeList adds an (empty) $ATTRIBUTE_LIST, marking the
	// record as one whose attributes overflow elsewhere.
	WithAttributeList bool
}

// NonResident describes a non-resident $DATA attribute's sizes.
type NonResident struct {
	AllocatedSize   uint64
	RealSize        uint64
	InitializedSize uint64
}

// Build assembles a whole $MFT from the given records, in order.
//
// Records are placed at their RecordNumber index, and any gap is left as
// zeroed slack -- exactly as a real table carries unused records.
func Build(files []File) []byte {
	maxIndex := uint64(0)
	for _, f := range files {
		if f.RecordNumber > maxIndex {
			maxIndex = f.RecordNumber
		}
	}
	out := make([]byte, int(maxIndex+1)*RecordSize)
	for _, f := range files {
		rec := BuildRecord(f)
		copy(out[int(f.RecordNumber)*RecordSize:], rec)
	}
	return out
}

// BuildRecord assembles one FILE record, fixups included.
func BuildRecord(f File) []byte {
	rec := make([]byte, RecordSize)

	const usaOffset = 0x30
	sectors := RecordSize / SectorSize
	usaCount := sectors + 1
	firstAttr := usaOffset + usaCount*2
	if firstAttr%8 != 0 {
		firstAttr += 8 - firstAttr%8
	}

	copy(rec[0:4], "FILE")
	binary.LittleEndian.PutUint16(rec[0x04:], uint16(usaOffset))
	binary.LittleEndian.PutUint16(rec[0x06:], uint16(usaCount))
	binary.LittleEndian.PutUint64(rec[0x08:], 0x0102030405060708) // $LogFile LSN
	binary.LittleEndian.PutUint16(rec[0x10:], f.SequenceNumber)
	binary.LittleEndian.PutUint16(rec[0x12:], f.HardLinks)
	binary.LittleEndian.PutUint16(rec[0x14:], uint16(firstAttr))

	var flags uint16
	if f.InUse {
		flags |= 0x0001
	}
	if f.IsDirectory {
		flags |= 0x0002
	}
	binary.LittleEndian.PutUint16(rec[0x16:], flags)
	binary.LittleEndian.PutUint32(rec[0x1C:], RecordSize)
	binary.LittleEndian.PutUint64(rec[0x20:], f.BaseRecordRef)
	binary.LittleEndian.PutUint16(rec[0x28:], 6) // next attribute id
	binary.LittleEndian.PutUint32(rec[0x2C:], uint32(f.RecordNumber))

	off := firstAttr
	id := uint16(0)
	nextID := func() uint16 { id++; return id }

	if !f.OmitStandardInformation {
		content := make([]byte, 48)
		binary.LittleEndian.PutUint64(content[0x00:], toFileTime(f.SI.Created))
		binary.LittleEndian.PutUint64(content[0x08:], toFileTime(f.SI.Modified))
		binary.LittleEndian.PutUint64(content[0x10:], toFileTime(f.SI.Changed))
		binary.LittleEndian.PutUint64(content[0x18:], toFileTime(f.SI.Accessed))
		binary.LittleEndian.PutUint32(content[0x20:], 0x20) // FILE_ATTRIBUTE_ARCHIVE
		off = putResident(rec, off, 0x10, nextID(), content)
	}

	if f.WithAttributeList {
		off = putResident(rec, off, 0x20, nextID(), make([]byte, 32))
	}

	for _, n := range f.Names {
		times := n.Times
		if !times.Created.IsZero() || !times.Modified.IsZero() || !times.Changed.IsZero() || !times.Accessed.IsZero() {
			// use as given
		} else {
			times = f.SI
		}
		units := utf16.Encode([]rune(n.Name))
		content := make([]byte, 0x42+len(units)*2)
		binary.LittleEndian.PutUint64(content[0x00:], n.ParentRef|uint64(n.ParentSeq)<<48)
		binary.LittleEndian.PutUint64(content[0x08:], toFileTime(times.Created))
		binary.LittleEndian.PutUint64(content[0x10:], toFileTime(times.Modified))
		binary.LittleEndian.PutUint64(content[0x18:], toFileTime(times.Changed))
		binary.LittleEndian.PutUint64(content[0x20:], toFileTime(times.Accessed))
		binary.LittleEndian.PutUint64(content[0x28:], n.PhysicalSize)
		binary.LittleEndian.PutUint64(content[0x30:], n.LogicalSize)
		content[0x40] = byte(len(units))
		content[0x41] = n.Namespace
		for i, u := range units {
			binary.LittleEndian.PutUint16(content[0x42+i*2:], u)
		}
		off = putResident(rec, off, 0x30, nextID(), content)
	}

	switch {
	case f.NonResidentData != nil:
		off = putNonResidentData(rec, off, nextID(), *f.NonResidentData)
	case f.ResidentData != nil:
		off = putResident(rec, off, 0x80, nextID(), f.ResidentData)
	}

	// End-of-attributes marker.
	binary.LittleEndian.PutUint32(rec[off:], 0xFFFFFFFF)
	off += 8
	binary.LittleEndian.PutUint32(rec[0x18:], uint32(off)) // used size

	applyFixups(rec, usaOffset, usaCount)
	return rec
}

// putResident writes one resident attribute and returns the next offset.
func putResident(rec []byte, off int, attrType uint32, id uint16, content []byte) int {
	const headerLen = 0x18
	length := headerLen + len(content)
	if length%8 != 0 {
		length += 8 - length%8
	}
	if off+length > len(rec) {
		return off
	}
	binary.LittleEndian.PutUint32(rec[off+0x00:], attrType)
	binary.LittleEndian.PutUint32(rec[off+0x04:], uint32(length))
	rec[off+0x08] = 0 // resident
	rec[off+0x09] = 0 // no name
	binary.LittleEndian.PutUint16(rec[off+0x0A:], 0)
	binary.LittleEndian.PutUint16(rec[off+0x0C:], 0)
	binary.LittleEndian.PutUint16(rec[off+0x0E:], id)
	binary.LittleEndian.PutUint32(rec[off+0x10:], uint32(len(content)))
	binary.LittleEndian.PutUint16(rec[off+0x14:], headerLen)
	copy(rec[off+headerLen:], content)
	return off + length
}

// putNonResidentData writes a non-resident $DATA attribute carrying only
// its sizes, which is all a metadata reader needs.
func putNonResidentData(rec []byte, off int, id uint16, nr NonResident) int {
	const headerLen = 0x40
	length := headerLen + 8
	if off+length > len(rec) {
		return off
	}
	binary.LittleEndian.PutUint32(rec[off+0x00:], 0x80)
	binary.LittleEndian.PutUint32(rec[off+0x04:], uint32(length))
	rec[off+0x08] = 1 // non-resident
	rec[off+0x09] = 0
	binary.LittleEndian.PutUint16(rec[off+0x0A:], 0)
	binary.LittleEndian.PutUint16(rec[off+0x0E:], id)
	binary.LittleEndian.PutUint64(rec[off+0x10:], 0) // starting VCN
	binary.LittleEndian.PutUint64(rec[off+0x18:], 7) // last VCN
	binary.LittleEndian.PutUint16(rec[off+0x20:], headerLen)
	binary.LittleEndian.PutUint64(rec[off+0x28:], nr.AllocatedSize)
	binary.LittleEndian.PutUint64(rec[off+0x30:], nr.RealSize)
	binary.LittleEndian.PutUint64(rec[off+0x38:], nr.InitializedSize)
	// A minimal, valid data run: one run, then the terminator. Never
	// decoded by the metadata reader, but present so the record is
	// structurally honest.
	rec[off+headerLen] = 0x21
	rec[off+headerLen+1] = 0x08
	binary.LittleEndian.PutUint16(rec[off+headerLen+2:], 0x1234)
	return off + length
}

// applyFixups installs the update sequence array, replacing the last two
// bytes of each sector exactly as NTFS does.
func applyFixups(rec []byte, usaOffset, usaCount int) {
	signature := []byte{0xAA, 0x55}
	copy(rec[usaOffset:], signature)
	sectors := usaCount - 1
	sectorSize := len(rec) / sectors
	for i := 1; i <= sectors; i++ {
		end := i*sectorSize - 2
		// Stash the real bytes in the array, then stamp the signature.
		copy(rec[usaOffset+i*2:], rec[end:end+2])
		copy(rec[end:], signature)
	}
}

func toFileTime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	const epochDelta = 11644473600
	return uint64((t.UTC().Unix()+epochDelta)*10_000_000) + uint64(t.Nanosecond()/100)
}

// Corrupt returns a copy of table with the record at index damaged in
// the named way, for failure-path tests.
func Corrupt(table []byte, index int, how string) []byte {
	out := append([]byte(nil), table...)
	base := index * RecordSize
	if base+RecordSize > len(out) {
		return out
	}
	switch how {
	case "signature":
		copy(out[base:], "XXXX")
	case "baad":
		copy(out[base:], "BAAD")
	case "attr-length":
		// Zero the first attribute's length, which would loop a reader
		// that does not guard against it.
		first := int(binary.LittleEndian.Uint16(out[base+0x14:]))
		binary.LittleEndian.PutUint32(out[base+first+4:], 0)
	case "attr-offset":
		binary.LittleEndian.PutUint16(out[base+0x14:], 0xFFF0)
	case "fixup":
		// Break one sector's update sequence signature.
		out[base+SectorSize-2] ^= 0xFF
	case "used-size":
		binary.LittleEndian.PutUint32(out[base+0x18:], 0xFFFFFFFF)
	}
	return out
}

// SystemRecords returns the low, always-present records a real table
// opens with: $MFT itself at 0 and the volume root at 5.
//
// Fixtures include these because a real $MFT always does, and a reader
// that only ever sees tables starting at an arbitrary record would not
// be exercised against the layout it will actually meet.
func SystemRecords(t Times) []File {
	return []File{
		{
			RecordNumber: 0, SequenceNumber: 1, InUse: true, HardLinks: 1, SI: t,
			Names:           []Name{{Name: "$MFT", Namespace: NamespaceWin32, ParentRef: 5, ParentSeq: 5}},
			NonResidentData: &NonResident{AllocatedSize: 1 << 20, RealSize: 1 << 20, InitializedSize: 1 << 20},
		},
		{
			RecordNumber: 5, SequenceNumber: 5, InUse: true, IsDirectory: true, HardLinks: 1, SI: t,
			Names: []Name{{Name: ".", Namespace: NamespaceWin32, ParentRef: 5, ParentSeq: 5}},
		},
	}
}
