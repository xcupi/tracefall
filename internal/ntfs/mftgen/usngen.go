package mftgen

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// USN change journal fixture generation.
//
// Emits real USN_RECORD_V2 and V3 structures -- correct lengths, 8-byte
// alignment, real FILETIME values and UTF-16 names -- so the reader is
// exercised against the layout it will actually meet.

// USN reason flags, mirroring internal/ntfs.
const (
	ReasonDataOverwrite   = 0x00000001
	ReasonDataExtend      = 0x00000002
	ReasonDataTruncation  = 0x00000004
	ReasonFileCreate      = 0x00000100
	ReasonFileDelete      = 0x00000200
	ReasonEAChange        = 0x00000400
	ReasonSecurityChange  = 0x00000800
	ReasonRenameOldName   = 0x00001000
	ReasonRenameNewName   = 0x00002000
	ReasonBasicInfoChange = 0x00008000
	ReasonHardLinkChange  = 0x00010000
	ReasonStreamChange    = 0x00200000
	ReasonClose           = 0x80000000
)

// UsnEntry describes one journal record to build.
type UsnEntry struct {
	// Version selects the record layout: 2 (default) or 3.
	Version uint16
	// MinorVersion defaults to 0.
	MinorVersion uint16

	FileRecord   uint64
	FileSequence uint16
	ParentRecord uint64
	ParentSeq    uint16

	Usn            uint64
	Timestamp      time.Time
	Reason         uint32
	SourceInfo     uint32
	SecurityID     uint32
	FileAttributes uint32
	FileName       string
}

// BuildUsnJournal concatenates entries into a $UsnJrnl:$J stream.
//
// leadingZeros prepends a sparse run, as a collected journal routinely
// carries: Windows deallocates the front of $J as it ages out, so a real
// stream almost never begins with a record.
func BuildUsnJournal(leadingZeros int, entries []UsnEntry) []byte {
	out := make([]byte, leadingZeros)
	for _, e := range entries {
		out = append(out, BuildUsnRecord(e)...)
	}
	return out
}

// BuildUsnRecord assembles one record.
func BuildUsnRecord(e UsnEntry) []byte {
	version := e.Version
	if version == 0 {
		version = 2
	}
	units := utf16.Encode([]rune(e.FileName))
	nameBytes := len(units) * 2

	var headerLen int
	switch version {
	case 3:
		headerLen = 0x4C
	default:
		headerLen = 0x3C
	}
	total := headerLen + nameBytes
	if total%8 != 0 {
		total += 8 - total%8
	}
	rec := make([]byte, total)
	binary.LittleEndian.PutUint32(rec[0x00:], uint32(total))
	binary.LittleEndian.PutUint16(rec[0x04:], version)
	binary.LittleEndian.PutUint16(rec[0x06:], e.MinorVersion)

	fileRef := e.FileRecord | uint64(e.FileSequence)<<48
	parentRef := e.ParentRecord | uint64(e.ParentSeq)<<48

	switch version {
	case 3:
		binary.LittleEndian.PutUint64(rec[0x08:], fileRef)
		binary.LittleEndian.PutUint64(rec[0x10:], 0)
		binary.LittleEndian.PutUint64(rec[0x18:], parentRef)
		binary.LittleEndian.PutUint64(rec[0x20:], 0)
		binary.LittleEndian.PutUint64(rec[0x28:], e.Usn)
		binary.LittleEndian.PutUint64(rec[0x30:], toFileTime(e.Timestamp))
		binary.LittleEndian.PutUint32(rec[0x38:], e.Reason)
		binary.LittleEndian.PutUint32(rec[0x3C:], e.SourceInfo)
		binary.LittleEndian.PutUint32(rec[0x40:], e.SecurityID)
		binary.LittleEndian.PutUint32(rec[0x44:], e.FileAttributes)
		binary.LittleEndian.PutUint16(rec[0x48:], uint16(nameBytes))
		binary.LittleEndian.PutUint16(rec[0x4A:], uint16(headerLen))
	default:
		binary.LittleEndian.PutUint64(rec[0x08:], fileRef)
		binary.LittleEndian.PutUint64(rec[0x10:], parentRef)
		binary.LittleEndian.PutUint64(rec[0x18:], e.Usn)
		binary.LittleEndian.PutUint64(rec[0x20:], toFileTime(e.Timestamp))
		binary.LittleEndian.PutUint32(rec[0x28:], e.Reason)
		binary.LittleEndian.PutUint32(rec[0x2C:], e.SourceInfo)
		binary.LittleEndian.PutUint32(rec[0x30:], e.SecurityID)
		binary.LittleEndian.PutUint32(rec[0x34:], e.FileAttributes)
		binary.LittleEndian.PutUint16(rec[0x38:], uint16(nameBytes))
		binary.LittleEndian.PutUint16(rec[0x3A:], uint16(headerLen))
	}
	for i, u := range units {
		binary.LittleEndian.PutUint16(rec[headerLen+i*2:], u)
	}
	return rec
}

// CorruptUsn damages the record starting at byte offset, for
// failure-path tests.
func CorruptUsn(stream []byte, offset int, how string) []byte {
	out := append([]byte(nil), stream...)
	if offset+8 > len(out) {
		return out
	}
	switch how {
	case "zero-length":
		binary.LittleEndian.PutUint32(out[offset:], 0)
	case "huge-length":
		binary.LittleEndian.PutUint32(out[offset:], 0x00FFFFFF)
	case "unaligned-length":
		binary.LittleEndian.PutUint32(out[offset:], 61)
	case "bad-version":
		binary.LittleEndian.PutUint16(out[offset+4:], 99)
	case "name-offset":
		binary.LittleEndian.PutUint16(out[offset+0x3A:], 0xFFF0)
	case "name-length":
		binary.LittleEndian.PutUint16(out[offset+0x38:], 0xFFF0)
	case "zero-time":
		binary.LittleEndian.PutUint64(out[offset+0x20:], 0)
	}
	return out
}
