package mftgen

import (
	"encoding/binary"
	"unicode/utf16"
)

// $LogFile fixture generation.
//
// Emits real RSTR restart pages and RCRD record pages with genuine
// update sequence arrays, so the reader's fixup handling and page
// validation are exercised rather than bypassed.

// LogPageSize is the page size generated fixtures use. 4096 is what
// NTFS uses on every modern volume.
const LogPageSize = 4096

// LogRestart describes a restart page to build.
type LogRestart struct {
	// Chkdsk emits a CHKD signature instead of RSTR, marking a page
	// rewritten by chkdsk.
	Chkdsk          bool
	MajorVersion    uint16
	MinorVersion    uint16
	CurrentLSN      uint64
	ChkdskLSN       uint64
	FileSize        uint64
	SequenceBits    uint32
	RecordHeaderLen uint16
	LogPageDataOff  uint16
	Clients         []LogClientEntry
}

// LogClientEntry is one LOG_CLIENT_RECORD.
type LogClientEntry struct {
	Name             string
	OldestLSN        uint64
	ClientRestartLSN uint64
	SequenceNumber   uint16
}

// LogRec describes one LOG_RECORD_HEADER to build.
type LogRec struct {
	ThisLSN           uint64
	ClientPreviousLSN uint64
	ClientUndoNextLSN uint64
	ClientDataLength  uint32
	ClientIndex       uint16
	ClientSeqNumber   uint16
	RecordType        uint32
	TransactionID     uint32
	Flags             uint16
	RedoOperation     uint16
	UndoOperation     uint16
	RedoOffset        uint16
	RedoLength        uint16
	UndoOffset        uint16
	UndoLength        uint16
	TargetAttribute   uint16
	TargetVCN         uint64
	TargetLCN         uint64
}

// BuildRestartPage assembles one RSTR (or CHKD) page.
func BuildRestartPage(r LogRestart) []byte {
	page := make([]byte, LogPageSize)
	sig := "RSTR"
	if r.Chkdsk {
		sig = "CHKD"
	}
	copy(page[0:4], sig)

	const usaOffset = 0x1E
	sectors := LogPageSize / SectorSize
	usaCount := sectors + 1
	binary.LittleEndian.PutUint16(page[0x04:], usaOffset)
	binary.LittleEndian.PutUint16(page[0x06:], uint16(usaCount))
	binary.LittleEndian.PutUint64(page[0x08:], r.ChkdskLSN)
	binary.LittleEndian.PutUint32(page[0x10:], LogPageSize)
	binary.LittleEndian.PutUint32(page[0x14:], LogPageSize)

	restartOffset := 0x30
	binary.LittleEndian.PutUint16(page[0x18:], uint16(restartOffset))
	major := r.MajorVersion
	if major == 0 {
		major = 1
	}
	binary.LittleEndian.PutUint16(page[0x1A:], r.MinorVersion)
	binary.LittleEndian.PutUint16(page[0x1C:], major)

	ra := page[restartOffset:]
	clientArrayOff := 0x30
	headerLen := r.RecordHeaderLen
	if headerLen == 0 {
		headerLen = 0x58
	}
	dataOff := r.LogPageDataOff
	if dataOff == 0 {
		dataOff = 0x40
	}
	binary.LittleEndian.PutUint64(ra[0x00:], r.CurrentLSN)
	binary.LittleEndian.PutUint16(ra[0x08:], uint16(len(r.Clients)))
	binary.LittleEndian.PutUint16(ra[0x0A:], 0xFFFF)
	binary.LittleEndian.PutUint16(ra[0x0C:], 0)
	binary.LittleEndian.PutUint16(ra[0x0E:], 0)
	binary.LittleEndian.PutUint32(ra[0x10:], r.SequenceBits)
	binary.LittleEndian.PutUint16(ra[0x14:], uint16(clientArrayOff+len(r.Clients)*0x30))
	binary.LittleEndian.PutUint16(ra[0x16:], uint16(clientArrayOff))
	binary.LittleEndian.PutUint64(ra[0x18:], r.FileSize)
	binary.LittleEndian.PutUint32(ra[0x20:], 0)
	binary.LittleEndian.PutUint16(ra[0x24:], headerLen)
	binary.LittleEndian.PutUint16(ra[0x26:], dataOff)
	binary.LittleEndian.PutUint32(ra[0x28:], 1)

	for i, c := range r.Clients {
		start := clientArrayOff + i*0x30
		if restartOffset+start+0x30 > len(page) {
			break
		}
		cr := ra[start:]
		binary.LittleEndian.PutUint64(cr[0x00:], c.OldestLSN)
		binary.LittleEndian.PutUint64(cr[0x08:], c.ClientRestartLSN)
		binary.LittleEndian.PutUint16(cr[0x10:], 0xFFFF)
		binary.LittleEndian.PutUint16(cr[0x12:], 0xFFFF)
		binary.LittleEndian.PutUint16(cr[0x14:], c.SequenceNumber)
		units := utf16.Encode([]rune(c.Name))
		binary.LittleEndian.PutUint32(cr[0x1C:], uint32(len(units)*2))
		for j, u := range units {
			if 0x20+j*2+2 > len(cr) {
				break
			}
			binary.LittleEndian.PutUint16(cr[0x20+j*2:], u)
		}
	}
	applyFixups(page, usaOffset, usaCount)
	return page
}

// BuildRecordPage assembles one RCRD page holding the given records.
func BuildRecordPage(lastLSN uint64, pagePosition, pageCount uint16, recs []LogRec) []byte {
	page := make([]byte, LogPageSize)
	copy(page[0:4], "RCRD")

	const usaOffset = 0x28
	sectors := LogPageSize / SectorSize
	usaCount := sectors + 1
	binary.LittleEndian.PutUint16(page[0x04:], usaOffset)
	binary.LittleEndian.PutUint16(page[0x06:], uint16(usaCount))
	binary.LittleEndian.PutUint64(page[0x08:], lastLSN)
	binary.LittleEndian.PutUint32(page[0x10:], 0)
	binary.LittleEndian.PutUint16(page[0x14:], pageCount)
	binary.LittleEndian.PutUint16(page[0x16:], pagePosition)

	const dataOffset = 0x40
	const headerLen = 0x58
	off := dataOffset
	for _, r := range recs {
		total := headerLen + int(r.ClientDataLength)
		if total%8 != 0 {
			total += 8 - total%8
		}
		if off+total > LogPageSize-2 {
			break
		}
		b := page[off:]
		binary.LittleEndian.PutUint64(b[0x00:], r.ThisLSN)
		binary.LittleEndian.PutUint64(b[0x08:], r.ClientPreviousLSN)
		binary.LittleEndian.PutUint64(b[0x10:], r.ClientUndoNextLSN)
		binary.LittleEndian.PutUint32(b[0x18:], r.ClientDataLength)
		binary.LittleEndian.PutUint16(b[0x1C:], r.ClientSeqNumber)
		binary.LittleEndian.PutUint16(b[0x1E:], r.ClientIndex)
		binary.LittleEndian.PutUint32(b[0x20:], r.RecordType)
		binary.LittleEndian.PutUint32(b[0x24:], r.TransactionID)
		binary.LittleEndian.PutUint16(b[0x28:], r.Flags)
		binary.LittleEndian.PutUint16(b[0x30:], r.RedoOperation)
		binary.LittleEndian.PutUint16(b[0x32:], r.UndoOperation)
		binary.LittleEndian.PutUint16(b[0x34:], r.RedoOffset)
		binary.LittleEndian.PutUint16(b[0x36:], r.RedoLength)
		binary.LittleEndian.PutUint16(b[0x38:], r.UndoOffset)
		binary.LittleEndian.PutUint16(b[0x3A:], r.UndoLength)
		binary.LittleEndian.PutUint16(b[0x3C:], r.TargetAttribute)
		binary.LittleEndian.PutUint64(b[0x48:], r.TargetVCN)
		binary.LittleEndian.PutUint64(b[0x50:], r.TargetLCN)
		off += total
	}
	binary.LittleEndian.PutUint16(page[0x18:], uint16(off))
	applyFixups(page, usaOffset, usaCount)
	return page
}

// BuildLogFile concatenates pages into a $LogFile.
func BuildLogFile(pages ...[]byte) []byte {
	var out []byte
	for _, p := range pages {
		out = append(out, p...)
	}
	return out
}

// CorruptLogPage damages the page at index, for failure-path tests.
func CorruptLogPage(logfile []byte, index int, how string) []byte {
	out := append([]byte(nil), logfile...)
	base := index * LogPageSize
	if base+LogPageSize > len(out) {
		return out
	}
	switch how {
	case "signature":
		copy(out[base:], "ZZZZ")
	case "fixup":
		out[base+SectorSize-2] ^= 0xFF
	case "next-record-offset":
		binary.LittleEndian.PutUint16(out[base+0x18:], 0xFFFF)
	case "client-data-length":
		binary.LittleEndian.PutUint32(out[base+0x40+0x18:], 0x7FFFFFFF)
	case "page-size":
		binary.LittleEndian.PutUint32(out[base+0x14:], 12345)
	}
	return out
}
