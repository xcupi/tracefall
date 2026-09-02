package ntfs

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// NTFS $LogFile.
//
// $LogFile is the volume's write-ahead transaction log: NTFS records
// what it is about to do before doing it, so an interrupted operation
// can be replayed or rolled back at mount.
//
// # Why this parser is deliberately conservative
//
// A $LogFile record describes a low-level metadata mutation -- "set
// these bytes in this attribute of this MFT record" -- not a file
// operation. Turning those back into "the user deleted X at time T"
// requires replaying the log against the volume state, tracking the open
// attribute table across pages, and resolving records that span page
// boundaries in a circular buffer that wraps. Each of those steps can go
// wrong quietly, and a wrong answer here is a fabricated filesystem
// event on a forensic timeline.
//
// So this package parses and VALIDATES the log's structure -- restart
// areas, page headers, log record headers, LSNs, transaction IDs and
// redo/undo opcodes -- and exposes them as metadata. It does not
// synthesize filesystem events.
//
// The decisive constraint is simpler than any of that, and it is worth
// stating plainly: a LOG_RECORD_HEADER carries no timestamp. There is
// no time field to put on a timeline. Inventing one from the enclosing
// page, or from the restart area, would be inventing evidence.
//
// # What that leaves
//
// Genuinely useful metadata: whether the log is a valid NTFS log, which
// version, how large, the current and oldest LSNs, which clients hold
// it, how many transactions are represented, and the distribution of
// operations. That answers "was this volume mounted dirty?", "how much
// history does this log hold?" and "what kind of activity dominates it?"
// without asserting anything the log does not state.

var (
	// ErrNotLogFile means the data carries no valid NTFS log structure.
	ErrNotLogFile = errors.New("ntfs: not an NTFS $LogFile")
)

const (
	restartSignature = "RSTR"
	recordSignature2 = "RCRD"
	// chkdskSignature marks a restart page rewritten by chkdsk.
	chkdskSignature = "CHKD"
)

// LogRestartArea is one parsed restart page.
//
// $LogFile carries two, so a torn write to one still leaves a usable
// copy. Both are reported; disagreement between them is itself a finding
// about the volume's state.
type LogRestartArea struct {
	// PageOffset is where this restart page began.
	PageOffset int64
	// Signature is RSTR normally, or CHKD when chkdsk rewrote the page.
	Signature string

	MajorVersion   uint16
	MinorVersion   uint16
	SystemPageSize uint32
	LogPageSize    uint32

	ChkdskLSN  uint64
	CurrentLSN uint64
	// LogClients is how many client records the area holds; NTFS itself
	// is the only normal client.
	LogClients      uint16
	Flags           uint16
	SequenceBits    uint32
	FileSize        uint64
	LastLSNDataLen  uint32
	RecordHeaderLen uint16
	LogPageDataOff  uint16
	RevisionNumber  uint32

	Clients  []LogClient
	Warnings []string
}

// LogClient is one LOG_CLIENT_RECORD.
type LogClient struct {
	Name             string
	OldestLSN        uint64
	ClientRestartLSN uint64
	SequenceNumber   uint16
}

// LogPage is one RCRD page's header.
type LogPage struct {
	PageOffset       int64
	LastLSN          uint64
	Flags            uint32
	PageCount        uint16
	PagePosition     uint16
	NextRecordOffset uint16
	Records          []LogRecord
	Warnings         []string
}

// LogRecord is one LOG_RECORD_HEADER.
//
// Every field here is read directly from the record. Nothing is derived,
// and in particular there is NO timestamp -- the structure does not
// carry one.
type LogRecord struct {
	// Offset is the record's position within the file.
	Offset int64

	ThisLSN           uint64
	ClientPreviousLSN uint64
	ClientUndoNextLSN uint64
	ClientDataLength  uint32
	ClientIndex       uint16
	ClientSeqNumber   uint16
	RecordType        uint32
	TransactionID     uint32
	Flags             uint16

	RedoOperation uint16
	UndoOperation uint16
	RedoOffset    uint16
	RedoLength    uint16
	UndoOffset    uint16
	UndoLength    uint16

	TargetAttribute uint16
	LCNsToFollow    uint16
	RecordOffset    uint16
	AttributeOffset uint16
	TargetVCN       uint64
	TargetLCN       uint64

	Warnings []string
}

// RedoName / UndoName render the operation codes.
func (r LogRecord) RedoName() string { return LogOperationName(r.RedoOperation) }
func (r LogRecord) UndoName() string { return LogOperationName(r.UndoOperation) }

// logOperations are NTFS's documented log opcodes.
var logOperations = map[uint16]string{
	0x00: "Noop",
	0x01: "CompensationLogRecord",
	0x02: "InitializeFileRecordSegment",
	0x03: "DeallocateFileRecordSegment",
	0x04: "WriteEndOfFileRecordSegment",
	0x05: "CreateAttribute",
	0x06: "DeleteAttribute",
	0x07: "UpdateResidentValue",
	0x08: "UpdateNonResidentValue",
	0x09: "UpdateMappingPairs",
	0x0A: "DeleteDirtyClusters",
	0x0B: "SetNewAttributeSizes",
	0x0C: "AddIndexEntryRoot",
	0x0D: "DeleteIndexEntryRoot",
	0x0E: "AddIndexEntryAllocation",
	0x0F: "DeleteIndexEntryAllocation",
	0x10: "WriteEndOfIndexBuffer",
	0x11: "SetIndexEntryVcnRoot",
	0x12: "SetIndexEntryVcnAllocation",
	0x13: "UpdateFileNameRoot",
	0x14: "UpdateFileNameAllocation",
	0x15: "SetBitsInNonResidentBitMap",
	0x16: "ClearBitsInNonResidentBitMap",
	0x17: "HotFix",
	0x18: "EndTopLevelAction",
	0x19: "PrepareTransaction",
	0x1A: "CommitTransaction",
	0x1B: "ForgetTransaction",
	0x1C: "OpenNonResidentAttribute",
	0x1D: "OpenAttributeTableDump",
	0x1E: "AttributeNamesDump",
	0x1F: "DirtyPageTableDump",
	0x20: "TransactionTableDump",
	0x21: "UpdateRecordDataRoot",
	0x22: "UpdateRecordDataAllocation",
}

// LogOperationName renders an opcode, or names it as unknown rather than
// silently reporting a blank.
func LogOperationName(op uint16) string {
	if n, ok := logOperations[op]; ok {
		return n
	}
	return fmt.Sprintf("Unknown(0x%02X)", op)
}

// LogFileSummary is what a scan produces: validated structure, not
// reconstructed history.
type LogFileSummary struct {
	FileSize      int64
	PageSize      int
	RestartAreas  []LogRestartArea
	PagesScanned  int
	ValidPages    int
	RecordsParsed int
	// TransactionIDs is the set of distinct transaction identifiers seen.
	TransactionIDs map[uint32]int
	// RedoCounts / UndoCounts tally operations by name.
	RedoCounts map[string]int
	UndoCounts map[string]int
	// LSN range actually observed in log records.
	MinLSN, MaxLSN uint64
	Warnings       []string
}

// LogScanOptions configures a $LogFile scan.
type LogScanOptions struct {
	Limits    Limits
	Cancelled func() bool
	Progress  func(pagesRead int)
	// MaxRecordsRetained bounds how many individual log records are
	// handed to the callback. Zero means all.
	MaxRecordsRetained int
}

// SniffLogFile reports whether header is an NTFS $LogFile.
//
// Requires a restart page that describes itself coherently: the
// signature, a page size that is a power of two in the plausible range,
// and a restart-area offset inside the page. A bare "RSTR" is not
// enough -- the point is to avoid claiming an unrelated file.
func SniffLogFile(header []byte) bool {
	if len(header) < 0x30 {
		return false
	}
	sig := string(header[0:4])
	if sig != restartSignature && sig != chkdskSignature {
		return false
	}
	systemPageSize := u32(header, 0x10)
	logPageSize := u32(header, 0x14)
	if !isPowerOfTwoInRange(systemPageSize, 512, 65536) || !isPowerOfTwoInRange(logPageSize, 512, 65536) {
		return false
	}
	restartOffset := int(u16(header, 0x18))
	if restartOffset < 0x18 || uint32(restartOffset) >= systemPageSize {
		return false
	}
	usaOff := int(u16(header, 0x04))
	usaCount := int(u16(header, 0x06))
	if usaCount < 1 || usaOff < 0x1E || uint32(usaOff+usaCount*2) > systemPageSize {
		return false
	}
	return true
}

func isPowerOfTwoInRange(v, lo, hi uint32) bool {
	return v >= lo && v <= hi && v&(v-1) == 0
}

// ParseRestartPage decodes one restart page. page is modified in place
// by the fixup step.
func ParseRestartPage(page []byte, offset int64) (area LogRestartArea, err error) {
	defer func() {
		if r := recover(); r != nil {
			area, err = LogRestartArea{}, fmt.Errorf("%w: recovered from %v", ErrCorrupt, r)
		}
	}()
	if len(page) < 0x30 {
		return LogRestartArea{}, fmt.Errorf("%w: restart page is %d bytes", ErrCorrupt, len(page))
	}
	sig := string(page[0:4])
	if sig != restartSignature && sig != chkdskSignature {
		return LogRestartArea{}, ErrNotLogFile
	}
	area = LogRestartArea{PageOffset: offset, Signature: sig}
	area.Warnings = append(area.Warnings, applyFixups(page)...)

	area.ChkdskLSN = u64(page, 0x08)
	area.SystemPageSize = u32(page, 0x10)
	area.LogPageSize = u32(page, 0x14)
	restartOffset := int(u16(page, 0x18))
	area.MinorVersion = u16(page, 0x1A)
	area.MajorVersion = u16(page, 0x1C)

	if restartOffset < 0x18 || restartOffset+0x2C > len(page) {
		area.Warnings = append(area.Warnings, "restart area offset lies outside the page; only the page header was read")
		return area, nil
	}
	ra := page[restartOffset:]
	area.CurrentLSN = u64(ra, 0x00)
	area.LogClients = u16(ra, 0x08)
	area.Flags = u16(ra, 0x0E)
	area.SequenceBits = u32(ra, 0x10)
	restartLen := int(u16(ra, 0x14))
	clientArrayOff := int(u16(ra, 0x16))
	area.FileSize = u64(ra, 0x18)
	area.LastLSNDataLen = u32(ra, 0x20)
	area.RecordHeaderLen = u16(ra, 0x24)
	area.LogPageDataOff = u16(ra, 0x26)
	area.RevisionNumber = u32(ra, 0x28)

	// Client records. NTFS is normally the only one.
	const clientRecordLen = 0x30
	if clientArrayOff <= 0 || area.LogClients == 0 {
		return area, nil
	}
	if restartLen > 0 && clientArrayOff >= restartLen {
		area.Warnings = append(area.Warnings, "client array offset lies outside the restart area")
		return area, nil
	}
	for i := 0; i < int(area.LogClients) && i < 64; i++ {
		start := clientArrayOff + i*clientRecordLen
		if start+clientRecordLen > len(ra) {
			area.Warnings = append(area.Warnings, "client record array is truncated")
			break
		}
		c := ra[start:]
		nameLen := int(u32(c, 0x1C))
		name := ""
		if nameLen > 0 && 0x20+nameLen <= len(c) {
			name = decodeUTF16(c[0x20:], nameLen/2, 128)
		}
		area.Clients = append(area.Clients, LogClient{
			Name:             name,
			OldestLSN:        u64(c, 0x00),
			ClientRestartLSN: u64(c, 0x08),
			SequenceNumber:   u16(c, 0x14),
		})
	}
	return area, nil
}

// parseLogPage decodes one RCRD page and the log record headers in it.
func parseLogPage(page []byte, offset int64, headerLen int) (LogPage, bool) {
	if len(page) < 0x28 || string(page[0:4]) != recordSignature2 {
		return LogPage{}, false
	}
	p := LogPage{PageOffset: offset}
	p.Warnings = append(p.Warnings, applyFixups(page)...)
	p.LastLSN = u64(page, 0x08)
	p.Flags = u32(page, 0x10)
	p.PageCount = u16(page, 0x14)
	p.PagePosition = u16(page, 0x16)
	p.NextRecordOffset = u16(page, 0x18)

	// Log records begin after the page header. The restart area declares
	// the offset; 0x40 is the near-universal value and is used when the
	// restart area did not give a usable one.
	start := headerLen
	if start < 0x28 || start >= len(page) {
		start = 0x40
	}
	// Records run until the page's declared next-record offset, which is
	// where NTFS would append the next one.
	end := int(p.NextRecordOffset)
	if end <= start || end > len(page) {
		end = len(page)
	}

	const logRecordHeaderLen = 0x58
	for off := start; off+logRecordHeaderLen <= end; {
		r, size, ok := parseLogRecord(page[off:end], offset+int64(off))
		if !ok || size <= 0 {
			break
		}
		p.Records = append(p.Records, r)
		off += size
		if len(p.Records) > 4096 {
			p.Warnings = append(p.Warnings, "page holds more than 4096 log records; the rest were not read")
			break
		}
	}
	return p, true
}

// parseLogRecord decodes one LOG_RECORD_HEADER and returns its total
// length including client data.
func parseLogRecord(buf []byte, offset int64) (LogRecord, int, bool) {
	const headerLen = 0x58
	if len(buf) < headerLen {
		return LogRecord{}, 0, false
	}
	r := LogRecord{
		Offset:            offset,
		ThisLSN:           u64(buf, 0x00),
		ClientPreviousLSN: u64(buf, 0x08),
		ClientUndoNextLSN: u64(buf, 0x10),
		ClientDataLength:  u32(buf, 0x18),
		ClientSeqNumber:   u16(buf, 0x1C),
		ClientIndex:       u16(buf, 0x1E),
		RecordType:        u32(buf, 0x20),
		TransactionID:     u32(buf, 0x24),
		Flags:             u16(buf, 0x28),
		RedoOperation:     u16(buf, 0x30),
		UndoOperation:     u16(buf, 0x32),
		RedoOffset:        u16(buf, 0x34),
		RedoLength:        u16(buf, 0x36),
		UndoOffset:        u16(buf, 0x38),
		UndoLength:        u16(buf, 0x3A),
		TargetAttribute:   u16(buf, 0x3C),
		LCNsToFollow:      u16(buf, 0x3E),
		RecordOffset:      u16(buf, 0x40),
		AttributeOffset:   u16(buf, 0x42),
		TargetVCN:         u64(buf, 0x48),
		TargetLCN:         u64(buf, 0x50),
	}
	// A record with a zero LSN and no operation is padding, not data.
	if r.ThisLSN == 0 && r.RedoOperation == 0 && r.UndoOperation == 0 && r.ClientDataLength == 0 {
		return LogRecord{}, 0, false
	}
	// The client data length is attacker-influenced; bound it against
	// the page before it is used to advance.
	total := headerLen + int(r.ClientDataLength)
	if total%8 != 0 {
		total += 8 - total%8
	}
	if r.ClientDataLength > uint32(len(buf)) || total > len(buf) {
		r.Warnings = append(r.Warnings,
			fmt.Sprintf("client data length %d runs past the end of the page", r.ClientDataLength))
		return r, headerLen, true
	}
	if total <= 0 {
		return r, headerLen, true
	}
	return r, total, true
}

// ScanLogFile streams a $LogFile, validating its structure and reporting
// metadata. fn is called for each log record, if non-nil.
//
// Pages are read ONE AT A TIME, so a multi-gigabyte log costs one page
// of memory. Nothing is accumulated beyond the summary counters.
func ScanLogFile(path string, opts LogScanOptions, fn func(LogPage, LogRecord) error) (LogFileSummary, error) {
	lim := opts.Limits.withDefaults()
	sum := LogFileSummary{
		TransactionIDs: map[uint32]int{},
		RedoCounts:     map[string]int{},
		UndoCounts:     map[string]int{},
	}

	info, err := os.Stat(path)
	if err != nil {
		return sum, err
	}
	if info.Size() > lim.MaxFileBytes {
		return sum, fmt.Errorf("%w: file is %d bytes", ErrLimitExceeded, info.Size())
	}
	sum.FileSize = info.Size()

	f, err := os.Open(path)
	if err != nil {
		return sum, err
	}
	defer f.Close()

	head := make([]byte, 4096)
	n, _ := io.ReadFull(f, head)
	if n < 0x30 || !SniffLogFile(head[:n]) {
		return sum, ErrNotLogFile
	}
	pageSize := int(u32(head, 0x14))
	if !isPowerOfTwoInRange(uint32(pageSize), 512, 65536) {
		pageSize = 4096
	}
	sum.PageSize = pageSize

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return sum, err
	}

	page := make([]byte, pageSize)
	headerLen := 0x40
	retained := 0
	for index := 0; ; index++ {
		if opts.Cancelled != nil && index%32 == 0 && opts.Cancelled() {
			return sum, ErrCancelled
		}
		nn, rerr := io.ReadFull(f, page)
		if rerr == io.EOF {
			break
		}
		if rerr == io.ErrUnexpectedEOF {
			if nn < 0x30 {
				break
			}
			// A trailing partial page. Everything before it stands.
			sum.Warnings = append(sum.Warnings, "the final page is truncated and was not parsed")
			break
		}
		if rerr != nil {
			return sum, rerr
		}
		sum.PagesScanned++
		if opts.Progress != nil && index%512 == 0 {
			opts.Progress(index)
		}

		switch string(page[0:4]) {
		case restartSignature, chkdskSignature:
			area, aerr := ParseRestartPage(page, int64(index)*int64(pageSize))
			if aerr != nil {
				sum.Warnings = append(sum.Warnings, fmt.Sprintf("restart page at %d: %v", index, aerr))
				continue
			}
			sum.ValidPages++
			if area.LogPageDataOff >= 0x28 && int(area.LogPageDataOff) < pageSize {
				headerLen = int(area.LogPageDataOff)
			}
			sum.RestartAreas = append(sum.RestartAreas, area)

		case recordSignature2:
			lp, ok := parseLogPage(page, int64(index)*int64(pageSize), headerLen)
			if !ok {
				continue
			}
			sum.ValidPages++
			for _, r := range lp.Records {
				sum.RecordsParsed++
				sum.TransactionIDs[r.TransactionID]++
				sum.RedoCounts[r.RedoName()]++
				sum.UndoCounts[r.UndoName()]++
				if r.ThisLSN != 0 {
					if sum.MinLSN == 0 || r.ThisLSN < sum.MinLSN {
						sum.MinLSN = r.ThisLSN
					}
					if r.ThisLSN > sum.MaxLSN {
						sum.MaxLSN = r.ThisLSN
					}
				}
				if fn != nil {
					if opts.MaxRecordsRetained > 0 && retained >= opts.MaxRecordsRetained {
						continue
					}
					retained++
					if err := fn(lp, r); err != nil {
						return sum, err
					}
				}
			}

		default:
			// Uninitialized or wiped page. Normal in a circular log.
		}
	}
	if sum.ValidPages == 0 {
		return sum, ErrNotLogFile
	}
	return sum, nil
}
