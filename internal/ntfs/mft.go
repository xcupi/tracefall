// Package ntfs reads the NTFS Master File Table ($MFT) directly from its
// binary form.
//
// The $MFT is the filesystem's own index: one FILE record per file and
// directory on the volume, each carrying the four MACB timestamps, the
// name, the parent directory, the size, and whether the record is still
// in use. For triage it answers questions no application artifact can --
// when a file was created, when its metadata last changed, and whether
// its record has since been marked free.
//
// # What this package does and does not do
//
// It reads $MFT records. It is NOT a filesystem driver: it does not walk
// $I30 index allocations, decode data runs to recover file CONTENT, read
// $LogFile or $UsnJrnl, or reconstruct resident data streams. Those are
// separate artifacts and pretending otherwise would misrepresent what
// Tracefall has actually examined.
//
// # Timestamps
//
// Every record carries two independent sets of four timestamps: one in
// $STANDARD_INFORMATION and one in $FILE_NAME. They are NOT merged.
// $SI is what most tools display and what timestomping tools alter; $FN
// is updated by the kernel on rename/move and is comparatively awkward
// to forge. Keeping both, separately labelled, is the entire point --
// their disagreement is itself evidence, and averaging or preferring one
// silently would destroy it.
//
// # Hostile input
//
// An $MFT is attacker-influenced: filenames, sizes, offsets and parent
// references all come from the volume. Every offset is bounds-checked
// against the record it came from, counts are capped, and a record that
// fails to parse is reported as a warning and skipped rather than
// aborting the scan. A malformed table yields fewer records; it never
// panics, loops forever, or allocates without bound.
package ntfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

var (
	// ErrNotMFT means the data carries no FILE record signature at all.
	ErrNotMFT = errors.New("ntfs: not an NTFS $MFT (no FILE record signature)")
	// ErrCorrupt means the structure is invalid, truncated, or
	// self-inconsistent in a way that prevents scanning.
	ErrCorrupt = errors.New("ntfs: $MFT is corrupt, truncated, or structurally invalid")
	// ErrLimitExceeded means a hard safety ceiling was reached.
	ErrLimitExceeded = errors.New("ntfs: $MFT exceeds a safety limit")
)

// Attribute type codes. Only the ones this package reads are named.
const (
	attrStandardInformation = 0x10
	attrAttributeList       = 0x20
	attrFileName            = 0x30
	attrObjectID            = 0x40
	attrData                = 0x80
	attrIndexRoot           = 0x90
	attrIndexAllocation     = 0xA0
	attrEnd                 = 0xFFFFFFFF
)

// Record header flags.
const (
	flagInUse     = 0x0001
	flagDirectory = 0x0002
)

// $FILE_NAME namespaces.
const (
	NamespacePOSIX     = 0
	NamespaceWin32     = 1
	NamespaceDOS       = 2
	NamespaceWin32DOS  = 3
	recordSignature    = "FILE"
	badRecordSignature = "BAAD"
)

// Limits bounds what one $MFT may consume.
type Limits struct {
	// StrictNames refuses lossy filename decoding; compatibility readers may opt out.
	StrictNames       bool
	MaxFileBytes      int64
	MaxRecords        int
	MaxNamesPerRecord int
	MaxNameChars      int
}

// DefaultLimits are generous enough for a real volume's table while
// still bounding a hostile one. A 1,000,000-record table is a large
// production volume; beyond that the scan stops and says so rather than
// consuming the host.
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:      8 << 30, // 8 GiB
		MaxRecords:        1_000_000,
		MaxNamesPerRecord: 16,
		MaxNameChars:      255, // NTFS's own maximum
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxRecords <= 0 {
		l.MaxRecords = d.MaxRecords
	}
	if l.MaxNamesPerRecord <= 0 {
		l.MaxNamesPerRecord = d.MaxNamesPerRecord
	}
	if l.MaxNameChars <= 0 {
		l.MaxNameChars = d.MaxNameChars
	}
	return l
}

// Timestamps is one NTFS MACB set. Zero values mean the field was absent
// or implausible; they are never substituted with anything.
type Timestamps struct {
	Created  time.Time // birth
	Modified time.Time // file content last written
	Changed  time.Time // MFT record last changed
	Accessed time.Time
}

// Any reports whether at least one timestamp is usable.
func (t Timestamps) Any() bool {
	return !t.Created.IsZero() || !t.Modified.IsZero() || !t.Changed.IsZero() || !t.Accessed.IsZero()
}

// FileName is one $FILE_NAME attribute. A record commonly carries two --
// the long Win32 name and its 8.3 DOS short name -- and may carry more
// when the file is hard-linked into several directories.
type FileName struct {
	Name      string
	Namespace uint8
	ParentRef uint64 // parent record number (48-bit)
	ParentSeq uint16
	Times     Timestamps
	// LogicalSize and PhysicalSize as recorded in $FILE_NAME. These lag
	// the real size (the kernel does not update them on every write), so
	// they are reported as what they are and $DATA is preferred.
	LogicalSize  uint64
	PhysicalSize uint64
}

// Record is one parsed FILE record.
type Record struct {
	// RecordNumber is this record's index in the table.
	RecordNumber uint64
	// SequenceNumber increments each time the record is reused, and is
	// what makes a file reference unambiguous over time.
	SequenceNumber uint16
	InUse          bool
	IsDirectory    bool
	HardLinkCount  uint16
	// BaseRecordRef is non-zero on an EXTENSION record, naming the base
	// record it belongs to. Extension records carry no independent
	// identity and are not events in their own right.
	BaseRecordRef uint64

	// SI holds the $STANDARD_INFORMATION timestamps. HasSI distinguishes
	// "all four were zero" from "the attribute was absent".
	SI    Timestamps
	HasSI bool

	// Names holds every $FILE_NAME attribute, in the order found.
	Names []FileName

	// LogicalSize / PhysicalSize come from the unnamed $DATA attribute
	// when present. SizeKnown is false for a directory or a record whose
	// $DATA could not be read.
	LogicalSize  uint64
	PhysicalSize uint64
	SizeKnown    bool
	// DataResident reports whether the unnamed $DATA attribute stores its
	// content inside the record. A resident $DATA means the file is small
	// enough to live entirely in the MFT.
	DataResident bool
	HasData      bool
	// HasAttributeList marks a record whose attributes overflow into
	// extension records. Such a record's $DATA size and name set may be
	// incomplete here; see the package limitations.
	HasAttributeList bool

	// AttributeTypes lists the attribute type codes present, for context.
	AttributeTypes []uint32

	// Warnings describe recoverable problems found while parsing THIS
	// record. A record with warnings is still returned -- partial
	// evidence, labelled as such, beats silently dropping it.
	Warnings []string
}

// BestName returns the most human-meaningful filename attribute: a Win32
// name in preference to an 8.3 DOS alias, which is a derived short form
// rather than the name a user or attacker chose.
func (r Record) BestName() (FileName, bool) {
	if len(r.Names) == 0 {
		return FileName{}, false
	}
	best := -1
	rank := func(ns uint8) int {
		switch ns {
		case NamespaceWin32, NamespaceWin32DOS:
			return 0
		case NamespacePOSIX:
			return 1
		case NamespaceDOS:
			return 2
		}
		return 3
	}
	for i := range r.Names {
		if best == -1 || rank(r.Names[i].Namespace) < rank(r.Names[best].Namespace) {
			best = i
		}
	}
	return r.Names[best], true
}

// IsBaseRecord reports whether this is a base record rather than an
// extension of another one.
func (r Record) IsBaseRecord() bool { return r.BaseRecordRef == 0 }

// fileTime converts a Windows FILETIME to UTC.
//
// Implausible values are returned as the zero time rather than as a
// year-1601 or year-30828 timestamp: an out-of-range value is a parse
// artifact, and putting it on a forensic timeline would be inventing an
// observation. The window matches internal/prefetch's, for one rule
// across the codebase.
func fileTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ticksPerSecond = 10_000_000
	const epochDelta = 11644473600
	t := time.Unix(int64(ft/ticksPerSecond)-epochDelta, int64(ft%ticksPerSecond)*100).UTC()
	if t.Year() < 1990 || t.Year() > 2200 {
		return time.Time{}
	}
	return t
}

func validUTF16LE(b []byte) bool {
	if len(b)%2 != 0 {
		return false
	}
	for i := 0; i < len(b); i += 2 {
		c := u16(b, i)
		if c >= 0xd800 && c <= 0xdbff {
			if i+2 >= len(b) || u16(b, i+2) < 0xdc00 || u16(b, i+2) > 0xdfff {
				return false
			}
			i += 2
		} else if c >= 0xdc00 && c <= 0xdfff {
			return false
		}
	}
	return true
}
func u16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off : off+2]) }
func u32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off : off+4]) }
func u64(b []byte, off int) uint64 { return binary.LittleEndian.Uint64(b[off : off+8]) }

// fileRef splits an 8-byte NTFS file reference into its 48-bit record
// number and 16-bit sequence number.
func fileRef(v uint64) (uint64, uint16) {
	return v & 0x0000FFFFFFFFFFFF, uint16(v >> 48)
}

// decodeUTF16 decodes a little-endian UTF-16 name of n characters.
func decodeUTF16(b []byte, chars int, max int) string {
	if chars > max {
		chars = max
	}
	if chars*2 > len(b) {
		chars = len(b) / 2
	}
	if chars <= 0 {
		return ""
	}
	units := make([]uint16, chars)
	for i := 0; i < chars; i++ {
		units[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return strings.TrimRight(string(utf16.Decode(units)), "\x00")
}

// applyFixups undoes the update sequence array.
//
// NTFS overwrites the last two bytes of every sector in a record with a
// signature value, keeping the originals in an array at the top of the
// record; a reader that skips this step gets two corrupted bytes per
// sector and decodes plausible-looking nonsense. Restoring them is
// mandatory, not optional.
//
// A mismatched signature means the record was torn mid-write. That is
// reported rather than silently accepted, because the record's contents
// after such a tear are not trustworthy.
func applyFixups(rec []byte) []string {
	var warnings []string
	if len(rec) < 8 {
		return []string{"record too short to carry an update sequence array"}
	}
	usaOff := int(u16(rec, 0x04))
	usaCount := int(u16(rec, 0x06))
	if usaCount < 1 || usaOff < 0 || usaOff+usaCount*2 > len(rec) {
		return []string{"update sequence array offset or count is outside the record"}
	}
	sectors := usaCount - 1
	if sectors <= 0 {
		return nil
	}
	sectorSize := len(rec) / sectors
	if sectorSize < 4 || sectorSize*sectors > len(rec) {
		return []string{"update sequence array implies an impossible sector size"}
	}
	signature := rec[usaOff : usaOff+2]
	for i := 1; i <= sectors; i++ {
		end := i*sectorSize - 2
		if end < 0 || end+2 > len(rec) {
			warnings = append(warnings, fmt.Sprintf("sector %d fixup lands outside the record", i))
			continue
		}
		if rec[end] != signature[0] || rec[end+1] != signature[1] {
			warnings = append(warnings,
				fmt.Sprintf("sector %d update sequence signature does not match; the record may have been torn mid-write", i))
			continue
		}
		src := usaOff + i*2
		rec[end] = rec[src]
		rec[end+1] = rec[src+1]
	}
	return warnings
}

// ParseRecord parses one FILE record from an already-sized buffer.
//
// buf is modified in place by the fixup step, so callers hand it a
// scratch buffer rather than a view of shared evidence.
func ParseRecord(buf []byte, recordNumber uint64, lim Limits) (rec Record, ok bool, err error) {
	lim = lim.withDefaults()

	// A backstop only. Every index below is bounds-checked; this
	// guarantees the package's promise even if one of them is ever
	// wrong.
	defer func() {
		if r := recover(); r != nil {
			rec, ok, err = Record{}, false, fmt.Errorf("%w: recovered from %v", ErrCorrupt, r)
		}
	}()

	if len(buf) < 48 {
		return Record{}, false, fmt.Errorf("%w: record is %d bytes", ErrCorrupt, len(buf))
	}
	switch string(buf[0:4]) {
	case recordSignature:
	case badRecordSignature:
		// NTFS itself marked this record bad. Reporting it is useful;
		// parsing its contents is not.
		return Record{RecordNumber: recordNumber, Warnings: []string{"record is marked BAAD by NTFS and was not parsed"}}, false, nil
	default:
		// Unused slack in the table. Not an error.
		return Record{}, false, nil
	}

	rec.RecordNumber = recordNumber
	rec.Warnings = append(rec.Warnings, applyFixups(buf)...)

	rec.SequenceNumber = u16(buf, 0x10)
	rec.HardLinkCount = u16(buf, 0x12)
	firstAttr := int(u16(buf, 0x14))
	flags := u16(buf, 0x16)
	rec.InUse = flags&flagInUse != 0
	rec.IsDirectory = flags&flagDirectory != 0
	usedSize := int(u32(buf, 0x18))
	rec.BaseRecordRef = u64(buf, 0x20)

	// NTFS 3.1 records carry their own number at 0x2C. When present it is
	// authoritative -- it survives the record being read out of order --
	// so it is preferred over the caller's index, and a disagreement is
	// worth recording.
	if len(buf) >= 0x30 {
		if self := uint64(u32(buf, 0x2C)); self != 0 && self != recordNumber {
			rec.Warnings = append(rec.Warnings,
				fmt.Sprintf("record self-identifies as %d but sits at table index %d", self, recordNumber))
		}
	}

	if usedSize <= 0 || usedSize > len(buf) {
		usedSize = len(buf)
	}
	if firstAttr < 42 || firstAttr >= usedSize {
		rec.Warnings = append(rec.Warnings, "first attribute offset is outside the record; no attributes were read")
		return rec, true, nil
	}

	off := firstAttr
	for guard := 0; off+4 <= usedSize; guard++ {
		if guard > 512 {
			rec.Warnings = append(rec.Warnings, "attribute chain exceeded 512 entries and was truncated")
			break
		}
		attrType := u32(buf, off)
		if attrType == attrEnd {
			break
		}
		if off+16 > usedSize {
			rec.Warnings = append(rec.Warnings, "attribute header runs past the end of the record")
			break
		}
		attrLen := int(u32(buf, off+4))
		// A zero or negative length would loop forever; an oversized one
		// would read another attribute's bytes.
		if attrLen < 16 || off+attrLen > usedSize {
			rec.Warnings = append(rec.Warnings,
				fmt.Sprintf("attribute at offset %d declares an impossible length %d", off, attrLen))
			break
		}
		rec.AttributeTypes = append(rec.AttributeTypes, attrType)

		nonResident := buf[off+8] != 0
		nameLen := int(buf[off+9])

		switch attrType {
		case attrAttributeList:
			rec.HasAttributeList = true

		case attrStandardInformation:
			if nonResident {
				rec.Warnings = append(rec.Warnings, "$STANDARD_INFORMATION is non-resident, which is not expected; timestamps were not read")
				break
			}
			content, cok := residentContent(buf, off, attrLen)
			if !cok || len(content) < 32 {
				rec.Warnings = append(rec.Warnings, "$STANDARD_INFORMATION is shorter than its four timestamps")
				break
			}
			rec.SI = Timestamps{
				Created:  fileTime(u64(content, 0x00)),
				Modified: fileTime(u64(content, 0x08)),
				Changed:  fileTime(u64(content, 0x10)),
				Accessed: fileTime(u64(content, 0x18)),
			}
			rec.HasSI = true

		case attrFileName:
			if nonResident {
				rec.Warnings = append(rec.Warnings, "$FILE_NAME is non-resident, which is not expected; the name was not read")
				break
			}
			if len(rec.Names) >= lim.MaxNamesPerRecord {
				if lim.StrictNames {
					return Record{}, false, fmt.Errorf("%w: FILE_NAME attribute count at record %d", ErrLimitExceeded, recordNumber)
				}
				rec.Warnings = append(rec.Warnings, "record carries more $FILE_NAME attributes than the limit allows")
				break
			}
			content, cok := residentContent(buf, off, attrLen)
			if !cok || len(content) < 66 {
				rec.Warnings = append(rec.Warnings, "$FILE_NAME is shorter than its fixed header")
				break
			}
			parentRef, parentSeq := fileRef(u64(content, 0x00))
			nameChars := int(content[0x40])
			namespace := content[0x41]
			if lim.StrictNames && nameChars > lim.MaxNameChars {
				return Record{}, false, fmt.Errorf("%w: FILE_NAME character count at record %d", ErrLimitExceeded, recordNumber)
			}
			if lim.StrictNames && (nameChars*2 > len(content)-66 || !validUTF16LE(content[66:66+nameChars*2])) {
				return Record{}, false, fmt.Errorf("%w: invalid FILE_NAME UTF-16 or bounds at record %d", ErrCorrupt, recordNumber)
			}
			name := decodeUTF16(content[0x42:], nameChars, lim.MaxNameChars)
			if name == "" {
				rec.Warnings = append(rec.Warnings, "$FILE_NAME carries an empty or undecodable name")
				break
			}
			rec.Names = append(rec.Names, FileName{
				Name:      name,
				Namespace: namespace,
				ParentRef: parentRef,
				ParentSeq: parentSeq,
				Times: Timestamps{
					Created:  fileTime(u64(content, 0x08)),
					Modified: fileTime(u64(content, 0x10)),
					Changed:  fileTime(u64(content, 0x18)),
					Accessed: fileTime(u64(content, 0x20)),
				},
				PhysicalSize: u64(content, 0x28),
				LogicalSize:  u64(content, 0x30),
			})

		case attrData:
			// Only the UNNAMED $DATA stream is the file's own size; a
			// named stream is an alternate data stream and is reported
			// separately rather than mistaken for the file.
			if nameLen != 0 {
				break
			}
			rec.HasData = true
			if nonResident {
				if off+0x38 > usedSize {
					rec.Warnings = append(rec.Warnings, "non-resident $DATA header is truncated; size not read")
					break
				}
				rec.PhysicalSize = u64(buf, off+0x28)
				rec.LogicalSize = u64(buf, off+0x30)
				rec.SizeKnown = true
				rec.DataResident = false
			} else {
				content, cok := residentContent(buf, off, attrLen)
				if !cok {
					rec.Warnings = append(rec.Warnings, "resident $DATA content is outside the record; size not read")
					break
				}
				rec.LogicalSize = uint64(len(content))
				rec.PhysicalSize = uint64(len(content))
				rec.SizeKnown = true
				rec.DataResident = true
			}
		}

		off += attrLen
	}
	return rec, true, nil
}

// residentContent returns a resident attribute's content, bounds-checked
// against the attribute it belongs to.
func residentContent(buf []byte, attrOff, attrLen int) ([]byte, bool) {
	if attrOff+0x16 > len(buf) {
		return nil, false
	}
	contentLen := int(u32(buf, attrOff+0x10))
	contentOff := int(u16(buf, attrOff+0x14))
	if contentLen < 0 || contentOff < 0x18 || contentOff > attrLen {
		return nil, false
	}
	start := attrOff + contentOff
	end := start + contentLen
	if contentLen > attrLen-contentOff || end > len(buf) || start > end {
		return nil, false
	}
	return buf[start:end], true
}

// DetectRecordSize reads the first record's declared allocation size.
//
// It is taken from the table itself rather than assumed to be 1024,
// because a volume formatted with a larger cluster can use 4096 -- and a
// reader that guesses wrong misaligns every record after the first.
func DetectRecordSize(header []byte) (int, error) {
	if len(header) < 0x20 {
		return 0, fmt.Errorf("%w: fewer than 32 bytes", ErrNotMFT)
	}
	if string(header[0:4]) != recordSignature {
		return 0, ErrNotMFT
	}
	size := int(u32(header, 0x1C))
	switch size {
	case 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536:
		return size, nil
	}
	// Some tools emit tables whose first record understates its
	// allocation. 1024 is the near-universal value; fall back to it
	// rather than refusing the whole table, and let the caller's
	// signature checks catch a genuine misalignment.
	return 1024, nil
}

// Sniff reports whether header looks like an $MFT.
//
// Deliberately strict: a bare "FILE" signature also appears in unrelated
// formats, so the record's own self-description must agree with it --
// a plausible allocation size, and an update sequence array inside the
// record. Misclassifying an arbitrary file as the master file table
// would put invented filesystem events on a timeline.
func Sniff(header []byte) bool {
	if len(header) < 0x30 || string(header[0:4]) != recordSignature {
		return false
	}
	usaOff := int(u16(header, 0x04))
	usaCount := int(u16(header, 0x06))
	allocated := int(u32(header, 0x1C))
	used := int(u32(header, 0x18))
	switch allocated {
	case 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536:
	default:
		return false
	}
	if used <= 0 || used > allocated {
		return false
	}
	if usaCount < 1 || usaOff < 0x2A || usaOff+usaCount*2 > allocated {
		return false
	}
	// The array must describe exactly the sectors the record spans.
	if sectors := usaCount - 1; sectors <= 0 || allocated%sectors != 0 {
		return false
	}
	firstAttr := int(u16(header, 0x14))
	return firstAttr >= 0x2A && firstAttr < allocated
}

// ScanOptions configures a streaming scan.
type ScanOptions struct {
	// Strict rejects structural damage rather than returning a partial table.
	Strict bool
	Limits Limits
	// Cancelled is polled between records so a long scan can be stopped
	// by the ingestion pipeline. Nil means never cancelled.
	Cancelled func() bool
	// Progress is called periodically with the number of records read so
	// far. Nil disables reporting.
	Progress func(recordsRead int)
	// EmptySlot is called for every slot that holds no record (all zero or
	// not a usable FILE record) and is skipped, so a caller can state how many
	// slots were not counted as records. Nil disables it.
	EmptySlot func(index int)
}

// OffsetError carries the byte offset in the source at which a structural
// refusal happened. Its message is the wrapped error's, unchanged; callers
// read the offset with ErrorOffset.
type OffsetError struct {
	Offset int64
	Err    error
}

func (e *OffsetError) Error() string { return e.Err.Error() }
func (e *OffsetError) Unwrap() error { return e.Err }

// ErrorOffset returns the source offset recorded by the nearest OffsetError.
func ErrorOffset(err error) (int64, bool) {
	var oe *OffsetError
	if errors.As(err, &oe) {
		return oe.Offset, true
	}
	return 0, false
}

func atOffset(off int64, err error) error { return &OffsetError{Offset: off, Err: err} }

// ErrCancelled is returned by Scan when Cancelled reported true.
var ErrCancelled = errors.New("ntfs: scan cancelled")

// Scan streams an $MFT, calling fn for every FILE record found.
//
// Records are read ONE AT A TIME into a single reusable buffer, so peak
// memory is one record regardless of table size -- a multi-gigabyte
// $MFT costs the same as a small one. Nothing is accumulated here; what
// the caller keeps is the caller's decision.
func Scan(path string, opts ScanOptions, fn func(Record) error) error {
	lim := opts.Limits.withDefaults()

	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Size() > lim.MaxFileBytes {
		return fmt.Errorf("%w: file is %d bytes", ErrLimitExceeded, info.Size())
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Establish the record size from the table itself.
	//
	// The first record is NOT assumed to be valid. A real $MFT begins
	// with $MFT's own record, but evidence is routinely carved, padded,
	// or collected with its opening records zeroed, and refusing those
	// outright would discard a readable table. The first 64 KiB is
	// probed at sector alignment for a record that describes itself
	// coherently; that record's declared allocation size is then the
	// stride for the whole table.
	probe := make([]byte, 64<<10)
	n, _ := io.ReadFull(f, probe)
	if n < 64 {
		return fmt.Errorf("%w: file is only %d bytes", ErrNotMFT, n)
	}
	probe = probe[:n]

	recordSize := 0
	for off := 0; off+0x30 <= len(probe); off += 512 {
		if !Sniff(probe[off:]) {
			continue
		}
		size, derr := DetectRecordSize(probe[off:])
		if derr != nil {
			continue
		}
		// The table is an array from offset zero, so a genuine record
		// must sit on a record-size boundary. A "FILE" signature that
		// does not is something else's data.
		if off%size != 0 {
			continue
		}
		recordSize = size
		break
	}
	if recordSize == 0 {
		return ErrNotMFT
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	buf := make([]byte, recordSize)
	for index := 0; ; index++ {
		if index >= lim.MaxRecords {
			return fmt.Errorf("%w: more than %d records", ErrLimitExceeded, lim.MaxRecords)
		}
		if opts.Cancelled != nil && index%64 == 0 && opts.Cancelled() {
			return ErrCancelled
		}
		n, rerr := io.ReadFull(f, buf)
		if rerr == io.EOF {
			break
		}
		if rerr == io.ErrUnexpectedEOF {
			// A trailing partial record: the table was truncated during
			// collection. Everything before it is still good.
			if n < 48 {
				break
			}
			return atOffset(int64(index)*int64(recordSize), fmt.Errorf("%w: trailing partial record of %d bytes", ErrCorrupt, n))
		}
		if rerr != nil {
			return rerr
		}
		if opts.Strict {
			if string(buf[:4]) != "FILE" {
				nonzero := false
				for _, v := range buf {
					if v != 0 {
						nonzero = true
						break
					}
				}
				if nonzero {
					return atOffset(int64(index)*int64(recordSize), fmt.Errorf("%w: non-FILE nonzero slot %d", ErrCorrupt, index))
				}
			} else if !Sniff(buf) {
				return atOffset(int64(index)*int64(recordSize), fmt.Errorf("%w: inconsistent FILE header at slot %d", ErrCorrupt, index))
			}
		}
		rec, ok, perr := ParseRecord(buf, uint64(index), lim)
		if perr != nil {
			if opts.Strict {
				return atOffset(int64(index)*int64(recordSize), perr)
			}
			// One unparseable record must not end the scan.
			rec = Record{RecordNumber: uint64(index), Warnings: []string{perr.Error()}}
			ok = true
		}
		if !ok && len(rec.Warnings) == 0 {
			if opts.EmptySlot != nil {
				opts.EmptySlot(index)
			}
			continue // unused slack
		}
		if err := fn(rec); err != nil {
			return err
		}
		if opts.Progress != nil && index%4096 == 0 {
			opts.Progress(index)
		}
	}
	return nil
}

// DirectoryIndex maps a record number to the directory it names, for
// path reconstruction.
//
// Only DIRECTORIES are retained. A volume's directories are a small
// fraction of its records, so this stays bounded where keeping every
// record would not.
type DirectoryIndex struct {
	entries map[uint64]dirEntry
	// RootNumber is the record number of the volume root (always 5 on
	// NTFS).
	RootNumber uint64
}

type dirEntry struct {
	name   string
	parent uint64
}

// RootRecordNumber is NTFS's fixed record number for the volume root.
const RootRecordNumber = 5

// BuildDirectoryIndex streams the table once and records every
// directory's name and parent.
func BuildDirectoryIndex(path string, opts ScanOptions) (*DirectoryIndex, error) {
	idx := &DirectoryIndex{entries: map[uint64]dirEntry{}, RootNumber: RootRecordNumber}
	err := Scan(path, opts, func(r Record) error {
		if !r.IsDirectory || !r.IsBaseRecord() {
			return nil
		}
		n, ok := r.BestName()
		if !ok {
			return nil
		}
		idx.entries[r.RecordNumber] = dirEntry{name: n.Name, parent: n.ParentRef}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return idx, nil
}

// Len reports how many directories are indexed.
func (d *DirectoryIndex) Len() int { return len(d.entries) }

// Path reconstructs the full path of a name whose parent is parentRef.
//
// Returns the path and whether it is COMPLETE -- that is, whether the
// walk actually reached the volume root. An incomplete path is still
// returned, prefixed to show where the chain broke, because a partial
// path is useful and a silently truncated one is misleading. A cycle in
// the parent chain (only possible in a corrupt table) terminates the
// walk rather than hanging.
func (d *DirectoryIndex) Path(parentRef uint64, name string) (string, bool) {
	const maxDepth = 256
	parts := []string{name}
	current := parentRef
	seen := map[uint64]bool{}
	for depth := 0; depth < maxDepth; depth++ {
		if current == d.RootNumber {
			reverse(parts)
			return "\\" + strings.Join(parts, "\\"), true
		}
		if seen[current] {
			reverse(parts)
			return "<cycle>\\" + strings.Join(parts, "\\"), false
		}
		seen[current] = true
		entry, ok := d.entries[current]
		if !ok {
			reverse(parts)
			return fmt.Sprintf("<unresolved:%d>\\%s", current, strings.Join(parts, "\\")), false
		}
		parts = append(parts, entry.name)
		current = entry.parent
	}
	reverse(parts)
	return "<depth-limit>\\" + strings.Join(parts, "\\"), false
}

func reverse(s []string) {
	sort.SliceStable(s, func(i, j int) bool { return false }) // keep stable semantics explicit
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// NamespaceLabel names a $FILE_NAME namespace for display.
func NamespaceLabel(ns uint8) string {
	switch ns {
	case NamespacePOSIX:
		return "POSIX"
	case NamespaceWin32:
		return "Win32"
	case NamespaceDOS:
		return "DOS (8.3)"
	case NamespaceWin32DOS:
		return "Win32 and DOS"
	}
	return fmt.Sprintf("unknown (%d)", ns)
}
