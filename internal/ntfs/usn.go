package ntfs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// NTFS USN Change Journal ($UsnJrnl:$J).
//
// The journal is the volume's own append-only record of what changed:
// one record per change, each naming the file, its parent, the reason
// bits describing WHAT changed, and when. Unlike the $MFT -- which holds
// only the current state of each file -- the journal retains a history,
// including records for files that have since been deleted.
//
// # What a USN record is and is not
//
// A record says the filesystem observed a change of a given kind at a
// given time. It records NO user, NO process and NO intent. The reason
// bits are preserved verbatim so an examiner can see exactly why an
// event was produced rather than trusting a translation.
//
// # The $J stream is sparse
//
// Windows deallocates the front of the journal as it ages out, so a
// collected $J routinely begins with a large run of zeros and the first
// real record can be megabytes in. The reader therefore scans forward
// for the first structurally coherent record instead of assuming one at
// offset zero.

var (
	// ErrNotUSN means no valid USN record could be found.
	ErrNotUSN = errors.New("ntfs: not a USN change journal ($UsnJrnl:$J)")
	// ErrUnsupportedUSNVersion means the record uses a major version this
	// package does not decode.
	ErrUnsupportedUSNVersion = errors.New("ntfs: unsupported USN record version")
)

// USN reason flags, as documented by Microsoft. Preserved verbatim on
// every event; the names below are for display only.
const (
	UsnReasonDataOverwrite       = 0x00000001
	UsnReasonDataExtend          = 0x00000002
	UsnReasonDataTruncation      = 0x00000004
	UsnReasonNamedDataOverwrite  = 0x00000010
	UsnReasonNamedDataExtend     = 0x00000020
	UsnReasonNamedDataTruncation = 0x00000040
	UsnReasonFileCreate          = 0x00000100
	UsnReasonFileDelete          = 0x00000200
	UsnReasonEAChange            = 0x00000400
	UsnReasonSecurityChange      = 0x00000800
	UsnReasonRenameOldName       = 0x00001000
	UsnReasonRenameNewName       = 0x00002000
	UsnReasonIndexableChange     = 0x00004000
	UsnReasonBasicInfoChange     = 0x00008000
	UsnReasonHardLinkChange      = 0x00010000
	UsnReasonCompressionChange   = 0x00020000
	UsnReasonEncryptionChange    = 0x00040000
	UsnReasonObjectIDChange      = 0x00080000
	UsnReasonReparsePointChange  = 0x00100000
	UsnReasonStreamChange        = 0x00200000
	UsnReasonTransactedChange    = 0x00400000
	UsnReasonIntegrityChange     = 0x00800000
	UsnReasonClose               = 0x80000000
)

// usnReasonNames maps each documented bit to its Microsoft name.
var usnReasonNames = []struct {
	bit  uint32
	name string
}{
	{UsnReasonDataOverwrite, "DATA_OVERWRITE"},
	{UsnReasonDataExtend, "DATA_EXTEND"},
	{UsnReasonDataTruncation, "DATA_TRUNCATION"},
	{UsnReasonNamedDataOverwrite, "NAMED_DATA_OVERWRITE"},
	{UsnReasonNamedDataExtend, "NAMED_DATA_EXTEND"},
	{UsnReasonNamedDataTruncation, "NAMED_DATA_TRUNCATION"},
	{UsnReasonFileCreate, "FILE_CREATE"},
	{UsnReasonFileDelete, "FILE_DELETE"},
	{UsnReasonEAChange, "EA_CHANGE"},
	{UsnReasonSecurityChange, "SECURITY_CHANGE"},
	{UsnReasonRenameOldName, "RENAME_OLD_NAME"},
	{UsnReasonRenameNewName, "RENAME_NEW_NAME"},
	{UsnReasonIndexableChange, "INDEXABLE_CHANGE"},
	{UsnReasonBasicInfoChange, "BASIC_INFO_CHANGE"},
	{UsnReasonHardLinkChange, "HARD_LINK_CHANGE"},
	{UsnReasonCompressionChange, "COMPRESSION_CHANGE"},
	{UsnReasonEncryptionChange, "ENCRYPTION_CHANGE"},
	{UsnReasonObjectIDChange, "OBJECT_ID_CHANGE"},
	{UsnReasonReparsePointChange, "REPARSE_POINT_CHANGE"},
	{UsnReasonStreamChange, "STREAM_CHANGE"},
	{UsnReasonTransactedChange, "TRANSACTED_CHANGE"},
	{UsnReasonIntegrityChange, "INTEGRITY_CHANGE"},
	{UsnReasonClose, "CLOSE"},
}

// UsnReasonNames renders a reason mask as its documented flag names.
//
// An undocumented bit is reported as UNKNOWN_0x… rather than dropped:
// silently discarding a bit would hide the fact that the record said
// something this build does not understand.
func UsnReasonNames(reason uint32) []string {
	var out []string
	var covered uint32
	for _, r := range usnReasonNames {
		if reason&r.bit != 0 {
			out = append(out, r.name)
			covered |= r.bit
		}
	}
	if unknown := reason &^ covered; unknown != 0 {
		out = append(out, fmt.Sprintf("UNKNOWN_0x%08X", unknown))
	}
	sort.Strings(out)
	return out
}

// UsnSourceInfo flags.
const (
	UsnSourceDataManagement          = 0x00000001
	UsnSourceAuxiliaryData           = 0x00000002
	UsnSourceReplicationManagement   = 0x00000004
	UsnSourceClientReplicationManage = 0x00000008
)

// UsnSourceNames renders the SourceInfo mask.
//
// SourceInfo marks a change made by the SYSTEM rather than by a user --
// replication, hierarchical storage, backup. Preserving it matters: an
// examiner reading a burst of changes needs to know whether the
// filesystem attributed them to housekeeping.
func UsnSourceNames(source uint32) []string {
	var out []string
	var covered uint32
	for _, s := range []struct {
		bit  uint32
		name string
	}{
		{UsnSourceDataManagement, "DATA_MANAGEMENT"},
		{UsnSourceAuxiliaryData, "AUXILIARY_DATA"},
		{UsnSourceReplicationManagement, "REPLICATION_MANAGEMENT"},
		{UsnSourceClientReplicationManage, "CLIENT_REPLICATION_MANAGEMENT"},
	} {
		if source&s.bit != 0 {
			out = append(out, s.name)
			covered |= s.bit
		}
	}
	if unknown := source &^ covered; unknown != 0 {
		out = append(out, fmt.Sprintf("UNKNOWN_0x%08X", unknown))
	}
	return out
}

// UsnRecord is one parsed USN change journal record.
type UsnRecord struct {
	// Offset is where the record began in the $J stream, for provenance.
	Offset int64
	Length uint32

	MajorVersion uint16
	MinorVersion uint16

	// FileReference / ParentFileReference are the 48-bit record numbers
	// with their sequence numbers, matching how the $MFT identifies a
	// file. RawFileReference keeps the undecoded value.
	FileReference      uint64
	FileSequence       uint16
	RawFileReference   string
	ParentReference    uint64
	ParentSequence     uint16
	RawParentReference string

	Usn            uint64
	Timestamp      time.Time
	Reason         uint32
	SourceInfo     uint32
	SecurityID     uint32
	FileAttributes uint32
	FileName       string

	// Warnings describe recoverable problems with THIS record.
	Warnings []string
}

// ReasonNames renders this record's reason mask.
func (r UsnRecord) ReasonNames() []string { return UsnReasonNames(r.Reason) }

// usnMinRecordV2 is the fixed header length of a version-2 record; the
// filename follows.
const (
	usnMinRecordV2 = 0x3C
	usnMinRecordV3 = 0x4C
	// usnMaxRecord bounds a single record. Real records are a header
	// plus a filename of at most 255 UTF-16 characters.
	usnMaxRecord = 4096
)

// ParseUsnRecord decodes one record from buf.
//
// Returns the record and its length. A length of zero means buf does not
// begin with a coherent record.
func ParseUsnRecord(buf []byte, offset int64, lim Limits) (rec UsnRecord, size int, err error) {
	lim = lim.withDefaults()
	defer func() {
		if r := recover(); r != nil {
			rec, size, err = UsnRecord{}, 0, fmt.Errorf("%w: recovered from %v", ErrCorrupt, r)
		}
	}()

	if len(buf) < 8 {
		return UsnRecord{}, 0, nil
	}
	length := u32(buf, 0)
	major := u16(buf, 4)
	minor := u16(buf, 6)

	// A record's declared length must be plausible before anything is
	// read from it: 8-byte aligned, at least a header, and within the
	// buffer.
	if length < usnMinRecordV2 || length > usnMaxRecord || length%8 != 0 {
		return UsnRecord{}, 0, nil
	}
	if int(length) > len(buf) {
		return UsnRecord{}, 0, fmt.Errorf("%w: record at %d declares %d bytes but only %d remain",
			ErrCorrupt, offset, length, len(buf))
	}

	rec = UsnRecord{Offset: offset, Length: length, MajorVersion: major, MinorVersion: minor}

	var nameLenOff, nameOffOff int
	switch major {
	case 2:
		if length < usnMinRecordV2 {
			return UsnRecord{}, 0, nil
		}
		fr := u64(buf, 0x08)
		pr := u64(buf, 0x10)
		rec.FileReference, rec.FileSequence = fileRef(fr)
		rec.ParentReference, rec.ParentSequence = fileRef(pr)
		rec.RawFileReference = fmt.Sprintf("0x%016X", fr)
		rec.RawParentReference = fmt.Sprintf("0x%016X", pr)
		rec.Usn = u64(buf, 0x18)
		rec.Timestamp = fileTime(u64(buf, 0x20))
		rec.Reason = u32(buf, 0x28)
		rec.SourceInfo = u32(buf, 0x2C)
		rec.SecurityID = u32(buf, 0x30)
		rec.FileAttributes = u32(buf, 0x34)
		nameLenOff, nameOffOff = 0x38, 0x3A

	case 3:
		// Version 3 widens both file references to 128 bits for ReFS-era
		// identifiers. The low 64 bits still carry the NTFS-style record
		// number, and the full value is preserved.
		if length < usnMinRecordV3 {
			return UsnRecord{}, 0, nil
		}
		lowF, highF := u64(buf, 0x08), u64(buf, 0x10)
		lowP, highP := u64(buf, 0x18), u64(buf, 0x20)
		rec.FileReference, rec.FileSequence = fileRef(lowF)
		rec.ParentReference, rec.ParentSequence = fileRef(lowP)
		rec.RawFileReference = fmt.Sprintf("0x%016X%016X", highF, lowF)
		rec.RawParentReference = fmt.Sprintf("0x%016X%016X", highP, lowP)
		rec.Usn = u64(buf, 0x28)
		rec.Timestamp = fileTime(u64(buf, 0x30))
		rec.Reason = u32(buf, 0x38)
		rec.SourceInfo = u32(buf, 0x3C)
		rec.SecurityID = u32(buf, 0x40)
		rec.FileAttributes = u32(buf, 0x44)
		nameLenOff, nameOffOff = 0x48, 0x4A

	default:
		// A version this build does not decode. Reported rather than
		// guessed at -- decoding a v4 range-tracking record with v2
		// offsets would produce confident nonsense.
		return UsnRecord{
			Offset: offset, Length: length, MajorVersion: major, MinorVersion: minor,
			Warnings: []string{fmt.Sprintf("USN record version %d.%d is not decoded by this build", major, minor)},
		}, int(length), nil
	}

	nameLen := int(u16(buf, nameLenOff))
	nameOff := int(u16(buf, nameOffOff))
	switch {
	case nameOff < nameLenOff+4 || nameOff > int(length):
		rec.Warnings = append(rec.Warnings, "filename offset lies outside the record")
	case nameLen < 0 || nameOff+nameLen > int(length):
		rec.Warnings = append(rec.Warnings, "filename length runs past the end of the record")
	case nameLen == 0:
		rec.Warnings = append(rec.Warnings, "record carries no filename")
	default:
		rec.FileName = decodeUTF16(buf[nameOff:int(length)], nameLen/2, lim.MaxNameChars)
		if rec.FileName == "" {
			rec.Warnings = append(rec.Warnings, "filename could not be decoded")
		}
	}
	if rec.Timestamp.IsZero() {
		rec.Warnings = append(rec.Warnings, "record carries no usable timestamp")
	}
	return rec, int(length), nil
}

// UsnScanOptions configures a journal scan.
type UsnScanOptions struct {
	// Strict rejects undecodable nonzero regions instead of resynchronizing.
	Strict bool
	// NonRecordRegion records unrecognized aligned bytes while preserving the
	// legacy sparse/resynchronizing scan. Identifiable malformed records still fail.
	NonRecordRegion func(offset int64, bytes int)
	Limits          Limits
	Cancelled       func() bool
	Progress        func(recordsRead int, bytesRead int64)
}

// ScanUsnJournal streams a $UsnJrnl:$J file, calling fn for each record.
//
// The journal is read in a sliding window rather than loaded whole: a
// production $J is routinely hundreds of megabytes and is exactly the
// kind of file that must not be materialized in memory. Records are
// variable length and 8-byte aligned, and the stream is resynchronized
// on the next alignment boundary whenever a record fails to decode --
// a corrupt region costs the records inside it, not the rest of the
// journal.
func ScanUsnJournal(path string, opts UsnScanOptions, fn func(UsnRecord) error) error {
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

	const window = 1 << 20 // 1 MiB
	buf := make([]byte, 0, window+usnMaxRecord)
	chunk := make([]byte, window)

	var (
		fileOffset int64 // offset in the file of buf[0]
		records    int
		found      bool
		eof        bool
	)
	steps := 0
	resync := false
	for {
		if !eof && len(buf) < usnMaxRecord {
			n, rerr := f.Read(chunk)
			if n > 0 {
				buf = append(buf, chunk[:n]...)
			}
			if rerr == io.EOF {
				eof = true
			} else if rerr != nil {
				return rerr
			}
		}
		if len(buf) == 0 {
			break
		}
		steps++
		if opts.Cancelled != nil && (steps == 1 || steps%256 == 0) && opts.Cancelled() {
			return ErrCancelled
		}
		if records >= lim.MaxRecords {
			return fmt.Errorf("%w: more than %d USN records", ErrLimitExceeded, lim.MaxRecords)
		}

		// Once framing is lost, arbitrary words are not record headers merely
		// because one field resembles a version. Restore framing only after a
		// complete independently bounded V2/V3 header and UTF-16 name validate.
		if opts.Strict && opts.NonRecordRegion != nil && resync && !coherentUsnCandidate(buf) {
			n := 8
			if len(buf) < n {
				n = len(buf)
			}
			if !bytes.Equal(buf[:n], make([]byte, n)) {
				opts.NonRecordRegion(fileOffset, n)
			}
			buf, fileOffset = advance(buf, fileOffset, 8)
			continue
		}
		if opts.Strict && len(buf) >= 8 {
			major := u16(buf, 4)
			length := u32(buf, 0)
			plausibleLength := length >= usnMinRecordV2 && length <= usnMaxRecord && length%8 == 0
			if opts.NonRecordRegion != nil && (major < 2 || major > 4 || (major == 4 && !plausibleLength)) {
				if !bytes.Equal(buf[:8], make([]byte, 8)) {
					resync = true
					opts.NonRecordRegion(fileOffset, 8)
				}
				buf, fileOffset = advance(buf, fileOffset, 8)
				continue
			}
			if major >= 2 && major <= 4 {
				length := u32(buf, 0)
				if length < usnMinRecordV2 || length > usnMaxRecord || length%8 != 0 {
					return atOffset(fileOffset, fmt.Errorf("%w: invalid USN record length at %d", ErrCorrupt, fileOffset))
				}
			}
		}
		rec, size, perr := ParseUsnRecord(buf, fileOffset, lim)
		switch {
		case perr != nil && !eof:
			// The record straddles the window; pull more and retry.
			if len(buf) >= usnMaxRecord {
				// It cannot straddle: the declared length is bogus.
				buf, fileOffset = advance(buf, fileOffset, 8)
				continue
			}
			n, rerr := f.Read(chunk)
			if n > 0 {
				buf = append(buf, chunk[:n]...)
				continue
			}
			if rerr == io.EOF {
				eof = true
				continue
			}
			return rerr
		case perr != nil:
			if opts.Strict {
				return atOffset(fileOffset, perr)
			}
			// Truncated tail. Everything before it stands.
			return nil
		case size == 0:
			n := 8
			if len(buf) < n {
				n = len(buf)
			}
			if !bytes.Equal(buf[:n], make([]byte, n)) {
				if opts.NonRecordRegion != nil {
					opts.NonRecordRegion(fileOffset, n)
				} else if opts.Strict {
					return atOffset(fileOffset, fmt.Errorf("%w: nonzero undecodable USN bytes at %d", ErrCorrupt, fileOffset))
				}
			}
			// Sparse zeros or an unrecognizable region: step to the next
			// 8-byte boundary and keep looking.
			buf, fileOffset = advance(buf, fileOffset, 8)
			continue
		}

		if opts.Strict {
			if (rec.MajorVersion != 2 && rec.MajorVersion != 3) || rec.MinorVersion != 0 {
				return atOffset(fileOffset, ErrUnsupportedUSNVersion)
			}
			no := 58
			nl := 56
			if rec.MajorVersion == 3 {
				no = 74
				nl = 72
			}
			off, n := int(u16(buf, no)), int(u16(buf, nl))
			if n/2 > lim.MaxNameChars {
				return atOffset(fileOffset, fmt.Errorf("%w: USN filename exceeds %d UTF-16 code units at %d", ErrLimitExceeded, lim.MaxNameChars, fileOffset))
			}
			if n == 0 || n%2 != 0 || off%2 != 0 || off < no+2 || off+n > size {
				return atOffset(fileOffset, fmt.Errorf("%w: invalid USN filename at %d", ErrCorrupt, fileOffset))
			}
			for i := off; i < off+n; i += 2 {
				c := u16(buf, i)
				if c >= 0xd800 && c <= 0xdbff {
					if i+2 >= off+n || u16(buf, i+2) < 0xdc00 || u16(buf, i+2) > 0xdfff {
						return atOffset(fileOffset, fmt.Errorf("%w: invalid UTF-16 at %d", ErrCorrupt, fileOffset))
					}
					i += 2
				} else if c >= 0xdc00 && c <= 0xdfff {
					return atOffset(fileOffset, fmt.Errorf("%w: invalid UTF-16 at %d", ErrCorrupt, fileOffset))
				}
			}
		}
		resync = false
		found = true
		records++
		if err := fn(rec); err != nil {
			return err
		}
		if opts.Progress != nil && records%4096 == 0 {
			opts.Progress(records, fileOffset)
		}
		buf, fileOffset = advance(buf, fileOffset, size)
	}
	if !found {
		return ErrNotUSN
	}
	return nil
}

// coherentUsnCandidate is used only to regain lost framing. It does not
// authorize relaxed decoding of a malformed record at an established boundary.
func coherentUsnCandidate(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	length := int(u32(b, 0))
	major := u16(b, 4)
	if length < usnMinRecordV2 || length > usnMaxRecord || length%8 != 0 || length > len(b) || u16(b, 6) != 0 || (major != 2 && major != 3) {
		return false
	}
	nl, no := 56, 58
	timestampOffset := 32
	if major == 3 {
		if length < usnMinRecordV3 {
			return false
		}
		nl, no = 72, 74
		timestampOffset = 48
	}
	// A plausible recorded instant is necessary to identify a new boundary
	// inside arbitrary non-record bytes. At an established boundary the strict
	// decoder still accepts genuinely undated records and reports them unmapped.
	if fileTime(u64(b, timestampOffset)).IsZero() {
		return false
	}
	n, off := int(u16(b, nl)), int(u16(b, no))
	return n > 0 && n%2 == 0 && off%2 == 0 && off >= no+2 && off+n <= length && validUTF16LE(b[off:off+n])
}

// advance drops n bytes from the front of the window.
func advance(buf []byte, offset int64, n int) ([]byte, int64) {
	if n > len(buf) {
		n = len(buf)
	}
	return buf[n:], offset + int64(n)
}

// SniffUsnJournal reports whether header looks like a $UsnJrnl:$J.
//
// The stream is sparse, so leading zeros are expected and skipped. A
// coherent record must then be found: plausible length and alignment, a
// version this format actually uses, and a timestamp in a sane range.
// Requiring all of them together is what stops an arbitrary file being
// claimed as a change journal.
func SniffUsnJournal(header []byte) bool {
	for off := 0; off+usnMinRecordV2 <= len(header); off += 8 {
		length := u32(header, off)
		if length == 0 {
			continue // sparse region
		}
		if length < usnMinRecordV2 || length > usnMaxRecord || length%8 != 0 {
			return false
		}
		major := u16(header, off+4)
		if major != 2 && major != 3 {
			return false
		}
		if int(length) > len(header)-off {
			// Cannot fully validate from the sniff window, but the
			// header is coherent so far.
			return true
		}
		rec, size, err := ParseUsnRecord(header[off:off+int(length)], int64(off), Limits{})
		if err != nil || size == 0 {
			return false
		}
		// A real record names a file and carries a plausible time.
		return rec.FileName != "" && !rec.Timestamp.IsZero()
	}
	return false
}

// FileAttributeNames renders the Windows file attribute mask.
func FileAttributeNames(attr uint32) []string {
	var out []string
	for _, a := range []struct {
		bit  uint32
		name string
	}{
		{0x00000001, "READONLY"}, {0x00000002, "HIDDEN"}, {0x00000004, "SYSTEM"},
		{0x00000010, "DIRECTORY"}, {0x00000020, "ARCHIVE"}, {0x00000040, "DEVICE"},
		{0x00000080, "NORMAL"}, {0x00000100, "TEMPORARY"}, {0x00000200, "SPARSE_FILE"},
		{0x00000400, "REPARSE_POINT"}, {0x00000800, "COMPRESSED"}, {0x00001000, "OFFLINE"},
		{0x00002000, "NOT_CONTENT_INDEXED"}, {0x00004000, "ENCRYPTED"},
	} {
		if attr&a.bit != 0 {
			out = append(out, a.name)
		}
	}
	return out
}

// IsDirectoryAttr reports whether the attribute mask marks a directory.
func IsDirectoryAttr(attr uint32) bool { return attr&0x00000010 != 0 }

// JoinNames is a small helper for rendering flag lists.
func JoinNames(names []string) string { return strings.Join(names, "|") }
