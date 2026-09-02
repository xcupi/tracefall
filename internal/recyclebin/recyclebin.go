// Package recyclebin reads Windows Recycle Bin $I metadata records.
//
// # What an $I file is, and what it is not
//
// When a file is sent to the Recycle Bin, Windows splits it in two:
//
//	$I<id><ext>  a small METADATA record -- the original full path, the
//	             original size, and the moment of deletion.
//	$R<id><ext>  the file's CONTENT, renamed and moved.
//
// This package reads the $I record ONLY. It never opens or interprets an
// $R file, and an $I record on its own says nothing about whether the
// content still exists or what it contained. The two are paired by their
// shared identifier, and where that pairing can be established from the
// collection it is reported as an observation about the evidence -- not
// as a claim about the content.
//
// # What the deletion time means
//
// The timestamp is when the file was moved to the Recycle Bin. It is not
// the file's last-write time, not its creation time, and not evidence
// that anything ran. Nothing here or above it converts it into one.
//
// # Versions
//
// Two record formats exist and both are read:
//
//	Version 1  Windows Vista through 8.1. Fixed 544 bytes: the path
//	           occupies a fixed 260-character UTF-16 field.
//	Version 2  Windows 10 and later. Variable: a character count
//	           precedes a path of exactly that length.
//
// A record declaring any other version is REPORTED as unsupported
// rather than decoded with a layout that may not apply -- reading a
// version-3 record with the version-2 offsets would produce a path that
// looks authoritative and is not.
package recyclebin

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	// ErrNotRecycleBinRecord means the file is not an $I metadata record.
	ErrNotRecycleBinRecord = errors.New("recyclebin: not a Recycle Bin $I metadata record")
	// ErrUnsupportedVersion means the record declares a format version
	// this build does not decode.
	ErrUnsupportedVersion = errors.New("recyclebin: unsupported $I record version")
	// ErrCorrupt means the record is structurally invalid or truncated.
	ErrCorrupt = errors.New("recyclebin: $I record is corrupt or truncated")
	// ErrLimitExceeded means a declared size exceeded a safety ceiling.
	ErrLimitExceeded = errors.New("recyclebin: $I record exceeds a safety limit")
)

const (
	// headerBytes is the fixed prefix both versions share: version,
	// file size, deletion time.
	headerBytes = 24
	// v1PathChars is version 1's fixed path field, in UTF-16 characters.
	v1PathChars = 260
	// v1RecordBytes is version 1's total, fixed, size.
	v1RecordBytes = headerBytes + v1PathChars*2 // 544
	// maxPathChars bounds a version 2 path. Windows extended paths reach
	// 32767 characters; anything beyond that is a corrupt length field.
	maxPathChars = 32767
)

// Version numbers this package decodes.
const (
	Version1 = 1 // Vista - 8.1
	Version2 = 2 // Windows 10+
)

// Limits bounds what one record may consume.
type Limits struct {
	MaxFileBytes int64
}

// DefaultLimits comfortably fit any real record: version 1 is 544 bytes
// and version 2 is a header plus one path.
func DefaultLimits() Limits { return Limits{MaxFileBytes: 1 << 20} }

func (l Limits) withDefaults() Limits {
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = DefaultLimits().MaxFileBytes
	}
	return l
}

// Record is one parsed $I metadata record.
type Record struct {
	Version uint64
	// OriginalSize is the deleted file's size in bytes, as recorded at
	// deletion. It describes the ORIGINAL file, not the $I record and
	// not the $R file on disk now.
	OriginalSize uint64
	// DeletionTime is when the file was moved to the Recycle Bin, in UTC.
	// Zero means the record carried no usable time.
	DeletionTime time.Time
	// OriginalPath is the full path the file had before deletion.
	OriginalPath string
	// PathChars is the character count version 2 declared. Zero for
	// version 1, whose field is fixed.
	PathChars uint32
	Warnings  []string
}

// OriginalName is the file's own name, without its directory.
func (r Record) OriginalName() string {
	p := strings.ReplaceAll(r.OriginalPath, `\`, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// OriginalDirectory is the directory the file was deleted from.
func (r Record) OriginalDirectory() string {
	if i := strings.LastIndex(r.OriginalPath, `\`); i > 0 {
		return r.OriginalPath[:i]
	}
	return ""
}

// Sniff reports whether header begins an $I metadata record.
//
// Detection is structural, never by filename. The version word alone is
// far too weak -- a little-endian 1 or 2 in the first eight bytes is
// common -- so the record must also declare a deletion time that
// converts to a plausible date and, for version 1, a path field that
// begins like a path. Requiring all of that together is what keeps
// unrelated files out.
func Sniff(header []byte) bool {
	if len(header) < headerBytes {
		return false
	}
	version := binary.LittleEndian.Uint64(header[0:8])
	if version != Version1 && version != Version2 {
		return false
	}
	if fileTime(binary.LittleEndian.Uint64(header[16:24])).IsZero() {
		return false
	}
	switch version {
	case Version1:
		// The fixed path field starts immediately. A real record begins
		// with a drive letter or a UNC prefix.
		if len(header) < headerBytes+8 {
			return false
		}
		return plausiblePathStart(decodeUTF16(header[headerBytes : headerBytes+8]))
	default:
		if len(header) < headerBytes+4 {
			return false
		}
		n := binary.LittleEndian.Uint32(header[24:28])
		if n == 0 || n > maxPathChars {
			return false
		}
		avail := (len(header) - headerBytes - 4) / 2
		if avail > int(n) {
			avail = int(n)
		}
		if avail < 4 {
			return false
		}
		return plausiblePathStart(decodeUTF16(header[headerBytes+4 : headerBytes+4+avail*2]))
	}
}

// plausiblePathStart reports whether s begins like a Windows path:
// "C:\..." or a UNC "\\server\...".
func plausiblePathStart(s string) bool {
	if strings.HasPrefix(s, `\\`) {
		return true
	}
	if len(s) < 3 {
		return false
	}
	c := s[0]
	isLetter := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
	return isLetter && s[1] == ':' && s[2] == '\\'
}

// ParseFile reads one $I file.
func ParseFile(path string, lim Limits) (Record, error) {
	lim = lim.withDefaults()
	info, err := os.Stat(path)
	if err != nil {
		return Record{}, err
	}
	if info.Size() > lim.MaxFileBytes {
		return Record{}, fmt.Errorf("%w: file is %d bytes", ErrLimitExceeded, info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Record{}, err
	}
	return Parse(data)
}

// Parse reads a record from memory.
func Parse(data []byte) (rec Record, err error) {
	defer func() {
		if r := recover(); r != nil {
			rec, err = Record{}, fmt.Errorf("%w: recovered from %v", ErrCorrupt, r)
		}
	}()

	if len(data) < headerBytes {
		return Record{}, fmt.Errorf("%w: %d bytes, shorter than the fixed header", ErrCorrupt, len(data))
	}
	version := binary.LittleEndian.Uint64(data[0:8])
	if version != Version1 && version != Version2 {
		return Record{}, fmt.Errorf("%w: record declares version %d; this build reads versions 1 and 2",
			ErrUnsupportedVersion, version)
	}

	r := Record{
		Version:      version,
		OriginalSize: binary.LittleEndian.Uint64(data[8:16]),
	}
	rawTime := binary.LittleEndian.Uint64(data[16:24])
	r.DeletionTime = fileTime(rawTime)
	if r.DeletionTime.IsZero() && rawTime != 0 {
		r.Warnings = append(r.Warnings,
			"the deletion timestamp is outside any plausible range and was discarded rather than placed on a timeline")
	}

	switch version {
	case Version1:
		// A fixed 260-character field. A short file is read as far as it
		// goes: the path is the point of the record, and a truncated one
		// still carries its beginning.
		end := headerBytes + v1PathChars*2
		if end > len(data) {
			r.Warnings = append(r.Warnings, fmt.Sprintf(
				"version 1 records are %d bytes; this file is %d, so the path field is truncated",
				v1RecordBytes, len(data)))
			end = len(data)
		}
		r.OriginalPath = safeString(decodeUTF16NulTerminated(data[headerBytes:end]))
	default:
		if len(data) < headerBytes+4 {
			return Record{}, fmt.Errorf("%w: version 2 record ends before its path length", ErrCorrupt)
		}
		n := binary.LittleEndian.Uint32(data[24:28])
		if n == 0 || n > maxPathChars {
			return Record{}, fmt.Errorf("%w: version 2 record declares a %d-character path", ErrCorrupt, n)
		}
		r.PathChars = n
		end := headerBytes + 4 + int(n)*2
		if end > len(data) {
			r.Warnings = append(r.Warnings, fmt.Sprintf(
				"the record declares a %d-character path but only %d characters are present; the path is truncated",
				n, (len(data)-headerBytes-4)/2))
			end = len(data)
		}
		r.OriginalPath = safeString(decodeUTF16NulTerminated(data[headerBytes+4 : end]))
	}

	if r.OriginalPath == "" {
		return Record{}, fmt.Errorf("%w: the record carries no original path", ErrCorrupt)
	}
	return r, nil
}

// PairedRFile is the $R file that holds a deleted file's content.
type PairedRFile struct {
	// Name is the $R file's name, derived from the $I file's own name by
	// the format's own rule: the same identifier and extension.
	Name string
	// Found reports whether that file was actually present beside the $I
	// record in the collection. When false, Name is what WOULD pair, not
	// something observed.
	Found bool
	// SizeBytes is the paired file's size on disk, when found. It may
	// legitimately differ from Record.OriginalSize.
	SizeBytes int64
}

// PairedName derives the $R filename for an $I filename.
//
// The rule is the format's own and is deterministic: $I and $R records
// share everything after the first two characters. A name that does not
// start with "$I" has no derivable pair, and this returns "" rather than
// constructing one.
//
// The CASE of the prefix letter is preserved. Windows writes "$I"/"$R"
// in upper case, but Tracefall resolves the pair by opening a file on a
// case-sensitive filesystem: a collection carrying "$iABC" would be sent
// looking for "$RABC", find nothing, and report a false orphan. Deriving
// "$rABC" from "$iABC" keeps the lookup honest.
func PairedName(iName string) string {
	if len(iName) < 2 || !strings.EqualFold(iName[:2], "$I") {
		return ""
	}
	return iName[:1] + swapCaseOf(iName[1], 'R') + iName[2:]
}

// swapCaseOf returns want in the same case as the letter it replaces.
func swapCaseOf(observed byte, want byte) string {
	if observed >= 'a' && observed <= 'z' {
		return string(want + ('a' - 'A'))
	}
	return string(want)
}

// ResolvePair looks for the $R file beside the given $I file.
//
// It stats a sibling; it never reads one. The distinction matters: the
// association is an observation about the COLLECTION -- "the paired file
// was present, at this size" -- and is reported as such. Nothing about
// the deleted content is claimed, and when the sibling is absent the
// result says so rather than implying the content is gone from the
// original system.
func ResolvePair(iPath string) PairedRFile {
	name := PairedName(filepath.Base(iPath))
	if name == "" {
		return PairedRFile{}
	}
	p := PairedRFile{Name: name}
	info, err := os.Stat(filepath.Join(filepath.Dir(iPath), name))
	if err != nil || info.IsDir() {
		return p
	}
	p.Found = true
	p.SizeBytes = info.Size()
	return p
}

// decodeUTF16NulTerminated decodes little-endian UTF-16, stopping at the
// first NUL character -- which is how both record versions terminate a
// path that is shorter than its field.
func decodeUTF16NulTerminated(b []byte) string {
	limit := len(b) - len(b)%2
	for i := 0; i+1 < limit; i += 2 {
		if b[i] == 0 && b[i+1] == 0 {
			limit = i
			break
		}
	}
	return decodeUTF16(b[:limit])
}

func decodeUTF16(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	return string(utf16.Decode(u))
}

func safeString(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return -1
		}
		return r
	}, s)
}

// fileTime converts a Windows FILETIME to UTC, matching the rule used by
// internal/prefetch, internal/ntfs and internal/shelllink: zero means
// "not recorded", and a value outside a plausible window is discarded
// rather than placed on a timeline.
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

// ---------- $R: the deleted file's content ----------
//
// Everything above reads the $I metadata record. What follows resolves
// the other half of the pair: the $R file, which holds the CONTENT of
// the deleted file and no metadata whatsoever.
//
// The asymmetry matters. An $I record is self-describing -- a version,
// a size, a timestamp and a path, all verifiable from its own bytes. An
// $R file is whatever the deleted file was: a document, an executable,
// an empty file. It carries no signature, no header and no name beyond
// the identifier it shares with its $I. So NOTHING about a $R file can
// be established from the file itself, and every fact about it -- what
// it was called, where it lived, when it was deleted -- comes from the
// paired $I record or from nowhere at all.

// ContentStatus says what happened when the deleted content was read.
type ContentStatus string

const (
	// ContentRecovered means the whole file was read and hashed.
	ContentRecovered ContentStatus = "recovered"
	// ContentUnreadable means the file exists but could not be read --
	// a permission error, an I/O failure, a directory in its place.
	ContentUnreadable ContentStatus = "unreadable"
	// ContentTooLarge means the file exceeded the size ceiling and was
	// deliberately not read. Not an error, and not a recovery either.
	ContentTooLarge ContentStatus = "not_read_size_limit"
)

// RecoveredContent describes a $R file's actual content.
//
// It states only what was measured. Nothing here is taken from the $I
// record: OriginalPath and DeletionTime live on the Record, and keeping
// the two apart is what stops a size measured on disk being reported as
// the size the deletion recorded.
type RecoveredContent struct {
	// Name is the $R file's own on-disk name. It is an identifier, NOT
	// the deleted file's name -- see Record.OriginalName for that.
	Name   string
	Status ContentStatus
	// SizeBytes is what the collected file actually measures.
	SizeBytes int64
	// SHA256 is the hash of the bytes actually read. Empty unless
	// Status is ContentRecovered: a partial read must not produce a
	// digest that looks like the file's.
	SHA256 string
	// ReadError is the sanitized failure reason when Status is
	// ContentUnreadable.
	ReadError string
	Warnings  []string
}

// PairedIName derives the $I filename for a $R filename.
//
// The inverse of PairedName, and equally deterministic: the two halves
// of a pair share everything after the first two characters. A name that
// does not start with "$R" has no derivable pair, and this returns ""
// rather than constructing one. The prefix letter's case is preserved
// for the same reason PairedName preserves it.
func PairedIName(rName string) string {
	if len(rName) < 2 || !strings.EqualFold(rName[:2], "$R") {
		return ""
	}
	return rName[:1] + swapCaseOf(rName[1], 'I') + rName[2:]
}

// PairedRecord is the outcome of resolving a $R file's metadata.
type PairedRecord struct {
	// IName is the $I file that WOULD pair, derived from the $R name.
	// Always set for a validly named $R, whether or not it was found.
	IName string
	// Found reports that the $I file exists beside the $R file.
	Found bool
	// Record is the parsed metadata. Valid only when Err is nil.
	Record Record
	// Err is why the pairing produced no metadata: the $I was absent,
	// or present and unreadable as a record.
	Err error
}

// Valid reports whether this pairing yielded usable metadata.
func (p PairedRecord) Valid() bool { return p.Found && p.Err == nil }

// ResolveIRecord finds and parses the $I record that describes a $R
// file's content.
//
// This is the ONE place a Recycle Bin parser reads a file other than the
// one it was given, and it is justified by the format rather than by
// convenience: a $R file is meaningless alone, and the pairing rule is
// the format's own, deterministic, and confined to the same directory.
// The $I is opened read-only and parsed by the same code path any other
// $I record goes through -- no second, looser parser exists for this.
//
// Every failure is reported, never smoothed over. A missing $I, an $I
// that is not a record, and an $I of an unsupported version are three
// different findings and reach the caller as three different errors.
func ResolveIRecord(rPath string, lim Limits) PairedRecord {
	name := PairedIName(filepath.Base(rPath))
	if name == "" {
		return PairedRecord{Err: fmt.Errorf("%w: %q is not a $R filename, so no $I record can be derived from it",
			ErrNotRecycleBinRecord, filepath.Base(rPath))}
	}
	p := PairedRecord{IName: name}

	iPath := filepath.Join(filepath.Dir(rPath), name)
	info, err := os.Stat(iPath)
	if err != nil || info.IsDir() {
		p.Err = fmt.Errorf("the paired metadata record %q was not collected with this file", name)
		return p
	}
	p.Found = true

	rec, err := ParseFile(iPath, lim)
	if err != nil {
		p.Err = fmt.Errorf("the paired file %q is present but is not a readable $I record: %w", name, err)
		return p
	}
	p.Record = rec
	return p
}

// ReadContent measures and hashes a $R file's content.
//
// The hash is computed by streaming, so a large deleted file is never
// held in memory, and it covers the bytes ACTUALLY read: a read that
// fails part-way produces no digest at all rather than one that
// describes a fragment while looking like it describes the file.
func ReadContent(rPath string, maxBytes int64) RecoveredContent {
	c := RecoveredContent{Name: filepath.Base(rPath), Status: ContentUnreadable}

	info, err := os.Stat(rPath)
	if err != nil {
		c.ReadError = "the file could not be opened"
		return c
	}
	if info.IsDir() {
		c.ReadError = "a directory exists where the deleted content should be"
		return c
	}
	c.SizeBytes = info.Size()
	if maxBytes > 0 && c.SizeBytes > maxBytes {
		c.Status = ContentTooLarge
		c.Warnings = append(c.Warnings, fmt.Sprintf(
			"the recovered file is %d bytes, above the %d-byte ceiling for hashing; its size is recorded and its content was not read",
			c.SizeBytes, maxBytes))
		return c
	}

	f, err := os.Open(rPath)
	if err != nil {
		c.ReadError = "the file could not be opened"
		return c
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		// A partial read is NOT a recovery. Reporting a digest here
		// would produce a hash that identifies neither the file nor
		// anything else an examiner could verify.
		c.ReadError = "the file could not be read to completion"
		c.Warnings = append(c.Warnings, fmt.Sprintf(
			"reading stopped after %d of %d bytes; no hash was computed for a partial read", n, c.SizeBytes))
		return c
	}
	if n != c.SizeBytes {
		c.Warnings = append(c.Warnings, fmt.Sprintf(
			"the file measured %d bytes but %d were read; it changed while being read", c.SizeBytes, n))
		c.SizeBytes = n
	}
	c.Status = ContentRecovered
	c.SHA256 = hex.EncodeToString(h.Sum(nil))
	return c
}

// CompareSize reports how a recovered file's size relates to the size
// the $I record stated at deletion.
//
// Both values are returned to the caller untouched. The $I value is what
// the system recorded when the file was deleted; the measured value is
// what the collection actually holds. When they differ, that is a fact
// about the evidence -- not a reason to correct either number.
func CompareSize(recordedSize uint64, measured int64) (matches bool, warning string) {
	if measured < 0 {
		return false, ""
	}
	if uint64(measured) == recordedSize {
		return true, ""
	}
	return false, fmt.Sprintf(
		"the $I record states an original size of %d bytes but the collected $R file measures %d; "+
			"both values are preserved and neither has been adjusted",
		recordedSize, measured)
}
