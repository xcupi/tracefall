// Package jumplist reads Windows Jump Lists.
//
// # What a Jump List is
//
// Windows keeps a per-application list of the items a user has recently
// or frequently reached through that application. It is stored in two
// quite different containers:
//
//	*.automaticDestinations-ms  an OLE compound file. Each numbered
//	                            stream holds one embedded shortcut, and
//	                            a "DestList" stream holds the most-
//	                            recently-used order plus, per entry, an
//	                            access count and a last-recorded access
//	                            time.
//	*.customDestinations-ms     NOT a compound file. A sequence of
//	                            embedded shortcuts written back to back,
//	                            which an application supplies for its own
//	                            "Tasks" and pinned categories.
//
// The two are read by separate code paths because they are separate
// formats; forcing one onto the other would mean guessing.
//
// # What a Jump List entry proves
//
// That the named application holds a reference to the target, and -- for
// Automatic Destinations, where a DestList entry exists -- that the
// reference was last touched at a recorded time and has been reached a
// recorded number of times.
//
// It is NOT proof that the target was executed. Windows adds entries for
// files opened, saved, previewed, or reached through a dialog, and an
// application may add its own without user action. The embedded
// shortcut's three timestamps belong to the TARGET FILE, exactly as they
// do in a standalone .lnk, and are not moments of use.
//
// # Reuse
//
// Embedded shortcuts are decoded by internal/shelllink -- the same
// parser that reads standalone .lnk files, with the same bounds checks
// and the same refusal to invent fields. Nothing about the shell link
// format is reimplemented here.
//
// # Deliberately not decoded
//
// The DestList entry's four droid GUIDs (link-tracking volume and object
// identifiers) are read as opaque identifiers and not resolved to
// volumes or MAC addresses. The "pinned" flag is reported; the several
// undocumented fields around it are not guessed at.
package jumplist

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"tracefall/internal/olecf"
	"tracefall/internal/shelllink"
)

var (
	// ErrNotJumpList means the file is neither container format.
	ErrNotJumpList = errors.New("jumplist: not a Windows Jump List")
	// ErrCorrupt means the container is structurally invalid.
	ErrCorrupt = errors.New("jumplist: Jump List is corrupt or truncated")
	// ErrLimitExceeded means a declared size exceeded a safety ceiling.
	ErrLimitExceeded = errors.New("jumplist: Jump List exceeds a safety limit")
	// ErrUnsupportedVersion means a DestList version this build does not
	// decode. The shortcuts are still readable when this happens.
	ErrUnsupportedVersion = errors.New("jumplist: unsupported DestList version")
)

// Kind names which container a Jump List came from.
type Kind string

const (
	KindAutomatic Kind = "automatic_destinations"
	KindCustom    Kind = "custom_destinations"
)

// Limits bounds what one Jump List may consume.
type Limits struct {
	MaxFileBytes int64
	MaxEntries   int
	Link         shelllink.Limits
	OLE          olecf.Limits
}

// DefaultLimits comfortably fit any real Jump List: a large one holds a
// few hundred entries of a few kilobytes each.
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes: 64 << 20,
		MaxEntries:   4096,
		Link:         shelllink.DefaultLimits(),
		OLE:          olecf.DefaultLimits(),
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = d.MaxEntries
	}
	return l
}

// DestListEntry is one row of the DestList stream: the Jump List's own
// record of an item, as distinct from the shortcut that describes the
// target.
type DestListEntry struct {
	// EntryNumber ties this row to the stream holding its shortcut. The
	// stream is named for this number in lower-case hexadecimal.
	EntryNumber uint32
	// StreamName is EntryNumber rendered the way the container names it.
	StreamName string
	// MRUPosition is the row's index in the DestList, where 0 is the
	// most recently used. It is an ORDER, not a time.
	MRUPosition int
	// AccessCount is how many times the application recorded reaching
	// this item.
	AccessCount uint32
	// LastRecordedAccess is the Jump List's OWN timestamp for the entry:
	// when the application last recorded touching it. Zero when the
	// record carried none.
	LastRecordedAccess time.Time
	// Pinned reports that the user pinned the item to the Jump List.
	Pinned bool
	// Hostname is the NetBIOS name the record carries, when set.
	Hostname string
	// Path is the target path as the DestList itself recorded it. It is
	// kept SEPARATE from the shortcut's path: the two can legitimately
	// differ, and a disagreement is worth seeing.
	Path string
	// Warnings records fields that failed validation on this row.
	Warnings []string
}

// Entry is one Jump List item: an embedded shortcut, plus the DestList
// row describing it where one exists.
type Entry struct {
	// StreamName is where the shortcut lived inside the container. For
	// Custom Destinations, which has no streams, it is a synthesized
	// position such as "entry 3".
	StreamName string
	// StreamIndex is the compound-file directory index of the stream, or
	// -1 for Custom Destinations.
	StreamIndex int
	// Offset is where the shortcut began, relative to the start of the
	// stream (Automatic) or of the file (Custom).
	Offset int
	// Bytes is the shortcut's length.
	Bytes int
	// Link is the decoded shortcut. Valid only when LinkError is nil.
	Link shelllink.Link
	// LinkError is why this item's shortcut could not be decoded. The
	// item is still reported: an entry that failed to parse is itself
	// evidence, and the DestList row beside it may still be readable.
	LinkError error
	// Dest is the DestList row for this entry, when one was found.
	Dest *DestListEntry
}

// JumpList is one parsed Jump List file.
type JumpList struct {
	Kind Kind
	// AppID is the identifier the filename carries -- a 16-hex-digit
	// application hash. Empty when the file was renamed and no longer
	// carries one.
	AppID string
	// Application is the resolved application name, or "" when the AppID
	// is not one this build recognizes. Never guessed.
	Application string
	// DestListVersion is the version the DestList declared. Zero when
	// there was no DestList, which is normal for Custom Destinations.
	DestListVersion uint32
	// DeclaredEntries and PinnedEntries are what the DestList header
	// stated, which can legitimately differ from what was recovered.
	DeclaredEntries int
	PinnedEntries   int
	// Entries are the items recovered, in container order.
	Entries []Entry
	// StreamsSeen is how many streams the container held, so "we found
	// three shortcuts in a nine-stream container" is answerable.
	StreamsSeen int
	Warnings    []string
}

// Sniff reports whether data begins either Jump List container.
func Sniff(data []byte) bool {
	return SniffAutomatic(data) || SniffCustom(data)
}

// SniffAutomatic reports whether data is a compound file, the container
// an Automatic Destinations Jump List uses.
//
// It is a NECESSARY condition, not a sufficient one. The compound file
// format is shared with pre-2007 Office documents, MSI packages and
// Thumbs.db, and a Jump List cannot be told from those by its first 512
// bytes -- what distinguishes it is a DestList stream and numbered
// shortcut streams, which are only visible once the container's
// allocation tables have been walked.
//
// So this is deliberately not used to CLAIM a file by content: doing so
// would classify every old .doc in a collection as a Jump List. It is
// exported for callers that have already narrowed by another means, and
// the parser above validates by opening the container.
func SniffAutomatic(data []byte) bool { return olecf.Sniff(data) }

// SniffCustom recognizes a Custom Destinations file.
//
// The format has no signature of its own, but every one begins with a
// small header followed by embedded shortcuts written back to back, and
// a shell link header is 20 bytes of fixed content. Requiring one to
// appear shortly AFTER the start -- never at offset zero -- is what
// makes this both safe and specific: an arbitrary file does not contain
// that sequence by accident, and a file that begins with one is a
// standalone .lnk, which is a different artifact entirely.
func SniffCustom(data []byte) bool {
	limit := len(data)
	if limit > 1024 {
		limit = 1024
	}
	if findLinkHeader(data[:limit], 1) > 0 {
		return true
	}
	// An empty Custom Destinations list has no embedded shortcut and is
	// still one. Recognized by its footer signature.
	return hasCustomFooter(data)
}

// sniffCustom is the internal spelling used by Parse.
func sniffCustom(data []byte) bool { return SniffCustom(data) }

// customFooter terminates a Custom Destinations file. Its presence is
// what lets an EMPTY list be told apart from an unrelated file.
const customFooter = 0xBABFFBAB

// hasCustomFooter reports whether data ends with the Custom Destinations
// footer signature and is long enough to be a header plus that footer.
func hasCustomFooter(data []byte) bool {
	const minCustom = 8
	if len(data) < minCustom {
		return false
	}
	return binary.LittleEndian.Uint32(data[len(data)-4:]) == customFooter
}

// findLinkHeader returns the offset of the next shell link header at or
// after from, or -1.
func findLinkHeader(data []byte, from int) int {
	for i := from; i+0x4C <= len(data); i++ {
		if data[i] != 0x4C {
			continue
		}
		if shelllink.Sniff(data[i:]) {
			return i
		}
	}
	return -1
}

// ParseFile reads one Jump List from disk.
func ParseFile(path string, lim Limits) (JumpList, error) {
	lim = lim.withDefaults()
	info, err := os.Stat(path)
	if err != nil {
		return JumpList{}, err
	}
	if info.Size() > lim.MaxFileBytes {
		return JumpList{}, fmt.Errorf("%w: file is %d bytes", ErrLimitExceeded, info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return JumpList{}, err
	}
	jl, err := Parse(data, lim)
	if err != nil {
		return JumpList{}, err
	}
	jl.AppID, jl.Application = AppIDFromFilename(baseName(path))
	return jl, nil
}

// Parse reads a Jump List already in memory.
//
// The container decides the code path, and the container is identified
// by its own bytes rather than by any name.
func Parse(data []byte, lim Limits) (jl JumpList, err error) {
	lim = lim.withDefaults()
	defer func() {
		if r := recover(); r != nil {
			jl, err = JumpList{}, fmt.Errorf("%w: recovered from %v", ErrCorrupt, r)
		}
	}()

	switch {
	case olecf.Sniff(data):
		return parseAutomatic(data, lim)
	case sniffCustom(data):
		return parseCustom(data, lim)
	default:
		return JumpList{}, ErrNotJumpList
	}
}

// parseAutomatic reads an Automatic Destinations compound file.
//
// Each numbered stream holds one embedded shortcut; the DestList stream
// holds the ordering and the Jump List's own per-entry metadata. A
// failure in either is contained: an unreadable DestList still leaves
// every shortcut readable, and an unreadable shortcut leaves the others
// and the DestList row intact.
func parseAutomatic(data []byte, lim Limits) (JumpList, error) {
	f, err := olecf.Open(data, lim.OLE)
	if err != nil {
		return JumpList{}, fmt.Errorf("jumplist: %w", err)
	}
	jl := JumpList{Kind: KindAutomatic, Warnings: append([]string(nil), f.Warnings...)}

	// The DestList first, so each shortcut can be matched to its row.
	byNumber := map[string]*DestListEntry{}
	if e, ok := f.Find("DestList"); ok {
		raw, rerr := f.Stream(e)
		if rerr != nil {
			jl.Warnings = append(jl.Warnings, "the DestList stream could not be read: "+rerr.Error())
		} else {
			version, declared, pinned, rows, warnings := parseDestList(raw, lim)
			jl.DestListVersion, jl.DeclaredEntries, jl.PinnedEntries = version, declared, pinned
			jl.Warnings = append(jl.Warnings, warnings...)
			for i := range rows {
				byNumber[strings.ToLower(rows[i].StreamName)] = &rows[i]
			}
		}
	} else {
		jl.Warnings = append(jl.Warnings,
			"the container holds no DestList stream, so no most-recently-used order or access times are available")
	}

	for _, e := range f.Streams() {
		if strings.EqualFold(e.Name, "DestList") {
			continue
		}
		jl.StreamsSeen++
		if len(jl.Entries) >= lim.MaxEntries {
			jl.Warnings = append(jl.Warnings, fmt.Sprintf("stopped at the %d-entry limit", lim.MaxEntries))
			break
		}

		entry := Entry{StreamName: e.Name, StreamIndex: e.Index, Offset: 0, Bytes: int(e.Size)}
		raw, serr := f.Stream(e)
		switch {
		case serr != nil:
			entry.LinkError = fmt.Errorf("the stream could not be read: %w", serr)
		case !shelllink.Sniff(raw):
			entry.LinkError = fmt.Errorf("%w: the stream does not begin with a shell link header", shelllink.ErrNotShellLink)
		default:
			link, lerr := shelllink.Parse(raw, lim.Link)
			if lerr != nil {
				entry.LinkError = lerr
			} else {
				entry.Link = link
			}
		}
		if d, ok := byNumber[strings.ToLower(e.Name)]; ok {
			entry.Dest = d
		}
		jl.Entries = append(jl.Entries, entry)
	}

	// A DestList row whose stream is missing is still evidence: the
	// application recorded the item, and the shortcut is simply gone.
	for name, d := range byNumber {
		found := false
		for _, en := range jl.Entries {
			if strings.EqualFold(en.StreamName, name) {
				found = true
				break
			}
		}
		if !found {
			row := d
			jl.Entries = append(jl.Entries, Entry{
				StreamName:  d.StreamName,
				StreamIndex: -1,
				Dest:        row,
				LinkError: fmt.Errorf("%w: the DestList names stream %q but the container holds no such stream",
					ErrCorrupt, d.StreamName),
			})
		}
	}
	return jl, nil
}

// DestList layouts. The fixed part differs by version, and a version
// whose layout is not known is REPORTED rather than decoded with
// another version's offsets -- reading the path length from the wrong
// place produces a path that looks authoritative and is not.
const (
	destListHeaderBytes = 32
	// v1 (Windows 7): the path length sits at 0x70.
	destListV1Fixed = 0x70
	// v3/v4 (Windows 10): four more fields push it to 0x80, and each
	// row carries four trailing bytes after its path.
	destListV3Fixed    = 0x80
	destListV3Trailing = 4
	// maxDestPathChars bounds a declared path length.
	maxDestPathChars = 32767
)

// parseDestList decodes the DestList stream.
func parseDestList(b []byte, lim Limits) (version uint32, declared, pinned int, rows []DestListEntry, warnings []string) {
	if len(b) < destListHeaderBytes {
		return 0, 0, 0, nil, []string{"the DestList stream is shorter than its own header"}
	}
	version = binary.LittleEndian.Uint32(b[0:4])
	declared = int(int32(binary.LittleEndian.Uint32(b[4:8])))
	pinned = int(int32(binary.LittleEndian.Uint32(b[8:12])))
	if declared < 0 {
		warnings = append(warnings, "the DestList declares a negative entry count; the header is damaged")
		declared = 0
	}
	if pinned < 0 {
		pinned = 0
	}

	var fixed, trailing int
	switch version {
	case 1:
		fixed, trailing = destListV1Fixed, 0
	case 3, 4:
		fixed, trailing = destListV3Fixed, destListV3Trailing
	default:
		return version, declared, pinned, nil, append(warnings, fmt.Sprintf(
			"the DestList declares version %d, whose row layout this build does not decode; "+
				"the most-recently-used order and access times are not available, and the shortcuts are unaffected",
			version))
	}

	pos := destListHeaderBytes
	for i := 0; pos+fixed+2 <= len(b); i++ {
		if len(rows) >= lim.MaxEntries {
			warnings = append(warnings, fmt.Sprintf("the DestList stopped at the %d-row limit", lim.MaxEntries))
			break
		}
		row, size, ok := decodeDestListRow(b[pos:], fixed, trailing, i)
		if !ok {
			warnings = append(warnings, fmt.Sprintf(
				"a DestList row at offset %d could not be decoded; the rows after it were not read", pos))
			break
		}
		rows = append(rows, row)
		pos += size
	}
	if declared > 0 && len(rows) != declared {
		warnings = append(warnings, fmt.Sprintf(
			"the DestList declares %d entries but %d rows were decoded", declared, len(rows)))
	}
	return version, declared, pinned, rows, warnings
}

// decodeDestListRow decodes one row, returning its total size.
//
// Every field is validated before the row is accepted. A row whose path
// length does not fit, or whose entry number is implausible, is rejected
// rather than emitted with fields read from the wrong offsets.
func decodeDestListRow(b []byte, fixed, trailing, position int) (DestListEntry, int, bool) {
	if len(b) < fixed+2 {
		return DestListEntry{}, 0, false
	}
	pathChars := int(binary.LittleEndian.Uint16(b[fixed : fixed+2]))
	if pathChars < 0 || pathChars > maxDestPathChars {
		return DestListEntry{}, 0, false
	}
	total := fixed + 2 + pathChars*2 + trailing
	if total > len(b) {
		return DestListEntry{}, 0, false
	}

	e := DestListEntry{
		MRUPosition: position,
		Hostname:    trimNul(string(b[0x48:0x58])),
		EntryNumber: binary.LittleEndian.Uint32(b[0x58:0x5C]),
		AccessCount: binary.LittleEndian.Uint32(b[0x60:0x64]),
	}
	e.StreamName = fmt.Sprintf("%x", e.EntryNumber)
	e.LastRecordedAccess = fileTime(binary.LittleEndian.Uint64(b[0x64:0x6C]))
	if e.LastRecordedAccess.IsZero() && binary.LittleEndian.Uint64(b[0x64:0x6C]) != 0 {
		e.Warnings = append(e.Warnings,
			"the recorded access time is outside any plausible range and was discarded rather than placed on a timeline")
	}
	// 0xFFFFFFFF is the format's "not pinned" sentinel; any other value
	// is a pin position.
	e.Pinned = binary.LittleEndian.Uint32(b[0x6C:0x70]) != 0xFFFFFFFF
	e.Path = safeString(decodeUTF16(b[fixed+2 : fixed+2+pathChars*2]))
	return e, total, true
}

// parseCustom reads a Custom Destinations file.
//
// It is NOT a compound file and is not treated as one. The format is a
// short header followed by embedded shortcuts written back to back, so
// the shortcuts are located by their own 20-byte header signature and
// each is measured by parsing it. Scanning is safe here precisely
// because that signature is fixed and long: a run of bytes does not
// produce one by chance.
func parseCustom(data []byte, lim Limits) (JumpList, error) {
	jl := JumpList{Kind: KindCustom}

	pos := findLinkHeader(data, 0)
	if pos < 0 {
		// No embedded shortcut. That is not automatically "not a Jump
		// List": Windows writes a Custom Destinations file with a header
		// and the footer signature and NO destinations at all, and three
		// such files in one real image were reported as unparseable when
		// they are simply empty. An empty artifact is evidence too --
		// the application registered a custom list and recorded nothing
		// in it -- and calling it corrupt overstates what is known.
		//
		// The footer is what distinguishes an empty list from an
		// unrelated file, so it is required rather than assumed.
		if hasCustomFooter(data) {
			jl.Warnings = append(jl.Warnings,
				"this Custom Destinations list contains no destinations; the container is well-formed and empty")
			return jl, nil
		}
		return JumpList{}, ErrNotJumpList
	}
	if pos > 0 {
		jl.Warnings = append(jl.Warnings, fmt.Sprintf(
			"%d leading bytes precede the first embedded shortcut; the Custom Destinations header is recorded but not decoded", pos))
	}

	for pos >= 0 && pos < len(data) {
		if len(jl.Entries) >= lim.MaxEntries {
			jl.Warnings = append(jl.Warnings, fmt.Sprintf("stopped at the %d-entry limit", lim.MaxEntries))
			break
		}
		entry := Entry{
			StreamName:  fmt.Sprintf("entry %d", len(jl.Entries)),
			StreamIndex: -1,
			Offset:      pos,
		}
		link, err := shelllink.Parse(data[pos:], lim.Link)
		if err != nil {
			entry.LinkError = err
			jl.Entries = append(jl.Entries, entry)
			// Resume the search PAST this header so a malformed entry
			// costs one item, not the rest of the file.
			pos = findLinkHeader(data, pos+1)
			continue
		}
		entry.Link = link

		// The next shortcut's header marks where this one ended. Without
		// a length field in the container, that boundary is the only
		// measurement available, and it is reported as such.
		next := findLinkHeader(data, pos+1)
		if next < 0 {
			entry.Bytes = len(data) - pos
		} else {
			entry.Bytes = next - pos
		}
		jl.Entries = append(jl.Entries, entry)
		jl.StreamsSeen++
		pos = next
	}

	if len(jl.Entries) == 0 {
		return JumpList{}, ErrNotJumpList
	}
	return jl, nil
}

// TargetPath returns the best path for an entry, and where it came from.
//
// The shortcut is preferred: it is a structured record of the target.
// The DestList's own path is used only when the shortcut supplied none,
// and the source is always reported so the two are never conflated.
func (e Entry) TargetPath() (path, source string) {
	if e.LinkError == nil {
		if p := e.Link.TargetPath(); p != "" {
			return p, "embedded shortcut"
		}
	}
	if e.Dest != nil && e.Dest.Path != "" {
		return e.Dest.Path, "DestList record"
	}
	return "", ""
}

// PathsDisagree reports whether the shortcut and the DestList record
// different targets -- a fact worth surfacing rather than resolving.
func (e Entry) PathsDisagree() bool {
	if e.LinkError != nil || e.Dest == nil || e.Dest.Path == "" {
		return false
	}
	lnk := e.Link.TargetPath()
	return lnk != "" && !strings.EqualFold(lnk, e.Dest.Path)
}

func baseName(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func trimNul(s string) string {
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return safeString(s)
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
		s = strings.ToValidUTF8(s, "�")
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return -1
		}
		return r
	}, s)
}

// fileTime converts a Windows FILETIME to UTC, following the rule used
// across the codebase: zero means "not recorded", and a value outside a
// plausible window is discarded rather than shown as a date.
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
