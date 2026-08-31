// Package prefetch reads raw Windows Prefetch (.pf) files directly from
// their binary form.
//
// Prefetch is one of the highest-value execution artifacts on a Windows
// system: it records that a program ran, how many times, when it last
// ran (and on Windows 8 and later, the last eight times), and which
// files and directories it touched while starting. Tracefall previously
// classified .pf as a recognized-but-unparsed artifact; this reads it.
//
// The format is implemented against libyal's "Windows Prefetch File (PF)
// format" specification. Supported format versions:
//
//	17  Windows XP / 2003
//	23  Windows Vista / 7
//	26  Windows 8.0 / 8.1
//	30  Windows 10   (both file-information variants)
//	31  Windows 11
//
// # The MAM limitation, stated plainly
//
// Windows 10 and 11 store Prefetch files LZXPRESS-Huffman compressed
// behind a "MAM\x04" header. This package does NOT implement that
// decompression, so such a file is detected and reported as a structured
// parse failure naming the reason -- never silently skipped, and never
// pretended to be parsed. In practice that means raw .pf collected from
// a modern Windows host will usually need decompressing before Tracefall
// can read it. See docs/evidence-triage.md.
//
// # Hostile input
//
// Every offset and count in the file is attacker-controlled. Each is
// bounds-checked against the actual file size before use, counts are
// capped, and strings are length-limited. A malformed file returns an
// error; it never panics, loops forever, or allocates without bound.
package prefetch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

var (
	// ErrNotPrefetch means the file carries no SCCA signature.
	ErrNotPrefetch = errors.New("prefetch: not a Windows Prefetch file (bad signature)")
	// ErrCompressed means the file is a MAM-compressed Prefetch, which
	// this package deliberately does not decompress.
	ErrCompressed = errors.New("prefetch: file is MAM (LZXPRESS Huffman) compressed, which Tracefall does not decompress")
	// ErrUnsupportedVersion means the SCCA signature is present but the
	// format version is one this package has no layout for.
	ErrUnsupportedVersion = errors.New("prefetch: unsupported Prefetch format version")
	// ErrCorrupt means the structure is invalid, truncated, or
	// self-inconsistent.
	ErrCorrupt = errors.New("prefetch: file is corrupt, truncated, or structurally invalid")
	// ErrLimitExceeded means a hard safety ceiling was reached.
	ErrLimitExceeded = errors.New("prefetch: file exceeds a safety limit")
)

const (
	headerSize   = 84
	signature    = "SCCA"
	mamSignature = "MAM\x04"
)

// Limits bounds what one Prefetch file may consume.
type Limits struct {
	MaxFileBytes   int64
	MaxFilenames   int
	MaxVolumes     int
	MaxStringChars int
}

// DefaultLimits comfortably fit any real Prefetch file -- they are
// typically well under a megabyte and reference a few hundred files.
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:   64 << 20, // 64 MiB
		MaxFilenames:   65536,
		MaxVolumes:     64,
		MaxStringChars: 32768,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxFilenames <= 0 {
		l.MaxFilenames = d.MaxFilenames
	}
	if l.MaxVolumes <= 0 {
		l.MaxVolumes = d.MaxVolumes
	}
	if l.MaxStringChars <= 0 {
		l.MaxStringChars = d.MaxStringChars
	}
	return l
}

// Volume is one volume a prefetched executable touched.
type Volume struct {
	DevicePath   string
	SerialNumber uint32
	CreationTime time.Time
}

// Prefetch is one parsed .pf file.
type Prefetch struct {
	// Version is the SCCA format version (17/23/26/30/31).
	Version uint32
	// ExecutableName is the name recorded INSIDE the file, which is the
	// authoritative one -- the .pf filename can be renamed, this cannot.
	ExecutableName string
	// PrefetchHash is the path-hash component Windows puts in the .pf
	// filename. Reported as evidence, not recomputed.
	PrefetchHash uint32
	RunCount     uint32
	// LastRunTimes are the recorded execution times, most recent first.
	// Version 17 and 23 record one; 26 and later record up to eight.
	// Entries Windows left empty are dropped rather than reported as
	// year-1601 timestamps.
	LastRunTimes []time.Time
	// Filenames are the full paths the executable referenced while
	// starting, in the order the file lists them.
	Filenames []string
	Volumes   []Volume
	// ExecutablePath is the referenced filename that looks like the
	// executable itself, when one can be identified from the referenced
	// file list. Empty when it cannot -- never guessed.
	ExecutablePath string
}

// Sniff reports whether header looks like a Prefetch file. It matches
// both the plain SCCA form and the MAM-compressed wrapper, so a
// compressed file is still RECOGNIZED as Prefetch (and then reported as
// unreadable) rather than being mistaken for an unknown artifact.
func Sniff(header []byte) bool {
	if len(header) >= 4 && string(header[:4]) == mamSignature {
		return true
	}
	// The signature sits at offset 4, after the version.
	return len(header) >= 8 && string(header[4:8]) == signature
}

// IsCompressed reports whether header is the MAM-compressed variant.
func IsCompressed(header []byte) bool {
	return len(header) >= 4 && string(header[:4]) == mamSignature
}

// Parse reads one Prefetch file.
func Parse(path string, lim Limits) (p Prefetch, err error) {
	lim = lim.withDefaults()

	// The format is dense pointer-chasing over hostile bytes. Every read
	// is bounds-checked, but recovering here guarantees the package's
	// promise -- malformed evidence can never take the process down --
	// even if one of those checks is ever missed.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: recovered from %v", ErrCorrupt, r)
		}
	}()

	info, err := os.Stat(path)
	if err != nil {
		return Prefetch{}, err
	}
	if info.Size() > lim.MaxFileBytes {
		return Prefetch{}, fmt.Errorf("%w: file is %d bytes", ErrLimitExceeded, info.Size())
	}
	// Prefetch files are small; reading whole is simpler and safer than
	// seeking around a file whose own offsets cannot be trusted.
	data, err := os.ReadFile(path)
	if err != nil {
		return Prefetch{}, err
	}
	return ParseBytes(data, lim)
}

// ParseBytes parses an in-memory Prefetch file.
func ParseBytes(data []byte, lim Limits) (Prefetch, error) {
	lim = lim.withDefaults()

	if IsCompressed(data) {
		return Prefetch{}, ErrCompressed
	}
	if len(data) < headerSize {
		return Prefetch{}, fmt.Errorf("%w: file is %d bytes, smaller than the 84-byte header", ErrCorrupt, len(data))
	}
	if string(data[4:8]) != signature {
		return Prefetch{}, ErrNotPrefetch
	}

	p := Prefetch{
		Version:        binary.LittleEndian.Uint32(data[0:4]),
		ExecutableName: decodeUTF16(data[16:76]),
		PrefetchHash:   binary.LittleEndian.Uint32(data[76:80]),
	}

	layout, ok := layoutFor(p.Version)
	if !ok {
		return Prefetch{}, fmt.Errorf("%w: version %d", ErrUnsupportedVersion, p.Version)
	}

	fi := data[headerSize:]
	if len(fi) < layout.minSize {
		return Prefetch{}, fmt.Errorf("%w: file information section is %d bytes, need %d", ErrCorrupt, len(fi), layout.minSize)
	}

	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(fi[off : off+4]) }

	filenameOffset := u32(16)
	filenameSize := u32(20)
	volumesOffset := u32(24)
	volumeCount := u32(28)
	p.RunCount = u32(layout.runCountOffset)

	// Last run times.
	for i := 0; i < layout.runTimeCount; i++ {
		off := layout.runTimeOffset + i*8
		if off+8 > len(fi) {
			break
		}
		if t := fileTime(binary.LittleEndian.Uint64(fi[off : off+8])); !t.IsZero() {
			p.LastRunTimes = append(p.LastRunTimes, t)
		}
	}
	// Most recent first, and deduplicated: Windows repeats the newest
	// value into unused slots on some builds, and reporting the same
	// execution eight times would be inventing runs.
	sort.Slice(p.LastRunTimes, func(i, j int) bool { return p.LastRunTimes[i].After(p.LastRunTimes[j]) })
	p.LastRunTimes = dedupeTimes(p.LastRunTimes)

	// Referenced filenames: one NUL-terminated UTF-16 string after
	// another, within a bounded region.
	names, err := readFilenames(data, int(filenameOffset), int(filenameSize), lim)
	if err != nil {
		return Prefetch{}, err
	}
	p.Filenames = names
	p.ExecutablePath = findExecutablePath(p.ExecutableName, names)

	vols, err := readVolumes(data, int(volumesOffset), int(volumeCount), p.Version, lim)
	if err != nil {
		// A damaged volume section must not cost the execution evidence
		// that has already been read -- run count and last-run times are
		// the forensically important part.
		p.Volumes = nil
	} else {
		p.Volumes = vols
	}
	return p, nil
}

// fileInfoLayout captures the version-specific field positions.
type fileInfoLayout struct {
	minSize        int
	runTimeOffset  int
	runTimeCount   int
	runCountOffset int
}

// layoutFor returns the file-information layout for a format version.
//
// Versions 26, 30 and 31 share the same field positions for everything
// this package reads (eight last-run times at 44, run count at 124), so
// they share one layout. Version 30 does have a second documented
// variant whose run count sits at 116 instead; it is NOT distinguished
// here, because the two cannot be told apart from the version field
// alone and guessing would risk misreporting how many times a program
// ran. A file in that variant yields a run count read from the wrong
// offset -- a known limitation recorded in docs/evidence-triage.md
// rather than papered over.
func layoutFor(version uint32) (fileInfoLayout, bool) {
	switch version {
	case 17:
		return fileInfoLayout{minSize: 68, runTimeOffset: 36, runTimeCount: 1, runCountOffset: 60}, true
	case 23:
		return fileInfoLayout{minSize: 156, runTimeOffset: 44, runTimeCount: 1, runCountOffset: 68}, true
	case 26, 30, 31:
		return fileInfoLayout{minSize: 212, runTimeOffset: 44, runTimeCount: 8, runCountOffset: 124}, true
	default:
		return fileInfoLayout{}, false
	}
}

// readFilenames decodes the filename strings section.
func readFilenames(data []byte, offset, size int, lim Limits) ([]string, error) {
	if size == 0 {
		return nil, nil
	}
	if offset < 0 || size < 0 || offset > len(data) || offset+size > len(data) {
		return nil, fmt.Errorf("%w: filename strings section (offset %d, size %d) is outside the file", ErrCorrupt, offset, size)
	}
	section := data[offset : offset+size]

	var out []string
	start := 0
	for i := 0; i+1 < len(section); i += 2 {
		if section[i] != 0 || section[i+1] != 0 {
			continue
		}
		if i > start {
			out = append(out, decodeUTF16(section[start:i]))
			if len(out) > lim.MaxFilenames {
				return nil, fmt.Errorf("%w: more than %d referenced filenames", ErrLimitExceeded, lim.MaxFilenames)
			}
		}
		start = i + 2
	}
	if start < len(section) {
		if s := decodeUTF16(section[start:]); s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// readVolumes decodes the volume information entries.
func readVolumes(data []byte, offset, count int, version uint32, lim Limits) ([]Volume, error) {
	if count <= 0 || offset <= 0 {
		return nil, nil
	}
	if count > lim.MaxVolumes {
		count = lim.MaxVolumes
	}
	entrySize := 96
	switch version {
	case 17:
		entrySize = 40
	case 23, 26:
		entrySize = 104
	}
	if offset > len(data) {
		return nil, fmt.Errorf("%w: volume section outside the file", ErrCorrupt)
	}

	out := make([]Volume, 0, count)
	for i := 0; i < count; i++ {
		base := offset + i*entrySize
		if base+entrySize > len(data) {
			break
		}
		e := data[base : base+entrySize]
		pathOffset := int(binary.LittleEndian.Uint32(e[0:4]))
		pathChars := int(binary.LittleEndian.Uint32(e[4:8]))
		v := Volume{
			CreationTime: fileTime(binary.LittleEndian.Uint64(e[8:16])),
			SerialNumber: binary.LittleEndian.Uint32(e[16:20]),
		}
		// The device path offset is relative to the START of the volume
		// information section, not to this entry.
		if pathChars > 0 && pathChars <= lim.MaxStringChars {
			s := offset + pathOffset
			n := pathChars * 2
			if s >= 0 && s+n <= len(data) {
				v.DevicePath = decodeUTF16(data[s : s+n])
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// findExecutablePath picks the referenced file that IS the executable,
// by matching the name Windows recorded in the header. Returns "" when
// no referenced path matches -- the path is reported only when the
// evidence actually contains it.
func findExecutablePath(exeName string, filenames []string) string {
	if exeName == "" {
		return ""
	}
	want := "\\" + strings.ToUpper(exeName)
	for _, f := range filenames {
		if strings.HasSuffix(strings.ToUpper(f), want) {
			return f
		}
	}
	return ""
}

func dedupeTimes(times []time.Time) []time.Time {
	if len(times) == 0 {
		return nil
	}
	out := times[:1]
	for _, t := range times[1:] {
		if !t.Equal(out[len(out)-1]) {
			out = append(out, t)
		}
	}
	return out
}

// decodeUTF16 decodes little-endian UTF-16, stopping at the first NUL.
func decodeUTF16(b []byte) string {
	n := len(b) &^ 1
	u := make([]uint16, 0, n/2)
	for i := 0; i < n; i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// fileTime converts a Windows FILETIME to a Go time, rejecting values
// outside a plausible range rather than placing an execution in 1601.
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
