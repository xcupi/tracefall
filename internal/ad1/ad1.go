// Package ad1 reads AccessData Logical Image (AD1) forensic containers --
// the proprietary format FTK Imager writes for a "Custom Content"/logical
// (file-level, not full-disk) acquisition. AD1 has no official published
// specification; this package's understanding of the binary layout is
// derived from published, cross-referenced reverse-engineering work --
// most directly the actively-maintained, professionally-run
// dissect.evidence project (https://github.com/fox-it/dissect.evidence,
// Fox-IT/NCC Group), cross-checked against pyad1
// (https://github.com/pcbje/pyad1) and AD1-tools
// (https://github.com/al3ks1s/AD1-tools). Only AD1v4 (the version FTK
// Imager has produced for years) is supported -- see Open's version check.
//
// This package only READS. It never writes to, truncates, or otherwise
// modifies the segment files it's given; every exported operation opens
// its inputs O_RDONLY. It is deliberately narrow in scope: enough to
// enumerate the container's file tree cheaply (Discover, matching
// Tracefall's Discover/Select/Import evidence workflow -- see
// internal/ingest's identical two-phase design) and to extract exactly
// one selected entry's bytes on demand (Extract) -- there is no attempt
// to be a general-purpose AD1 library, mount a filesystem, or support
// every metadata attribute AD1 can carry.
//
// Safety, mirroring internal/archive's approach to untrusted ZIP input
// (see that package's doc comment) applied here to an untrusted,
// possibly-corrupt-or-hostile binary container instead:
//
//   - every struct field is bounds-checked against the stream's actual
//     size before use; a length/offset field is never trusted blindly
//   - the FileEntry tree is walked iteratively (an explicit stack, never
//     recursion) with a hard cap on entries visited (Limits.MaxEntries),
//     which also bounds a corrupt/hostile file whose next/child pointers
//     form a cycle -- see walk's doc comment
//   - name/metadata field lengths are capped (Limits.MaxNameBytes /
//     MaxMetaBytes) before the corresponding allocation+read happens
//   - a catalog path is sanitized the same way internal/archive sanitizes
//     a zip entry name before it's ever used to construct an on-disk
//     extraction path (see internal/api's AD1 import adapter, which is
//     what actually writes bytes to disk -- this package only hands back
//     validated relative path strings, it never touches the local
//     filesystem itself except to open the segment files it's given)
//   - decompressed chunk output during Extract is capped
//     (Limits.MaxFileBytes), the same zlib-bomb defense
//     internal/archive.extractFile applies to a zip entry
//
// An ADCRYPT-encrypted container (see isADCrypt) is detected and rejected
// with ErrEncrypted -- decrypting it would need a passphrase or private
// key from the investigator, which is out of this phase's scope (see
// docs/ad1-ingestion.md); it is never silently treated as empty.
package ad1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Sentinel errors. Wrap with fmt.Errorf's %w so callers can classify a
// failure with errors.Is while still getting a specific message -- same
// convention internal/archive uses.
var (
	// ErrNotAD1 means the input's first bytes don't match either the
	// plain AD1 segmented-file magic or the ADCRYPT magic -- this isn't
	// an AD1 container at all (see Sniff).
	ErrNotAD1 = errors.New("ad1: not an AD1 forensic image")
	// ErrEncrypted means the container is ADCRYPT-encrypted. Decryption
	// (passphrase/private-key unlock) is not implemented -- see the
	// package doc comment.
	ErrEncrypted = errors.New("ad1: AD1 image is encrypted (ADCRYPT) -- decryption is not supported")
	// ErrUnsupportedVersion means the logical image header declares a
	// version other than 4.
	ErrUnsupportedVersion = errors.New("ad1: unsupported AD1 logical image version (only version 4 is supported)")
	// ErrCorrupt means a structurally invalid header, an out-of-bounds
	// offset/length, or a truncated read was encountered while parsing.
	// Never silently treated as an empty/valid image.
	ErrCorrupt = errors.New("ad1: AD1 image is corrupt, truncated, or structurally invalid")
	// ErrSegmentsMissing means the first segment declares more than one
	// total segment, but fewer segment files were provided/found.
	ErrSegmentsMissing = errors.New("ad1: AD1 image is segmented and not all segments were provided")
	// ErrLimitExceeded means the image (or one entry in it) exceeds a
	// configured safety limit.
	ErrLimitExceeded = errors.New("ad1: AD1 image exceeds safety limits")
	// ErrNotFound means Extract was asked for a path that doesn't exist
	// in the container's catalog.
	ErrNotFound = errors.New("ad1: path not found in AD1 image")
)

const (
	SegmentedFileMagicText = "ADSEGMENTEDFILE"
	LogicalImageMagicText  = "ADLOGICALIMAGE"
	adcryptMagicText       = "ADCRYPT"
	SegmentHeaderSize      = 512
)

// Limits bounds resource usage while cataloging/extracting an AD1 image.
// All fields are required to be positive; use DefaultLimits for
// production, or construct a small Limits in tests. Mirrors
// internal/archive.Limits' role and shape for the same untrusted-input
// reasons.
type Limits struct {
	MaxEntries   int   // maximum FileEntry nodes visited while walking the tree (also bounds a cyclic/hostile tree)
	MaxNameBytes int   // maximum bytes for one entry's name field
	MaxMetaBytes int   // maximum bytes for one metadata value (hash text, timestamp text, ...)
	MaxPathBytes int   // maximum bytes for one entry's constructed catalog path
	MaxFileBytes int64 // maximum decompressed size accepted for a single Extract call
	MaxSegments  int   // maximum number of segment files a single image may declare
}

// DefaultLimits are conservative but generous enough for a real logical
// acquisition of a user profile or small drive (hundreds of thousands of
// files, deeply nested application data directories).
var DefaultLimits = Limits{
	MaxEntries:   2_000_000,
	MaxNameBytes: 4096,
	MaxMetaBytes: 65536,
	MaxPathBytes: 8192,
	MaxFileBytes: 1 << 30, // 1 GiB per extracted file
	MaxSegments:  256,
}

// Sniff peeks at the first bytes of r (which must have at least 16 bytes
// available; fewer is reported as isAD1=false, not an error) and reports
// whether they match the AD1 segmented-file magic, and separately whether
// the container is ADCRYPT-encrypted. It reads at most 16 bytes and does
// not consume more of r than that if r is also an io.Seeker positioned at
// the start -- callers that need to keep reading from the same position
// should pass a fresh reader or seek back to 0 themselves. This is the
// cheap, magic-bytes-only check internal/api uses to decide whether an
// uploaded/local-path file should be routed to this package instead of
// internal/archive's ZIP handling.
func Sniff(r io.Reader) (isAD1, isEncrypted bool, err error) {
	buf := make([]byte, 16)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return false, false, nil
		}
		return false, false, err
	}
	_ = n
	if bytes.Equal(buf[:8], []byte(adcryptMagicText+"\x00")) {
		return true, true, nil
	}
	if bytes.Equal(buf[:16], MagicField(SegmentedFileMagicText)) {
		return true, false, nil
	}
	return false, false, nil
}

// MagicField pads text to a 16-byte, NUL-padded fixed field the way every
// magic in this format is stored.
func MagicField(text string) []byte {
	b := make([]byte, 16)
	copy(b, text)
	return b
}

// segmentHeader is SegmentedFileHeader: the fixed 512-byte header at the
// start of every .adN segment file.
type segmentHeader struct {
	number     uint32
	count      uint32
	size       uint64 // segment size INCLUDING this 512-byte header
	logicalOff uint32 // only meaningful in the first segment
}

func readSegmentHeader(r io.Reader) (segmentHeader, error) {
	buf := make([]byte, SegmentHeaderSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return segmentHeader{}, fmt.Errorf("%w: reading segment header: %v", ErrCorrupt, err)
	}
	if !bytes.Equal(buf[0:16], MagicField(SegmentedFileMagicText)) {
		return segmentHeader{}, fmt.Errorf("%w: bad segment magic", ErrCorrupt)
	}
	h := segmentHeader{
		number:     binary.LittleEndian.Uint32(buf[24:28]),
		count:      binary.LittleEndian.Uint32(buf[28:32]),
		size:       binary.LittleEndian.Uint64(buf[32:40]),
		logicalOff: binary.LittleEndian.Uint32(buf[40:44]),
	}
	if h.size < SegmentHeaderSize {
		return segmentHeader{}, fmt.Errorf("%w: segment declares size %d smaller than its own header", ErrCorrupt, h.size)
	}
	return h, nil
}

// logicalImageHeader is LogicalImageHeader (AD1v4 layout only -- see
// Open's version check).
type logicalImageHeader struct {
	version         uint32
	chunkSize       uint32
	metadataOffset  uint64
	firstFileOffset uint64
	name            string
}

const LogicalImageFixedSize = 92 // see package doc comment's offset derivation

func readLogicalImageHeader(r io.Reader, limits Limits) (logicalImageHeader, error) {
	buf := make([]byte, LogicalImageFixedSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return logicalImageHeader{}, fmt.Errorf("%w: reading logical image header: %v", ErrCorrupt, err)
	}
	if !bytes.Equal(buf[0:16], MagicField(LogicalImageMagicText)) {
		return logicalImageHeader{}, fmt.Errorf("%w: bad logical image magic", ErrCorrupt)
	}
	h := logicalImageHeader{
		version:         binary.LittleEndian.Uint32(buf[16:20]),
		chunkSize:       binary.LittleEndian.Uint32(buf[24:28]),
		metadataOffset:  binary.LittleEndian.Uint64(buf[28:36]),
		firstFileOffset: binary.LittleEndian.Uint64(buf[36:44]),
	}
	nameLen := binary.LittleEndian.Uint32(buf[44:48])
	if h.version != 4 {
		// Don't even attempt to read the version-dependent tail --
		// version 3's layout differs and isn't supported (see
		// ErrUnsupportedVersion's doc comment).
		return logicalImageHeader{}, ErrUnsupportedVersion
	}
	if nameLen == 0 || int(nameLen) > limits.MaxNameBytes {
		return logicalImageHeader{}, fmt.Errorf("%w: implausible logical image name length %d", ErrLimitExceeded, nameLen)
	}
	if h.chunkSize == 0 {
		return logicalImageHeader{}, fmt.Errorf("%w: zero chunk size", ErrCorrupt)
	}
	nameBuf := make([]byte, nameLen)
	if _, err := io.ReadFull(r, nameBuf); err != nil {
		return logicalImageHeader{}, fmt.Errorf("%w: reading logical image name: %v", ErrCorrupt, err)
	}
	h.name = strings.TrimRight(string(nameBuf), "\x00")
	return h, nil
}

// isADCrypt reports whether the first 8 bytes read from r match the
// ADCRYPT magic ("ADCRYPT\x00").
func isADCrypt(r io.Reader) (bool, error) {
	buf := make([]byte, 8)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return n >= 7 && bytes.Equal(buf[:n], []byte(adcryptMagicText)[:n]), nil
		}
		return false, err
	}
	return bytes.Equal(buf, []byte(adcryptMagicText+"\x00")), nil
}

// segmentExtRe matches a segment file's numbered extension (".ad1",
// ".ad2", ... ".ad137", case-insensitive) -- used by FindSiblingSegments
// to locate a multi-segment image's remaining parts given its first
// segment's path.
var segmentExtRe = regexp.MustCompile(`(?i)^\.ad([0-9]+)$`)

// FindSiblingSegments returns every segment file sharing first's base
// name (minus extension) in the same directory, sorted by segment
// number and always including first itself -- for a multi-segment
// local-path AD1 (see docs/ad1-ingestion.md's "Segmented images" section
// for why this is local-path-only: an uploaded AD1 is a single multipart
// file, so a segmented upload is reported as ErrSegmentsMissing rather
// than requiring a multi-file upload UI). For a non-segmented image this
// simply returns []string{first}.
func FindSiblingSegments(first string) ([]string, error) {
	dir := filepath.Dir(first)
	stem := strings.TrimSuffix(filepath.Base(first), filepath.Ext(first))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type numbered struct {
		path string
		n    int
	}
	var found []numbered
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.TrimSuffix(name, filepath.Ext(name)) != stem {
			continue
		}
		m := segmentExtRe.FindStringSubmatch(filepath.Ext(name))
		if m == nil {
			continue
		}
		var n int
		fmt.Sscanf(m[1], "%d", &n)
		found = append(found, numbered{filepath.Join(dir, name), n})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].n < found[j].n })
	out := make([]string, len(found))
	for i, f := range found {
		out[i] = f.path
	}
	return out, nil
}

// segment is one open, header-validated .adN file plus the byte range of
// its payload (excluding its own 512-byte header) within the stitched
// logical stream.
type segment struct {
	f          *os.File
	payloadLen int64 // segment.size - SegmentHeaderSize
	streamOff  int64 // this segment's payload's starting offset in the stitched stream
}

// Container is an opened, validated AD1 image ready to be walked
// (Discover) or read from (Extract). Always Close it. A Container never
// writes to any of its segment files.
type Container struct {
	segments  []segment
	streamLen int64
	image     logicalImageHeader
	limits    Limits
}

// Open opens and validates an AD1 image from one or more segment file
// paths (segmentPaths[0] must be the first segment, ".ad1"). It reads
// each segment's header, verifies segment numbering and magic, and reads
// the first segment's LogicalImageHeader -- it does not walk the file
// tree yet (see Walk). Returns ErrEncrypted if the first segment is
// ADCRYPT-encrypted, ErrSegmentsMissing if the first segment declares
// more total segments than were provided, and ErrUnsupportedVersion for
// anything other than AD1v4.
func Open(segmentPaths []string, limits Limits) (*Container, error) {
	if len(segmentPaths) == 0 {
		return nil, fmt.Errorf("%w: no segment files provided", ErrCorrupt)
	}
	if len(segmentPaths) > limits.MaxSegments {
		return nil, fmt.Errorf("%w: %d segments exceeds limit %d", ErrLimitExceeded, len(segmentPaths), limits.MaxSegments)
	}

	first, err := os.Open(segmentPaths[0])
	if err != nil {
		return nil, err
	}
	defer first.Close()

	encrypted, err := isADCrypt(first)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if encrypted {
		return nil, ErrEncrypted
	}
	if _, err := first.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	c := &Container{limits: limits}
	closeAll := func() {
		for _, s := range c.segments {
			s.f.Close()
		}
	}

	var streamOff int64
	var declaredCount uint32
	for i, p := range segmentPaths {
		f, err := os.Open(p)
		if err != nil {
			closeAll()
			return nil, err
		}
		hdr, err := readSegmentHeader(f)
		if err != nil {
			f.Close()
			closeAll()
			return nil, err
		}
		if int(hdr.number) != i+1 {
			f.Close()
			closeAll()
			return nil, fmt.Errorf("%w: segment %d has segment_number %d, expected %d", ErrCorrupt, i, hdr.number, i+1)
		}
		if i == 0 {
			declaredCount = hdr.count
		} else if hdr.count != declaredCount {
			f.Close()
			closeAll()
			return nil, fmt.Errorf("%w: segment %d declares a different segment_count than segment 1", ErrCorrupt, i)
		}
		payloadLen := int64(hdr.size) - SegmentHeaderSize
		c.segments = append(c.segments, segment{f: f, payloadLen: payloadLen, streamOff: streamOff})
		streamOff += payloadLen
	}
	c.streamLen = streamOff

	if int(declaredCount) > len(segmentPaths) {
		closeAll()
		return nil, fmt.Errorf("%w: image declares %d segment(s), only %d provided", ErrSegmentsMissing, declaredCount, len(segmentPaths))
	}

	// logicalOff (from the first segment's own header, read again here
	// since the earlier read was only for the ADCRYPT sniff on a
	// separate, already-closed handle) is a RAW offset from the start of
	// the first segment FILE, not from the start of its payload --
	// unlike every FileEntry/FileMeta/chunk offset (which are relative to
	// the stitched logical stream starting at the LogicalImageHeader, see
	// Container.reader), this one field is seeked directly against the
	// segment file handle by the reference implementation. It must
	// therefore be at least SegmentHeaderSize (past this segment's own
	// 512-byte header).
	logicalOff, err := firstSegmentHeaderLogicalOffset(c.segments[0].f)
	if err != nil {
		closeAll()
		return nil, err
	}
	if int64(logicalOff) < SegmentHeaderSize || int64(logicalOff) >= SegmentHeaderSize+c.segments[0].payloadLen {
		closeAll()
		return nil, fmt.Errorf("%w: logical image offset %d out of bounds", ErrCorrupt, logicalOff)
	}
	sr := io.NewSectionReader(c.segments[0].f, int64(logicalOff), SegmentHeaderSize+c.segments[0].payloadLen-int64(logicalOff))
	img, err := readLogicalImageHeader(sr, limits)
	if err != nil {
		closeAll()
		return nil, err
	}
	c.image = img
	return c, nil
}

func firstSegmentHeaderLogicalOffset(f *os.File) (uint32, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	hdr, err := readSegmentHeader(f)
	if err != nil {
		return 0, err
	}
	return hdr.logicalOff, nil
}

// Close releases every open segment file handle.
func (c *Container) Close() error {
	var firstErr error
	for _, s := range c.segments {
		if err := s.f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// RootName returns the logical image's declared acquisition root (e.g.
// `C:\Users\jdoe\Desktop\Data`, or the literal string
// "Custom Content Image([Multi])" for a multi-source custom-content
// capture -- see docs/ad1-ingestion.md's "Multi-source images" note on
// why that case's paths are presented flatly rather than re-rooted per
// source).
func (c *Container) RootName() string { return c.image.name }

// newStreamReader returns an io.ReaderAt over the whole stitched logical
// stream (every segment's payload concatenated, each segment's own
// 512-byte header skipped) -- entry/meta/chunk offsets in this format are
// always relative to this stitched stream, never to an individual
// segment file directly (mirrors the reference implementation's
// AD1Stream).
type stitchedReaderAt struct {
	c *Container
}

func (c *Container) reader() io.ReaderAt { return stitchedReaderAt{c} }

func (sr stitchedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > sr.c.streamLen {
		return 0, fmt.Errorf("%w: read at out-of-bounds offset %d", ErrCorrupt, off)
	}
	total := 0
	for len(p) > 0 {
		if off >= sr.c.streamLen {
			if total == 0 {
				return 0, io.EOF
			}
			return total, io.EOF
		}
		idx := segmentForOffset(sr.c.segments, off)
		seg := sr.c.segments[idx]
		inSeg := off - seg.streamOff
		n := len(p)
		if remain := seg.payloadLen - inSeg; int64(n) > remain {
			n = int(remain)
		}
		read, err := seg.f.ReadAt(p[:n], SegmentHeaderSize+inSeg)
		total += read
		off += int64(read)
		p = p[read:]
		if err != nil && !errors.Is(err, io.EOF) {
			return total, fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if read == 0 {
			return total, io.ErrUnexpectedEOF
		}
	}
	return total, nil
}

func segmentForOffset(segs []segment, off int64) int {
	// segs is small (bounded by Limits.MaxSegments) and already sorted by
	// construction -- a linear scan is simpler than importing sort's
	// binary-search helpers for what's never more than a few hundred
	// entries.
	idx := len(segs) - 1
	for i, s := range segs {
		if off < s.streamOff+s.payloadLen {
			idx = i
			break
		}
	}
	return idx
}
