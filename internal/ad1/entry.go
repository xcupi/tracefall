package ad1

import (
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// EntryType mirrors AD1's on-disk FileEntry.type enum.
type EntryType uint32

const (
	EntryTypeFile        EntryType = 0x0
	EntryTypeUnknownFile EntryType = 0x1
	EntryTypeDeleted     EntryType = 0x2
	EntryTypeDirectory   EntryType = 0x5
)

// Metadata type IDs this package reads. AD1 carries dozens more (NTFS
// attributes, ACLs, MFT record numbers, ...) that Tracefall's catalog has
// no use for -- see the package doc comment on scope.
const (
	MetaFileSize     = 0x3
	MetaDateAccessed = 0x7
	MetaDateCreated  = 0x8
	MetaDateModified = 0x9
	MetaMD5          = 0x5001
	MetaSHA1         = 0x5002
)

// Entry is one file or directory cataloged from an AD1 image -- the unit
// internal/api turns into a model.SourceFile row (see docs/ad1-ingestion.md).
type Entry struct {
	Path  string // forward-slash path from the image's declared root (Container.RootName), e.g. "C:/Users/jdoe/NTUSER.DAT"
	Name  string // basename
	IsDir bool

	// SizeBytes is the FileSize metadata value if present, else the raw
	// FileEntry.size field (0 for directories and files with no
	// recorded size). Never guessed beyond that fallback.
	SizeBytes int64

	// MD5/SHA1 are the hash AD1 itself recorded during acquisition, if
	// FTK Imager was configured to compute one -- often absent. This is
	// a hash AD1 *reported*, not one Tracefall independently verified;
	// see internal/model.SourceFile.EmbeddedHash's doc comment for how
	// this is surfaced and why it's kept clearly distinct from the
	// SHA-256 Tracefall computes itself once a file is actually
	// imported.
	MD5, SHA1 string

	// Timestamps default to the zero time.Time (never fabricated) when
	// the corresponding metadata item is absent.
	AccessedAt, CreatedAt, ModifiedAt time.Time

	// entryOffset/childOffset are internal, used by Extract to relocate
	// this entry's chunk table without re-walking the whole tree.
	entryOffset int64
	zlibMeta    uint64
	rawSize     uint64
}

// rawFileEntry is the fixed-size-prefix portion of FileEntry (see the
// package doc comment's derived layout) -- next/child/meta/zlib_meta are
// stream offsets, not sequential positions, so nothing after `name` (the
// trailing parent_index field) needs to be read; every traversal here is
// offset-driven, never sequential.
type rawFileEntry struct {
	next, child, meta, zlibMeta, size uint64
	entryType                         EntryType
	name                              string
}

const FileEntryFixedSize = 48

func readRawFileEntry(sr io.ReaderAt, off int64, limits Limits) (rawFileEntry, error) {
	hdr := make([]byte, FileEntryFixedSize)
	if _, err := sr.ReadAt(hdr, off); err != nil {
		return rawFileEntry{}, fmt.Errorf("%w: reading file entry at %d: %v", ErrCorrupt, off, err)
	}
	e := rawFileEntry{
		next:      binary.LittleEndian.Uint64(hdr[0:8]),
		child:     binary.LittleEndian.Uint64(hdr[8:16]),
		meta:      binary.LittleEndian.Uint64(hdr[16:24]),
		zlibMeta:  binary.LittleEndian.Uint64(hdr[24:32]),
		size:      binary.LittleEndian.Uint64(hdr[32:40]),
		entryType: EntryType(binary.LittleEndian.Uint32(hdr[40:44])),
	}
	nameLen := binary.LittleEndian.Uint32(hdr[44:48])
	if int(nameLen) > limits.MaxNameBytes {
		return rawFileEntry{}, fmt.Errorf("%w: entry name length %d at offset %d exceeds limit %d", ErrLimitExceeded, nameLen, off, limits.MaxNameBytes)
	}
	nameBuf := make([]byte, nameLen)
	if nameLen > 0 {
		if _, err := sr.ReadAt(nameBuf, off+FileEntryFixedSize); err != nil {
			return rawFileEntry{}, fmt.Errorf("%w: reading entry name at %d: %v", ErrCorrupt, off, err)
		}
	}
	e.name = strings.TrimRight(string(nameBuf), "\x00")
	return e, nil
}

// validateEntryName rejects a FileEntry name that isn't a plain single
// path component -- a name containing a path separator (forward or back
// slash), a NUL byte, or that is empty, ".", or ".." would let a
// corrupt-or-hostile AD1 image escape Container.Walk's path-prefix
// construction (e.g. a name of "../../../../etc/passwd" attempting to
// climb out of internal/api's extraction directory once Walk's output
// reaches Extract/extractAD1Entry). Every real name AD1 stores is one
// filename component; anything else fails closed here, the same
// "reject the whole entry rather than silently sanitize it" approach
// internal/archive's safeJoin takes for a zip entry name -- see that
// package's doc comment.
func validateEntryName(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("%w: invalid entry name %q", ErrCorrupt, name)
	}
	if strings.ContainsAny(name, "/\\\x00") {
		return fmt.Errorf("%w: entry name %q contains a path separator or NUL byte", ErrCorrupt, name)
	}
	return nil
}

type rawMeta struct {
	next     uint64
	category uint32
	typ      uint32
	data     []byte
}

const metaFixedSize = 20

func readRawMeta(sr io.ReaderAt, off int64, limits Limits) (rawMeta, error) {
	hdr := make([]byte, metaFixedSize)
	if _, err := sr.ReadAt(hdr, off); err != nil {
		return rawMeta{}, fmt.Errorf("%w: reading metadata at %d: %v", ErrCorrupt, off, err)
	}
	m := rawMeta{
		next:     binary.LittleEndian.Uint64(hdr[0:8]),
		category: binary.LittleEndian.Uint32(hdr[8:12]),
		typ:      binary.LittleEndian.Uint32(hdr[12:16]),
	}
	length := binary.LittleEndian.Uint32(hdr[16:20])
	if int(length) > limits.MaxMetaBytes {
		return rawMeta{}, fmt.Errorf("%w: metadata value length %d at offset %d exceeds limit %d", ErrLimitExceeded, length, off, limits.MaxMetaBytes)
	}
	if length > 0 {
		data := make([]byte, length)
		if _, err := sr.ReadAt(data, off+metaFixedSize); err != nil {
			return rawMeta{}, fmt.Errorf("%w: reading metadata value at %d: %v", ErrCorrupt, off, err)
		}
		m.data = data
	}
	return m, nil
}

// maxMetaChainItems bounds how many linked FileMeta entries are followed
// for a single FileEntry -- deliberately much smaller than
// Limits.MaxEntries (which bounds the whole tree): a real entry carries a
// few dozen metadata items at most, so a chain anywhere near this length
// is either corrupt or hostile (e.g. a cycle crafted to multiply cost by
// MaxEntries per node). See Walk's doc comment for the tree-level cap.
const maxMetaChainItems = 256

// readMetaChain follows a FileEntry's `meta` linked list and returns the
// values found, keyed by type (a later entry with the same type
// overwrites an earlier one, matching the reference implementation's
// dict-building behavior).
func readMetaChain(sr io.ReaderAt, off uint64, streamLen int64, limits Limits) (map[uint32]rawMeta, error) {
	result := map[uint32]rawMeta{}
	visited := 0
	for off != 0 {
		visited++
		if visited > maxMetaChainItems {
			return nil, fmt.Errorf("%w: metadata chain exceeds %d items (possible cycle)", ErrLimitExceeded, maxMetaChainItems)
		}
		if int64(off) < 0 || int64(off) >= streamLen {
			return nil, fmt.Errorf("%w: metadata offset %d out of bounds", ErrCorrupt, off)
		}
		m, err := readRawMeta(sr, int64(off), limits)
		if err != nil {
			return nil, err
		}
		result[m.typ] = m
		off = m.next
	}
	return result, nil
}

// convertTimestamp parses an AD1 timestamp text value
// ("20260115T090000.123456" or "20260115T090000"), assumed UTC per the
// reference implementation. Returns the zero time.Time (never fabricated)
// if data doesn't parse.
func convertTimestamp(data []byte) time.Time {
	s := string(data)
	layout := "20060102T150405"
	if strings.Contains(s, ".") {
		layout = "20060102T150405.000000"
	}
	t, err := time.Parse(layout, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// buildEntry turns a raw file-entry-plus-metadata pair into the public
// Entry the catalog exposes.
func buildEntry(fe rawFileEntry, off int64, meta map[uint32]rawMeta) Entry {
	e := Entry{
		Name:        fe.name,
		IsDir:       fe.entryType == EntryTypeDirectory,
		entryOffset: off,
		zlibMeta:    fe.zlibMeta,
		rawSize:     fe.size,
	}
	if m, ok := meta[MetaFileSize]; ok {
		if n, err := strconv.ParseInt(strings.TrimRight(string(m.data), "\x00"), 10, 64); err == nil {
			e.SizeBytes = n
		}
	}
	if e.SizeBytes == 0 && fe.size != 0 {
		e.SizeBytes = int64(fe.size)
	}
	if m, ok := meta[MetaMD5]; ok {
		e.MD5 = strings.TrimRight(string(m.data), "\x00")
	}
	if m, ok := meta[MetaSHA1]; ok {
		e.SHA1 = strings.TrimRight(string(m.data), "\x00")
	}
	if m, ok := meta[MetaDateAccessed]; ok {
		e.AccessedAt = convertTimestamp(m.data)
	}
	if m, ok := meta[MetaDateCreated]; ok {
		e.CreatedAt = convertTimestamp(m.data)
	}
	if m, ok := meta[MetaDateModified]; ok {
		e.ModifiedAt = convertTimestamp(m.data)
	}
	return e
}

// walkStackItem is one pending directory to descend into: the stream
// offset of its first child and the catalog path prefix its children's
// paths are built from.
type walkStackItem struct {
	firstChild int64
	pathPrefix string
}

// Walk enumerates every entry (file and directory, including entries
// AD1 marks EntryTypeDeleted -- a recovered-deleted-file capture is
// still real acquired content, never silently dropped from the catalog)
// reachable from the image's root, calling fn once per entry in a
// deterministic pre-order (each directory's own entry, if it has one,
// before its children; siblings in on-disk order). fn's error, if any,
// aborts the walk and is returned as-is (not wrapped), so a caller can
// use a sentinel to stop early.
//
// The walk is iterative (an explicit stack, never recursion) with a hard
// cap on total entries visited (Limits.MaxEntries) -- this is what
// prevents a corrupt or hostile image whose next/child offsets form a
// cycle from hanging enumeration forever: every entry dereference, via
// either the sibling chain or a directory descent, counts against the
// same cap, so cycle or not, Walk terminates (with ErrLimitExceeded, not
// an infinite loop) once the cap is reached.
func (c *Container) Walk(fn func(Entry) error) error {
	sr := c.reader()
	root := c.image.firstFileOffset
	stack := []walkStackItem{{int64(root), ""}}
	visited := 0

	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		off := item.firstChild
		for off != 0 {
			visited++
			if visited > c.limits.MaxEntries {
				return fmt.Errorf("%w: more than %d entries in AD1 image", ErrLimitExceeded, c.limits.MaxEntries)
			}
			if off < 0 || off >= c.streamLen {
				return fmt.Errorf("%w: entry offset %d out of bounds", ErrCorrupt, off)
			}

			fe, err := readRawFileEntry(sr, off, c.limits)
			if err != nil {
				return err
			}
			if err := validateEntryName(fe.name); err != nil {
				return err
			}

			var meta map[uint32]rawMeta
			if fe.meta != 0 {
				meta, err = readMetaChain(sr, fe.meta, c.streamLen, c.limits)
				if err != nil {
					return err
				}
			}

			fullPath := item.pathPrefix + "/" + fe.name
			if len(fullPath) > c.limits.MaxPathBytes {
				return fmt.Errorf("%w: catalog path exceeds %d bytes", ErrLimitExceeded, c.limits.MaxPathBytes)
			}

			entry := buildEntry(fe, off, meta)
			entry.Path = strings.TrimPrefix(fullPath, "/")

			if err := fn(entry); err != nil {
				return err
			}

			if fe.entryType == EntryTypeDirectory && fe.child != 0 {
				stack = append(stack, walkStackItem{int64(fe.child), entry.Path})
			}
			off = int64(fe.next)
		}
	}
	return nil
}
