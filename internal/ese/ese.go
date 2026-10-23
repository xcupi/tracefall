// Package ese reads Extensible Storage Engine databases (.edb, .dat, .dit) such
// as the Windows Search index, the SRUM database, WebCacheV01.dat and the
// Active Directory database. It reads; it never writes, replays a transaction
// log or repairs anything.
//
// The format follows libyal's "Extensible Storage Engine (ESE) Database File
// (EDB) format" specification. Where that specification leaves a point open,
// the behaviour was decided by comparing against two independent
// implementations (libesedb and dissect.esedb) on real databases; see
// docs/ese.md for what was compared and what was not.
//
// Every number read from the file is a number an attacker controls, so every
// page number, offset, size and count is bounds-checked before use, tree
// traversal is bounded and cycle-safe, and nothing is allocated from a size the
// file merely claims without a cap.
package ese

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

var (
	// ErrNotESE means the file does not begin with the ESE header signature.
	ErrNotESE = errors.New("ese: not an ESE database (bad signature)")
	// ErrUnsupported means a valid database of a kind this reader does not read.
	ErrUnsupported = errors.New("ese: unsupported database")
	// ErrCorrupt means a structure inside the database is inconsistent.
	ErrCorrupt = errors.New("ese: database is corrupt or truncated")
)

const (
	headerSignature = 0x89ABCDEF // bytes EF CD AB 89 at offset 4, read little-endian
	maxPageCache    = 256
	maxTreeDepth    = 32
	maxColumns      = 1 << 15
	maxValueBytes   = 64 << 20

	pageFlagRoot       = 0x0001
	pageFlagLeaf       = 0x0002
	pageFlagParent     = 0x0004
	pageFlagEmpty      = 0x0008
	pageFlagSpaceTree  = 0x0020
	pageFlagIndex      = 0x0040
	pageFlagLongValue  = 0x0080
	pageFlagNewRecord  = 0x2000
	tagFlagDefunct     = 0x02
	tagFlagCommonKey   = 0x04
	catalogRootPage    = 4
	catalogShadowPage  = 24
	headerChecksumSeed = 0x89abcdef
)

// State is the database state recorded in the header.
type State uint32

const (
	StateJustCreated    State = 1
	StateDirtyShutdown  State = 2
	StateCleanShutdown  State = 3
	StateBeingConverted State = 4
	StateForceDetach    State = 5
)

func (s State) String() string {
	switch s {
	case StateJustCreated:
		return "just created"
	case StateDirtyShutdown:
		return "dirty shutdown"
	case StateCleanShutdown:
		return "clean shutdown"
	case StateBeingConverted:
		return "being converted"
	case StateForceDetach:
		return "force detach"
	}
	return fmt.Sprintf("unknown (%d)", uint32(s))
}

// DB is an open, read-only ESE database.
type DB struct {
	r    io.ReaderAt
	size int64

	PageSize int
	Version  uint32
	Revision uint32
	State    State
	// HeaderChecksumOK is whether the header's own checksum is right.
	HeaderChecksumOK bool

	pages     int64 // data pages, page numbers 1..pages
	small     bool  // page size up to 8 KiB: 13-bit tags, 40-byte page header
	hdrLen    int
	mu        sync.Mutex
	cache     map[uint32]*page
	tables    map[string]*Table
	order     []*Table
	catalogOK bool
}

// Open validates the header and reads the catalog.
func Open(r io.ReaderAt, size int64) (*DB, error) {
	var h [668]byte
	if size < int64(len(h)) {
		return nil, fmt.Errorf("%w: file is %d bytes", ErrCorrupt, size)
	}
	if _, err := r.ReadAt(h[:], 0); err != nil {
		return nil, fmt.Errorf("%w: reading header: %v", ErrCorrupt, err)
	}
	if binary.LittleEndian.Uint32(h[4:8]) != headerSignature {
		return nil, ErrNotESE
	}
	db := &DB{r: r, size: size}
	db.Version = binary.LittleEndian.Uint32(h[8:12])
	if ft := binary.LittleEndian.Uint32(h[12:16]); ft != 0 {
		return nil, fmt.Errorf("%w: file type %d is a streaming file, not a database", ErrUnsupported, ft)
	}
	if db.Version != 0x620 {
		return nil, fmt.Errorf("%w: format version %#x", ErrUnsupported, db.Version)
	}
	db.State = State(binary.LittleEndian.Uint32(h[52:56]))
	db.Revision = binary.LittleEndian.Uint32(h[232:236])
	ps := int(binary.LittleEndian.Uint32(h[236:240]))
	if ps == 0 {
		ps = 4096 // the original format does not record it
	}
	switch ps {
	case 2048, 4096, 8192, 16384, 32768:
	default:
		return nil, fmt.Errorf("%w: page size %d", ErrCorrupt, ps)
	}
	db.PageSize = ps
	db.small = ps <= 8192
	db.hdrLen = 40
	if !db.small {
		db.hdrLen = 80
	}
	if size < int64(2*ps) {
		return nil, fmt.Errorf("%w: file is smaller than the two header pages", ErrCorrupt)
	}
	db.pages = size/int64(ps) - 2
	db.HeaderChecksumOK = db.headerChecksum()
	db.cache = map[uint32]*page{}
	if err := db.readCatalog(); err != nil {
		return nil, err
	}
	return db, nil
}

func (db *DB) headerChecksum() bool {
	buf := make([]byte, db.PageSize)
	if _, err := db.r.ReadAt(buf, 0); err != nil {
		return false
	}
	x := uint32(headerChecksumSeed)
	for i := 4; i+4 <= len(buf); i += 4 {
		x ^= binary.LittleEndian.Uint32(buf[i:])
	}
	return x == binary.LittleEndian.Uint32(buf[0:4])
}

// Pages is the number of data pages the file holds.
func (db *DB) Pages() int64 { return db.pages }

type tag struct {
	off, size int
	flags     uint8
}

type page struct {
	no      uint32
	buf     []byte
	flags   uint32
	prev    uint32
	next    uint32
	fdp     uint32
	tags    []tag
	hdrLen  int
	checked bool
}

func (p *page) is(f uint32) bool { return p.flags&f != 0 }

// page returns page n, parsed and cached. Page 0 does not exist: page numbers
// start at 1 and page 1 sits after the two header pages.
func (db *DB) page(n uint32) (*page, error) {
	if n == 0 || int64(n) > db.pages {
		return nil, fmt.Errorf("%w: page %d is outside the file (%d pages)", ErrCorrupt, n, db.pages)
	}
	db.mu.Lock()
	if p, ok := db.cache[n]; ok {
		db.mu.Unlock()
		return p, nil
	}
	db.mu.Unlock()
	buf := make([]byte, db.PageSize)
	if _, err := db.r.ReadAt(buf, (int64(n)+1)*int64(db.PageSize)); err != nil {
		return nil, fmt.Errorf("%w: reading page %d: %v", ErrCorrupt, n, err)
	}
	p, err := db.parsePage(n, buf)
	if err != nil {
		return nil, err
	}
	db.mu.Lock()
	if len(db.cache) >= maxPageCache {
		db.cache = map[uint32]*page{}
	}
	db.cache[n] = p
	db.mu.Unlock()
	return p, nil
}

func (db *DB) parsePage(n uint32, buf []byte) (*page, error) {
	p := &page{no: n, buf: buf, hdrLen: db.hdrLen}
	p.prev = binary.LittleEndian.Uint32(buf[16:20])
	p.next = binary.LittleEndian.Uint32(buf[20:24])
	p.fdp = binary.LittleEndian.Uint32(buf[24:28])
	itag := int(binary.LittleEndian.Uint16(buf[34:36]) & 0x0FFF)
	p.flags = binary.LittleEndian.Uint32(buf[36:40])
	if itag*4 > len(buf)-db.hdrLen {
		return nil, fmt.Errorf("%w: page %d claims %d tags", ErrCorrupt, n, itag)
	}
	avail := len(buf) - db.hdrLen
	p.tags = make([]tag, itag)
	for i := 0; i < itag; i++ {
		pos := len(buf) - 4*(i+1)
		cb := int(binary.LittleEndian.Uint16(buf[pos:]))
		ib := int(binary.LittleEndian.Uint16(buf[pos+2:]))
		var t tag
		if db.small {
			t.size, t.off, t.flags = cb&0x1FFF, ib&0x1FFF, uint8(ib>>13)
		} else {
			t.size, t.off = cb&0x7FFF, ib&0x7FFF
		}
		if t.size > 0 && (t.off+t.size > avail) {
			// A tag that points outside the page is unusable; keep the slot so
			// numbering holds, but mark it empty.
			t = tag{}
		}
		if !db.small && t.size >= 2 {
			t.flags = buf[db.hdrLen+t.off+1] >> 5
		}
		p.tags[i] = t
	}
	return p, nil
}

func (p *page) tagData(i int) []byte {
	if i < 0 || i >= len(p.tags) {
		return nil
	}
	t := p.tags[i]
	if t.size == 0 {
		return nil
	}
	return p.buf[p.hdrLen+t.off : p.hdrLen+t.off+t.size]
}

// entry splits tag i of a non-root-header slot into its page key and data.
// prefix is the page's common key (tag 0 of a page that is not a root).
func (db *DB) entry(p *page, i int) (key, data []byte, ok bool) {
	key, data, _, ok = db.entryFlags(p, i)
	return
}

// entryFlags is entry plus the tag flags (defunct, common key).
func (db *DB) entryFlags(p *page, i int) (key, data []byte, flags uint8, ok bool) {
	t := p.tags[i]
	v := p.tagData(i)
	if len(v) < 2 {
		return nil, nil, 0, false
	}
	flags = t.flags
	first := binary.LittleEndian.Uint16(v[0:2])
	if !db.small {
		flags = uint8(first >> 13)
	}
	pos := 0
	var prefix []byte
	if flags&tagFlagCommonKey != 0 {
		n := int(first & 0x1FFF)
		// The shared prefix is the first n bytes of the page's first tag. If the
		// page does not hold that many, or this is a root page that has no such
		// tag, the key cannot be rebuilt and is not invented.
		hdr := p.tagData(0)
		if p.is(pageFlagRoot) || n > len(hdr) {
			return nil, nil, flags, false
		}
		prefix = hdr[:n]
		pos = 2
		if len(v) < pos+2 {
			return nil, nil, flags, false
		}
		first = binary.LittleEndian.Uint16(v[pos : pos+2])
	}
	local := int(first & 0x1FFF)
	pos += 2
	if pos+local > len(v) {
		return nil, nil, flags, false
	}
	key = append(append([]byte{}, prefix...), v[pos:pos+local]...)
	return key, v[pos+local:], flags, true
}

// walk visits every leaf entry of the tree rooted at page root, in key order.
// An entry that cannot be taken apart is passed with nil key and data.
func (db *DB) walk(root uint32, fn func(p *page, flags uint8, key, data []byte) error) error {
	seen := map[uint32]bool{}
	var rec func(n uint32, depth int) error
	rec = func(n uint32, depth int) error {
		if depth > maxTreeDepth {
			return fmt.Errorf("%w: tree deeper than %d levels", ErrCorrupt, maxTreeDepth)
		}
		if seen[n] {
			return fmt.Errorf("%w: page %d is reached twice in one tree", ErrCorrupt, n)
		}
		seen[n] = true
		p, err := db.page(n)
		if err != nil {
			return err
		}
		if p.is(pageFlagEmpty) {
			return nil
		}
		for i := 1; i < len(p.tags); i++ {
			key, data, flags, ok := db.entryFlags(p, i)
			if !ok {
				if p.is(pageFlagLeaf) {
					// the entry exists but cannot be taken apart; the caller is
					// told (data == nil) so it can count it
					if err := fn(p, p.tags[i].flags, nil, nil); err != nil {
						return err
					}
				}
				continue
			}
			if p.is(pageFlagLeaf) {
				if err := fn(p, flags, key, data); err != nil {
					return err
				}
				continue
			}
			if len(data) < 4 {
				continue
			}
			if err := rec(binary.LittleEndian.Uint32(data[:4]), depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return rec(root, 0)
}
