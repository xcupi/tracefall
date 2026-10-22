package image

import (
	"bytes"
	"compress/zlib"
	"container/list"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// VMware VMDK reader (read-only).
//
// Supported: hosted sparse extents ("KDMV", including deflate-compressed
// grains and stream-optimized files whose real header sits in a footer), and
// descriptor-based disks of createType monolithicSparse, streamOptimized,
// monolithicFlat, twoGbMaxExtentFlat and twoGbMaxExtentSparse.
//
// Refused with ErrUnsupported and a reason: child disks (parentCID other than
// ffffffff; snapshot chains are not followed), vmfsSparse, seSparse, vmfsRaw,
// vmfsRDM, custom, fullDevice, partitionedDevice, and extent names that are
// not plain file names inside the descriptor's directory.
//
// A damaged or inconsistent structure is ErrCorrupt. A grain that is not
// allocated, or is marked zeroed, reads as zeros. The view is the guest disk:
// Size is the sum of extent capacities.
//
// Limits: the grain directory of a sparse file is checked against the real
// file size, the redundant (secondary) directory is bounds-checked but not
// compared with the primary, and the extent file is opened by its resolved
// path, so a file swapped for a link between the check and the open is not
// detected.
const (
	vmdkSector             = 512
	vmdkMaxDescriptor      = 1 << 20 // bytes of descriptor text accepted
	vmdkMaxCapacitySectors = 1 << 40 // 512 TiB per extent and per disk
	vmdkMaxGrainSectors    = 1 << 16 // 32 MiB
	vmdkMaxExtents         = 4096
	vmdkGTEntries          = 512
	vmdkGTCacheMax         = 64
	vmdkGrainCacheBytes    = 16 << 20

	vmdkFlagNewlineCheck = 1 << 0
	vmdkFlagCompressed   = 1 << 16
)

var vmdkNoGD = ^uint64(0)

// vmdkExtent is one contiguous run of the guest disk.
type vmdkExtent interface {
	capacity() int64
	// readFull fills p from off (within the extent) or returns an error.
	readFull(p []byte, off int64) error
	close() error
}

type vmdkImage struct {
	extents []vmdkExtent
	starts  []int64
	size    int64
	info    Info
}

func (v *vmdkImage) Size() int64 { return v.size }
func (v *vmdkImage) Info() Info {
	in := v.info
	in.Meta = make(map[string]string, len(v.info.Meta))
	for k, val := range v.info.Meta {
		in.Meta[k] = val
	}
	return in
}

func (v *vmdkImage) Close() error {
	var first error
	for _, e := range v.extents {
		if err := e.close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (v *vmdkImage) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("image: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= v.size {
		return 0, io.EOF
	}
	want := int64(len(p))
	short := false
	if avail := v.size - off; want > avail {
		want = avail
		short = true
	}
	done := int64(0)
	i := sort.Search(len(v.starts), func(i int) bool { return v.starts[i] > off }) - 1
	for done < want {
		e := v.extents[i]
		local := off - v.starts[i]
		n := e.capacity() - local
		if n > want-done {
			n = want - done
		}
		if err := e.readFull(p[done:done+n], local); err != nil {
			return int(done), err
		}
		done += n
		off += n
		i++
	}
	if short {
		return int(done), io.EOF
	}
	return int(done), nil
}

// ---- flat extent

type vmdkFlatExtent struct {
	f    *os.File
	base int64
	size int64
}

func (e *vmdkFlatExtent) capacity() int64 { return e.size }
func (e *vmdkFlatExtent) close() error    { return e.f.Close() }
func (e *vmdkFlatExtent) readFull(p []byte, off int64) error {
	n, err := e.f.ReadAt(p, e.base+off)
	if n == len(p) {
		return nil
	}
	if err == nil || errors.Is(err, io.EOF) {
		err = fmt.Errorf("%w: flat extent is shorter than when it was opened", ErrCorrupt)
	}
	return err
}

// ---- sparse extent

type vmdkSparseHdr struct {
	version, flags    uint32
	capacity, grain   uint64
	descOff, descSize uint64
	numGTE            uint32
	rgd, gd, overhead uint64
	unclean           bool
	compress          uint16
}

func parseVMDKHeader(b []byte) (vmdkSparseHdr, error) {
	var h vmdkSparseHdr
	if len(b) < vmdkSector || string(b[:4]) != vmdkSparseMagic {
		return h, fmt.Errorf("%w: bad sparse extent magic", ErrCorrupt)
	}
	le := binary.LittleEndian
	h.version = le.Uint32(b[4:])
	h.flags = le.Uint32(b[8:])
	h.capacity = le.Uint64(b[12:])
	h.grain = le.Uint64(b[20:])
	h.descOff = le.Uint64(b[28:])
	h.descSize = le.Uint64(b[36:])
	h.numGTE = le.Uint32(b[44:])
	h.rgd = le.Uint64(b[48:])
	h.gd = le.Uint64(b[56:])
	h.overhead = le.Uint64(b[64:])
	h.unclean = b[72] != 0
	h.compress = le.Uint16(b[77:])
	if h.version < 1 || h.version > 3 {
		return h, fmt.Errorf("%w: sparse extent version %d is not read", ErrUnsupported, h.version)
	}
	if h.flags&vmdkFlagNewlineCheck != 0 && (b[73] != '\n' || b[74] != ' ' || b[75] != '\r' || b[76] != '\n') {
		return h, fmt.Errorf("%w: the sparse header's line-ending check bytes are damaged (text-mode transfer?)", ErrCorrupt)
	}
	if h.flags&vmdkFlagCompressed != 0 {
		switch h.compress {
		case 1:
		case 0:
			return h, fmt.Errorf("%w: compressed grains are flagged but no compression algorithm is set", ErrCorrupt)
		default:
			return h, fmt.Errorf("%w: sparse extent compression algorithm %d is not read (only deflate)", ErrUnsupported, h.compress)
		}
	}
	if h.capacity == 0 || h.capacity > vmdkMaxCapacitySectors {
		return h, fmt.Errorf("%w: sparse extent capacity of %d sectors is zero or absurd", ErrCorrupt, h.capacity)
	}
	if h.grain < 8 || h.grain&(h.grain-1) != 0 || h.grain > vmdkMaxGrainSectors {
		return h, fmt.Errorf("%w: grain size of %d sectors is not a power of two between 8 and %d", ErrCorrupt, h.grain, vmdkMaxGrainSectors)
	}
	if h.numGTE != vmdkGTEntries {
		return h, fmt.Errorf("%w: %d grain table entries per table, expected %d", ErrCorrupt, h.numGTE, vmdkGTEntries)
	}
	return h, nil
}

type vmdkLRU struct {
	max int
	ll  *list.List
	m   map[int64]*list.Element
}

type vmdkLRUEntry struct {
	k int64
	v any
}

func newVMDKLRU(max int) *vmdkLRU {
	return &vmdkLRU{max: max, ll: list.New(), m: map[int64]*list.Element{}}
}

func (c *vmdkLRU) get(k int64) (any, bool) {
	if e, ok := c.m[k]; ok {
		c.ll.MoveToFront(e)
		return e.Value.(*vmdkLRUEntry).v, true
	}
	return nil, false
}

func (c *vmdkLRU) put(k int64, v any) {
	if e, ok := c.m[k]; ok {
		e.Value.(*vmdkLRUEntry).v = v
		c.ll.MoveToFront(e)
		return
	}
	c.m[k] = c.ll.PushFront(&vmdkLRUEntry{k, v})
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.m, last.Value.(*vmdkLRUEntry).k)
	}
}

type sparseExtent struct {
	f            *os.File
	fileSize     int64
	capBytes     int64
	grainSectors int64
	grainBytes   int64
	gdOff        int64 // bytes
	compressed   bool
	unclean      bool
	desc         string // embedded descriptor text, "" when none

	mu     sync.Mutex
	gts    *vmdkLRU // table index -> []uint32
	grains *vmdkLRU // grain index -> []byte (decompressed)
}

func (s *sparseExtent) capacity() int64 { return s.capBytes }
func (s *sparseExtent) close() error    { return s.f.Close() }

func (s *sparseExtent) gtCacheLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gts.ll.Len()
}

// inFile reports whether [sector*512, sector*512+n) lies inside the file.
func (s *sparseExtent) inFile(sector uint64, n int64) bool {
	if sector > uint64(s.fileSize)/vmdkSector {
		return false
	}
	return int64(sector)*vmdkSector+n <= s.fileSize
}

// newSparseExtent reads and validates the header (and footer) of a sparse
// extent. On success it owns f.
func newSparseExtent(f *os.File) (*sparseExtent, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUnsupported, f.Name())
	}
	s := &sparseExtent{f: f, fileSize: st.Size()}
	hb := make([]byte, vmdkSector)
	if n, _ := f.ReadAt(hb, 0); n < vmdkSector {
		return nil, fmt.Errorf("%w: sparse extent is shorter than its header", ErrCorrupt)
	}
	h, err := parseVMDKHeader(hb)
	if err != nil {
		return nil, err
	}
	unclean := h.unclean
	gd, rgd := h.gd, h.rgd
	if gd == vmdkNoGD {
		// Stream optimized: the real header is the footer, kept between a
		// footer marker and the end-of-stream marker at the end of the file.
		if s.fileSize < 3*vmdkSector {
			return nil, fmt.Errorf("%w: the grain directory is at the end of the file but the file has no room for a footer", ErrCorrupt)
		}
		tail := make([]byte, 3*vmdkSector)
		if n, _ := f.ReadAt(tail, s.fileSize-int64(len(tail))); n < len(tail) {
			return nil, fmt.Errorf("%w: cannot read the footer", ErrCorrupt)
		}
		le := binary.LittleEndian
		fm, eos := tail[:vmdkSector], tail[2*vmdkSector:]
		if le.Uint64(fm) != 1 || le.Uint32(fm[8:]) != 0 || le.Uint32(fm[12:]) != 3 ||
			le.Uint32(eos[8:]) != 0 || le.Uint32(eos[12:]) != 0 || le.Uint64(eos) != 0 {
			return nil, fmt.Errorf("%w: the footer marker or end-of-stream marker is missing", ErrCorrupt)
		}
		fh, err := parseVMDKHeader(tail[vmdkSector : 2*vmdkSector])
		if err != nil {
			return nil, fmt.Errorf("footer header: %w", err)
		}
		if fh.capacity != h.capacity || fh.grain != h.grain || fh.flags&vmdkFlagCompressed != h.flags&vmdkFlagCompressed || fh.compress != h.compress {
			return nil, fmt.Errorf("%w: the footer header disagrees with the leading header", ErrCorrupt)
		}
		if fh.gd == vmdkNoGD {
			return nil, fmt.Errorf("%w: the footer header has no grain directory", ErrCorrupt)
		}
		gd, rgd = fh.gd, fh.rgd
		unclean = unclean || fh.unclean
	}
	s.unclean = unclean
	s.compressed = h.flags&vmdkFlagCompressed != 0
	s.grainSectors = int64(h.grain)
	s.grainBytes = s.grainSectors * vmdkSector
	s.capBytes = int64(h.capacity) * vmdkSector

	nGrains := (h.capacity + h.grain - 1) / h.grain
	nTables := (nGrains + vmdkGTEntries - 1) / vmdkGTEntries
	gdBytes := int64(nTables) * 4
	if gd == 0 || !s.inFile(gd, gdBytes) {
		return nil, fmt.Errorf("%w: the grain directory (sector %d, %d bytes) is not inside the file", ErrCorrupt, gd, gdBytes)
	}
	if rgd != 0 && !s.inFile(rgd, gdBytes) {
		return nil, fmt.Errorf("%w: the redundant grain directory (sector %d) is not inside the file", ErrCorrupt, rgd)
	}
	s.gdOff = int64(gd) * vmdkSector

	if h.descOff != 0 && h.descSize != 0 {
		if h.descSize > vmdkMaxDescriptor/vmdkSector {
			return nil, fmt.Errorf("%w: embedded descriptor of %d sectors exceeds the %d byte limit", ErrCorrupt, h.descSize, vmdkMaxDescriptor)
		}
		if !s.inFile(h.descOff, int64(h.descSize)*vmdkSector) {
			return nil, fmt.Errorf("%w: embedded descriptor lies outside the file", ErrCorrupt)
		}
		db := make([]byte, h.descSize*vmdkSector)
		if _, err := f.ReadAt(db, int64(h.descOff)*vmdkSector); err != nil {
			return nil, fmt.Errorf("%w: cannot read the embedded descriptor: %v", ErrCorrupt, err)
		}
		if i := bytes.IndexByte(db, 0); i >= 0 {
			db = db[:i]
		}
		s.desc = string(db)
	}

	s.gts = newVMDKLRU(vmdkGTCacheMax)
	gmax := vmdkGrainCacheBytes / int(s.grainBytes)
	if gmax < 1 {
		gmax = 1
	}
	s.grains = newVMDKLRU(gmax)
	return s, nil
}

func (s *sparseExtent) table(t int64) ([]uint32, error) {
	s.mu.Lock()
	if v, ok := s.gts.get(t); ok {
		s.mu.Unlock()
		tbl, _ := v.([]uint32)
		return tbl, nil
	}
	s.mu.Unlock()
	var eb [4]byte
	if _, err := s.f.ReadAt(eb[:], s.gdOff+t*4); err != nil {
		return nil, fmt.Errorf("%w: cannot read grain directory entry %d: %v", ErrCorrupt, t, err)
	}
	sec := binary.LittleEndian.Uint32(eb[:])
	var tbl []uint32
	if sec != 0 {
		if !s.inFile(uint64(sec), vmdkGTEntries*4) {
			return nil, fmt.Errorf("%w: grain directory entry %d points to sector %d, past the end of the file", ErrCorrupt, t, sec)
		}
		raw := make([]byte, vmdkGTEntries*4)
		if _, err := s.f.ReadAt(raw, int64(sec)*vmdkSector); err != nil {
			return nil, fmt.Errorf("%w: cannot read grain table %d: %v", ErrCorrupt, t, err)
		}
		tbl = make([]uint32, vmdkGTEntries)
		for i := range tbl {
			tbl[i] = binary.LittleEndian.Uint32(raw[i*4:])
		}
	}
	s.mu.Lock()
	s.gts.put(t, tbl)
	s.mu.Unlock()
	return tbl, nil
}

// entry returns the grain table entry of grain gi: 0 or 1 mean zeros.
func (s *sparseExtent) entry(gi int64) (uint32, error) {
	tbl, err := s.table(gi / vmdkGTEntries)
	if err != nil || tbl == nil {
		return 0, err
	}
	return tbl[gi%vmdkGTEntries], nil
}

func (s *sparseExtent) readFull(p []byte, off int64) error {
	for len(p) > 0 {
		gi, within := off/s.grainBytes, off%s.grainBytes
		n := s.grainBytes - within
		if n > int64(len(p)) {
			n = int64(len(p))
		}
		v, err := s.entry(gi)
		if err != nil {
			return err
		}
		switch {
		case v <= 1:
			clear(p[:n])
		case s.compressed:
			g, err := s.compressedGrain(gi, v)
			if err != nil {
				return err
			}
			copy(p[:n], g[within:])
		default:
			if !s.inFile(uint64(v), s.grainBytes) {
				return fmt.Errorf("%w: grain %d at sector %d lies past the end of the file", ErrCorrupt, gi, v)
			}
			if m, err := s.f.ReadAt(p[:n], int64(v)*vmdkSector+within); int64(m) != n {
				return fmt.Errorf("%w: cannot read grain %d: %v", ErrCorrupt, gi, err)
			}
		}
		p = p[n:]
		off += n
	}
	return nil
}

func (s *sparseExtent) compressedGrain(gi int64, sector uint32) ([]byte, error) {
	s.mu.Lock()
	if v, ok := s.grains.get(gi); ok {
		s.mu.Unlock()
		return v.([]byte), nil
	}
	s.mu.Unlock()
	if !s.inFile(uint64(sector), 12) {
		return nil, fmt.Errorf("%w: compressed grain %d at sector %d lies past the end of the file", ErrCorrupt, gi, sector)
	}
	base := int64(sector) * vmdkSector
	var mk [12]byte
	if _, err := s.f.ReadAt(mk[:], base); err != nil {
		return nil, fmt.Errorf("%w: cannot read the marker of grain %d: %v", ErrCorrupt, gi, err)
	}
	lba, size := binary.LittleEndian.Uint64(mk[:]), int64(binary.LittleEndian.Uint32(mk[8:]))
	if lba != uint64(gi*s.grainSectors) {
		return nil, fmt.Errorf("%w: grain %d's marker says LBA %d, expected %d", ErrCorrupt, gi, lba, gi*s.grainSectors)
	}
	if size == 0 {
		return nil, fmt.Errorf("%w: grain %d points at a metadata marker, not a compressed grain", ErrCorrupt, gi)
	}
	if size > 2*s.grainBytes+64 || base+12+size > s.fileSize {
		return nil, fmt.Errorf("%w: compressed grain %d claims %d bytes, more than is possible", ErrCorrupt, gi, size)
	}
	data := make([]byte, size)
	if _, err := s.f.ReadAt(data, base+12); err != nil {
		return nil, fmt.Errorf("%w: cannot read compressed grain %d: %v", ErrCorrupt, gi, err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: grain %d is not a valid zlib stream: %v", ErrCorrupt, gi, err)
	}
	out := make([]byte, s.grainBytes)
	if _, err := io.ReadFull(zr, out); err != nil {
		return nil, fmt.Errorf("%w: grain %d decompresses to fewer than the grain size (%d bytes): %v", ErrCorrupt, gi, s.grainBytes, err)
	}
	var extra [1]byte
	if n, err := zr.Read(extra[:]); n != 0 || err != io.EOF {
		return nil, fmt.Errorf("%w: grain %d decompresses to more than the grain size or fails its checksum (%v)", ErrCorrupt, gi, err)
	}
	s.mu.Lock()
	s.grains.put(gi, out)
	s.mu.Unlock()
	return out, nil
}

// ---- descriptor

type vmdkExtentLine struct {
	access, typ string
	sectors     uint64
	name        string
	offset      uint64
}

type vmdkDescriptor struct {
	kv      map[string]string // lower-case key -> value
	extents []vmdkExtentLine
}

func (d *vmdkDescriptor) get(k string) string { return d.kv[strings.ToLower(k)] }

type vmdkTok struct {
	s      string
	quoted bool
}

func vmdkTokens(line string) ([]vmdkTok, error) {
	var out []vmdkTok
	for i := 0; i < len(line); {
		switch c := line[i]; {
		case c == ' ' || c == '\t':
			i++
		case c == '"':
			j := strings.IndexByte(line[i+1:], '"')
			if j < 0 {
				return nil, fmt.Errorf("%w: unterminated quote in extent line", ErrCorrupt)
			}
			out = append(out, vmdkTok{line[i+1 : i+1+j], true})
			i += j + 2
		default:
			j := i
			for j < len(line) && line[j] != ' ' && line[j] != '\t' {
				j++
			}
			out = append(out, vmdkTok{line[i:j], false})
			i = j
		}
	}
	return out, nil
}

func parseVMDKDescriptor(text string) (*vmdkDescriptor, error) {
	d := &vmdkDescriptor{kv: map[string]string{}}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "\xef\xbb\xbf"))
		if line == "" || line[0] == '#' {
			continue
		}
		first := line
		if i := strings.IndexAny(line, " \t"); i > 0 {
			first = line[:i]
		}
		if first == "RW" || first == "RDONLY" || first == "NOACCESS" {
			toks, err := vmdkTokens(line)
			if err != nil {
				return nil, err
			}
			if len(toks) < 3 {
				return nil, fmt.Errorf("%w: extent line %q is incomplete", ErrCorrupt, line)
			}
			sectors, err := strconv.ParseUint(toks[1].s, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: extent line %q has an invalid sector count", ErrCorrupt, line)
			}
			e := vmdkExtentLine{access: first, sectors: sectors, typ: strings.ToUpper(toks[2].s)}
			rest := toks[3:]
			if len(rest) > 0 && rest[0].quoted {
				e.name = rest[0].s
				rest = rest[1:]
			}
			if len(rest) > 0 {
				e.offset, err = strconv.ParseUint(rest[0].s, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("%w: extent line %q has an invalid offset", ErrCorrupt, line)
				}
			}
			if len(d.extents) >= vmdkMaxExtents {
				return nil, fmt.Errorf("%w: the descriptor lists more than %d extents", ErrUnsupported, vmdkMaxExtents)
			}
			d.extents = append(d.extents, e)
			continue
		}
		if i := strings.IndexByte(line, '='); i > 0 {
			k := strings.ToLower(strings.TrimSpace(line[:i]))
			v := strings.TrimSpace(line[i+1:])
			if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
				v = v[1 : len(v)-1]
			}
			if _, dup := d.kv[k]; !dup {
				d.kv[k] = v
			}
		}
	}
	return d, nil
}

const (
	vmdkSparseTypes = "monolithicSparse streamOptimized twoGbMaxExtentSparse"
	vmdkFlatTypes   = "monolithicFlat twoGbMaxExtentFlat"
)

func vmdkIn(list, s string) bool {
	for _, w := range strings.Fields(list) {
		if w == s {
			return true
		}
	}
	return false
}

// validate checks the descriptor against what this reader handles.
func (d *vmdkDescriptor) validate() error {
	ct := d.get("createType")
	if ct == "" {
		return fmt.Errorf("%w: the descriptor has no createType", ErrCorrupt)
	}
	parent, ok := d.kv["parentcid"]
	if !ok {
		return fmt.Errorf("%w: the descriptor has no parentCID", ErrCorrupt)
	}
	if !strings.EqualFold(parent, "ffffffff") {
		return fmt.Errorf("%w: this is a child (snapshot) disk, parentCID=%s; snapshot chains are not followed", ErrUnsupported, parent)
	}
	if hint := d.get("parentFileNameHint"); hint != "" {
		return fmt.Errorf("%w: this is a child (snapshot) disk with a parent file %q; snapshot chains are not followed", ErrUnsupported, hint)
	}
	if !vmdkIn(vmdkSparseTypes, ct) && !vmdkIn(vmdkFlatTypes, ct) {
		return fmt.Errorf("%w: createType %q is not read (supported: monolithicSparse, streamOptimized, monolithicFlat, twoGbMaxExtentFlat, twoGbMaxExtentSparse); snapshot chains are not followed", ErrUnsupported, ct)
	}
	if len(d.extents) == 0 {
		return fmt.Errorf("%w: the descriptor lists no extents", ErrCorrupt)
	}
	var total uint64
	for _, e := range d.extents {
		if e.access == "NOACCESS" {
			return fmt.Errorf("%w: extent with NOACCESS is not read", ErrUnsupported)
		}
		if e.typ != "FLAT" && e.typ != "SPARSE" {
			return fmt.Errorf("%w: extent type %s of createType %s is not read", ErrUnsupported, e.typ, ct)
		}
		want := "SPARSE"
		if vmdkIn(vmdkFlatTypes, ct) {
			want = "FLAT"
		}
		if e.typ != want {
			return fmt.Errorf("%w: createType %s with a %s extent", ErrCorrupt, ct, e.typ)
		}
		if e.sectors == 0 || e.sectors > vmdkMaxCapacitySectors {
			return fmt.Errorf("%w: extent of %d sectors is zero or absurd", ErrCorrupt, e.sectors)
		}
		total += e.sectors
	}
	if total > vmdkMaxCapacitySectors {
		return fmt.Errorf("%w: the disk's %d sectors are absurd", ErrCorrupt, total)
	}
	if (ct == "monolithicSparse" || ct == "streamOptimized") && len(d.extents) != 1 {
		return fmt.Errorf("%w: createType %s with %d extents", ErrCorrupt, ct, len(d.extents))
	}
	return nil
}

// ---- opening

// vmdkExtentPath resolves an extent name to a file inside dir. Only plain file
// names are accepted; the result, after symbolic links are resolved, must
// still be inside dir.
func vmdkExtentPath(dir, name string) (string, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") ||
		filepath.IsAbs(name) || filepath.Base(name) != name {
		return "", fmt.Errorf("%w: extent name %q is not a plain file name in the descriptor's directory; it is not opened", ErrUnsupported, name)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	realDir, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(realDir, name))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(realDir, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: extent %q resolves outside the descriptor's directory; it is not opened", ErrUnsupported, name)
	}
	return resolved, nil
}

func openVMDKExtentFile(path string) (*os.File, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: extent %s is not a regular file", ErrUnsupported, filepath.Base(path))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if st2, err := f.Stat(); err != nil || !st2.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%w: extent %s is not a regular file", ErrUnsupported, filepath.Base(path))
	}
	return f, nil
}

type vmdkOpener struct {
	exts []vmdkExtent
}

func (o *vmdkOpener) closeAll() {
	for _, e := range o.exts {
		e.close()
	}
	o.exts = nil
}

func (o *vmdkOpener) addSparse(f *os.File, wantSectors uint64) error {
	s, err := newSparseExtent(f)
	if err != nil {
		f.Close()
		return err
	}
	if wantSectors != 0 && uint64(s.capBytes/vmdkSector) != wantSectors {
		s.close()
		return fmt.Errorf("%w: extent %s holds %d sectors, the descriptor declares %d", ErrCorrupt, filepath.Base(f.Name()), s.capBytes/vmdkSector, wantSectors)
	}
	o.exts = append(o.exts, s)
	return nil
}

func (o *vmdkOpener) addFlat(f *os.File, e vmdkExtentLine) error {
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	avail := uint64(st.Size() / vmdkSector)
	if e.offset > avail || e.sectors > avail-e.offset {
		f.Close()
		return fmt.Errorf("%w: flat extent %s is %d bytes, shorter than the %d sectors at offset %d the descriptor declares", ErrCorrupt, filepath.Base(f.Name()), st.Size(), e.sectors, e.offset)
	}
	o.exts = append(o.exts, &vmdkFlatExtent{f: f, base: int64(e.offset) * vmdkSector, size: int64(e.sectors) * vmdkSector})
	return nil
}

// resolve opens every extent a descriptor names, as plain file names in dir.
func (o *vmdkOpener) resolve(dir string, d *vmdkDescriptor) error {
	for _, e := range d.extents {
		p, err := vmdkExtentPath(dir, e.name)
		if err != nil {
			return err
		}
		f, err := openVMDKExtentFile(p)
		if err != nil {
			return err
		}
		if e.typ == "FLAT" {
			err = o.addFlat(f, e)
		} else {
			err = o.addSparse(f, e.sectors)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func readVMDKDescriptorFile(f *os.File) (string, error) {
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if st.Size() > vmdkMaxDescriptor {
		return "", fmt.Errorf("%w: %s is %d bytes, more than the %d byte descriptor limit, and is not a sparse extent", ErrCorrupt, f.Name(), st.Size(), vmdkMaxDescriptor)
	}
	b := make([]byte, st.Size())
	if _, err := f.ReadAt(b, 0); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b), nil
}

// openVMDK reads a VMware VMDK: a sparse extent (alone, or the first of several
// given in order) or a text descriptor naming flat or sparse extents.
func openVMDK(paths []string) (Image, error) {
	if len(paths) == 0 {
		return nil, errors.New("image: no path given")
	}
	f, err := os.Open(paths[0])
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUnsupported, paths[0])
	}
	var magic [4]byte
	f.ReadAt(magic[:], 0)

	o := &vmdkOpener{}
	var desc *vmdkDescriptor
	ok := false
	defer func() {
		if !ok {
			o.closeAll()
		}
	}()
	dir := filepath.Dir(paths[0])

	if string(magic[:]) == vmdkSparseMagic {
		if err := o.addSparse(f, 0); err != nil {
			return nil, err
		}
		first := o.exts[0].(*sparseExtent)
		if first.desc != "" {
			if desc, err = parseVMDKDescriptor(first.desc); err != nil {
				return nil, err
			}
			if err := desc.validate(); err != nil {
				return nil, err
			}
			ct := desc.get("createType")
			if vmdkIn(vmdkFlatTypes, ct) {
				return nil, fmt.Errorf("%w: a sparse extent carries a %s descriptor", ErrCorrupt, ct)
			}
			if len(paths) == 1 && ct == "twoGbMaxExtentSparse" {
				o.closeAll()
				if err := o.resolve(dir, desc); err != nil {
					return nil, err
				}
			}
		}
		if len(o.exts) == 1 && len(paths) > 1 {
			for _, p := range paths[1:] {
				ef, err := openVMDKExtentFile(p)
				if err != nil {
					return nil, err
				}
				if err := o.addSparse(ef, 0); err != nil {
					return nil, err
				}
			}
		}
		if desc != nil {
			if len(o.exts) != len(desc.extents) {
				return nil, fmt.Errorf("%w: the descriptor lists %d extents, %d were given", ErrCorrupt, len(desc.extents), len(o.exts))
			}
			for i, e := range desc.extents {
				if o.exts[i].capacity() != int64(e.sectors)*vmdkSector {
					return nil, fmt.Errorf("%w: extent %d holds %d sectors, the descriptor declares %d", ErrCorrupt, i+1, o.exts[i].capacity()/vmdkSector, e.sectors)
				}
			}
		}
	} else {
		text, err := readVMDKDescriptorFile(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(strings.TrimLeft(text, " \t\r\n\xef\xbb\xbf"), "# Disk DescriptorFile") {
			return nil, fmt.Errorf("%w: %s is neither a sparse extent (KDMV) nor a VMDK descriptor", ErrCorrupt, paths[0])
		}
		if desc, err = parseVMDKDescriptor(text); err != nil {
			return nil, err
		}
		if err := desc.validate(); err != nil {
			return nil, err
		}
		if err := o.resolve(dir, desc); err != nil {
			return nil, err
		}
	}

	img := &vmdkImage{extents: o.exts}
	unclean := false
	for _, e := range o.exts {
		img.starts = append(img.starts, img.size)
		img.size += e.capacity()
		if s, isSparse := e.(*sparseExtent); isSparse && s.unclean {
			unclean = true
		}
	}
	if img.size <= 0 {
		return nil, fmt.Errorf("%w: the disk is empty", ErrCorrupt)
	}
	meta := map[string]string{"vmdk_unclean_shutdown": strconv.FormatBool(unclean)}
	if desc != nil {
		meta["vmdk_create_type"] = desc.get("createType")
		meta["vmdk_cid"] = desc.get("CID")
		meta["vmdk_parent_cid"] = desc.get("parentCID")
		if v := desc.get("ddb.uuid"); v != "" {
			meta["vmdk_uuid"] = v
		}
		if v := desc.get("ddb.adapterType"); v != "" {
			meta["vmdk_adapter_type"] = v
		}
	}
	img.info = Info{Format: FormatVMDK, Size: img.size, SectorSize: 512, Segments: len(o.exts), Meta: meta}
	ok = true
	return img, nil
}
