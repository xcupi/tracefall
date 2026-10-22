package image

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
	"unicode/utf16"
)

// Reader for the Virtual PC / Hyper-V VHD container (Microsoft's public "Virtual
// Hard Disk Image Format Specification"), fixed and dynamic disks.
//
//	fixed:   raw disk bytes, then a 512-byte footer.
//	dynamic: footer copy | 1024-byte dynamic header | BAT | blocks... | footer.
//	         A block is a sector bitmap (one bit per sector, MSB first, padded to
//	         512 bytes) followed by the block's data sectors. A BAT entry is a
//	         32-bit big-endian sector number, 0xFFFFFFFF for an unallocated block.
//
// A block that is not allocated, and a sector whose bitmap bit is 0 inside an
// allocated block, read as zeros. Differencing disks (and any disk that names a
// parent) are refused with ErrUnsupported: the parent chain is not followed.
// Every offset and size taken from the file is bounds-checked against the real
// file size before it is used, and allocations are capped.
const (
	vhdFooterSize   = 512
	vhdHeaderSize   = 1024
	vhdSector       = 512
	vhdMaxBlockSize = 256 << 20 // largest block size accepted
	vhdMaxEntries   = 1 << 24   // largest BAT accepted (64 MiB)
	vhdMaxSize      = 1 << 62
	vhdUnallocated  = 0xFFFFFFFF
	vhdCacheBlocks  = 8
	vhdEpochOffset  = 946684800 // 2000-01-01 UTC in Unix seconds

	vhdTypeFixed   = 2
	vhdTypeDynamic = 3
	vhdTypeDiff    = 4
)

type vhdFooter struct {
	version  uint32
	dataOff  uint64
	stamp    uint32
	creator  string
	origSize uint64
	curSize  uint64
	diskType uint32
	uuid     [16]byte
}

func vhdCorrupt(format string, a ...any) error {
	return fmt.Errorf("%w: VHD: "+format, append([]any{ErrCorrupt}, a...)...)
}

func parseVHDFooter(b []byte, where string) (vhdFooter, error) {
	var f vhdFooter
	if len(b) != vhdFooterSize || string(b[:8]) != vhdCookie {
		return f, vhdCorrupt("%s footer has no 'conectix' cookie", where)
	}
	if got, want := vhdChecksum(b, 64), binary.BigEndian.Uint32(b[64:]); got != want {
		return f, vhdCorrupt("%s footer checksum is %#08x, computed %#08x", where, want, got)
	}
	f.version = binary.BigEndian.Uint32(b[12:])
	if f.version>>16 != 1 {
		return f, vhdCorrupt("%s footer has file format version %#x; only major version 1 is defined", where, f.version)
	}
	f.dataOff = binary.BigEndian.Uint64(b[16:])
	f.stamp = binary.BigEndian.Uint32(b[24:])
	f.creator = vhdASCII(b[28:32])
	f.origSize = binary.BigEndian.Uint64(b[40:])
	f.curSize = binary.BigEndian.Uint64(b[48:])
	f.diskType = binary.BigEndian.Uint32(b[60:])
	copy(f.uuid[:], b[68:84])
	return f, nil
}

// vhdChecksum is the one's complement of the byte sum with the 4-byte checksum
// field at csumOff left out.
func vhdChecksum(b []byte, csumOff int) uint32 {
	var s uint32
	for i, c := range b {
		if i >= csumOff && i < csumOff+4 {
			continue
		}
		s += uint32(c)
	}
	return ^s
}

func vhdASCII(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		out[i] = c
	}
	return string(out)
}

func vhdUUID(u [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

type vhdImage struct {
	f    *os.File
	size int64
	meta map[string]string

	dynamic   bool
	blockSize int64
	bat       []uint32
	bmBytes   int64 // sector bitmap size, padded to 512

	mu     sync.Mutex
	cache  map[int64][]byte // block index -> bitmap
	cached []int64          // insertion order, oldest first
}

func openVHD(paths []string) (Image, error) {
	if len(paths) != 1 {
		return nil, fmt.Errorf("%w: a VHD is a single file; %d segments were given", ErrUnsupported, len(paths))
	}
	f, err := os.Open(paths[0])
	if err != nil {
		return nil, err
	}
	v, err := newVHD(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return v, nil
}

func vhdReadFull(f *os.File, off int64, n int, what string) ([]byte, error) {
	b := make([]byte, n)
	if _, err := f.ReadAt(b, off); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, vhdCorrupt("%s lies beyond the end of the file", what)
		}
		return nil, err
	}
	return b, nil
}

func newVHD(f *os.File) (*vhdImage, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("image: %s is a directory", f.Name())
	}
	fileSize := st.Size()
	if fileSize < vhdFooterSize {
		return nil, vhdCorrupt("file is %d bytes, shorter than the 512-byte footer", fileSize)
	}
	endOff := fileSize - vhdFooterSize
	endRaw, err := vhdReadFull(f, endOff, vhdFooterSize, "end footer")
	if err != nil {
		return nil, err
	}
	if string(endRaw[:8]) != vhdCookie {
		if head, _ := vhdReadFull(f, 0, 8, "start"); string(head) == vhdCookie {
			return nil, vhdCorrupt("the footer at the end of the file is missing; the file is truncated or damaged")
		}
		return nil, vhdCorrupt("no 'conectix' footer at the end of the file")
	}
	foot, err := parseVHDFooter(endRaw, "end-of-file")
	if err != nil {
		return nil, err
	}
	if foot.curSize == 0 || foot.curSize > vhdMaxSize {
		return nil, vhdCorrupt("footer current size %d is not plausible", foot.curSize)
	}

	v := &vhdImage{f: f, size: int64(foot.curSize), cache: map[int64][]byte{}}
	v.meta = map[string]string{
		"vhd_creator_application": foot.creator,
		"vhd_creation_utc":        time.Unix(vhdEpochOffset+int64(foot.stamp), 0).UTC().Format(time.RFC3339),
		"vhd_uuid":                vhdUUID(foot.uuid),
	}

	switch foot.diskType {
	case vhdTypeFixed:
		if foot.curSize != uint64(endOff) {
			return nil, vhdCorrupt("fixed disk: footer current size %d does not match the %d data bytes in the file", foot.curSize, endOff)
		}
		v.meta["vhd_type"] = "fixed"
		return v, nil
	case vhdTypeDynamic:
		v.meta["vhd_type"] = "dynamic"
		if err := v.openDynamic(f, foot, fileSize); err != nil {
			return nil, err
		}
		return v, nil
	case vhdTypeDiff:
		return nil, vhdDifferencingError(f, foot, fileSize)
	default:
		return nil, fmt.Errorf("%w: VHD disk type %d (none, deprecated or reserved) is not read", ErrUnsupported, foot.diskType)
	}
}

// vhdDifferencingError names the parent from the dynamic header when it can be
// read; the disk is refused either way.
func vhdDifferencingError(f *os.File, foot vhdFooter, fileSize int64) error {
	parent := ""
	if foot.dataOff >= vhdFooterSize && foot.dataOff <= uint64(fileSize) && uint64(fileSize)-foot.dataOff >= vhdHeaderSize+vhdFooterSize {
		if h, err := vhdReadFull(f, int64(foot.dataOff), vhdHeaderSize, "dynamic header"); err == nil && string(h[:8]) == "cxsparse" {
			parent = vhdParentName(h)
		}
	}
	if parent != "" {
		return fmt.Errorf("%w: differencing VHD (type 4) whose parent locator names %q; a parent chain is not followed, so the disk cannot be read on its own", ErrUnsupported, parent)
	}
	return fmt.Errorf("%w: differencing VHD (type 4) with a parent locator; a parent chain is not followed, so the disk cannot be read on its own", ErrUnsupported)
}

func vhdParentName(h []byte) string {
	raw := h[64:576]
	u := make([]uint16, 0, 256)
	for i := 0; i+1 < len(raw); i += 2 {
		c := binary.BigEndian.Uint16(raw[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

func (v *vhdImage) openDynamic(f *os.File, foot vhdFooter, fileSize int64) error {
	if fileSize < vhdFooterSize+vhdHeaderSize+vhdFooterSize {
		return vhdCorrupt("file of %d bytes is too small for a dynamic disk", fileSize)
	}
	startRaw, err := vhdReadFull(f, 0, vhdFooterSize, "start footer")
	if err != nil {
		return err
	}
	start, err := parseVHDFooter(startRaw, "start-of-file")
	if err != nil {
		return err
	}
	if start.diskType != foot.diskType || start.curSize != foot.curSize || start.origSize != foot.origSize ||
		start.dataOff != foot.dataOff || start.uuid != foot.uuid {
		return vhdCorrupt("the footer copy at the start of the file disagrees with the one at the end (type, size, data offset or unique id)")
	}
	limit := uint64(fileSize - vhdFooterSize) // metadata and blocks must end before the trailing footer
	if foot.dataOff < vhdFooterSize || foot.dataOff > limit || limit-foot.dataOff < vhdHeaderSize {
		return vhdCorrupt("dynamic header offset %d is outside the file", foot.dataOff)
	}
	h, err := vhdReadFull(f, int64(foot.dataOff), vhdHeaderSize, "dynamic header")
	if err != nil {
		return err
	}
	if string(h[:8]) != "cxsparse" {
		return vhdCorrupt("dynamic header has no 'cxsparse' cookie")
	}
	if got, want := vhdChecksum(h, 36), binary.BigEndian.Uint32(h[36:]); got != want {
		return vhdCorrupt("dynamic header checksum is %#08x, computed %#08x", want, got)
	}
	if ver := binary.BigEndian.Uint32(h[24:]); ver>>16 != 1 {
		return vhdCorrupt("dynamic header version %#x; only major version 1 is defined", ver)
	}
	// A parent named by a type 3 disk: refuse rather than read an incomplete disk.
	if name := vhdParentName(h); name != "" || !bytes.Equal(h[40:56], make([]byte, 16)) || vhdHasLocator(h) {
		if name == "" {
			return fmt.Errorf("%w: VHD names a parent (parent id or parent locator entries present); a parent chain is not followed", ErrUnsupported)
		}
		return fmt.Errorf("%w: VHD parent locator names %q; a parent chain is not followed", ErrUnsupported, name)
	}

	tableOff := binary.BigEndian.Uint64(h[16:])
	maxEntries := uint64(binary.BigEndian.Uint32(h[28:]))
	bs := uint64(binary.BigEndian.Uint32(h[32:]))
	if bs == 0 || bs > vhdMaxBlockSize || bs%vhdSector != 0 {
		return vhdCorrupt("block size %d is not a sane multiple of 512 (at most %d)", bs, vhdMaxBlockSize)
	}
	need := (uint64(v.size) + bs - 1) / bs
	if maxEntries > vhdMaxEntries {
		return vhdCorrupt("max table entries %d is absurd", maxEntries)
	}
	if need > maxEntries {
		return vhdCorrupt("the block table has %d entries but a %d-byte disk of %d-byte blocks needs %d", maxEntries, v.size, bs, need)
	}
	batBytes := maxEntries * 4
	if tableOff%vhdSector != 0 || tableOff < foot.dataOff+vhdHeaderSize || tableOff > limit || limit-tableOff < batBytes {
		return vhdCorrupt("block allocation table at %d (%d bytes) is outside the file or overlaps the header", tableOff, batBytes)
	}
	raw, err := vhdReadFull(f, int64(tableOff), int(need*4), "block allocation table")
	if err != nil {
		return err
	}
	v.dynamic = true
	v.blockSize = int64(bs)
	v.bmBytes = int64((bs/vhdSector+7)/8+vhdSector-1) / vhdSector * vhdSector
	v.bat = make([]uint32, need)
	dataFloor := tableOff + batBytes
	for i := range v.bat {
		e := binary.BigEndian.Uint32(raw[i*4:])
		v.bat[i] = e
		if e == vhdUnallocated {
			continue
		}
		off := uint64(e) * vhdSector
		if off < dataFloor || off > limit || limit-off < uint64(v.bmBytes)+bs {
			return vhdCorrupt("block %d is at byte %d, outside the file or inside the metadata", i, off)
		}
	}
	v.meta["vhd_block_size"] = fmt.Sprint(bs)
	return nil
}

func vhdHasLocator(h []byte) bool {
	for i := 0; i < 8; i++ {
		if !bytes.Equal(h[576+i*24:576+i*24+4], []byte{0, 0, 0, 0}) {
			return true
		}
	}
	return false
}

func (v *vhdImage) Size() int64 { return v.size }

func (v *vhdImage) Info() Info {
	meta := make(map[string]string, len(v.meta))
	for k, s := range v.meta {
		meta[k] = s
	}
	return Info{Format: FormatVHD, Size: v.size, SectorSize: vhdSector, Segments: 1, Meta: meta}
}

func (v *vhdImage) Close() error { return v.f.Close() }

func (v *vhdImage) ReadAt(p []byte, off int64) (int, error) {
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
	if want > v.size-off {
		want = v.size - off
		short = true
	}
	var n int64
	var err error
	if v.dynamic {
		n, err = v.readDynamic(p[:want], off)
	} else {
		n, err = v.readFixed(p[:want], off)
	}
	if err != nil {
		return int(n), err
	}
	if short {
		return int(n), io.EOF
	}
	return int(n), nil
}

func (v *vhdImage) readFixed(p []byte, off int64) (int64, error) {
	n, err := v.f.ReadAt(p, off)
	if err != nil && !(errors.Is(err, io.EOF) && n == len(p)) {
		if errors.Is(err, io.EOF) {
			err = vhdCorrupt("the file is shorter than when it was opened")
		}
		return int64(n), err
	}
	return int64(n), nil
}

func (v *vhdImage) readDynamic(p []byte, off int64) (int64, error) {
	var done int64
	for done < int64(len(p)) {
		pos := off + done
		blk := pos / v.blockSize
		in := pos % v.blockSize
		chunk := min(int64(len(p))-done, v.blockSize-in)
		entry := v.bat[blk]
		if entry == vhdUnallocated {
			clear(p[done : done+chunk])
			done += chunk
			continue
		}
		bm, err := v.bitmap(blk)
		if err != nil {
			return done, err
		}
		base := int64(entry)*vhdSector + v.bmBytes
		for chunk > 0 {
			sec := in / vhdSector
			set := bm[sec/8]&(0x80>>(sec%8)) != 0
			// extend the run over following sectors with the same bit
			end := (sec + 1) * vhdSector
			for end-in < chunk && end < v.blockSize {
				s := end / vhdSector
				if (bm[s/8]&(0x80>>(s%8)) != 0) != set {
					break
				}
				end += vhdSector
			}
			run := min(end-in, chunk)
			dst := p[done : done+run]
			if set {
				if _, err := v.f.ReadAt(dst, base+in); err != nil {
					if errors.Is(err, io.EOF) {
						err = vhdCorrupt("block %d data lies beyond the end of the file", blk)
					}
					return done, err
				}
			} else {
				clear(dst)
			}
			done += run
			in += run
			chunk -= run
		}
	}
	return done, nil
}

// bitmap returns the sector bitmap of an allocated block, through a small
// bounded cache. The returned slice is never modified.
func (v *vhdImage) bitmap(blk int64) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if b, ok := v.cache[blk]; ok {
		return b, nil
	}
	b, err := vhdReadFull(v.f, int64(v.bat[blk])*vhdSector, int(v.bmBytes), "sector bitmap")
	if err != nil {
		return nil, err
	}
	if len(v.cached) >= vhdCacheBlocks {
		delete(v.cache, v.cached[0])
		v.cached = v.cached[1:]
	}
	v.cache[blk] = b
	v.cached = append(v.cached, blk)
	return b, nil
}
