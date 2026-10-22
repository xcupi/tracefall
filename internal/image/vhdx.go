package image

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strconv"
	"sync"
	"unicode/utf16"
)

// Reader for the Hyper-V VHDX container (MS-VHDX), fixed and dynamic, read-only.
//
// The file is never written. Everything taken from it is bounds-checked before use:
// the headers and the region table by their CRC-32C, every region against the file
// size, the metadata table item by item, and the whole block allocation table (BAT)
// once at open, so a read can only fail later if the file changes under us.
//
// Deliberately not handled, and reported as ErrUnsupported with the reason:
//   - a non-empty log (the log must be replayed first; replaying writes to the file, and
//     reading without replay could return stale blocks),
//   - a differencing disk (the parent chain is not followed),
//   - partially present blocks (they only occur with a parent),
//   - an unknown region or metadata item that the file marks as required.
//
// Block data is read straight from the file at the offset the BAT gives. The only cache is
// of BAT pages (the block map), bounded to vhdxMaxBATPages; the operating system caches the
// data itself, and a data cache of 256 MiB blocks would not be bounded in any useful sense.

const (
	vhdxHeaderSection = 1 << 20 // the first MiB is reserved for the identifier, headers and region tables
	vhdxMinBlock      = 1 << 20
	vhdxMaxBlock      = 256 << 20
	vhdxMaxDiskSize   = 64 << 40 // 64 TiB, the format's limit
	vhdxMaxTableItems = 2047
	vhdxBATPageSize   = 4096
	vhdxMaxBATPages   = 64
)

const (
	vhdxGUIDBAT      = "2DC27766-F623-4200-9D64-115E9BFD4A08"
	vhdxGUIDMetadata = "8B7CA206-4790-4B9A-B8FE-575F050F886E"
	vhdxGUIDFilePar  = "CAA16737-FA36-4D43-B3B6-33F0AA44E76B"
	vhdxGUIDVSize    = "2FA54224-CD1B-4876-B211-5DBED83BF4B8"
	vhdxGUIDDiskID   = "BECA12AB-B2E6-4523-93EF-C309E000C746"
	vhdxGUIDLogical  = "8141BF1D-A96F-4709-BA47-F233A8FAAB5F"
	vhdxGUIDPhysical = "CDA348C7-445D-4471-9CC9-E9885251C556"
	vhdxGUIDParent   = "A8D35F2D-B30B-454D-ABF7-D3D84834AB0C"
)

var vhdxCRC = crc32.MakeTable(crc32.Castagnoli)

type vhdxImage struct {
	f         *os.File
	fileSize  int64
	size      int64
	blockSize int64
	ratio     int64 // payload blocks per sector-bitmap entry
	batOff    int64
	batCount  int64
	info      Info

	mu    sync.Mutex
	pages map[int64][]uint64
	order []int64
}

func vhdxCorrupt(format string, a ...any) error {
	return fmt.Errorf("%w: VHDX: "+format, append([]any{ErrCorrupt}, a...)...)
}

// vhdxGUID formats an on-disk (mixed-endian) GUID as upper-case text.
func vhdxGUID(b []byte) string {
	const hexd = "0123456789ABCDEF"
	order := []int{3, 2, 1, 0, -1, 5, 4, -1, 7, 6, -1, 8, 9, -1, 10, 11, 12, 13, 14, 15}
	out := make([]byte, 0, 36)
	for _, i := range order {
		if i < 0 {
			out = append(out, '-')
			continue
		}
		out = append(out, hexd[b[i]>>4], hexd[b[i]&15])
	}
	return string(out)
}

func vhdxZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// vhdxCheckedCRC reports whether the CRC-32C of buf, computed with the 4 bytes at crcAt
// treated as zero, equals the stored value.
func vhdxCheckedCRC(buf []byte, crcAt int) bool {
	stored := binary.LittleEndian.Uint32(buf[crcAt:])
	var sum uint32
	sum = crc32.Update(sum, vhdxCRC, buf[:crcAt])
	sum = crc32.Update(sum, vhdxCRC, []byte{0, 0, 0, 0})
	sum = crc32.Update(sum, vhdxCRC, buf[crcAt+4:])
	return sum == stored
}

func (v *vhdxImage) readFull(p []byte, off int64, what string) error {
	n, err := v.f.ReadAt(p, off)
	if n == len(p) {
		return nil
	}
	if err == nil || errors.Is(err, io.EOF) {
		return vhdxCorrupt("%s at offset %d is truncated (file is %d bytes)", what, off, v.fileSize)
	}
	return err
}

type vhdxRegion struct{ off, length int64 }

func openVHDX(paths []string) (Image, error) {
	if len(paths) != 1 {
		return nil, fmt.Errorf("%w: a VHDX is a single file, %d paths were given", ErrUnsupported, len(paths))
	}
	f, err := os.Open(paths[0])
	if err != nil {
		return nil, err
	}
	v, err := parseVHDX(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return v, nil
}

func parseVHDX(f *os.File) (*vhdxImage, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("image: %s is a directory", f.Name())
	}
	v := &vhdxImage{f: f, fileSize: st.Size(), pages: map[int64][]uint64{}}
	if v.fileSize < vhdxHeaderSection {
		return nil, vhdxCorrupt("file is %d bytes, shorter than the 1 MiB header section", v.fileSize)
	}

	// File type identifier.
	ident := make([]byte, 8+512)
	if err := v.readFull(ident, 0, "file type identifier"); err != nil {
		return nil, err
	}
	if string(ident[:8]) != vhdxSignature {
		return nil, vhdxCorrupt("file type identifier signature is missing")
	}
	u := make([]uint16, 0, 256)
	for i := 8; i+1 < len(ident); i += 2 {
		c := binary.LittleEndian.Uint16(ident[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	creator := string(utf16.Decode(u))

	// Headers: the valid one with the higher sequence number is current.
	var cur []byte
	var curSeq uint64
	for _, off := range []int64{64 << 10, 128 << 10} {
		h := make([]byte, 4096)
		if err := v.readFull(h, off, "header"); err != nil {
			return nil, err
		}
		if string(h[:4]) != "head" || !vhdxCheckedCRC(h, 4) {
			continue
		}
		seq := binary.LittleEndian.Uint64(h[8:])
		if cur == nil || seq > curSeq {
			cur, curSeq = h, seq
		}
	}
	if cur == nil {
		return nil, vhdxCorrupt("neither header is valid (bad signature or CRC-32C)")
	}
	if ver := binary.LittleEndian.Uint16(cur[66:]); ver != 1 {
		return nil, fmt.Errorf("%w: VHDX header version %d is not understood", ErrUnsupported, ver)
	}
	if !vhdxZero(cur[48:64]) {
		return nil, fmt.Errorf("%w: VHDX log is not empty (log GUID %s): the log must be replayed before the disk can be read safely, "+
			"and replaying would modify the evidence file; refusing rather than returning possibly stale blocks",
			ErrUnsupported, vhdxGUID(cur[48:64]))
	}

	// Region table.
	var bat, meta *vhdxRegion
	var tableOK bool
	for _, off := range []int64{192 << 10, 256 << 10} {
		rt := make([]byte, 64<<10)
		if err := v.readFull(rt, off, "region table"); err != nil {
			return nil, err
		}
		if string(rt[:4]) != "regi" || !vhdxCheckedCRC(rt, 4) {
			continue
		}
		count := int(binary.LittleEndian.Uint32(rt[8:]))
		if count > vhdxMaxTableItems {
			continue
		}
		tableOK = true
		for i := 0; i < count; i++ {
			e := rt[16+32*i : 16+32*(i+1)]
			guid := vhdxGUID(e[:16])
			roff := binary.LittleEndian.Uint64(e[16:])
			rlen := uint64(binary.LittleEndian.Uint32(e[24:]))
			required := binary.LittleEndian.Uint32(e[28:])&1 != 0
			if guid != vhdxGUIDBAT && guid != vhdxGUIDMetadata {
				if required {
					return nil, fmt.Errorf("%w: VHDX region %s is marked required and is not understood", ErrUnsupported, guid)
				}
				continue
			}
			if roff%vhdxHeaderSection != 0 || roff < vhdxHeaderSection || rlen == 0 || rlen%vhdxHeaderSection != 0 ||
				roff > uint64(v.fileSize) || rlen > uint64(v.fileSize)-roff {
				return nil, vhdxCorrupt("region %s (offset %d, length %d) is misaligned or outside the %d-byte file", guid, roff, rlen, v.fileSize)
			}
			r := &vhdxRegion{int64(roff), int64(rlen)}
			if guid == vhdxGUIDBAT {
				if bat != nil {
					return nil, vhdxCorrupt("two BAT regions")
				}
				bat = r
			} else {
				if meta != nil {
					return nil, vhdxCorrupt("two metadata regions")
				}
				meta = r
			}
		}
		break
	}
	if !tableOK {
		return nil, vhdxCorrupt("neither region table is valid")
	}
	if bat == nil || meta == nil {
		return nil, vhdxCorrupt("the region table lacks the BAT or the metadata region")
	}
	if bat.off < meta.off+meta.length && meta.off < bat.off+bat.length {
		return nil, vhdxCorrupt("the BAT and metadata regions overlap")
	}

	// Metadata.
	if meta.length < 64<<10 {
		return nil, vhdxCorrupt("metadata region is smaller than its table")
	}
	mt := make([]byte, 64<<10)
	if err := v.readFull(mt, meta.off, "metadata table"); err != nil {
		return nil, err
	}
	if string(mt[:8]) != "metadata" {
		return nil, vhdxCorrupt("metadata table signature is missing")
	}
	count := int(binary.LittleEndian.Uint16(mt[10:]))
	if count > vhdxMaxTableItems {
		return nil, vhdxCorrupt("metadata table claims %d items", count)
	}
	items := map[string][]byte{}
	for i := 0; i < count; i++ {
		e := mt[32+32*i : 32+32*(i+1)]
		guid := vhdxGUID(e[:16])
		ioff := int64(binary.LittleEndian.Uint32(e[16:]))
		ilen := int64(binary.LittleEndian.Uint32(e[20:]))
		required := binary.LittleEndian.Uint32(e[24:])&4 != 0
		switch guid {
		case vhdxGUIDFilePar, vhdxGUIDVSize, vhdxGUIDDiskID, vhdxGUIDLogical, vhdxGUIDPhysical, vhdxGUIDParent:
		default:
			if required {
				return nil, fmt.Errorf("%w: VHDX metadata item %s is marked required and is not understood", ErrUnsupported, guid)
			}
			continue
		}
		if _, dup := items[guid]; dup {
			return nil, vhdxCorrupt("metadata item %s appears twice", guid)
		}
		if ioff < 64<<10 || ilen > 1<<20 || ioff > meta.length || ilen > meta.length-ioff {
			return nil, vhdxCorrupt("metadata item %s (offset %d, length %d) lies outside the metadata region", guid, ioff, ilen)
		}
		d := make([]byte, ilen)
		if err := v.readFull(d, meta.off+ioff, "metadata item"); err != nil {
			return nil, err
		}
		items[guid] = d
	}
	need := func(guid string, n int) ([]byte, error) {
		d, ok := items[guid]
		if !ok {
			return nil, vhdxCorrupt("required metadata item %s is missing", guid)
		}
		if len(d) != n {
			return nil, vhdxCorrupt("metadata item %s is %d bytes, expected %d", guid, len(d), n)
		}
		return d, nil
	}
	fp, err := need(vhdxGUIDFilePar, 8)
	if err != nil {
		return nil, err
	}
	vsb, err := need(vhdxGUIDVSize, 8)
	if err != nil {
		return nil, err
	}
	idb, err := need(vhdxGUIDDiskID, 16)
	if err != nil {
		return nil, err
	}
	lsb, err := need(vhdxGUIDLogical, 4)
	if err != nil {
		return nil, err
	}
	psb, err := need(vhdxGUIDPhysical, 4)
	if err != nil {
		return nil, err
	}
	blockSize := int64(binary.LittleEndian.Uint32(fp))
	flags := binary.LittleEndian.Uint32(fp[4:])
	if flags&2 != 0 {
		return nil, fmt.Errorf("%w: VHDX is a differencing disk (it has a parent; the parent locator names it) and the parent chain is not followed", ErrUnsupported)
	}
	vsize := binary.LittleEndian.Uint64(vsb)
	lss := int64(binary.LittleEndian.Uint32(lsb))
	pss := int64(binary.LittleEndian.Uint32(psb))
	if blockSize < vhdxMinBlock || blockSize > vhdxMaxBlock || blockSize&(blockSize-1) != 0 {
		return nil, vhdxCorrupt("block size %d is not a power of two between 1 MiB and 256 MiB", blockSize)
	}
	if lss != 512 && lss != 4096 {
		return nil, vhdxCorrupt("logical sector size %d is not 512 or 4096", lss)
	}
	if pss != 512 && pss != 4096 {
		return nil, vhdxCorrupt("physical sector size %d is not 512 or 4096", pss)
	}
	if vsize == 0 || vsize > vhdxMaxDiskSize || vsize%uint64(lss) != 0 {
		return nil, vhdxCorrupt("virtual disk size %d is zero, above 64 TiB, or not a multiple of the logical sector size", vsize)
	}
	v.size = int64(vsize)
	v.blockSize = blockSize

	// BAT geometry.
	v.ratio = (int64(1) << 23) * lss / blockSize
	payload := (v.size + blockSize - 1) / blockSize
	v.batCount = payload + (payload-1)/v.ratio
	if v.batCount > bat.length/8 {
		return nil, vhdxCorrupt("the BAT region holds %d entries but the disk needs %d", bat.length/8, v.batCount)
	}
	v.batOff = bat.off
	if err := v.validateBAT(); err != nil {
		return nil, err
	}

	typ := "dynamic"
	if flags&1 != 0 {
		typ = "fixed"
	}
	lower := []byte(vhdxGUID(idb))
	for i, c := range lower {
		if c >= 'A' && c <= 'F' {
			lower[i] = c + 32
		}
	}
	v.info = Info{Format: FormatVHDX, Size: v.size, SectorSize: int(lss), Segments: 1, Meta: map[string]string{
		"vhdx_type": typ, "vhdx_block_size": strconv.FormatInt(blockSize, 10),
		"vhdx_logical_sector": strconv.FormatInt(lss, 10), "vhdx_physical_sector": strconv.FormatInt(pss, 10),
		"vhdx_disk_id": string(lower), "vhdx_creator": creator,
		"vhdx_header_sequence": strconv.FormatUint(curSeq, 10),
	}}
	return v, nil
}

// classify interprets a payload BAT entry. For a present block it returns the file offset;
// an absent block (not present, undefined, zero, unmapped) reads as zeros.
func (v *vhdxImage) classify(i int64, e uint64) (present bool, off int64, err error) {
	switch e & 7 {
	case 0, 1, 2, 3:
		return false, 0, nil
	case 6:
		mibs := e >> 20
		if mibs > uint64(v.fileSize)>>20 {
			return false, 0, vhdxCorrupt("payload block %d points at MiB %d, beyond the %d-byte file", i, mibs, v.fileSize)
		}
		off = int64(mibs) << 20
		need := v.blockSize
		if rest := v.size - i*v.blockSize; rest < need {
			need = rest
		}
		if off < vhdxHeaderSection || need > v.fileSize-off {
			return false, 0, vhdxCorrupt("payload block %d (file offset %d, %d bytes) is inside the header section or past the end of the %d-byte file", i, off, need, v.fileSize)
		}
		return true, off, nil
	case 7:
		return false, 0, fmt.Errorf("%w: VHDX payload block %d is partially present, which only occurs with a parent disk whose chain is not followed", ErrUnsupported, i)
	}
	return false, 0, vhdxCorrupt("payload block %d has the reserved state %d", i, e&7)
}

// validateBAT walks every payload BAT entry once, in bounded chunks.
func (v *vhdxImage) validateBAT() error {
	const chunk = 1 << 20
	buf := make([]byte, chunk)
	for start := int64(0); start < v.batCount; start += chunk / 8 {
		n := v.batCount - start
		if n > chunk/8 {
			n = chunk / 8
		}
		b := buf[:n*8]
		if err := v.readFull(b, v.batOff+start*8, "BAT"); err != nil {
			return err
		}
		for k := int64(0); k < n; k++ {
			j := start + k
			if (j+1)%(v.ratio+1) == 0 {
				continue // sector bitmap entry; only a parent makes it matter
			}
			blk := j - j/(v.ratio+1)
			if _, _, err := v.classify(blk, binary.LittleEndian.Uint64(b[k*8:])); err != nil {
				return err
			}
		}
	}
	return nil
}

func (v *vhdxImage) entry(batIdx int64) (uint64, error) {
	const per = vhdxBATPageSize / 8
	page := batIdx / per
	v.mu.Lock()
	p, ok := v.pages[page]
	v.mu.Unlock()
	if !ok {
		start := page * per
		n := v.batCount - start
		if n > per {
			n = per
		}
		raw := make([]byte, n*8)
		if err := v.readFull(raw, v.batOff+start*8, "BAT"); err != nil {
			return 0, err
		}
		p = make([]uint64, n)
		for i := range p {
			p[i] = binary.LittleEndian.Uint64(raw[i*8:])
		}
		v.mu.Lock()
		if _, ok := v.pages[page]; !ok {
			v.pages[page] = p
			v.order = append(v.order, page)
			if len(v.order) > vhdxMaxBATPages {
				delete(v.pages, v.order[0])
				v.order = v.order[1:]
			}
		}
		v.mu.Unlock()
	}
	return p[batIdx%per], nil
}

func (v *vhdxImage) Size() int64 { return v.size }

func (v *vhdxImage) Info() Info {
	in := v.info
	in.Meta = make(map[string]string, len(v.info.Meta))
	for k, val := range v.info.Meta {
		in.Meta[k] = val
	}
	return in
}

func (v *vhdxImage) Close() error { return v.f.Close() }

func (v *vhdxImage) ReadAt(p []byte, off int64) (int, error) {
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
		want, short = v.size-off, true
	}
	var done int64
	for done < want {
		pos := off + done
		blk := pos / v.blockSize
		in := pos % v.blockSize
		n := v.blockSize - in
		if n > want-done {
			n = want - done
		}
		e, err := v.entry(blk + blk/v.ratio)
		if err != nil {
			return int(done), err
		}
		present, foff, err := v.classify(blk, e)
		if err != nil {
			return int(done), err
		}
		dst := p[done : done+n]
		if present {
			if err := v.readFull(dst, foff+in, "payload block"); err != nil {
				return int(done), err
			}
		} else {
			clear(dst)
		}
		done += n
	}
	if short {
		return int(done), io.EOF
	}
	return int(done), nil
}
