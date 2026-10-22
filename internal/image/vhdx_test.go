package image

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ---- synthetic VHDX builder, written from the MS-VHDX layout and independent of the reader ----

const mib = 1 << 20

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// guidBytes encodes "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" in the mixed-endian on-disk layout.
func guidBytes(s string) []byte {
	h := strings.ReplaceAll(s, "-", "")
	raw := make([]byte, 16)
	for i := range raw {
		var v byte
		for _, c := range h[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			default:
				v |= byte(c-'A') + 10
			}
		}
		raw[i] = v
	}
	out := make([]byte, 16)
	out[0], out[1], out[2], out[3] = raw[3], raw[2], raw[1], raw[0]
	out[4], out[5] = raw[5], raw[4]
	out[6], out[7] = raw[7], raw[6]
	copy(out[8:], raw[8:])
	return out
}

const (
	gBAT      = "2DC27766-F623-4200-9D64-115E9BFD4A08"
	gMeta     = "8B7CA206-4790-4B9A-B8FE-575F050F886E"
	gFilePar  = "CAA16737-FA36-4D43-B3B6-33F0AA44E76B"
	gVSize    = "2FA54224-CD1B-4876-B211-5DBED83BF4B8"
	gDiskID   = "BECA12AB-B2E6-4523-93EF-C309E000C746"
	gLSS      = "8141BF1D-A96F-4709-BA47-F233A8FAAB5F"
	gPSS      = "CDA348C7-445D-4471-9CC9-E9885251C556"
	gParent   = "A8D35F2D-B30B-454D-ABF7-D3D84834AB0C"
	gUnknown  = "11111111-2222-3333-4444-555555555555"
	diskIDStr = "0123ABCD-4567-89EF-0123-456789ABCDEF"
)

type vblk struct {
	state uint64
	fill  byte   // payload byte for state 6
	raw   uint64 // when non-zero, written to the BAT verbatim instead of the computed entry
}

type vspec struct {
	blockSize   uint32
	lss, pss    uint32
	vsize       uint64
	fpFlags     uint32
	blocks      []vblk
	seq1, seq2  uint64
	log1, log2  [16]byte
	extraRegion bool // unknown region with the required flag
	extraOpt    bool // unknown region without the required flag
	extraMeta   bool // unknown required metadata item
	hasParent   bool
	version     uint16
}

func newSpec() *vspec {
	return &vspec{blockSize: mib, lss: 512, pss: 4096, vsize: 5*mib + mib/2, seq1: 3, seq2: 4, version: 1,
		blocks: []vblk{{state: 6, fill: 0xA1}, {state: 0}, {state: 2}, {state: 6, fill: 0xB2}, {state: 3}, {state: 6, fill: 0xC3}}}
}

// expected returns the virtual disk content the spec describes.
func (s *vspec) expected() []byte {
	out := make([]byte, s.vsize)
	for i, b := range s.blocks {
		if b.state != 6 {
			continue
		}
		lo := uint64(i) * uint64(s.blockSize)
		for j := lo; j < lo+uint64(s.blockSize) && j < s.vsize; j++ {
			out[j] = b.fill
		}
	}
	return out
}

func putCRC(buf []byte, at int) {
	binary.LittleEndian.PutUint32(buf[at:], 0)
	binary.LittleEndian.PutUint32(buf[at:], crc32.Checksum(buf, castagnoli))
}

func (s *vspec) build() []byte {
	ratio := uint64(1 << 15)
	if s.blockSize != 0 && s.lss != 0 {
		if r := (uint64(1) << 23) * uint64(s.lss) / uint64(s.blockSize); r != 0 {
			ratio = r
		}
	}
	// allocate payload
	next := uint64(3)
	entries := map[int]uint64{}
	var payload [][2]uint64 // offset, block index
	for i, b := range s.blocks {
		idx := i + i/int(ratio)
		e := b.state
		if b.state == 6 {
			e |= next << 20
			payload = append(payload, [2]uint64{next * mib, uint64(i)})
			next++
		}
		if b.raw != 0 {
			e = b.raw
		}
		entries[idx] = e
	}
	fileSize := int(next * mib)
	f := make([]byte, fileSize)
	// file type identifier
	copy(f, "vhdxfile")
	for i, c := range []rune("synthetic-builder") {
		binary.LittleEndian.PutUint16(f[8+2*i:], uint16(c))
	}
	// headers
	hdr := func(off int, seq uint64, log [16]byte) {
		h := f[off : off+4096]
		copy(h, "head")
		binary.LittleEndian.PutUint64(h[8:], seq)
		copy(h[16:], bytes.Repeat([]byte{1}, 16))
		copy(h[32:], bytes.Repeat([]byte{2}, 16))
		copy(h[48:], log[:])
		binary.LittleEndian.PutUint16(h[64:], 0)
		binary.LittleEndian.PutUint16(h[66:], s.version)
		binary.LittleEndian.PutUint32(h[68:], mib)
		binary.LittleEndian.PutUint64(h[72:], 4*mib)
		putCRC(h, 4)
	}
	hdr(64<<10, s.seq1, s.log1)
	hdr(128<<10, s.seq2, s.log2)
	// region table
	rt := make([]byte, 64<<10)
	copy(rt, "regi")
	type ent struct {
		g        string
		off, len uint64
		req      uint32
	}
	ents := []ent{{gBAT, 2 * mib, mib, 1}, {gMeta, mib, mib, 1}}
	if s.extraRegion {
		ents = append(ents, ent{gUnknown, 8 * mib, mib, 1})
	}
	if s.extraOpt {
		ents = append(ents, ent{gUnknown, 8 * mib, mib, 0})
	}
	binary.LittleEndian.PutUint32(rt[8:], uint32(len(ents)))
	for i, e := range ents {
		o := 16 + 32*i
		copy(rt[o:], guidBytes(e.g))
		binary.LittleEndian.PutUint64(rt[o+16:], e.off)
		binary.LittleEndian.PutUint32(rt[o+24:], uint32(e.len))
		binary.LittleEndian.PutUint32(rt[o+28:], e.req)
	}
	putCRC(rt, 4)
	copy(f[192<<10:], rt)
	copy(f[256<<10:], rt)
	// metadata
	md := make([]byte, mib)
	copy(md, "metadata")
	type item struct {
		g     string
		data  []byte
		flags uint32
	}
	fp := make([]byte, 8)
	binary.LittleEndian.PutUint32(fp, s.blockSize)
	binary.LittleEndian.PutUint32(fp[4:], s.fpFlags)
	vs := make([]byte, 8)
	binary.LittleEndian.PutUint64(vs, s.vsize)
	l := make([]byte, 4)
	binary.LittleEndian.PutUint32(l, s.lss)
	p := make([]byte, 4)
	binary.LittleEndian.PutUint32(p, s.pss)
	items := []item{{gFilePar, fp, 4}, {gVSize, vs, 6}, {gDiskID, guidBytes(diskIDStr), 6}, {gLSS, l, 6}, {gPSS, p, 6}}
	if s.hasParent {
		binary.LittleEndian.PutUint32(fp[4:], s.fpFlags|2)
		items = append(items, item{gParent, bytes.Repeat([]byte{7}, 32), 4})
	}
	if s.extraMeta {
		items = append(items, item{gUnknown, []byte{1, 2, 3, 4}, 4})
	}
	binary.LittleEndian.PutUint16(md[10:], uint16(len(items)))
	for i, it := range items {
		o := 32 + 32*i
		dat := 65536 + 256*i
		copy(md[o:], guidBytes(it.g))
		binary.LittleEndian.PutUint32(md[o+16:], uint32(dat))
		binary.LittleEndian.PutUint32(md[o+20:], uint32(len(it.data)))
		binary.LittleEndian.PutUint32(md[o+24:], it.flags)
		copy(md[dat:], it.data)
	}
	copy(f[mib:], md)
	// BAT
	for idx, e := range entries {
		binary.LittleEndian.PutUint64(f[2*mib+idx*8:], e)
	}
	// payload
	for _, pb := range payload {
		fill := s.blocks[pb[1]].fill
		for j := uint64(0); j < uint64(s.blockSize) && pb[0]+j < uint64(len(f)); j++ {
			f[pb[0]+j] = fill
		}
	}
	return f
}

func writeTemp(t testing.TB, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "d.vhdx")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func openSpec(t *testing.T, data []byte) (Image, error) {
	t.Helper()
	return Open(writeTemp(t, data))
}

func vhdxReadAll(t *testing.T, img Image) []byte {
	t.Helper()
	buf := make([]byte, img.Size())
	n, err := img.ReadAt(buf, 0)
	if n != len(buf) || err != nil {
		t.Fatalf("ReadAt whole: n=%d err=%v", n, err)
	}
	return buf
}

// ---- positive: content, info ----

func TestVHDX_ReadsPresentZeroAndNotPresentBlocks(t *testing.T) {
	s := newSpec()
	img, err := openSpec(t, s.build())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer img.Close()
	if img.Size() != int64(s.vsize) {
		t.Fatalf("size %d want %d", img.Size(), s.vsize)
	}
	if got := vhdxReadAll(t, img); !bytes.Equal(got, s.expected()) {
		t.Fatal("decoded content differs from expected")
	}
	// straddle blocks 0|1, 2|3, and the end
	for _, c := range [][2]int64{{mib - 100, 300}, {3*mib - 7, 50}, {int64(s.vsize) - 10, 10}, {5*mib - 1, 3}} {
		buf := make([]byte, c[1])
		if n, err := img.ReadAt(buf, c[0]); n != len(buf) || err != nil {
			t.Fatalf("read %v: %d %v", c, n, err)
		}
		if !bytes.Equal(buf, s.expected()[c[0]:c[0]+c[1]]) {
			t.Fatalf("read %v mismatch", c)
		}
	}
}

func TestVHDX_Info(t *testing.T) {
	s := newSpec()
	img, err := openSpec(t, s.build())
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	in := img.Info()
	if in.Format != FormatVHDX || in.Size != int64(s.vsize) || in.SectorSize != 512 || in.Segments != 1 {
		t.Fatalf("info %+v", in)
	}
	if in.StoredMD5 != "" || in.StoredSHA1 != "" {
		t.Fatal("stored digests must be empty")
	}
	want := map[string]string{
		"vhdx_type": "dynamic", "vhdx_block_size": "1048576", "vhdx_logical_sector": "512",
		"vhdx_physical_sector": "4096", "vhdx_disk_id": strings.ToLower(diskIDStr),
		"vhdx_creator": "synthetic-builder", "vhdx_header_sequence": "4",
	}
	for k, v := range want {
		if !strings.EqualFold(in.Meta[k], v) || in.Meta[k] == "" {
			t.Errorf("meta[%s]=%q want %q", k, in.Meta[k], v)
		}
	}
}

func TestVHDX_FixedTypeAnd4KSector(t *testing.T) {
	s := newSpec()
	s.fpFlags = 1
	s.lss = 4096
	img, err := openSpec(t, s.build())
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	in := img.Info()
	if in.Meta["vhdx_type"] != "fixed" || in.SectorSize != 4096 || in.Meta["vhdx_logical_sector"] != "4096" {
		t.Fatalf("info %+v", in)
	}
}

func TestVHDX_ReadPastEnd(t *testing.T) {
	s := newSpec()
	img, err := openSpec(t, s.build())
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	buf := make([]byte, 100)
	if n, err := img.ReadAt(buf, img.Size()); n != 0 || err != io.EOF {
		t.Fatalf("at size: %d %v", n, err)
	}
	if n, err := img.ReadAt(buf, img.Size()+5000); n != 0 || err != io.EOF {
		t.Fatalf("beyond: %d %v", n, err)
	}
	n, err := img.ReadAt(buf, img.Size()-40)
	if n != 40 || err != io.EOF || !bytes.Equal(buf[:40], s.expected()[img.Size()-40:]) {
		t.Fatalf("short: %d %v", n, err)
	}
	if _, err := img.ReadAt(buf, -1); err == nil {
		t.Fatal("negative offset must fail")
	}
	if n, err := img.ReadAt(nil, 0); n != 0 || err != nil {
		t.Fatalf("empty read: %d %v", n, err)
	}
}

func TestVHDX_ConcurrentReads(t *testing.T) {
	s := newSpec()
	img, err := openSpec(t, s.build())
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	exp := s.expected()
	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(int64(g)))
			for i := 0; i < 300; i++ {
				off := r.Int63n(int64(len(exp)) - 1)
				n := 1 + r.Intn(200000)
				if int64(n) > int64(len(exp))-off {
					n = int(int64(len(exp)) - off)
				}
				buf := make([]byte, n)
				if got, err := img.ReadAt(buf, off); got != n || err != nil || !bytes.Equal(buf, exp[off:off+int64(n)]) {
					errs <- "mismatch"
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

func TestVHDX_ManyBlocksWithSectorBitmapInterleave(t *testing.T) {
	// 4096-byte logical sectors and 256 MiB blocks would make the ratio 1<<7; use lss 512 and
	// a 1 MiB block so ratio = 8; 20 blocks need bitmap entries after blocks 8 and 16.
	s := newSpec()
	s.lss = 512
	// ratio = 2^23*512/2^20 = 4096; to exercise interleave use block 8 MiB? Instead use lss/bs where
	// ratio is small: block 256 MiB, lss 512 -> ratio 16. File stays small because blocks are not present.
	s.blockSize = 256 * mib
	s.vsize = 40 * 256 * mib
	s.blocks = make([]vblk, 40)
	s.blocks[17] = vblk{state: 2}
	data := s.build()
	img, err := openSpec(t, data)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer img.Close()
	buf := make([]byte, 4096)
	for _, off := range []int64{0, 16*256*mib - 2048, 17 * 256 * mib, 39*256*mib + 100} {
		if n, err := img.ReadAt(buf, off); n != len(buf) || err != nil || !bytes.Equal(buf, make([]byte, len(buf))) {
			t.Fatalf("off %d: %d %v", off, n, err)
		}
	}
}

// A present block after the first bitmap entry must be found at i + i/ratio, not at i.
func TestVHDX_PresentBlockAfterSectorBitmapEntry(t *testing.T) {
	s := newSpec()
	s.blockSize = 256 * mib    // ratio 16 with 512-byte sectors
	s.vsize = 16*256*mib + mib // block 16 is the short last block, 1 MiB, so the file stays small
	s.blocks = make([]vblk, 17)
	s.blocks[16] = vblk{state: 6, fill: 0x5A}
	data := s.build()
	// payload block 16 lives at BAT index 17 (a bitmap entry sits at index 16)
	if st := binary.LittleEndian.Uint64(data[2*mib+17*8:]); st&7 != 6 {
		t.Fatalf("builder: BAT[17]=%x", st)
	}
	img, err := openSpec(t, data)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer img.Close()
	buf := make([]byte, 64)
	if _, err := img.ReadAt(buf, 16*256*mib+1000); err != nil || !bytes.Equal(buf, bytes.Repeat([]byte{0x5A}, 64)) {
		t.Fatalf("block 16: %v %x", err, buf[:4])
	}
	if _, err := img.ReadAt(buf, 15*256*mib+1000); err != nil || !bytes.Equal(buf, make([]byte, 64)) {
		t.Fatalf("block 15: %v", err)
	}
}

// ---- headers ----

func TestVHDX_HigherSequenceHeaderWins(t *testing.T) {
	s := newSpec()
	s.seq1, s.seq2 = 10, 11
	img, err := openSpec(t, s.build())
	if err != nil {
		t.Fatal(err)
	}
	if img.Info().Meta["vhdx_header_sequence"] != "11" {
		t.Fatalf("seq %q", img.Info().Meta["vhdx_header_sequence"])
	}
	img.Close()
	s.seq1, s.seq2 = 12, 11
	img, err = openSpec(t, s.build())
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	if img.Info().Meta["vhdx_header_sequence"] != "12" {
		t.Fatalf("seq %q", img.Info().Meta["vhdx_header_sequence"])
	}
}

func TestVHDX_HeaderWithBadChecksumIsIgnored(t *testing.T) {
	s := newSpec() // header 2 (seq 4) is the higher one
	d := s.build()
	d[128<<10+100] ^= 0xFF // damage header 2 body
	img, err := openSpec(t, d)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer img.Close()
	if img.Info().Meta["vhdx_header_sequence"] != "3" {
		t.Fatalf("used seq %q, want the intact header's 3", img.Info().Meta["vhdx_header_sequence"])
	}
}

func TestVHDX_BothHeadersBadIsCorrupt(t *testing.T) {
	d := newSpec().build()
	d[64<<10+100] ^= 0xFF
	d[128<<10+100] ^= 0xFF
	if _, err := openSpec(t, d); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err %v", err)
	}
}

func TestVHDX_NonZeroLogGUIDNeedsReplay(t *testing.T) {
	s := newSpec()
	s.log2[3] = 9
	_, err := openSpec(t, s.build())
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("err %v", err)
	}
}

func TestVHDX_LogGUIDOfIgnoredHeaderDoesNotMatter(t *testing.T) {
	s := newSpec()
	s.log1[3] = 9 // header 1 is the older one
	img, err := openSpec(t, s.build())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	img.Close()
}

func TestVHDX_UnknownVersionUnsupported(t *testing.T) {
	s := newSpec()
	s.version = 2
	if _, err := openSpec(t, s.build()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err %v", err)
	}
}

// ---- region table ----

func TestVHDX_RegionTableFallsBackToCopy(t *testing.T) {
	d := newSpec().build()
	d[192<<10+40] ^= 0xFF
	img, err := openSpec(t, d)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	img.Close()
}

func TestVHDX_BothRegionTablesBadIsCorrupt(t *testing.T) {
	d := newSpec().build()
	d[192<<10+40] ^= 0xFF
	d[256<<10+40] ^= 0xFF
	if _, err := openSpec(t, d); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err %v", err)
	}
}

func TestVHDX_UnknownRequiredRegionUnsupported(t *testing.T) {
	s := newSpec()
	s.extraRegion = true
	_, err := openSpec(t, s.build())
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err %v", err)
	}
}

func TestVHDX_UnknownOptionalRegionIgnored(t *testing.T) {
	s := newSpec()
	s.extraOpt = true
	img, err := openSpec(t, s.build())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	img.Close()
}

func TestVHDX_UnknownRequiredMetadataItemUnsupported(t *testing.T) {
	s := newSpec()
	s.extraMeta = true
	if _, err := openSpec(t, s.build()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err %v", err)
	}
}

// ---- parameters ----

func TestVHDX_HasParentUnsupported(t *testing.T) {
	s := newSpec()
	s.hasParent = true
	_, err := openSpec(t, s.build())
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "parent") {
		t.Fatalf("err %v", err)
	}
}

func TestVHDX_BadBlockSizeIsCorrupt(t *testing.T) {
	for _, bs := range []uint32{0, 3 * mib, mib + 512, mib / 2, 512 * mib, 1 << 31} {
		s := newSpec()
		s.blockSize = bs
		s.vsize = 4 * mib
		s.blocks = nil
		if _, err := openSpec(t, s.build()); !errors.Is(err, ErrCorrupt) {
			t.Errorf("block size %d: err %v", bs, err)
		}
	}
}

func TestVHDX_BadVirtualSizeIsCorrupt(t *testing.T) {
	for _, vs := range []uint64{0, 1 << 47, 1<<64 - 1, 5*mib + 100 /* not a multiple of the sector size */} {
		s := newSpec()
		s.vsize = vs
		s.blocks = nil
		if _, err := openSpec(t, s.build()); !errors.Is(err, ErrCorrupt) {
			t.Errorf("virtual size %d: err %v", vs, err)
		}
	}
}

func TestVHDX_BadSectorSizeIsCorrupt(t *testing.T) {
	for _, ls := range []uint32{0, 256, 1024, 8192} {
		s := newSpec()
		s.lss = ls
		if _, err := openSpec(t, s.build()); !errors.Is(err, ErrCorrupt) {
			t.Errorf("logical sector %d: err %v", ls, err)
		}
	}
}

// ---- BAT ----

func TestVHDX_BATEntryPastEndOfFileIsCorrupt(t *testing.T) {
	s := newSpec()
	s.blocks[3].raw = 6 | uint64(500)<<20
	_, err := openSpec(t, s.build())
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err %v", err)
	}
}

func TestVHDX_BATEntryOverflowingOffsetIsCorrupt(t *testing.T) {
	s := newSpec()
	s.blocks[0].raw = 6 | (uint64(1)<<44-1)<<20
	if _, err := openSpec(t, s.build()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err %v", err)
	}
}

func TestVHDX_BATEntryInsideHeaderRegionIsCorrupt(t *testing.T) {
	s := newSpec()
	s.blocks[0].raw = 6 // offset 0: would read the file identifier as disk data
	if _, err := openSpec(t, s.build()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err %v", err)
	}
}

func TestVHDX_PartiallyPresentUnsupported(t *testing.T) {
	s := newSpec()
	s.blocks[1] = vblk{raw: 7 | uint64(3)<<20}
	_, err := openSpec(t, s.build())
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "parent") {
		t.Fatalf("err %v", err)
	}
}

func TestVHDX_ReservedBATStateIsCorrupt(t *testing.T) {
	s := newSpec()
	s.blocks[1] = vblk{raw: 4}
	if _, err := openSpec(t, s.build()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err %v", err)
	}
}

func TestVHDX_BATTooSmallForDiskIsCorrupt(t *testing.T) {
	s := newSpec()
	s.blockSize = mib
	s.vsize = 200000 * mib // needs far more BAT entries than the 1 MiB region holds
	s.blocks = nil
	if _, err := openSpec(t, s.build()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err %v", err)
	}
}

func TestVHDX_TruncatedIsCorrupt(t *testing.T) {
	d := newSpec().build()
	for _, n := range []int{0, 7, 100, 64 << 10, 200 << 10, mib + 100, 2*mib + 100, 5*mib + 1000, 4*mib + 10} {
		if n > len(d) {
			continue
		}
		_, err := openSpec(t, d[:n])
		if n < 8 {
			continue // too short to be recognised as VHDX at all (opened as raw or rejected as empty)
		}
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("truncated to %d: err %v", n, err)
		}
	}
}

// ---- hostile input ----

func TestVHDX_RandomCorruptionNeverPanics(t *testing.T) {
	base := newSpec().build()
	p := writeTemp(t, base)
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := rand.New(rand.NewSource(20260101))
	hot := [][2]int{{0, 600}, {64 << 10, 4096}, {128 << 10, 4096}, {192 << 10, 160}, {256 << 10, 160}, {mib, 600}, {mib + 65536, 1300}, {2 * mib, 64}}
	var opened, rejected int
	for i := 0; i < 2000; i++ {
		type edit struct {
			off int64
			old []byte
		}
		var undo []edit
		for k := 0; k < 1+r.Intn(4); k++ {
			var off int64
			if r.Intn(10) < 8 {
				h := hot[r.Intn(len(hot))]
				off = int64(h[0] + r.Intn(h[1]))
			} else {
				off = r.Int63n(int64(len(base)))
			}
			old := make([]byte, 1+r.Intn(8))
			n, _ := f.ReadAt(old, off)
			old = old[:n]
			nb := make([]byte, n)
			r.Read(nb)
			f.WriteAt(nb, off)
			undo = append(undo, edit{off, old})
		}
		func() {
			defer func() {
				if x := recover(); x != nil {
					t.Fatalf("iteration %d panicked: %v", i, x)
				}
			}()
			img, err := openVHDX([]string{p})
			if err != nil {
				rejected++
				return
			}
			opened++
			buf := make([]byte, 64<<10)
			sz := img.Size()
			for _, off := range []int64{0, mib - 100, 3*mib - 5, sz - 1000, sz / 2} {
				if off < 0 {
					continue
				}
				img.ReadAt(buf, off)
			}
			img.Close()
		}()
		for j := len(undo) - 1; j >= 0; j-- {
			f.WriteAt(undo[j].old, undo[j].off)
		}
	}
	t.Logf("2000 corruptions: %d still opened, %d rejected", opened, rejected)
	if rejected == 0 || opened == 0 {
		t.Fatalf("harness not exercising the parser: opened=%d rejected=%d", opened, rejected)
	}
}
