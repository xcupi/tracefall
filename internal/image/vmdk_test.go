package image

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func mkfifo(p string) error { return syscall.Mkfifo(p, 0o644) }

func timeAfter() <-chan time.Time { return time.After(5 * time.Second) }

// ---- builders: write VMDK files from the documented layout, independent of
// the reader. Sector = 512 bytes.

const vsec = 512

type vmdkSpec struct {
	capSectors uint64
	grain      uint64 // sectors per grain, default 8
	desc       string
	unclean    bool
	grains     map[int][]byte // allocated grains: index -> exactly grain bytes
	zero       map[int]bool   // grains stored as "zeroed" (table entry 1)
	shortLen   map[int]int    // stream: compress only this many bytes of the grain
}

type vmdkBuilt struct {
	b           []byte
	gdSector    int
	rgdSector   int
	gtSector    []int
	grainSector map[int]int
}

func (s *vmdkSpec) g() uint64 {
	if s.grain == 0 {
		return 8
	}
	return s.grain
}

func (s *vmdkSpec) nGrains() int { return int((s.capSectors + s.g() - 1) / s.g()) }

func vmdkHeader(s *vmdkSpec, descOff, descSz, rgd, gd, overhead uint64, flags uint32, comp uint16, ver uint32) []byte {
	h := make([]byte, vsec)
	copy(h, "KDMV")
	le := binary.LittleEndian
	le.PutUint32(h[4:], ver)
	le.PutUint32(h[8:], flags)
	le.PutUint64(h[12:], s.capSectors)
	le.PutUint64(h[20:], s.g())
	le.PutUint64(h[28:], descOff)
	le.PutUint64(h[36:], descSz)
	le.PutUint32(h[44:], 512)
	le.PutUint64(h[48:], rgd)
	le.PutUint64(h[56:], gd)
	le.PutUint64(h[64:], overhead)
	if s.unclean {
		h[72] = 1
	}
	h[73], h[74], h[75], h[76] = '\n', ' ', '\r', '\n'
	le.PutUint16(h[77:], comp)
	return h
}

func padSector(b []byte) []byte {
	if r := len(b) % vsec; r != 0 {
		b = append(b, make([]byte, vsec-r)...)
	}
	return b
}

func descBlock(desc string) []byte {
	d := make([]byte, 20*vsec)
	copy(d, desc)
	return d
}

// buildSparseVMDK writes a hosted sparse extent with a redundant and a primary
// grain directory.
func buildSparseVMDK(s vmdkSpec) vmdkBuilt {
	ng := s.nGrains()
	nt := (ng + 511) / 512
	out := vmdkBuilt{grainSector: map[int]int{}}
	b := make([]byte, vsec)
	var descSz uint64
	b = append(b, descBlock(s.desc)...) // the descriptor area is reserved even when empty
	if s.desc != "" {
		descSz = 20
	}
	entries := make([]uint32, nt*512)
	for i := 0; i < ng; i++ {
		if d, ok := s.grains[i]; ok {
			if len(d) != int(s.g())*vsec {
				panic("bad grain length in builder")
			}
			entries[i] = uint32(len(b) / vsec)
			out.grainSector[i] = len(b) / vsec
			b = append(b, d...)
		} else if s.zero[i] {
			entries[i] = 1
		}
	}
	addDir := func(record bool) int {
		gd := make([]byte, nt*4)
		for t := 0; t < nt; t++ {
			empty := true
			raw := make([]byte, 2048)
			for k := 0; k < 512; k++ {
				v := entries[t*512+k]
				if v != 0 {
					empty = false
				}
				binary.LittleEndian.PutUint32(raw[k*4:], v)
			}
			if empty {
				continue
			}
			sec := len(b) / vsec
			if record {
				for len(out.gtSector) <= t {
					out.gtSector = append(out.gtSector, 0)
				}
				out.gtSector[t] = sec
			}
			binary.LittleEndian.PutUint32(gd[t*4:], uint32(sec))
			b = append(b, raw...)
		}
		sec := len(b) / vsec
		b = append(b, padSector(gd)...)
		return sec
	}
	out.rgdSector = addDir(false)
	out.gdSector = addDir(true)
	copy(b, vmdkHeader(&s, 1, descSz, uint64(out.rgdSector), uint64(out.gdSector), uint64(out.rgdSector), 3, 0, 1))
	if s.desc == "" {
		binary.LittleEndian.PutUint64(b[28:], 0)
	}
	out.b = b
	return out
}

func vmdkMarker(val uint64, size, typ uint32) []byte {
	m := make([]byte, vsec)
	binary.LittleEndian.PutUint64(m, val)
	binary.LittleEndian.PutUint32(m[8:], size)
	binary.LittleEndian.PutUint32(m[12:], typ)
	return m
}

// buildStreamVMDK writes a stream-optimized extent with deflate grains. With
// footer, the leading header carries gdOffset = -1 and the real header is in
// the footer.
func buildStreamVMDK(s vmdkSpec, footer bool) vmdkBuilt {
	ng := s.nGrains()
	nt := (ng + 511) / 512
	out := vmdkBuilt{grainSector: map[int]int{}}
	b := make([]byte, vsec)
	var descSz uint64
	b = append(b, descBlock(s.desc)...) // the descriptor area is reserved even when empty
	if s.desc != "" {
		descSz = 20
	}
	entries := make([]uint32, nt*512)
	for i := 0; i < ng; i++ {
		d, ok := s.grains[i]
		if !ok {
			if s.zero[i] {
				entries[i] = 1
			}
			continue
		}
		src := d
		if n, ok := s.shortLen[i]; ok {
			src = d[:n]
		}
		var zb bytes.Buffer
		zw := zlib.NewWriter(&zb)
		zw.Write(src)
		zw.Close()
		rec := make([]byte, 12)
		binary.LittleEndian.PutUint64(rec, uint64(i)*s.g())
		binary.LittleEndian.PutUint32(rec[8:], uint32(zb.Len()))
		rec = append(rec, zb.Bytes()...)
		entries[i] = uint32(len(b) / vsec)
		out.grainSector[i] = len(b) / vsec
		b = append(b, padSector(rec)...)
	}
	gd := make([]byte, nt*4)
	for t := 0; t < nt; t++ {
		empty := true
		raw := make([]byte, 2048)
		for k := 0; k < 512; k++ {
			v := entries[t*512+k]
			if v != 0 {
				empty = false
			}
			binary.LittleEndian.PutUint32(raw[k*4:], v)
		}
		if empty {
			continue
		}
		b = append(b, vmdkMarker(4, 0, 1)...)
		sec := len(b) / vsec
		for len(out.gtSector) <= t {
			out.gtSector = append(out.gtSector, 0)
		}
		out.gtSector[t] = sec
		binary.LittleEndian.PutUint32(gd[t*4:], uint32(sec))
		b = append(b, raw...)
	}
	gdPad := padSector(gd)
	b = append(b, vmdkMarker(uint64(len(gdPad)/vsec), 0, 2)...)
	out.gdSector = len(b) / vsec
	b = append(b, gdPad...)
	flags := uint32(1 | 1<<16 | 1<<17)
	first := out.gdSector
	if footer {
		b = append(b, vmdkMarker(1, 0, 3)...)
		b = append(b, vmdkHeader(&s, 1, descSz, 0, uint64(out.gdSector), 128, flags, 1, 3)...)
		first = -1
	}
	b = append(b, vmdkMarker(0, 0, 0)...)
	gdv := uint64(first)
	if first < 0 {
		gdv = ^uint64(0)
	}
	copy(b, vmdkHeader(&s, 1, descSz, 0, gdv, 128, flags, 1, 3))
	if s.desc == "" {
		binary.LittleEndian.PutUint64(b[28:], 0)
	}
	out.b = b
	return out
}

func descText(createType, parent string, extents []string, ddb ...string) string {
	var sb strings.Builder
	sb.WriteString("# Disk DescriptorFile\nversion=1\nCID=a1b2c3d4\n")
	fmt.Fprintf(&sb, "parentCID=%s\ncreateType=\"%s\"\n\n# Extent description\n", parent, createType)
	for _, e := range extents {
		sb.WriteString(e + "\n")
	}
	sb.WriteString("\n# The Disk Data Base\n#DDB\n\n")
	for _, d := range ddb {
		sb.WriteString(d + "\n")
	}
	return sb.String()
}

var stdDDB = []string{`ddb.adapterType = "lsilogic"`, `ddb.uuid = "60 00 C2 99 aa bb cc dd-11 22 33 44 55 66 77 88"`, `ddb.geometry.cylinders = "4"`}

func grainData(seed int, grainSectors uint64) []byte {
	r := rand.New(rand.NewSource(int64(seed) + 1000))
	d := make([]byte, int(grainSectors)*vsec)
	r.Read(d)
	d[0] |= 1 // never all zero
	return d
}

// expected disk image for a spec
func (s *vmdkSpec) expected() []byte {
	out := make([]byte, s.capSectors*vsec)
	gb := int(s.g()) * vsec
	for i, d := range s.grains {
		copy(out[i*gb:], d)
	}
	return out
}

func vmdkWriteTemp(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func le32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
func le64(b []byte, off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }

func multiGTSpec() vmdkSpec {
	// 600 grains of 4 KiB: two grain tables. Grain 0, 5, 511 (last of GT0),
	// 512 (first of GT1) and 599 (last) hold data; 6 is a zeroed grain.
	s := vmdkSpec{capSectors: 600 * 8, grains: map[int][]byte{}, zero: map[int]bool{6: true}}
	for _, i := range []int{0, 5, 511, 512, 599} {
		s.grains[i] = grainData(i, 8)
	}
	s.desc = descText("monolithicSparse", "ffffffff", []string{`RW 4800 SPARSE "disk.vmdk"`}, stdDDB...)
	return s
}

func mustOpen(t *testing.T, paths ...string) Image {
	t.Helper()
	img, err := Open(paths...)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { img.Close() })
	return img
}

func wantErr(t *testing.T, err, target error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error wrapping %v, got success", target)
	}
	if !errors.Is(err, target) {
		t.Fatalf("expected an error wrapping %v, got: %v", target, err)
	}
}

// ---- sparse extent

func TestVMDK_SparseReadsAllocatedZeroedAndUnallocatedGrains(t *testing.T) {
	s := multiGTSpec()
	built := buildSparseVMDK(s)
	p := vmdkWriteTemp(t, t.TempDir(), "disk.vmdk", built.b)
	img := mustOpen(t, p)
	in := img.Info()
	if in.Format != FormatVMDK || in.Size != int64(s.capSectors*vsec) || in.SectorSize != 512 || in.Segments != 1 {
		t.Fatalf("Info = %+v", in)
	}
	if in.StoredMD5 != "" || in.StoredSHA1 != "" {
		t.Fatalf("stored digests must stay empty: %+v", in)
	}
	for k, want := range map[string]string{
		"vmdk_create_type": "monolithicSparse", "vmdk_cid": "a1b2c3d4", "vmdk_parent_cid": "ffffffff",
		"vmdk_uuid": "60 00 C2 99 aa bb cc dd-11 22 33 44 55 66 77 88", "vmdk_adapter_type": "lsilogic",
		"vmdk_unclean_shutdown": "false",
	} {
		if in.Meta[k] != want {
			t.Errorf("Meta[%s] = %q, want %q", k, in.Meta[k], want)
		}
	}
	if img.Size() != in.Size {
		t.Fatalf("Size() = %d", img.Size())
	}
	got := readAll(t, img)
	if !bytes.Equal(got, s.expected()) {
		t.Fatal("decoded bytes differ from the expected disk")
	}
}

func TestVMDK_SparseReadsStraddleGrainsAndHonourEOF(t *testing.T) {
	s := multiGTSpec()
	p := vmdkWriteTemp(t, t.TempDir(), "disk.vmdk", buildSparseVMDK(s).b)
	img := mustOpen(t, p)
	want := s.expected()
	// straddles grain 5/6/7 (allocated, zeroed, unallocated) and the GT0/GT1 boundary
	for _, c := range []struct{ off, n int }{{5*4096 - 100, 9000}, {512*4096 - 50, 200}, {4096*599 + 4000, 96}, {0, 1}, {len(want) - 1, 1}} {
		buf := make([]byte, c.n)
		n, err := img.ReadAt(buf, int64(c.off))
		if n != c.n || err != nil {
			t.Fatalf("ReadAt(%d,%d) = %d, %v", c.off, c.n, n, err)
		}
		if !bytes.Equal(buf, want[c.off:c.off+c.n]) {
			t.Fatalf("ReadAt(%d,%d) returned the wrong bytes", c.off, c.n)
		}
	}
	buf := make([]byte, 100)
	n, err := img.ReadAt(buf, int64(len(want)-40))
	if n != 40 || err != io.EOF || !bytes.Equal(buf[:40], want[len(want)-40:]) {
		t.Fatalf("read across the end: n=%d err=%v", n, err)
	}
	if n, err := img.ReadAt(buf, int64(len(want))); n != 0 || err != io.EOF {
		t.Fatalf("read at Size: n=%d err=%v", n, err)
	}
	if n, err := img.ReadAt(buf, int64(len(want))+99); n != 0 || err != io.EOF {
		t.Fatalf("read past Size: n=%d err=%v", n, err)
	}
	if _, err := img.ReadAt(buf, -1); err == nil {
		t.Fatal("negative offset must fail")
	}
	if n, err := img.ReadAt(nil, 0); n != 0 || err != nil {
		t.Fatalf("empty read: %d %v", n, err)
	}
}

func TestVMDK_SparseDirectoryEntryZeroMeansUnallocatedTable(t *testing.T) {
	s := vmdkSpec{capSectors: 600 * 8, grains: map[int][]byte{3: grainData(3, 8)}}
	built := buildSparseVMDK(s)
	if len(built.gtSector) != 1 {
		t.Fatalf("builder wrote %d tables", len(built.gtSector))
	}
	img := mustOpen(t, vmdkWriteTemp(t, t.TempDir(), "d.vmdk", built.b))
	if !bytes.Equal(readAll(t, img), s.expected()) {
		t.Fatal("bytes differ")
	}
	if img.Info().Meta["vmdk_create_type"] != "" {
		t.Fatal("no descriptor: create type must not be invented")
	}
}

func TestVMDK_SparseLargerGrainSize(t *testing.T) {
	s := vmdkSpec{capSectors: 4096, grain: 128, grains: map[int][]byte{0: grainData(0, 128), 31: grainData(31, 128)}}
	img := mustOpen(t, vmdkWriteTemp(t, t.TempDir(), "d.vmdk", buildSparseVMDK(s).b))
	if !bytes.Equal(readAll(t, img), s.expected()) {
		t.Fatal("bytes differ")
	}
}

func TestVMDK_SparseCapacityNotMultipleOfGrain(t *testing.T) {
	s := vmdkSpec{capSectors: 20, grains: map[int][]byte{2: grainData(2, 8)}}
	img := mustOpen(t, vmdkWriteTemp(t, t.TempDir(), "d.vmdk", buildSparseVMDK(s).b))
	if img.Size() != 20*512 {
		t.Fatalf("Size = %d", img.Size())
	}
	got := readAll(t, img)
	want := s.expected()
	copy(want[16*512:], grainData(2, 8)[:4*512]) // only the 4 sectors inside the capacity
	if !bytes.Equal(got, want) {
		t.Fatal("last partial grain wrong")
	}
}

func TestVMDK_SparseUncleanShutdownIsReadAndFlagged(t *testing.T) {
	s := multiGTSpec()
	s.unclean = true
	img := mustOpen(t, vmdkWriteTemp(t, t.TempDir(), "d.vmdk", buildSparseVMDK(s).b))
	if img.Info().Meta["vmdk_unclean_shutdown"] != "true" {
		t.Fatalf("Meta = %v", img.Info().Meta)
	}
	if !bytes.Equal(readAll(t, img), s.expected()) {
		t.Fatal("an unclean image must still be read")
	}
}

func TestVMDK_ConcurrentReadsAreSafe(t *testing.T) {
	s := multiGTSpec()
	img := mustOpen(t, vmdkWriteTemp(t, t.TempDir(), "d.vmdk", buildSparseVMDK(s).b))
	want := s.expected()
	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(int64(g)))
			for i := 0; i < 300; i++ {
				off := r.Intn(len(want) - 10000)
				buf := make([]byte, 1+r.Intn(9000))
				if _, err := img.ReadAt(buf, int64(off)); err != nil || !bytes.Equal(buf, want[off:off+len(buf)]) {
					errs <- fmt.Sprintf("goroutine %d off %d: %v", g, off, err)
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

func TestVMDK_GrainTableCacheIsBounded(t *testing.T) {
	// 200 grain tables (200*512 grains), one allocated grain in each.
	const tables = 200
	s := vmdkSpec{capSectors: uint64(tables * 512 * 8), grains: map[int][]byte{}}
	for tb := 0; tb < tables; tb++ {
		s.grains[tb*512+7] = grainData(tb, 8)
	}
	img := mustOpen(t, vmdkWriteTemp(t, t.TempDir(), "d.vmdk", buildSparseVMDK(s).b))
	for tb := 0; tb < tables; tb++ {
		buf := make([]byte, 4096)
		off := int64(tb*512+7) * 4096
		if _, err := img.ReadAt(buf, off); err != nil || !bytes.Equal(buf, s.grains[tb*512+7]) {
			t.Fatalf("table %d: %v", tb, err)
		}
	}
	sp := img.(*vmdkImage).extents[0].(*sparseExtent)
	if n := sp.gtCacheLen(); n == 0 || n > vmdkGTCacheMax {
		t.Fatalf("grain table cache holds %d tables, limit %d", n, vmdkGTCacheMax)
	}
}

// ---- header and structure failures

func TestVMDK_BadMagicWithKDMVLikeText(t *testing.T) {
	data := append([]byte("kdmv sparse extent but not really"), make([]byte, 2048)...)
	p := vmdkWriteTemp(t, t.TempDir(), "d.vmdk", data)
	_, err := openVMDK([]string{p})
	wantErr(t, err, ErrCorrupt)
}

func TestVMDK_HeaderValuesAreValidated(t *testing.T) {
	base := func() []byte { return buildSparseVMDK(multiGTSpec()).b }
	cases := []struct {
		name string
		mut  func(b []byte)
		want error
	}{
		{"grain size not a power of two", func(b []byte) { le64(b, 20, 12) }, ErrCorrupt},
		{"grain size below 8 sectors", func(b []byte) { le64(b, 20, 4) }, ErrCorrupt},
		{"grain size absurd", func(b []byte) { le64(b, 20, 1<<40) }, ErrCorrupt},
		{"capacity zero", func(b []byte) { le64(b, 12, 0) }, ErrCorrupt},
		{"capacity absurd", func(b []byte) { le64(b, 12, 1<<50) }, ErrCorrupt},
		{"grain table entries not 512", func(b []byte) { le32(b, 44, 1024) }, ErrCorrupt},
		{"line ending bytes damaged", func(b []byte) { b[73] = 'x' }, ErrCorrupt},
		{"directory beyond the file", func(b []byte) { le64(b, 56, 1<<30) }, ErrCorrupt},
		{"directory offset zero", func(b []byte) { le64(b, 56, 0) }, ErrCorrupt},
		{"directory offset overflows", func(b []byte) { le64(b, 56, ^uint64(0)-3) }, ErrCorrupt},
		{"descriptor size oversized", func(b []byte) { le64(b, 36, 1<<20) }, ErrCorrupt},
		{"descriptor beyond the file", func(b []byte) { le64(b, 28, 1<<30) }, ErrCorrupt},
		{"unknown compression", func(b []byte) { binary.LittleEndian.PutUint16(b[77:], 7); le32(b, 8, 3|1<<16) }, ErrUnsupported},
		{"unknown version", func(b []byte) { le32(b, 4, 9) }, ErrUnsupported},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := base()
			c.mut(b)
			p := vmdkWriteTemp(t, t.TempDir(), "d.vmdk", b)
			img, err := Open(p)
			if err == nil {
				img.Close()
			}
			wantErr(t, err, c.want)
		})
	}
}

func TestVMDK_GrainTableAndGrainPastTheEndAreCorrupt(t *testing.T) {
	s := multiGTSpec()
	t.Run("directory entry past the end", func(t *testing.T) {
		built := buildSparseVMDK(s)
		le32(built.b, built.gdSector*vsec, 0x7fffff00)
		img := mustOpen(t, vmdkWriteTemp(t, t.TempDir(), "d.vmdk", built.b))
		buf := make([]byte, 4096)
		_, err := img.ReadAt(buf, 0)
		wantErr(t, err, ErrCorrupt)
	})
	t.Run("table entry past the end", func(t *testing.T) {
		built := buildSparseVMDK(s)
		le32(built.b, built.gtSector[0]*vsec, 0x7fffff00)
		img := mustOpen(t, vmdkWriteTemp(t, t.TempDir(), "d.vmdk", built.b))
		buf := make([]byte, 4096)
		_, err := img.ReadAt(buf, 0)
		wantErr(t, err, ErrCorrupt)
	})
	t.Run("grain truncated by the end of the file", func(t *testing.T) {
		built := buildSparseVMDK(s)
		le32(built.b, built.gtSector[0]*vsec, uint32(len(built.b)/vsec)-1)
		img := mustOpen(t, vmdkWriteTemp(t, t.TempDir(), "d.vmdk", built.b))
		buf := make([]byte, 4096)
		_, err := img.ReadAt(buf, 0)
		wantErr(t, err, ErrCorrupt)
	})
	t.Run("table entry 0xFFFFFFFF", func(t *testing.T) {
		built := buildSparseVMDK(s)
		le32(built.b, built.gtSector[0]*vsec+4*3, 0xFFFFFFFF) // grain 3
		img := mustOpen(t, vmdkWriteTemp(t, t.TempDir(), "d.vmdk", built.b))
		_, err := img.ReadAt(make([]byte, 16), 3*4096)
		wantErr(t, err, ErrCorrupt)
	})
}

// ---- stream optimized

func streamSpec() vmdkSpec {
	s := vmdkSpec{capSectors: 600 * 8, grains: map[int][]byte{}, zero: map[int]bool{6: true}}
	for _, i := range []int{0, 5, 511, 512, 599} {
		s.grains[i] = grainData(i, 8)
	}
	s.grains[7] = make([]byte, 4096) // compresses to almost nothing
	s.desc = descText("streamOptimized", "ffffffff", []string{`RW 4800 SPARSE "stream.vmdk"`}, stdDDB...)
	return s
}

func TestVMDK_StreamOptimizedCompressedGrains(t *testing.T) {
	for _, footer := range []bool{false, true} {
		t.Run(fmt.Sprintf("footer=%v", footer), func(t *testing.T) {
			s := streamSpec()
			built := buildStreamVMDK(s, footer)
			img := mustOpen(t, vmdkWriteTemp(t, t.TempDir(), "s.vmdk", built.b))
			in := img.Info()
			if in.Format != FormatVMDK || in.Size != 4800*512 || in.Meta["vmdk_create_type"] != "streamOptimized" {
				t.Fatalf("Info = %+v", in)
			}
			if !bytes.Equal(readAll(t, img), s.expected()) {
				t.Fatal("decoded bytes differ")
			}
			// repeated small reads inside one compressed grain
			buf := make([]byte, 100)
			for off := 5*4096 + 10; off < 5*4096+4000; off += 777 {
				if _, err := img.ReadAt(buf, int64(off)); err != nil || !bytes.Equal(buf, s.grains[5][off-5*4096:off-5*4096+100]) {
					t.Fatalf("small read at %d: %v", off, err)
				}
			}
		})
	}
}

func TestVMDK_StreamOptimizedDamageIsCorrupt(t *testing.T) {
	t.Run("decompressed length differs from the grain size", func(t *testing.T) {
		s := streamSpec()
		s.shortLen = map[int]int{5: 1000}
		img := mustOpen(t, vmdkWriteTemp(t, t.TempDir(), "s.vmdk", buildStreamVMDK(s, true).b))
		_, err := img.ReadAt(make([]byte, 4096), 5*4096)
		wantErr(t, err, ErrCorrupt)
	})
	t.Run("marker LBA is not the grain's own", func(t *testing.T) {
		s := streamSpec()
		built := buildStreamVMDK(s, true)
		le64(built.b, built.grainSector[5]*vsec, 9*8)
		img := mustOpen(t, vmdkWriteTemp(t, t.TempDir(), "s.vmdk", built.b))
		_, err := img.ReadAt(make([]byte, 4096), 5*4096)
		wantErr(t, err, ErrCorrupt)
	})
	t.Run("compressed size larger than the file", func(t *testing.T) {
		s := streamSpec()
		built := buildStreamVMDK(s, true)
		le32(built.b, built.grainSector[5]*vsec+8, 0x40000000)
		img := mustOpen(t, vmdkWriteTemp(t, t.TempDir(), "s.vmdk", built.b))
		_, err := img.ReadAt(make([]byte, 4096), 5*4096)
		wantErr(t, err, ErrCorrupt)
	})
	t.Run("deflate data damaged", func(t *testing.T) {
		s := streamSpec()
		built := buildStreamVMDK(s, true)
		for i := 0; i < 40; i++ {
			built.b[built.grainSector[5]*vsec+14+i] ^= 0x5a
		}
		img := mustOpen(t, vmdkWriteTemp(t, t.TempDir(), "s.vmdk", built.b))
		_, err := img.ReadAt(make([]byte, 4096), 5*4096)
		wantErr(t, err, ErrCorrupt)
	})
	t.Run("grain points at a metadata marker", func(t *testing.T) {
		s := streamSpec()
		built := buildStreamVMDK(s, true)
		le32(built.b, built.gtSector[0]*vsec+4*5, uint32(built.gtSector[0]-1)) // the GT marker sector
		img := mustOpen(t, vmdkWriteTemp(t, t.TempDir(), "s.vmdk", built.b))
		_, err := img.ReadAt(make([]byte, 4096), 5*4096)
		wantErr(t, err, ErrCorrupt)
	})
	t.Run("footer missing", func(t *testing.T) {
		s := streamSpec()
		built := buildStreamVMDK(s, true)
		b := built.b[:len(built.b)-1024] // drop footer header + end-of-stream
		img, err := Open(vmdkWriteTemp(t, t.TempDir(), "s.vmdk", b))
		if err == nil {
			img.Close()
		}
		wantErr(t, err, ErrCorrupt)
	})
	t.Run("footer disagrees with the leading header", func(t *testing.T) {
		s := streamSpec()
		built := buildStreamVMDK(s, true)
		le64(built.b, len(built.b)-1024+12, 9999*8) // footer capacity
		img, err := Open(vmdkWriteTemp(t, t.TempDir(), "s.vmdk", built.b))
		if err == nil {
			img.Close()
		}
		wantErr(t, err, ErrCorrupt)
	})
}

// ---- descriptor based disks

func flatExtentDisk(t *testing.T, dir string) (descPath string, want []byte) {
	t.Helper()
	a := bytes.Repeat([]byte("A"), 8*vsec)
	b := make([]byte, 16*vsec)
	rand.New(rand.NewSource(7)).Read(b)
	vmdkWriteTemp(t, dir, "d-f001.vmdk", a)
	vmdkWriteTemp(t, dir, "d-f002.vmdk", b)
	desc := descText("twoGbMaxExtentFlat", "ffffffff",
		[]string{`RW 8 FLAT "d-f001.vmdk" 0`, `RW 16 FLAT "d-f002.vmdk" 0`}, stdDDB...)
	return vmdkWriteTemp(t, dir, "d.vmdk", []byte(desc)), append(append([]byte{}, a...), b...)
}

func TestVMDK_FlatDescriptorConcatenatesExtents(t *testing.T) {
	dir := t.TempDir()
	p, want := flatExtentDisk(t, dir)
	img := mustOpen(t, p)
	in := img.Info()
	if in.Format != FormatVMDK || in.Size != int64(len(want)) || in.Segments != 2 || in.SectorSize != 512 {
		t.Fatalf("Info = %+v", in)
	}
	if in.Meta["vmdk_create_type"] != "twoGbMaxExtentFlat" || in.Meta["vmdk_cid"] != "a1b2c3d4" ||
		in.Meta["vmdk_parent_cid"] != "ffffffff" || in.Meta["vmdk_adapter_type"] != "lsilogic" ||
		in.Meta["vmdk_unclean_shutdown"] != "false" || in.Meta["vmdk_uuid"] == "" {
		t.Fatalf("Meta = %v", in.Meta)
	}
	if !bytes.Equal(readAll(t, img), want) {
		t.Fatal("bytes differ")
	}
	buf := make([]byte, 600)
	if _, err := img.ReadAt(buf, 8*vsec-300); err != nil || !bytes.Equal(buf, want[8*vsec-300:8*vsec+300]) {
		t.Fatalf("read across the extent boundary: %v", err)
	}
	if n, err := img.ReadAt(buf, int64(len(want))-10); n != 10 || err != io.EOF {
		t.Fatalf("end: %d %v", n, err)
	}
}

func TestVMDK_FlatExtentOffsetIsInSectors(t *testing.T) {
	dir := t.TempDir()
	raw := make([]byte, 20*vsec)
	rand.New(rand.NewSource(3)).Read(raw)
	vmdkWriteTemp(t, dir, "x-flat.vmdk", raw)
	desc := descText("monolithicFlat", "ffffffff", []string{`RW 12 FLAT "x-flat.vmdk" 5`})
	img := mustOpen(t, vmdkWriteTemp(t, dir, "x.vmdk", []byte(desc)))
	if !bytes.Equal(readAll(t, img), raw[5*vsec:17*vsec]) {
		t.Fatal("offset not applied")
	}
}

func TestVMDK_FlatExtentShorterThanDeclaredIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	vmdkWriteTemp(t, dir, "x-flat.vmdk", make([]byte, 5*vsec))
	desc := descText("monolithicFlat", "ffffffff", []string{`RW 8 FLAT "x-flat.vmdk" 0`})
	_, err := Open(vmdkWriteTemp(t, dir, "x.vmdk", []byte(desc)))
	wantErr(t, err, ErrCorrupt)
	// offset + size beyond the file
	desc = descText("monolithicFlat", "ffffffff", []string{`RW 4 FLAT "x-flat.vmdk" 3`})
	_, err = Open(vmdkWriteTemp(t, dir, "y.vmdk", []byte(desc)))
	wantErr(t, err, ErrCorrupt)
}

func TestVMDK_SplitSparseExtentsConcatenate(t *testing.T) {
	dir := t.TempDir()
	s1 := vmdkSpec{capSectors: 64, grains: map[int][]byte{0: grainData(1, 8), 7: grainData(2, 8)}}
	s2 := vmdkSpec{capSectors: 32, grains: map[int][]byte{1: grainData(3, 8)}}
	vmdkWriteTemp(t, dir, "d-s001.vmdk", buildSparseVMDK(s1).b)
	vmdkWriteTemp(t, dir, "d-s002.vmdk", buildSparseVMDK(s2).b)
	desc := descText("twoGbMaxExtentSparse", "ffffffff",
		[]string{`RW 64 SPARSE "d-s001.vmdk"`, `RW 32 SPARSE "d-s002.vmdk"`}, stdDDB...)
	want := append(s1.expected(), s2.expected()...)
	img := mustOpen(t, vmdkWriteTemp(t, dir, "d.vmdk", []byte(desc)))
	if img.Info().Segments != 2 || img.Size() != 96*512 {
		t.Fatalf("Info = %+v", img.Info())
	}
	if !bytes.Equal(readAll(t, img), want) {
		t.Fatal("bytes differ")
	}
	// the same extents given as explicit paths, first being a sparse extent
	img2 := mustOpen(t, filepath.Join(dir, "d-s001.vmdk"), filepath.Join(dir, "d-s002.vmdk"))
	if img2.Size() != 96*512 || !bytes.Equal(readAll(t, img2), want) {
		t.Fatal("explicit extent paths differ")
	}
}

func TestVMDK_SplitSparseDeclaredSizeMustMatchExtentHeader(t *testing.T) {
	dir := t.TempDir()
	vmdkWriteTemp(t, dir, "d-s001.vmdk", buildSparseVMDK(vmdkSpec{capSectors: 64}).b)
	desc := descText("twoGbMaxExtentSparse", "ffffffff", []string{`RW 80 SPARSE "d-s001.vmdk"`})
	_, err := Open(vmdkWriteTemp(t, dir, "d.vmdk", []byte(desc)))
	wantErr(t, err, ErrCorrupt)
}

func TestVMDK_SparseExtentNamedByDescriptorMustBeSparse(t *testing.T) {
	dir := t.TempDir()
	vmdkWriteTemp(t, dir, "d-s001.vmdk", make([]byte, 64*512))
	desc := descText("twoGbMaxExtentSparse", "ffffffff", []string{`RW 64 SPARSE "d-s001.vmdk"`})
	_, err := Open(vmdkWriteTemp(t, dir, "d.vmdk", []byte(desc)))
	wantErr(t, err, ErrCorrupt)
}

func TestVMDK_MissingExtentFileReportsNotExist(t *testing.T) {
	dir := t.TempDir()
	desc := descText("monolithicFlat", "ffffffff", []string{`RW 8 FLAT "gone.vmdk" 0`})
	_, err := Open(vmdkWriteTemp(t, dir, "x.vmdk", []byte(desc)))
	wantErr(t, err, os.ErrNotExist)
}

func TestVMDK_DescriptorEdgeCases(t *testing.T) {
	dir := t.TempDir()
	vmdkWriteTemp(t, dir, "x-flat.vmdk", make([]byte, 16*vsec))
	ok := func(createType, parent string, ext ...string) string {
		return descText(createType, parent, ext)
	}
	cases := []struct {
		name string
		text string
		want error
	}{
		{"capacity zero", ok("monolithicFlat", "ffffffff", `RW 0 FLAT "x-flat.vmdk" 0`), ErrCorrupt},
		{"capacity absurd", ok("monolithicFlat", "ffffffff", `RW 99999999999999999 FLAT "x-flat.vmdk" 0`), ErrCorrupt},
		{"capacity overflows int64", ok("monolithicFlat", "ffffffff", `RW 18446744073709551615 FLAT "x-flat.vmdk" 0`), ErrCorrupt},
		{"offset overflows", ok("monolithicFlat", "ffffffff", `RW 8 FLAT "x-flat.vmdk" 18446744073709551615`), ErrCorrupt},
		{"no extents", ok("monolithicFlat", "ffffffff"), ErrCorrupt},
		{"no parentCID", strings.Replace(ok("monolithicFlat", "ffffffff", `RW 8 FLAT "x-flat.vmdk" 0`), "parentCID=ffffffff\n", "", 1), ErrCorrupt},
		{"extent line garbage", ok("monolithicFlat", "ffffffff", `RW eight FLAT "x-flat.vmdk" 0`), ErrCorrupt},
		{"flat extent in sparse disk type", ok("twoGbMaxExtentSparse", "ffffffff", `RW 8 FLAT "x-flat.vmdk" 0`), ErrCorrupt},
		{"child disk", ok("monolithicFlat", "deadbeef", `RW 8 FLAT "x-flat.vmdk" 0`), ErrUnsupported},
		{"vmfsSparse", ok("vmfsSparse", "ffffffff", `RW 8 VMFSSPARSE "x-flat.vmdk"`), ErrUnsupported},
		{"seSparse", ok("seSparse", "ffffffff", `RW 8 SESPARSE "x-flat.vmdk"`), ErrUnsupported},
		{"vmfsRaw", ok("vmfsRaw", "ffffffff", `RW 8 VMFS "x-flat.vmdk"`), ErrUnsupported},
		{"fullDevice", ok("fullDevice", "ffffffff", `RW 8 FLAT "x-flat.vmdk" 0`), ErrUnsupported},
		{"unknown extent type", ok("monolithicFlat", "ffffffff", `RW 8 VMFSRDM "x-flat.vmdk" 0`), ErrUnsupported},
		{"unknown create type", ok("somethingNew", "ffffffff", `RW 8 FLAT "x-flat.vmdk" 0`), ErrUnsupported},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := vmdkWriteTemp(t, dir, "case.vmdk", []byte(c.text))
			img, err := Open(p)
			if err == nil {
				img.Close()
			}
			wantErr(t, err, c.want)
		})
	}
	t.Run("child message says snapshot chains are not followed", func(t *testing.T) {
		p := vmdkWriteTemp(t, dir, "child.vmdk", []byte(ok("monolithicFlat", "deadbeef", `RW 8 FLAT "x-flat.vmdk" 0`)))
		_, err := Open(p)
		if err == nil || !strings.Contains(err.Error(), "snapshot chains are not followed") || !strings.Contains(err.Error(), "deadbeef") {
			t.Fatalf("message = %v", err)
		}
	})
	t.Run("type message names the kind", func(t *testing.T) {
		p := vmdkWriteTemp(t, dir, "se.vmdk", []byte(ok("seSparse", "ffffffff", `RW 8 SESPARSE "x-flat.vmdk"`)))
		_, err := Open(p)
		if err == nil || !strings.Contains(err.Error(), "seSparse") {
			t.Fatalf("message = %v", err)
		}
	})
	t.Run("NUL padded descriptor file", func(t *testing.T) {
		txt := ok("monolithicFlat", "ffffffff", `RW 8 FLAT "x-flat.vmdk" 0`)
		p := vmdkWriteTemp(t, dir, "padded.vmdk", append([]byte(txt), make([]byte, 400)...))
		if img := mustOpen(t, p); img.Size() != 8*512 {
			t.Fatalf("Size = %d", img.Size())
		}
	})
	t.Run("oversized descriptor file", func(t *testing.T) {
		txt := ok("monolithicFlat", "ffffffff", `RW 8 FLAT "x-flat.vmdk" 0`) + strings.Repeat("# filler line to make the descriptor huge\n", 60000)
		p := vmdkWriteTemp(t, dir, "huge.vmdk", []byte(txt))
		_, err := Open(p)
		wantErr(t, err, ErrCorrupt)
	})
}

func TestVMDK_EmbeddedDescriptorChecks(t *testing.T) {
	t.Run("child disk", func(t *testing.T) {
		s := multiGTSpec()
		s.desc = descText("monolithicSparse", "deadbeef", []string{`RW 4800 SPARSE "disk.vmdk"`})
		_, err := Open(vmdkWriteTemp(t, t.TempDir(), "d.vmdk", buildSparseVMDK(s).b))
		wantErr(t, err, ErrUnsupported)
	})
	t.Run("sector count differs from the header", func(t *testing.T) {
		s := multiGTSpec()
		s.desc = descText("monolithicSparse", "ffffffff", []string{`RW 4000 SPARSE "disk.vmdk"`})
		_, err := Open(vmdkWriteTemp(t, t.TempDir(), "d.vmdk", buildSparseVMDK(s).b))
		wantErr(t, err, ErrCorrupt)
	})
	t.Run("flat create type inside a sparse file", func(t *testing.T) {
		s := multiGTSpec()
		s.desc = descText("monolithicFlat", "ffffffff", []string{`RW 4800 FLAT "disk.vmdk" 0`})
		_, err := Open(vmdkWriteTemp(t, t.TempDir(), "d.vmdk", buildSparseVMDK(s).b))
		wantErr(t, err, ErrCorrupt)
	})
	t.Run("seSparse in a sparse file", func(t *testing.T) {
		s := multiGTSpec()
		s.desc = descText("seSparse", "ffffffff", []string{`RW 4800 SESPARSE "disk.vmdk"`})
		_, err := Open(vmdkWriteTemp(t, t.TempDir(), "d.vmdk", buildSparseVMDK(s).b))
		wantErr(t, err, ErrUnsupported)
	})
}

// ---- path safety

func TestVMDK_ExtentNamesNeverLeaveTheDescriptorDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "case")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A valid, big-enough flat file outside the directory: if the reader ever
	// opens it, Open succeeds and the test fails.
	canary := vmdkWriteTemp(t, root, "outside.vmdk", bytes.Repeat([]byte("SECRET"), 4096))
	vmdkWriteTemp(t, dir, "sub/inner.vmdk", bytes.Repeat([]byte("X"), 8192))
	if err := os.Symlink(canary, filepath.Join(dir, "link.vmdk")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink("../outside.vmdk", filepath.Join(dir, "rel-link.vmdk")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub", filepath.Join(dir, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root), filepath.Join(dir, "updir")); err != nil {
		t.Fatal(err)
	}
	names := map[string]string{
		"dotdot":              "../outside.vmdk",
		"dotdot only":         "..",
		"dot":                 ".",
		"absolute":            canary,
		"separator":           "sub/inner.vmdk",
		"backslash":           `sub\inner.vmdk`,
		"windows drive":       `C:\outside.vmdk`,
		"symlink outside":     "link.vmdk",
		"relative symlink":    "rel-link.vmdk",
		"through dir symlink": "updir/outside.vmdk",
		"empty":               "",
		"directory":           "sub",
	}
	for label, name := range names {
		for _, kind := range []string{"FLAT", "SPARSE"} {
			t.Run(label+"/"+kind, func(t *testing.T) {
				ct := "monolithicFlat"
				ext := fmt.Sprintf(`RW 8 FLAT "%s" 0`, name)
				if kind == "SPARSE" {
					ct = "twoGbMaxExtentSparse"
					ext = fmt.Sprintf(`RW 8 SPARSE "%s"`, name)
				}
				p := vmdkWriteTemp(t, dir, "desc.vmdk", []byte(descText(ct, "ffffffff", []string{ext})))
				img, err := Open(p)
				if err == nil {
					img.Close()
				}
				wantErr(t, err, ErrUnsupported)
			})
		}
	}
	t.Run("symlink to a file inside the directory is fine", func(t *testing.T) {
		vmdkWriteTemp(t, dir, "real-flat.vmdk", bytes.Repeat([]byte("Z"), 8*vsec))
		if err := os.Symlink("real-flat.vmdk", filepath.Join(dir, "ok-link.vmdk")); err != nil {
			t.Fatal(err)
		}
		p := vmdkWriteTemp(t, dir, "ok.vmdk", []byte(descText("monolithicFlat", "ffffffff", []string{`RW 8 FLAT "ok-link.vmdk" 0`})))
		img := mustOpen(t, p)
		if !bytes.Equal(readAll(t, img), bytes.Repeat([]byte("Z"), 8*vsec)) {
			t.Fatal("bytes differ")
		}
	})
	t.Run("a FIFO is refused without being opened", func(t *testing.T) {
		fifo := filepath.Join(dir, "pipe.vmdk")
		if err := mkfifo(fifo); err != nil {
			t.Skipf("no fifo: %v", err)
		}
		p := vmdkWriteTemp(t, dir, "fifo.vmdk", []byte(descText("monolithicFlat", "ffffffff", []string{`RW 8 FLAT "pipe.vmdk" 0`})))
		done := make(chan error, 1)
		go func() {
			img, err := Open(p)
			if err == nil {
				img.Close()
			}
			done <- err
		}()
		select {
		case err := <-done:
			wantErr(t, err, ErrUnsupported)
		case <-timeAfter():
			t.Fatal("Open blocked on a FIFO")
		}
	})
}

func TestVMDK_ExplicitSparsePathsMustBeSparseExtents(t *testing.T) {
	dir := t.TempDir()
	a := vmdkWriteTemp(t, dir, "a.vmdk", buildSparseVMDK(vmdkSpec{capSectors: 64}).b)
	b := vmdkWriteTemp(t, dir, "b.vmdk", make([]byte, 4096))
	_, err := Open(a, b)
	wantErr(t, err, ErrCorrupt)
}

// ---- 2000 random corruptions of each valid kind: no panic, no hang.

func TestVMDK_RandomCorruptionNeverPanics(t *testing.T) {
	small := vmdkSpec{capSectors: 600 * 8, grains: map[int][]byte{0: grainData(0, 8), 9: grainData(9, 8), 512: grainData(512, 8)},
		zero: map[int]bool{4: true}}
	small.desc = descText("monolithicSparse", "ffffffff", []string{`RW 4800 SPARSE "f.vmdk"`}, stdDDB...)
	st := small
	st.desc = descText("streamOptimized", "ffffffff", []string{`RW 4800 SPARSE "f.vmdk"`}, stdDDB...)
	bases := map[string][]byte{
		"sparse":        buildSparseVMDK(small).b,
		"stream":        buildStreamVMDK(st, false).b,
		"stream-footer": buildStreamVMDK(st, true).b,
	}
	for name, base := range bases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			r := rand.New(rand.NewSource(20240607))
			opened := 0
			for i := 0; i < 2000; i++ {
				b := append([]byte(nil), base...)
				for k := 0; k < 1+r.Intn(4); k++ {
					var pos int
					switch r.Intn(3) {
					case 0:
						pos = r.Intn(vsec) // header
					case 1:
						pos = len(b) - 1 - r.Intn(min(len(b), 6*vsec)) // directories / footer
					default:
						pos = r.Intn(len(b))
					}
					switch r.Intn(3) {
					case 0:
						b[pos] = byte(r.Intn(256))
					case 1:
						b[pos] ^= 1 << uint(r.Intn(8))
					default:
						b[pos] = 0xff
					}
				}
				if r.Intn(10) == 0 {
					b = b[:r.Intn(len(b))]
				}
				p := vmdkWriteTemp(t, dir, "f.vmdk", b)
				func() {
					defer func() {
						if x := recover(); x != nil {
							t.Fatalf("iteration %d panicked: %v", i, x)
						}
					}()
					img, err := openVMDK([]string{p})
					if err != nil {
						return
					}
					defer img.Close()
					opened++
					if img.Size() > 1<<31 {
						return
					}
					buf := make([]byte, 1<<16)
					for off := int64(0); off < img.Size(); off += int64(len(buf)) {
						img.ReadAt(buf, off)
					}
				}()
			}
			if opened == 0 {
				t.Fatal("no corrupted file opened: the test mutates nothing useful")
			}
		})
	}
}
