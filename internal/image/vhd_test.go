package image

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ---- builders (independent of the reader) ----

const (
	tvSector    = 512
	tvBlockSize = 4096 // 8 sectors; one sector of bitmap
)

func tvChecksum(b []byte, csumOff int) uint32 {
	var s uint32
	for i, c := range b {
		if i >= csumOff && i < csumOff+4 {
			continue
		}
		s += uint32(c)
	}
	return ^s
}

type tvFooterSpec struct {
	typ      uint32
	cur      uint64
	orig     uint64
	dataOff  uint64
	stamp    uint32
	creator  string
	uuidByte byte
}

func tvFooter(s tvFooterSpec) []byte {
	f := make([]byte, 512)
	copy(f, "conectix")
	binary.BigEndian.PutUint32(f[8:], 2)
	binary.BigEndian.PutUint32(f[12:], 0x00010000)
	binary.BigEndian.PutUint64(f[16:], s.dataOff)
	binary.BigEndian.PutUint32(f[24:], s.stamp)
	creator := s.creator
	if creator == "" {
		creator = "tstr"
	}
	copy(f[28:32], creator)
	binary.BigEndian.PutUint32(f[32:], 0x00010000)
	copy(f[36:40], "Wi2k")
	if s.orig == 0 {
		s.orig = s.cur
	}
	binary.BigEndian.PutUint64(f[40:], s.orig)
	binary.BigEndian.PutUint64(f[48:], s.cur)
	binary.BigEndian.PutUint16(f[56:], 40)
	f[58], f[59] = 4, 17
	binary.BigEndian.PutUint32(f[60:], s.typ)
	for i := 0; i < 16; i++ {
		f[68+i] = s.uuidByte + byte(i)
	}
	binary.BigEndian.PutUint32(f[64:], tvChecksum(f, 64))
	return f
}

func tvFixFooter(b []byte, off int) {
	binary.BigEndian.PutUint32(b[off+64:], tvChecksum(b[off:off+512], 64))
}

func tvFixHeader(b []byte) {
	binary.BigEndian.PutUint32(b[512+36:], tvChecksum(b[512:512+1024], 36))
}

// tvStamp is 2021-03-04T05:06:07Z in seconds since 2000-01-01 UTC.
var tvStamp = uint32(time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC).Unix() - 946684800)

func tvPattern(seed byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i*7) | 1 // never zero
	}
	return b
}

func tvFixed(t testing.TB, disk []byte) []byte {
	t.Helper()
	f := tvFooter(tvFooterSpec{typ: 2, cur: uint64(len(disk)), dataOff: ^uint64(0), stamp: tvStamp, uuidByte: 0x10})
	return append(append([]byte{}, disk...), f...)
}

type tvBlock struct {
	bitmap byte // first bitmap byte; sectors 0..7 MSB first
	fill   byte
}

// tvDynamic builds a dynamic VHD of diskSize bytes. blocks maps block index to
// an allocated block. The returned expected is the decoded disk.
func tvDynamic(t testing.TB, diskSize int, blocks map[int]tvBlock) (file, expected []byte) {
	t.Helper()
	nBlocks := (diskSize + tvBlockSize - 1) / tvBlockSize
	batBytes := (nBlocks*4 + 511) / 512 * 512
	footer := tvFooter(tvFooterSpec{typ: 3, cur: uint64(diskSize), dataOff: 512, stamp: tvStamp, uuidByte: 0x30})
	hdr := make([]byte, 1024)
	copy(hdr, "cxsparse")
	binary.BigEndian.PutUint64(hdr[8:], ^uint64(0))
	binary.BigEndian.PutUint64(hdr[16:], 1536)
	binary.BigEndian.PutUint32(hdr[24:], 0x00010000)
	binary.BigEndian.PutUint32(hdr[28:], uint32(nBlocks))
	binary.BigEndian.PutUint32(hdr[32:], tvBlockSize)
	binary.BigEndian.PutUint32(hdr[36:], tvChecksum(hdr, 36))
	file = append(file, footer...)
	file = append(file, hdr...)
	bat := bytes.Repeat([]byte{0xFF}, batBytes)
	body := []byte{}
	expected = make([]byte, diskSize)
	base := 1536 + batBytes
	for i := 0; i < nBlocks; i++ {
		b, ok := blocks[i]
		if !ok {
			continue
		}
		off := base + len(body)
		binary.BigEndian.PutUint32(bat[i*4:], uint32(off/512))
		bm := make([]byte, 512)
		bm[0] = b.bitmap
		data := tvPattern(b.fill, tvBlockSize)
		body = append(body, bm...)
		body = append(body, data...)
		for s := 0; s < 8; s++ {
			if b.bitmap&(0x80>>s) != 0 {
				lo := i*tvBlockSize + s*512
				for k := 0; k < 512 && lo+k < diskSize; k++ {
					expected[lo+k] = data[s*512+k]
				}
			}
		}
	}
	file = append(file, bat...)
	file = append(file, body...)
	file = append(file, footer...)
	return file, expected
}

func tvWrite(t testing.TB, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.vhd")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func tvOpen(t testing.TB, b []byte) (Image, error) {
	t.Helper()
	return Open(tvWrite(t, b))
}

func tvReadAll(t testing.TB, img Image) []byte {
	t.Helper()
	out := make([]byte, img.Size())
	n, err := img.ReadAt(out, 0)
	if n != len(out) || (err != nil && err != io.EOF) {
		t.Fatalf("ReadAt all: n=%d err=%v", n, err)
	}
	return out
}

var tvBlocks = map[int]tvBlock{0: {0xFF, 0x11}, 2: {0xA0, 0x22}, 4: {0xFF, 0x33}}

const tvDiskSize = 5*tvBlockSize - 1024

// ---- fixed ----

func TestVHDFixedReadsExactBytes(t *testing.T) {
	disk := tvPattern(5, 10240+100)
	img, err := tvOpen(t, tvFixed(t, disk))
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	if img.Size() != int64(len(disk)) {
		t.Fatalf("size %d want %d", img.Size(), len(disk))
	}
	if got := tvReadAll(t, img); !bytes.Equal(got, disk) {
		t.Fatal("decoded bytes differ")
	}
	in := img.Info()
	if in.Format != FormatVHD || in.SectorSize != 512 || in.Segments != 1 || in.StoredMD5 != "" || in.StoredSHA1 != "" {
		t.Fatalf("info %+v", in)
	}
	want := map[string]string{
		"vhd_type":                "fixed",
		"vhd_creator_application": "tstr",
		"vhd_creation_utc":        "2021-03-04T05:06:07Z",
		"vhd_uuid":                "10111213-1415-1617-1819-1a1b1c1d1e1f",
	}
	for k, v := range want {
		if in.Meta[k] != v {
			t.Errorf("meta %s = %q want %q", k, in.Meta[k], v)
		}
	}
	if _, ok := in.Meta["vhd_block_size"]; ok {
		t.Error("fixed disk must not carry vhd_block_size")
	}
}

func TestVHDReadAtPastEndIsEOF(t *testing.T) {
	disk := tvPattern(5, 2048)
	img, err := tvOpen(t, tvFixed(t, disk))
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	buf := make([]byte, 100)
	n, err := img.ReadAt(buf, 2000)
	if n != 48 || err != io.EOF || !bytes.Equal(buf[:48], disk[2000:]) {
		t.Fatalf("straddle: n=%d err=%v", n, err)
	}
	if n, err = img.ReadAt(buf, 2048); n != 0 || err != io.EOF {
		t.Fatalf("at end: n=%d err=%v", n, err)
	}
	if n, err = img.ReadAt(buf, 99999); n != 0 || err != io.EOF {
		t.Fatalf("past end: n=%d err=%v", n, err)
	}
	if _, err = img.ReadAt(buf, -1); err == nil {
		t.Fatal("negative offset must fail")
	}
}

// ---- dynamic ----

func TestVHDDynamicReadsExactBytes(t *testing.T) {
	file, want := tvDynamic(t, tvDiskSize, tvBlocks)
	img, err := tvOpen(t, file)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	if img.Size() != tvDiskSize {
		t.Fatalf("size %d", img.Size())
	}
	if got := tvReadAll(t, img); !bytes.Equal(got, want) {
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("first difference at %d: got %#x want %#x", i, got[i], want[i])
			}
		}
	}
	// the partial-bitmap block: sector 1 of block 2 is not in the bitmap -> zeros
	buf := make([]byte, 512)
	if _, err := img.ReadAt(buf, 2*tvBlockSize+512); err != nil || !bytes.Equal(buf, make([]byte, 512)) {
		t.Fatalf("clear bitmap sector must be zero: %v", err)
	}
	if _, err := img.ReadAt(buf, 2*tvBlockSize); err != nil || bytes.Equal(buf, make([]byte, 512)) {
		t.Fatalf("set bitmap sector must carry data: %v", err)
	}
	in := img.Info()
	if in.Format != FormatVHD || in.Meta["vhd_type"] != "dynamic" || in.Meta["vhd_block_size"] != "4096" {
		t.Fatalf("info %+v", in)
	}
	if in.Meta["vhd_uuid"] != "30313233-3435-3637-3839-3a3b3c3d3e3f" {
		t.Errorf("uuid %q", in.Meta["vhd_uuid"])
	}
}

func TestVHDDynamicRandomReadsMatch(t *testing.T) {
	file, want := tvDynamic(t, tvDiskSize, tvBlocks)
	img, err := tvOpen(t, file)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 500; i++ {
		off := rng.Intn(tvDiskSize + 50)
		n := rng.Intn(9000) + 1
		buf := make([]byte, n)
		got, err := img.ReadAt(buf, int64(off))
		exp := 0
		if off < tvDiskSize {
			exp = min(n, tvDiskSize-off)
		}
		if got != exp || (exp < n) != (err == io.EOF) || (exp == n && err != nil) {
			t.Fatalf("off=%d n=%d: got %d err=%v want %d", off, n, got, err, exp)
		}
		if exp > 0 && !bytes.Equal(buf[:exp], want[off:off+exp]) {
			t.Fatalf("bytes differ off=%d n=%d", off, n)
		}
	}
}

func TestVHDDynamicConcurrentReads(t *testing.T) {
	file, want := tvDynamic(t, tvDiskSize, tvBlocks)
	img, err := tvOpen(t, file)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(g)))
			for i := 0; i < 200; i++ {
				off := rng.Intn(tvDiskSize - 1)
				buf := make([]byte, 700)
				n, _ := img.ReadAt(buf, int64(off))
				if !bytes.Equal(buf[:n], want[off:off+n]) {
					t.Errorf("goroutine %d: bytes differ at %d", g, off)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestVHDDynamicCacheIsBounded(t *testing.T) {
	// many blocks all allocated: reads must still be right after eviction.
	blocks := map[int]tvBlock{}
	for i := 0; i < 40; i++ {
		blocks[i] = tvBlock{0xFF - byte(i%3), byte(i + 1)}
	}
	file, want := tvDynamic(t, 40*tvBlockSize, blocks)
	img, err := tvOpen(t, file)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	if got := tvReadAll(t, img); !bytes.Equal(got, want) {
		t.Fatal("decoded bytes differ after cache eviction")
	}
	if got := tvReadAll(t, img); !bytes.Equal(got, want) {
		t.Fatal("second pass differs")
	}
}

func TestVHDReadOnly(t *testing.T) {
	file, _ := tvDynamic(t, tvDiskSize, tvBlocks)
	p := tvWrite(t, file)
	img, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	tvReadAll(t, img)
	img.Close()
	after, _ := os.ReadFile(p)
	if !bytes.Equal(after, file) {
		t.Fatal("file was modified")
	}
}

// ---- unsupported ----

func TestVHDDifferencingIsUnsupported(t *testing.T) {
	file, _ := tvDynamic(t, tvDiskSize, tvBlocks)
	for _, off := range []int{0, len(file) - 512} {
		binary.BigEndian.PutUint32(file[off+60:], 4)
		tvFixFooter(file, off)
	}
	copy(file[512+64:], []byte{0x00, 'p', 0x00, 'a', 0x00, 'r', 0x00, 'e', 0x00, 'n', 0x00, 't'})
	tvFixHeader(file)
	_, err := tvOpen(t, file)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
	if msg := err.Error(); !bytes.Contains([]byte(msg), []byte("parent")) {
		t.Fatalf("message must name the parent: %q", msg)
	}
}

func TestVHDDynamicWithParentFieldsIsUnsupported(t *testing.T) {
	file, _ := tvDynamic(t, tvDiskSize, tvBlocks)
	copy(file[512+40:], tvPattern(1, 16)) // parent unique id on a type 3 disk
	tvFixHeader(file)
	if _, err := tvOpen(t, file); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
	file, _ = tvDynamic(t, tvDiskSize, tvBlocks)
	file[512+576] = 'W' // a parent locator entry with a platform code
	tvFixHeader(file)
	if _, err := tvOpen(t, file); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("locator: want ErrUnsupported, got %v", err)
	}
}

func TestVHDUnknownDiskTypeIsUnsupported(t *testing.T) {
	disk := tvPattern(5, 1024)
	f := tvFixed(t, disk)
	binary.BigEndian.PutUint32(f[len(f)-512+60:], 1)
	tvFixFooter(f, len(f)-512)
	if _, err := tvOpen(t, f); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
}

// ---- corrupt ----

func TestVHDCorruptInputsAreErrCorrupt(t *testing.T) {
	dyn := func() []byte { f, _ := tvDynamic(t, tvDiskSize, tvBlocks); return f }
	fix := func() []byte { return tvFixed(t, tvPattern(5, 4096)) }
	setU32 := func(b []byte, off int, v uint32) { binary.BigEndian.PutUint32(b[off:], v) }
	setU64 := func(b []byte, off int, v uint64) { binary.BigEndian.PutUint64(b[off:], v) }
	cases := []struct {
		name string
		mk   func() []byte
	}{
		{"end footer bad checksum (dynamic)", func() []byte { b := dyn(); b[len(b)-512+70] ^= 1; return b }},
		{"start footer bad checksum", func() []byte { b := dyn(); b[70] ^= 1; return b }},
		{"fixed footer bad checksum", func() []byte { b := fix(); b[len(b)-512+70] ^= 1; return b }},
		{"header bad checksum", func() []byte { b := dyn(); b[512+20] ^= 1; return b }},
		{"header cookie wrong", func() []byte { b := dyn(); b[512] = 'X'; tvFixHeader(b); return b }},
		{"truncated tail", func() []byte { b := dyn(); return b[:len(b)-100] }},
		{"truncated to header", func() []byte { b := dyn(); return b[:700] }},
		{"truncated to one footer", func() []byte { b := dyn(); return b[:512] }},
		{"truncated half", func() []byte { b := dyn(); return b[:len(b)/2] }},
		{"BAT entry past end", func() []byte { b := dyn(); setU32(b, 1536+0, 0x00FFFFF0); return b }},
		{"BAT entry inside the footer", func() []byte {
			b := dyn()
			setU32(b, 1536+0, uint32((len(b)-512)/512))
			return b
		}},
		{"BAT entry before the BAT", func() []byte { b := dyn(); setU32(b, 1536+0, 1); return b }},
		{"block size zero", func() []byte { b := dyn(); setU32(b, 512+32, 0); tvFixHeader(b); return b }},
		{"block size absurd", func() []byte { b := dyn(); setU32(b, 512+32, 0x7FFFFE00); tvFixHeader(b); return b }},
		{"block size not a sector multiple", func() []byte { b := dyn(); setU32(b, 512+32, 1000); tvFixHeader(b); return b }},
		{"max table entries do not cover the disk", func() []byte { b := dyn(); setU32(b, 512+28, 2); tvFixHeader(b); return b }},
		{"max table entries absurd", func() []byte { b := dyn(); setU32(b, 512+28, 0xFFFFFFFF); tvFixHeader(b); return b }},
		{"table offset past end", func() []byte { b := dyn(); setU64(b, 512+16, 1<<40); tvFixHeader(b); return b }},
		{"table offset overflows", func() []byte { b := dyn(); setU64(b, 512+16, ^uint64(0)-100); tvFixHeader(b); return b }},
		{"table offset unaligned", func() []byte { b := dyn(); setU64(b, 512+16, 1537); tvFixHeader(b); return b }},
		{"data offset past end", func() []byte {
			b := dyn()
			for _, o := range []int{0, len(b) - 512} {
				setU64(b, o+16, 1<<40)
				tvFixFooter(b, o)
			}
			return b
		}},
		{"data offset overflows", func() []byte {
			b := dyn()
			for _, o := range []int{0, len(b) - 512} {
				setU64(b, o+16, ^uint64(0)-5)
				tvFixFooter(b, o)
			}
			return b
		}},
		{"footer copies disagree on size", func() []byte {
			b := dyn()
			setU64(b, 48, tvDiskSize-512)
			tvFixFooter(b, 0)
			return b
		}},
		{"current size zero (dynamic)", func() []byte {
			b := dyn()
			for _, o := range []int{0, len(b) - 512} {
				setU64(b, o+48, 0)
				tvFixFooter(b, o)
			}
			return b
		}},
		{"dynamic size larger than the table covers", func() []byte {
			b := dyn()
			for _, o := range []int{0, len(b) - 512} {
				setU64(b, o+48, 1<<50)
				tvFixFooter(b, o)
			}
			return b
		}},
		{"fixed footer size larger than file", func() []byte {
			b := fix()
			setU64(b, len(b)-512+48, 8192)
			tvFixFooter(b, len(b)-512)
			return b
		}},
		{"fixed footer size smaller than file", func() []byte {
			b := fix()
			setU64(b, len(b)-512+48, 2048)
			tvFixFooter(b, len(b)-512)
			return b
		}},
		{"file shorter than a footer", func() []byte { return fix()[:300] }},
		{"footer version major", func() []byte { b := fix(); setU32(b, len(b)-512+12, 0x00050000); tvFixFooter(b, len(b)-512); return b }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := tvWrite(t, c.mk())
			img, err := openVHD([]string{p})
			if err == nil {
				img.Close()
				t.Fatal("expected an error")
			}
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("want ErrCorrupt, got %v", err)
			}
		})
	}
}

func TestVHDNonVHDNeverReachesTheReader(t *testing.T) {
	p := tvWrite(t, tvPattern(9, 4096))
	img, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	if img.Info().Format != FormatRaw {
		t.Fatalf("format %v", img.Info().Format)
	}
}

func TestVHDOpenDispatches(t *testing.T) {
	file, _ := tvDynamic(t, tvDiskSize, tvBlocks)
	img, err := Open(tvWrite(t, file))
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	if img.Info().Format != FormatVHD {
		t.Fatalf("format %v", img.Info().Format)
	}
}

// ---- hostile input ----

func TestVHDRandomCorruptionsNeverPanic(t *testing.T) {
	base, _ := tvDynamic(t, tvDiskSize, tvBlocks)
	rng := rand.New(rand.NewSource(20260101))
	dir := t.TempDir()
	p := filepath.Join(dir, "f.vhd")
	opened, rejected := 0, 0
	for i := 0; i < 2000; i++ {
		b := append([]byte(nil), base...)
		for k := rng.Intn(6) + 1; k > 0; k-- {
			// bias toward the metadata so mutations are not all in block data
			var pos int
			if rng.Intn(3) > 0 {
				pos = rng.Intn(1536 + 64)
				if rng.Intn(2) == 0 {
					pos = len(b) - 512 + rng.Intn(512)
				}
			} else {
				pos = rng.Intn(len(b))
			}
			b[pos] = byte(rng.Intn(256))
		}
		if rng.Intn(2) == 0 { // get past the checksums
			tvFixFooter(b, 0)
			tvFixFooter(b, len(b)-512)
			tvFixHeader(b)
		}
		if rng.Intn(5) == 0 {
			b = b[:rng.Intn(len(b))]
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("iteration %d panicked: %v", i, r)
				}
			}()
			img, err := openVHD([]string{p})
			if err != nil {
				if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrUnsupported) {
					t.Fatalf("iteration %d: error is neither corrupt nor unsupported: %v", i, err)
				}
				rejected++
				return
			}
			defer img.Close()
			opened++
			buf := make([]byte, 3000)
			for off := int64(0); off < img.Size() && off < 1<<20; off += 2500 {
				if _, err := img.ReadAt(buf, off); err != nil && err != io.EOF && !errors.Is(err, ErrCorrupt) {
					t.Fatalf("iteration %d: unexpected read error %v", i, err)
				}
			}
		}()
	}
	t.Logf("2000 corruptions: %d opened, %d rejected", opened, rejected)
	if rejected == 0 || opened == 0 {
		t.Fatalf("opened=%d rejected=%d: the test must exercise both validation and reads", opened, rejected)
	}
}
