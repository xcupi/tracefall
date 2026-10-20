package fat

import (
	"encoding/binary"
	"os"
	"runtime"
	"sync"
	"testing"

	"tracefall/internal/fsvol"
)

// Same idea as the ext fuzzer: mutate metadata fields (boot sector, the FAT,
// directory entries) to extreme values, on images that otherwise parse. See
// internal/ext4/ext4_fuzz_test.go for how to run it with a hard memory limit:
//
//	(ulimit -v 6000000; go test ./internal/fat -run xxx -fuzz FuzzFATMetadata -fuzztime 3m)

type fuzzBase struct {
	img     []byte
	targets []int64
}

var (
	fuzzOnce  sync.Once
	fuzzBases []fuzzBase
)

func loadBase(tb testing.TB, path string) fuzzBase {
	img, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	v, err := Open(bytesReaderAt(img), int64(len(img)))
	if err != nil {
		tb.Fatalf("base image does not open: %v", err)
	}
	var targets []int64
	for o := int64(0); o < 128; o++ {
		targets = append(targets, o)
	}
	// The allocation table: start of the FAT region.
	if v.kind == "exFAT" {
		fo := int64(le32(img, 80)) * (int64(1) << img[108])
		for o := int64(0); o < 64; o += 4 {
			targets = append(targets, fo+o)
		}
	} else {
		fo := int64(le16(img, 14)) * int64(le16(img, 11))
		for o := int64(0); o < 64; o += 2 {
			targets = append(targets, fo+o)
		}
	}
	seen := map[int64]bool{}
	_, _ = v.Walk(func(f fsvol.File) error {
		dir := f.Record - f.Record%uint64(v.cluster)
		if !seen[int64(dir)] {
			seen[int64(dir)] = true
			for o := int64(0); o < 128; o += 2 {
				targets = append(targets, int64(dir)+o)
			}
		}
		for o := int64(0); o < 64; o++ {
			targets = append(targets, int64(f.Record)+o)
		}
		return nil
	})
	return fuzzBase{img: img, targets: targets}
}

func fuzzImages(tb testing.TB) []fuzzBase {
	fuzzOnce.Do(func() {
		p16, _ := writeFATTree(tb, "FAT16")
		p32, _ := writeFATTree(tb, "FAT32")
		px := writeExFATTree(tb)
		// The writers place images in a per-test temp dir that goes away; keep
		// the bytes.
		for _, p := range []string{p16, p32, px} {
			fuzzBases = append(fuzzBases, loadBase(tb, p))
		}
	})
	return fuzzBases
}

func exerciseFAT(m []byte) {
	v, err := Open(bytesReaderAt(m), int64(len(m)))
	if err != nil {
		return
	}
	_, _ = v.Walk(func(f fsvol.File) error {
		r, err := v.OpenStream(f.Record, "")
		if err != nil {
			return nil
		}
		buf := make([]byte, 4096)
		_, _ = r.ReadAt(buf, 0)
		_, _ = r.ReadAt(buf, r.Size()/2)
		_ = r.AllocatedRanges()
		return nil
	})
}

func put(m []byte, off int64, width uint8, val uint64) {
	if off < 0 || off+8 > int64(len(m)) {
		return
	}
	switch width % 4 {
	case 0:
		m[off] = byte(val)
	case 1:
		binary.LittleEndian.PutUint16(m[off:], uint16(val))
	case 2:
		binary.LittleEndian.PutUint32(m[off:], uint32(val))
	default:
		binary.LittleEndian.PutUint64(m[off:], val)
	}
}

func FuzzFATMetadata(f *testing.F) {
	huge := []uint64{0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 1 << 40, 0xFFFFFFFFFFFFFFFF, 65536, 0x0FFFFFF8}
	for i, v := range huge {
		f.Add(uint8(i), uint16(i*5), uint8(2), v, uint16(i*11+3), uint8(1), v, uint16(i+40), uint8(3), v)
	}
	f.Fuzz(func(t *testing.T, which uint8, s1 uint16, w1 uint8, v1 uint64, s2 uint16, w2 uint8, v2 uint64, s3 uint16, w3 uint8, v3 uint64) {
		bases := fuzzImages(t)
		b := bases[int(which)%len(bases)]
		m := append([]byte(nil), b.img...)
		for _, p := range []struct {
			s uint16
			w uint8
			v uint64
		}{{s1, w1, v1}, {s2, w2, v2}, {s3, w3, v3}} {
			put(m, b.targets[int(p.s)%len(b.targets)], p.w, p.v)
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		exerciseFAT(m)
		runtime.ReadMemStats(&after)
		if d := after.TotalAlloc - before.TotalAlloc; d > 512<<20 {
			t.Fatalf("one image of %d bytes caused %d MiB of allocation", len(m), d>>20)
		}
	})
}
