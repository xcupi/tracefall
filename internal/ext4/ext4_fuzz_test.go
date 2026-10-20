package ext4

import (
	"encoding/binary"
	"runtime"
	"sync"
	"testing"

	"tracefall/internal/fsvol"
)

// Random byte flips almost never produce a superblock that is internally
// consistent and also hostile, which is the kind that allocated gigabytes. This
// fuzzer mutates metadata FIELDS at their known offsets to extreme values, so
// the engine spends its time on parseable-but-absurd images.
//
// Run it for a while with a hard address-space limit, so an unbounded
// allocation kills the worker instead of passing quietly:
//
//	(ulimit -v 6000000; go test ./internal/ext4 -run xxx -fuzz FuzzExtMetadata -fuzztime 3m)
//
// A plain `go test` runs only the seed corpus.

var (
	fuzzBaseOnce sync.Once
	fuzzBase     memImage
	fuzzTargets  []int64 // byte offsets of metadata fields in the base image
)

func fuzzImage(tb testing.TB) (memImage, []int64) {
	fuzzBaseOnce.Do(func() {
		img, _ := buildFS(tb, "mkfs.ext4", "-b", "1024")
		fuzzBase = img
		v, err := Open(img, int64(len(img)))
		if err != nil {
			tb.Fatalf("base image does not open: %v", err)
		}
		// Superblock fields.
		for _, o := range []int64{0, 4, 12, 20, 24, 28, 32, 36, 40, 44, 56, 76, 84, 88, 92, 96, 100, 0x150, 254} {
			fuzzTargets = append(fuzzTargets, 1024+o)
		}
		// Group descriptors: inode table and bitmap locations, counters.
		gdt := int64(v.first+1) * v.bs
		for g := 0; g < len(v.itable) && g < 4; g++ {
			for _, o := range []int64{0, 4, 8, 12, 14, 16, 0x20, 0x28} {
				fuzzTargets = append(fuzzTargets, gdt+int64(g)*64+o)
			}
		}
		// Inode fields of the root and of a handful of files.
		inodes := []uint64{2}
		_, _ = v.Walk(func(f fsvol.File) error {
			if len(inodes) < 12 {
				inodes = append(inodes, f.Record)
			}
			return nil
		})
		for _, ino := range inodes {
			base := int64(v.itable[(ino-1)/v.ipg])*v.bs + int64((ino-1)%v.ipg)*v.isize
			for _, o := range []int64{0, 4, 8, 16, 20, 26, 32, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108} {
				fuzzTargets = append(fuzzTargets, base+o)
			}
		}
		// The root directory's first block: entry inode, record length, name length.
		if ino, err := v.readInode(rootIno); err == nil {
			if ext, err := v.blockMap(ino); err == nil && len(ext) > 0 {
				blk := int64(ext[0].physical) * v.bs
				for o := int64(0); o < 96; o += 2 {
					fuzzTargets = append(fuzzTargets, blk+o)
				}
			}
		}
	})
	return fuzzBase, fuzzTargets
}

// exercise opens the image and uses every reader entry point, tolerating any
// error. What it must not do is panic or allocate without bound.
func exercise(m memImage) {
	v, err := Open(m, int64(len(m)))
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

func putField(m memImage, off int64, width uint8, val uint64) {
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

func FuzzExtMetadata(f *testing.F) {
	huge := []uint64{0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 1 << 40, 0xFFFFFFFFFFFFFFFF, 1 << 27, 65536}
	for i, v := range huge {
		f.Add(uint16(i), uint8(2), v, uint16(i+3), uint8(1), v, uint16(i+7), uint8(2), v)
	}
	// The known case: an inode table far larger than the image.
	f.Add(uint16(5), uint8(2), uint64(1<<27), uint16(7), uint8(2), uint64(1<<27), uint16(0), uint8(2), uint64(1<<27))
	f.Fuzz(func(t *testing.T, s1 uint16, w1 uint8, v1 uint64, s2 uint16, w2 uint8, v2 uint64, s3 uint16, w3 uint8, v3 uint64) {
		base, targets := fuzzImage(t)
		m := append(memImage(nil), base...)
		for _, p := range []struct {
			s uint16
			w uint8
			v uint64
		}{{s1, w1, v1}, {s2, w2, v2}, {s3, w3, v3}} {
			putField(m, targets[int(p.s)%len(targets)], p.w, p.v)
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		exercise(m)
		runtime.ReadMemStats(&after)
		// The image is a few MiB; reading it should not allocate hundreds.
		if d := after.TotalAlloc - before.TotalAlloc; d > 512<<20 {
			t.Fatalf("one image of %d bytes caused %d MiB of allocation", len(m), d>>20)
		}
	})
}
