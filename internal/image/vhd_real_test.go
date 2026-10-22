package image

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/partition"
)

// Real-evidence test. TRACEFALL_REAL_VDISK_DIR holds disk.raw (the pinned
// source disk) and fixed.vhd / dynamic.vhd written by an independent tool from it.
func TestVHDRealDisks(t *testing.T) {
	dir := os.Getenv("TRACEFALL_REAL_VDISK_DIR")
	if dir == "" {
		t.Skip("TRACEFALL_REAL_VDISK_DIR not set")
	}
	const wantSHA = "3c6effa084abefa66a8bd1721061616f5422c2d18bedc5330685c70fb32a2c0e"
	const wantSize = 67108864
	raw, err := os.ReadFile(filepath.Join(dir, "disk.raw"))
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != wantSHA {
		t.Fatalf("disk.raw is not the pinned source: %x", sum)
	}
	for _, name := range []string{"fixed.vhd", "dynamic.vhd"} {
		t.Run(name, func(t *testing.T) {
			img, err := Open(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			defer img.Close()
			in := img.Info()
			if in.Format != FormatVHD || img.Size() != wantSize || in.Size != wantSize {
				t.Fatalf("info %+v size %d", in, img.Size())
			}
			t.Logf("%s: meta %v", name, in.Meta)
			h := sha256.New()
			if _, err := io.Copy(h, io.NewSectionReader(img, 0, img.Size())); err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA {
				t.Fatalf("sha256 %s want %s", got, wantSHA)
			}
			tb, err := partition.Read(img, img.Size(), 512)
			if err != nil {
				t.Fatal(err)
			}
			if len(tb.Partitions) != 1 {
				t.Fatalf("%d partitions", len(tb.Partitions))
			}
			rng := rand.New(rand.NewSource(42))
			offs := []int64{rng.Int63n(wantSize), 2<<20 - 100, wantSize - 1000, rng.Int63n(wantSize)}
			lens := []int{int(rng.Int63n(5<<20)) + 1, 4000, 5000, int(rng.Int63n(1<<20)) + 1}
			for i := range offs {
				buf := make([]byte, lens[i])
				n, err := img.ReadAt(buf, offs[i])
				exp := min(int64(lens[i]), wantSize-offs[i])
				if int64(n) != exp || (n < len(buf)) != (err == io.EOF) {
					t.Fatalf("read %d: off=%d len=%d n=%d err=%v", i, offs[i], lens[i], n, err)
				}
				if !bytes.Equal(buf[:n], raw[offs[i]:offs[i]+int64(n)]) {
					t.Fatalf("read %d differs from disk.raw (off=%d len=%d)", i, offs[i], lens[i])
				}
			}
		})
	}
}
