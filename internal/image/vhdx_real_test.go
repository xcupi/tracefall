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

// Real-evidence test: TRACEFALL_REAL_VDISK_DIR holds disk.raw (64 MiB, MBR, one NTFS partition)
// and VHDX files written from it by an independent tool (dynamic.vhdx, fixed.vhdx, and optional
// variant files named variant-*.vhdx).
const realVDiskSHA256 = "3c6effa084abefa66a8bd1721061616f5422c2d18bedc5330685c70fb32a2c0e"

func TestVHDX_RealEvidence(t *testing.T) {
	dir := os.Getenv("TRACEFALL_REAL_VDISK_DIR")
	if dir == "" {
		t.Skip("TRACEFALL_REAL_VDISK_DIR not set")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "disk.raw"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != realVDiskSHA256 {
		t.Fatalf("disk.raw is not the expected source: %x", sum)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.vhdx"))
	if len(files) < 2 {
		t.Fatalf("expected at least dynamic.vhdx and fixed.vhdx in %s, found %v", dir, files)
	}
	for _, p := range files {
		p := p
		t.Run(filepath.Base(p), func(t *testing.T) {
			img, err := Open(p)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer img.Close()
			in := img.Info()
			if in.Format != FormatVHDX || in.Size != 67108864 || img.Size() != 67108864 {
				t.Fatalf("info %+v", in)
			}
			h := sha256.New()
			if _, err := io.Copy(h, io.NewSectionReader(img, 0, img.Size())); err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(h.Sum(nil)); got != realVDiskSHA256 {
				t.Fatalf("stream sha256 %s", got)
			}
			tb, err := partition.Read(img, img.Size(), in.SectorSize)
			if err != nil {
				t.Fatal(err)
			}
			if len(tb.Partitions) != 1 {
				t.Fatalf("partitions %d, want 1", len(tb.Partitions))
			}
			r := rand.New(rand.NewSource(7))
			bs := int64(1 << 20)
			offs := []struct{ off, n int64 }{
				{bs - 1000 + r.Int63n(500), 4000},
				{7*bs - 4096 + r.Int63n(100), 9000},
				{r.Int63n(60 << 20), 70000},
				{img.Size() - 3000, 3000},
			}
			for _, o := range offs {
				buf := make([]byte, o.n)
				if n, err := img.ReadAt(buf, o.off); int64(n) != o.n || (err != nil && err != io.EOF) {
					t.Fatalf("read %v: %d %v", o, n, err)
				}
				if !bytes.Equal(buf, raw[o.off:o.off+o.n]) {
					t.Fatalf("read at %d len %d differs from disk.raw", o.off, o.n)
				}
			}
		})
	}
}
