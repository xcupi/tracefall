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

// Real-evidence test: needs a directory written by an independent tool
// (qemu-img) from one raw disk. Set TRACEFALL_REAL_VDISK_DIR to a directory
// holding disk.raw plus sparse.vmdk, stream.vmdk, flat.vmdk (+ its flat
// extent), split.vmdk (+ its split extents). The disk is 64 MiB with an MBR and
// one NTFS partition.
const (
	realVDiskSHA256 = "3c6effa084abefa66a8bd1721061616f5422c2d18bedc5330685c70fb32a2c0e"
	realVDiskSize   = 67108864
)

func TestVMDK_RealQemuWrittenDisks(t *testing.T) {
	dir := os.Getenv("TRACEFALL_REAL_VDISK_DIR")
	if dir == "" {
		t.Skip("TRACEFALL_REAL_VDISK_DIR not set")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "disk.raw"))
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != realVDiskSHA256 || len(raw) != realVDiskSize {
		t.Fatalf("disk.raw is not the expected source (sha256 %x, %d bytes)", sum, len(raw))
	}
	cases := map[string][]string{
		"sparse (monolithicSparse)":    {"sparse.vmdk"},
		"stream (streamOptimized)":     {"stream.vmdk"},
		"flat (monolithicFlat)":        {"flat.vmdk"},
		"split (twoGbMaxExtentSparse)": {"split.vmdk"},
	}
	if extents, _ := filepath.Glob(filepath.Join(dir, "split-s*.vmdk")); len(extents) > 0 {
		names := []string{}
		for _, e := range extents {
			names = append(names, filepath.Base(e))
		}
		cases["split extents given as paths"] = names
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			paths := make([]string, len(files))
			for i, f := range files {
				paths[i] = filepath.Join(dir, f)
				if _, err := os.Stat(paths[i]); err != nil {
					t.Skipf("fixture missing: %v", err)
				}
			}
			img, err := Open(paths...)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer img.Close()
			in := img.Info()
			if in.Format != FormatVMDK || in.Size != realVDiskSize || img.Size() != realVDiskSize {
				t.Fatalf("Info = %+v", in)
			}
			t.Logf("format=%s size=%d segments=%d meta=%v", in.Format, in.Size, in.Segments, in.Meta)

			h := sha256.New()
			if _, err := io.Copy(h, io.NewSectionReader(img, 0, img.Size())); err != nil {
				t.Fatalf("reading the whole stream: %v", err)
			}
			got := hex.EncodeToString(h.Sum(nil))
			t.Logf("sha256 of decoded stream = %s", got)
			if got != realVDiskSHA256 {
				t.Fatalf("sha256 = %s, want %s", got, realVDiskSHA256)
			}

			tb, err := partition.Read(img, img.Size(), 512)
			if err != nil {
				t.Fatalf("partition.Read: %v", err)
			}
			if len(tb.Partitions) != 1 {
				t.Fatalf("found %d partitions, want 1", len(tb.Partitions))
			}

			r := rand.New(rand.NewSource(424242))
			type rd struct{ off, n int }
			reads := []rd{
				{64*1024 - 100, 300},       // straddles a 64 KiB grain boundary
				{realVDiskSize - 777, 777}, // ends exactly at the end
				{r.Intn(realVDiskSize - 200000), 150000},
				{(1+r.Intn(500))*128*512 - 40, 97}, // another boundary
			}
			for _, c := range reads {
				buf := make([]byte, c.n)
				n, err := img.ReadAt(buf, int64(c.off))
				if n != c.n || (err != nil && err != io.EOF) || !bytes.Equal(buf, raw[c.off:c.off+c.n]) {
					t.Fatalf("read(%d,%d): n=%d err=%v, or bytes differ from disk.raw", c.off, c.n, n, err)
				}
			}
		})
	}
}
