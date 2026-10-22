package api

import (
	"os/exec"
	"path/filepath"
	"testing"

	"tracefall/internal/model"
)

// A virtual disk (VHD, VHDX, VMDK) must reach the same catalog and the same
// extracted bytes as the raw disk it was made from. The disks are produced from
// the repository's own raw fixture with qemu-img, so the container is written by
// an independent implementation; the test skips where qemu-img is absent.
func TestDiskImage_VirtualDisksListAndExtractTheSameEvidenceAsRaw(t *testing.T) {
	qemu, err := exec.LookPath("qemu-img")
	if err != nil {
		t.Skip("qemu-img not installed")
	}
	rawPath := rawFixture(t, "mbr")

	svc, c := newImageCase(t)
	rawRes, err := svc.DiscoverEvidenceFromPath(c.ID, rawPath)
	if err != nil {
		t.Fatal(err)
	}
	want := catalogPaths(t, svc, rawRes.Collection.ID)
	if len(want) == 0 {
		t.Fatal("the raw fixture catalogs nothing")
	}

	variants := []struct {
		name, format string
		opts         []string
	}{
		{"fixed.vhd", "vpc", []string{"subformat=fixed,force_size=on"}},
		{"dynamic.vhd", "vpc", []string{"subformat=dynamic,force_size=on"}},
		{"dynamic.vhdx", "vhdx", []string{"subformat=dynamic"}},
		{"fixed.vhdx", "vhdx", []string{"subformat=fixed"}},
		{"sparse.vmdk", "vmdk", []string{"subformat=monolithicSparse"}},
		{"stream.vmdk", "vmdk", []string{"subformat=streamOptimized"}},
		{"flat.vmdk", "vmdk", []string{"subformat=monolithicFlat"}},
		{"split.vmdk", "vmdk", []string{"subformat=twoGbMaxExtentSparse"}},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, v.name)
			args := []string{"convert", "-f", "raw", "-O", v.format}
			for _, o := range v.opts {
				args = append(args, "-o", o)
			}
			if b, err := exec.Command(qemu, append(args, rawPath, out)...).CombinedOutput(); err != nil {
				t.Skipf("qemu-img could not write %s: %v %s", v.name, err, b)
			}
			svc, c := newImageCase(t)
			res, err := svc.DiscoverEvidenceFromPath(c.ID, out)
			if err != nil {
				t.Fatalf("a %s virtual disk was not accepted: %v", v.name, err)
			}
			if res.Collection.SourceType != model.SourceTypeDiskImage {
				t.Fatalf("source type = %s", res.Collection.SourceType)
			}
			got := catalogPaths(t, svc, res.Collection.ID)
			if len(got) != len(want) {
				t.Fatalf("catalog has %d files, the raw disk has %d", len(got), len(want))
			}
			for p, wf := range want {
				gf, ok := got[p]
				if !ok {
					t.Fatalf("%s is missing from the virtual disk's catalog", p)
				}
				if gf.SHA256 != wf.SHA256 || gf.SizeBytes != wf.SizeBytes {
					t.Errorf("%s differs from the raw disk: %s/%d vs %s/%d", p, gf.SHA256, gf.SizeBytes, wf.SHA256, wf.SizeBytes)
				}
			}
			// The fingerprint of the evidence covers every file that holds the disk.
			own := fileSHA256(t, out)
			switch v.name {
			case "flat.vmdk", "split.vmdk":
				if res.Collection.ArchiveHash == own {
					t.Errorf("the evidence hash is that of the descriptor alone; it does not cover the extents that hold the disk")
				}
			default:
				if res.Collection.ArchiveHash != own {
					t.Errorf("evidence hash %s is not the hash of the container file %s", res.Collection.ArchiveHash, own)
				}
			}
			if res.Collection.IntegritySHA512 == "" {
				t.Error("no integrity digest was recorded")
			}
		})
	}
}
