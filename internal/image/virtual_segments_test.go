package image

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const flatDescriptor = `# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="twoGbMaxExtentFlat"

# Extent description
RW 8 FLAT "disk-f001.vmdk" 0
RW 8 FLAT "disk-f002.vmdk" 0

ddb.adapterType = "lsilogic"
`

func writeSeg(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The evidence hash is taken over the files FindSegments returns. A VMDK
// descriptor is a few hundred bytes; the disk is in the extents it names, so a
// fingerprint of the descriptor alone would not cover the evidence.
func TestFindSegments_VMDKDescriptorBringsItsExtents(t *testing.T) {
	dir := t.TempDir()
	desc := writeSeg(t, dir, "disk.vmdk", flatDescriptor)
	e1 := writeSeg(t, dir, "disk-f001.vmdk", string(make([]byte, 4096)))
	e2 := writeSeg(t, dir, "disk-f002.vmdk", string(make([]byte, 4096)))
	got, err := FindSegments(desc)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{desc, e1, e2}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("segments = %v, want %v", got, want)
	}
}

func TestFindSegments_VMDKDescriptorNeverNamesAFileOutsideItsDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "case")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := writeSeg(t, root, "secret.bin", "outside")
	desc := writeSeg(t, dir, "disk.vmdk", `# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="monolithicFlat"
RW 8 FLAT "../secret.bin" 0
`)
	got, err := FindSegments(desc)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range got {
		if p == outside {
			t.Fatalf("an extent outside the descriptor's directory was returned: %v", got)
		}
	}
	if len(got) != 1 || got[0] != desc {
		t.Fatalf("want only the descriptor (Open reports why it is refused), got %v", got)
	}
}

func TestFindSegments_VMDKMissingExtentFallsBackToTheDescriptorAlone(t *testing.T) {
	dir := t.TempDir()
	desc := writeSeg(t, dir, "disk.vmdk", flatDescriptor)
	writeSeg(t, dir, "disk-f001.vmdk", "x") // f002 absent
	got, err := FindSegments(desc)
	if err != nil || len(got) != 1 || got[0] != desc {
		t.Fatalf("got %v err=%v: a missing extent must not be silently skipped or invented", got, err)
	}
}

func TestFindSegments_OtherFormatsAreUnchanged(t *testing.T) {
	dir := t.TempDir()
	p := writeSeg(t, dir, "plain.bin", "not a vmdk")
	got, _ := FindSegments(p)
	if len(got) != 1 || got[0] != p {
		t.Fatalf("got %v", got)
	}
}

func TestIsVirtualDisk(t *testing.T) {
	dir := t.TempDir()
	if IsVirtualDisk(writeSeg(t, dir, "a.bin", string(make([]byte, 2048)))) {
		t.Error("zeros claimed as a virtual disk")
	}
	if !IsVirtualDisk(writeSeg(t, dir, "b.vhdx", "vhdxfile"+string(make([]byte, 2048)))) {
		t.Error("VHDX signature not claimed")
	}
	if !IsVirtualDisk(writeSeg(t, dir, "c.vmdk", flatDescriptor)) {
		t.Error("VMDK descriptor not claimed")
	}
	if !IsVirtualDisk(writeSeg(t, dir, "d.vmdk", "KDMV"+string(make([]byte, 2048)))) {
		t.Error("VMDK sparse signature not claimed")
	}
	if !IsVirtualDisk(writeSeg(t, dir, "e.vhd", "conectix"+string(make([]byte, 2048)))) {
		t.Error("dynamic VHD cookie not claimed")
	}
	if IsVirtualDisk(filepath.Join(dir, "missing")) {
		t.Error("a missing file was claimed")
	}
}
