package mftgen_test

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/ntfs/mftgen"
)

var write = flag.Bool("write-samples", false, "write the sample $MFT to MFT_OUT")

// Generates a synthetic but structurally faithful $MFT for browser
// verification. Entirely invented; no real filenames.
//
//	MFT_OUT=/path go test ./internal/ntfs/mftgen -run TestGenerateMFT -write-samples
func TestGenerateMFT(t *testing.T) {
	if !*write {
		t.Skip("pass -write-samples to regenerate")
	}
	root := os.Getenv("MFT_OUT")
	if root == "" {
		root = filepath.Join(os.TempDir(), "tracefall-mft")
	}
	base := time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)
	tm := func(off time.Duration) mftgen.Times {
		return mftgen.Times{
			Created: base.Add(off), Modified: base.Add(off + time.Hour),
			Changed: base.Add(off + time.Hour + time.Minute), Accessed: base.Add(off + 2*time.Hour),
		}
	}
	files := mftgen.SystemRecords(tm(0))
	files = append(files,
		mftgen.File{RecordNumber: 40, SequenceNumber: 1, InUse: true, IsDirectory: true, HardLinks: 1, SI: tm(0),
			Names: []mftgen.Name{{Name: "Windows", Namespace: mftgen.NamespaceWin32, ParentRef: 5, ParentSeq: 5}}},
		mftgen.File{RecordNumber: 41, SequenceNumber: 1, InUse: true, IsDirectory: true, HardLinks: 1, SI: tm(0),
			Names: []mftgen.Name{{Name: "Temp", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1}}},
	)
	for i := 0; i < 300; i++ {
		files = append(files, mftgen.File{
			RecordNumber: uint64(100 + i), SequenceNumber: 1, InUse: i%17 != 0, SI: tm(time.Duration(i) * time.Minute),
			Names: []mftgen.Name{{
				Name: fmt.Sprintf("artifact-%03d.dat", i), Namespace: mftgen.NamespaceWin32,
				ParentRef: 41, ParentSeq: 1, LogicalSize: uint64(1024 * (i + 1))}},
			NonResidentData: &mftgen.NonResident{
				AllocatedSize: uint64(4096 * (i + 1)), RealSize: uint64(1024 * (i + 1)), InitializedSize: uint64(1024 * (i + 1))},
		})
	}
	// One record with both a long and a short name, and a unicode one.
	files = append(files,
		mftgen.File{RecordNumber: 500, SequenceNumber: 1, InUse: true, HardLinks: 2, SI: tm(90 * time.Minute),
			Names: []mftgen.Name{
				{Name: "LONGNA~1.EXE", Namespace: mftgen.NamespaceDOS, ParentRef: 40, ParentSeq: 1},
				{Name: "Long Named Installer.exe", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1},
			},
			ResidentData: []byte("resident")},
		mftgen.File{RecordNumber: 501, SequenceNumber: 1, InUse: true, SI: tm(95 * time.Minute),
			Names:        []mftgen.Name{{Name: "отчёт-2026.docx", Namespace: mftgen.NamespaceWin32, ParentRef: 41, ParentSeq: 1}},
			ResidentData: []byte("x")},
	)
	dir := filepath.Join(root, "C")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "$MFT")
	if err := os.WriteFile(out, mftgen.Build(files), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%d records)", out, len(files))
}
