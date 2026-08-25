package archive

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// buildZip constructs an in-memory zip from name->content pairs and
// returns it as a *zip.Reader ready to pass to Extract.
func buildZip(t *testing.T, files map[string]string) *zip.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestExtract_ValidArchive(t *testing.T) {
	zr := buildZip(t, map[string]string{
		"EvtxECmd/output.csv":   "a,b,c\n1,2,3\n",
		"PECmd/output.csv":      "x,y\n1,2\n",
		"Tasks/subdir/task.xml": "<Task/>",
	})
	dest := t.TempDir()

	res, err := Extract(zr, dest, DefaultLimits)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if res.FilesExtracted != 3 {
		t.Errorf("FilesExtracted = %d, want 3", res.FilesExtracted)
	}

	data, err := os.ReadFile(filepath.Join(dest, "EvtxECmd", "output.csv"))
	if err != nil {
		t.Fatalf("reading extracted file: %v", err)
	}
	if string(data) != "a,b,c\n1,2,3\n" {
		t.Errorf("extracted content mismatch: %q", data)
	}

	// Extracted files must never be executable.
	fi, err := os.Stat(filepath.Join(dest, "EvtxECmd", "output.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o111 != 0 {
		t.Errorf("extracted file is executable: mode %v", fi.Mode())
	}
}

func TestExtract_PathTraversalRejected(t *testing.T) {
	cases := []string{
		"../../etc/passwd",
		"a/../../b",
		"..\\..\\windows\\evil.txt",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			zr := buildZip(t, map[string]string{name: "evil"})
			dest := t.TempDir()
			_, err := Extract(zr, dest, DefaultLimits)
			if err == nil {
				t.Fatalf("expected an error for traversal entry %q", name)
			}
			if !errors.Is(err, ErrUnsafeEntry) {
				t.Errorf("error = %v, want wrapping ErrUnsafeEntry", err)
			}
			assertDirEmpty(t, dest)
		})
	}
}

func TestExtract_AbsolutePathRejected(t *testing.T) {
	cases := []string{"/etc/passwd", `C:\Windows\evil.txt`, `c:/windows/evil.txt`}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			zr := buildZip(t, map[string]string{name: "evil"})
			dest := t.TempDir()
			_, err := Extract(zr, dest, DefaultLimits)
			if !errors.Is(err, ErrUnsafeEntry) {
				t.Errorf("error = %v, want wrapping ErrUnsafeEntry", err)
			}
		})
	}
}

func TestExtract_SymlinkRejected(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: "evil-link", Method: zip.Deflate}
	hdr.SetMode(os.ModeSymlink | 0o777)
	fw, err := w.CreateHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("/etc/passwd")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	_, err = Extract(zr, dest, DefaultLimits)
	if !errors.Is(err, ErrUnsafeEntry) {
		t.Fatalf("error = %v, want wrapping ErrUnsafeEntry", err)
	}
	if _, statErr := os.Lstat(filepath.Join(dest, "evil-link")); !os.IsNotExist(statErr) {
		t.Error("a symlink (or anything) was created on disk for the rejected entry")
	}
}

func TestExtract_TooManyFiles(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 5; i++ {
		files[filepath.Join("dir", string(rune('a'+i))+".txt")] = "x"
	}
	zr := buildZip(t, files)
	limits := DefaultLimits
	limits.MaxFiles = 3

	_, err := Extract(zr, t.TempDir(), limits)
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("error = %v, want wrapping ErrLimitExceeded", err)
	}
}

func TestExtract_FileTooLarge(t *testing.T) {
	zr := buildZip(t, map[string]string{"big.csv": "0123456789"})
	limits := DefaultLimits
	limits.MaxFileBytes = 5

	_, err := Extract(zr, t.TempDir(), limits)
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("error = %v, want wrapping ErrLimitExceeded", err)
	}
}

func TestExtract_TotalTooLarge(t *testing.T) {
	zr := buildZip(t, map[string]string{
		"a.csv": "0123456789",
		"b.csv": "0123456789",
	})
	limits := DefaultLimits
	limits.MaxFileBytes = 20
	limits.MaxTotalBytes = 15

	_, err := Extract(zr, t.TempDir(), limits)
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("error = %v, want wrapping ErrLimitExceeded", err)
	}
}

func TestExtract_CompressionRatioRejected(t *testing.T) {
	// A highly compressible payload well above the ratio-check size floor.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, err := w.Create("bomb.txt")
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 2_000_000)
	if _, err := fw.Write(zeros); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	limits := DefaultLimits
	limits.RatioMinBytes = 1000
	limits.MaxRatio = 10

	_, err = Extract(zr, t.TempDir(), limits)
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("error = %v, want wrapping ErrLimitExceeded (zip-bomb ratio check)", err)
	}
}

func TestExtractFile_MalformedArchive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-a-zip.zip")
	if err := os.WriteFile(path, []byte("this is definitely not a zip file"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ExtractFile(path, t.TempDir(), DefaultLimits)
	if !errors.Is(err, ErrInvalidArchive) {
		t.Fatalf("error = %v, want wrapping ErrInvalidArchive", err)
	}
}

func TestExtract_DirectoriesCreated(t *testing.T) {
	zr := buildZip(t, map[string]string{
		"EmptyDir/": "",
	})
	dest := t.TempDir()
	res, err := Extract(zr, dest, DefaultLimits)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if res.FilesExtracted != 0 {
		t.Errorf("FilesExtracted = %d, want 0 (only a directory entry)", res.FilesExtracted)
	}
	if fi, err := os.Stat(filepath.Join(dest, "EmptyDir")); err != nil || !fi.IsDir() {
		t.Errorf("expected EmptyDir to exist as a directory: %v", err)
	}
}

func assertDirEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("expected destination to remain empty after a rejected entry, found: %v", entries)
	}
}
