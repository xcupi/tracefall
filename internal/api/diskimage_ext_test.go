package api

import (
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/model"
)

// An ext4 volume is cataloged like an NTFS one: an artifact the parsers claim
// is supported, and a plain data file is listed as unsupported, never dropped.
// The image is built here with mkfs from a source tree, so the expected
// entries are known.
func TestDiskImage_ExtVolumeIsCatalogedLikeNTFS(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 not installed")
	}
	src := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(src, "var/log"), 0o755))
	must(os.WriteFile(filepath.Join(src, "var/log/auth.log"),
		[]byte("Oct 18 10:00:01 host sshd[101]: Accepted password for svc from 10.0.0.5 port 2222 ssh2\n"), 0o644))
	must(os.MkdirAll(filepath.Join(src, "data"), 0o755))
	blob := make([]byte, 64<<10)
	_, err := rand.Read(blob)
	must(err)
	must(os.WriteFile(filepath.Join(src, "data/blob.bin"), blob, 0o644))

	img := filepath.Join(t.TempDir(), "disk.img")
	if out, err := exec.Command("mkfs.ext4", "-q", "-F", "-d", src, img, "16M").CombinedOutput(); err != nil {
		t.Fatalf("mkfs.ext4: %v\n%s", err, out)
	}

	svc, c := newImageCase(t)
	res, err := svc.DiscoverEvidenceFromPath(c.ID, img)
	if err != nil {
		t.Fatal(err)
	}
	if res.Collection.SourceType != model.SourceTypeDiskImage {
		t.Fatalf("source type %q, want a disk image", res.Collection.SourceType)
	}
	files := catalogPaths(t, svc, res.Collection.ID)

	var auth, blobSF *model.SourceFile
	for p, sf := range files {
		sf := sf
		switch {
		case strings.HasSuffix(p, "/var/log/auth.log"):
			auth = &sf
		case strings.HasSuffix(p, "/data/blob.bin"):
			blobSF = &sf
		}
	}
	if auth == nil {
		t.Fatalf("auth.log is not cataloged; entries: %d", len(files))
	}
	if !auth.Supported || auth.Parser == "" {
		t.Errorf("auth.log: supported=%v parser=%q, want a claiming parser", auth.Supported, auth.Parser)
	}
	if blobSF == nil {
		t.Fatal("a plain data file was dropped instead of listed as unsupported")
	}
	if blobSF.Supported || blobSF.ImportStatus != model.SourceFileUnsupported {
		t.Errorf("blob.bin: supported=%v status=%s, want unsupported", blobSF.Supported, blobSF.ImportStatus)
	}
	if blobSF.SizeBytes != int64(len(blob)) {
		t.Errorf("blob.bin size %d, want %d", blobSF.SizeBytes, len(blob))
	}
}
