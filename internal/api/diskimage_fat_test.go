package api

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A FAT or exFAT volume is opened, not reported as unread. The image is empty
// (a fresh format), so this checks the volume is recognised and opened, not its
// listing; the listing is covered by the reader's own tests in internal/fat.
func TestDiskImage_FATAndExFATVolumesAreOpened(t *testing.T) {
	cases := []struct {
		name string
		make []string
		size string
	}{
		{"FAT16", []string{"mkfs.fat", "-C", "-F", "16", "-n", "TESTFAT"}, "32768"},
		{"exFAT", nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vol.img")
			if c.make != nil {
				if _, err := exec.LookPath(c.make[0]); err != nil {
					t.Skipf("%s not installed", c.make[0])
				}
				if out, err := exec.Command(c.make[0], append(c.make[1:], path, c.size)...).CombinedOutput(); err != nil {
					t.Fatalf("%v: %v\n%s", c.make, err, out)
				}
			} else {
				if _, err := exec.LookPath("mkfs.exfat"); err != nil {
					t.Skip("mkfs.exfat not installed")
				}
				f, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				f.Truncate(16 << 20)
				f.Close()
				if out, err := exec.Command("mkfs.exfat", "-n", "TESTEX", path).CombinedOutput(); err != nil {
					t.Fatalf("mkfs.exfat: %v\n%s", err, out)
				}
			}
			img, _, vols, notes, err := openDiskImage([]string{path})
			if err != nil {
				t.Fatal(err)
			}
			defer img.Close()
			if len(vols) != 1 {
				t.Fatalf("%d volumes opened, want 1; notes %v", len(vols), notes)
			}
			for _, n := range notes {
				if strings.Contains(n, "not read") {
					t.Errorf("the volume is still reported as unread: %s", n)
				}
			}
		})
	}
}
