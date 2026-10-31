package ingest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoveryCatalogsLinksWithoutReadingTargets(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ConsoleHost_history.txt"), []byte("Get-Date\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"inside", "outside", "broken"} {
		target := "ConsoleHost_history.txt"
		if name == "outside" {
			target = filepath.Join(t.TempDir(), "missing")
		}
		if name == "broken" {
			target = "absent"
		}
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := Discover(root, Registry())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("catalog lost link entries: got%d want4", len(rows))
	}
	for _, r := range rows {
		if r.Path != "ConsoleHost_history.txt" && (r.Supported || r.Parser != "" || r.SHA256 != "" || r.ArtifactType != "filesystem_nonregular_entry") {
			t.Fatalf("link target was read or entry unclassified: %+v", r)
		}
	}
}
