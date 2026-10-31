package evidencepath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEvidenceMemberReadAndCreateNoSymlinkTraversal(t *testing.T) {
	root := t.TempDir()
	f, err := Create(root, "repository/member")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("neutral")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	f, err = Open(root, "repository/member")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	outside := t.TempDir()
	if err = os.WriteFile(filepath.Join(outside, "sentinel"), []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(outside, "sentinel"), filepath.Join(root, "final")); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"../outside", "/absolute", "link/sentinel", "final", "repository/../final"} {
		for _, open := range []func(string, string) (*os.File, error){Open, Create} {
			if f, err = open(root, rel); err == nil {
				f.Close()
				t.Fatalf("unsafe path accepted: %s", rel)
			}
		}
	}
	b, err := os.ReadFile(filepath.Join(outside, "sentinel"))
	if err != nil || string(b) != "unchanged" {
		t.Fatal("evidence write traversed symlink")
	}
}
