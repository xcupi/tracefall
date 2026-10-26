package parsestaging

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryIsBoundedAndDoesNotFollowLinks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(outside, []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "tracefall-parse-link.partial")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	for i := 0; i < 300; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("tracefall-parse-%04d.partial", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	w, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "tracefall-parse-link.partial" && e.Name() != ".owner.lock" {
			t.Fatalf("unrecovered entry: %s", e.Name())
		}
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "preserved" {
		t.Fatalf("source changed: %v", err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(alias); err == nil {
		other.Close()
		t.Fatal("symlink staging root accepted")
	}
}
