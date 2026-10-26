//go:build linux || darwin

package parsestaging

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceRecoveryRequiresExclusiveOwnership(t *testing.T) {
	root := filepath.Join(t.TempDir(), "parser-staging")
	w, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	p := filepath.Join(root, "tracefall-parse-abcd.partial")
	if err := os.WriteFile(p, []byte("incomplete staging"), 0600); err != nil {
		t.Fatal(err)
	}
	other, err := Open(root)
	if err == nil {
		other.Close()
		t.Fatal("live staging workspace admitted a second owner")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("live staging removed: %v", err)
	}
	keep := filepath.Join(root, "unrelated")
	if err := os.WriteFile(keep, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	w.Close()
	recovered, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("abandoned staging not recovered: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("unrelated file touched: %v", err)
	}
}
