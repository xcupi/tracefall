package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Storage is closed to other users, including when it already exists with
// looser modes (an upgrade from a version that created it 0755/0644).
func TestLockDownStorage_RestrictsExistingLooseModes(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	db := filepath.Join(root, "t.db")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{db, db + "-wal", db + "-shm"} {
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := lockDownStorage(data, db); err != nil {
		t.Fatal(err)
	}
	check := func(p string, want os.FileMode) {
		t.Helper()
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != want {
			t.Errorf("%s: mode %o, want %o", filepath.Base(p), got, want)
		}
	}
	check(data, 0o700)
	check(db, 0o600)
	check(db+"-wal", 0o600)
	check(db+"-shm", 0o600)
}

func TestLockDownStorage_CreatesWhatIsMissing(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "new", "data")
	db := filepath.Join(root, "newdb", "t.db")
	if err := lockDownStorage(data, db); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{data: 0o700, db: 0o600} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != want {
			t.Errorf("%s: %v mode %v, want %o", p, err, st, want)
		}
	}
}
