package casefiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPaths(t *testing.T) {
	s := NewStore("/data")
	if got, want := s.CaseDir("case-1"), filepath.Join("/data", "cases", "case-1"); got != want {
		t.Errorf("CaseDir = %q, want %q", got, want)
	}
	if got, want := s.CollectionDir("case-1", "coll-1"), filepath.Join("/data", "cases", "case-1", "collections", "coll-1"); got != want {
		t.Errorf("CollectionDir = %q, want %q", got, want)
	}
	if got, want := s.UploadPath("case-1", "coll-1"), filepath.Join("/data", "cases", "case-1", "collections", "coll-1", "upload.zip"); got != want {
		t.Errorf("UploadPath = %q, want %q", got, want)
	}
	if got, want := s.EvidenceDir("case-1", "coll-1"), filepath.Join("/data", "cases", "case-1", "collections", "coll-1", "evidence"); got != want {
		t.Errorf("EvidenceDir = %q, want %q", got, want)
	}
	if got, want := s.MetadataPath("case-1", "coll-1"), filepath.Join("/data", "cases", "case-1", "collections", "coll-1", "metadata.json"); got != want {
		t.Errorf("MetadataPath = %q, want %q", got, want)
	}
}

func TestEnsureCollectionDir_CreatesEvidenceDir(t *testing.T) {
	root := t.TempDir()
	s := NewStore(root)

	if err := s.EnsureCollectionDir("case-1", "coll-1"); err != nil {
		t.Fatalf("EnsureCollectionDir: %v", err)
	}
	fi, err := os.Stat(s.EvidenceDir("case-1", "coll-1"))
	if err != nil || !fi.IsDir() {
		t.Fatalf("expected evidence dir to exist: %v", err)
	}
}

func TestEnsureCollectionDir_ClearsPriorState(t *testing.T) {
	root := t.TempDir()
	s := NewStore(root)

	if err := s.EnsureCollectionDir("case-1", "coll-1"); err != nil {
		t.Fatal(err)
	}
	leftover := filepath.Join(s.EvidenceDir("case-1", "coll-1"), "stale-from-crashed-attempt.txt")
	if err := os.WriteFile(leftover, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := s.EnsureCollectionDir("case-1", "coll-1"); err != nil {
		t.Fatalf("EnsureCollectionDir (second call): %v", err)
	}
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Error("expected leftover file from a prior attempt to be removed")
	}
}

func TestEnsureCollectionDir_DoesNotTouchSiblingCollections(t *testing.T) {
	root := t.TempDir()
	s := NewStore(root)

	if err := s.EnsureCollectionDir("case-1", "coll-1"); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(s.EvidenceDir("case-1", "coll-1"), "important-evidence.csv")
	if err := os.WriteFile(marker, []byte("real data"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Creating a second collection in the same case must not disturb the first.
	if err := s.EnsureCollectionDir("case-1", "coll-2"); err != nil {
		t.Fatalf("EnsureCollectionDir for second collection: %v", err)
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("collection-1's evidence was disturbed by creating collection-2: %v", err)
	}
	if string(data) != "real data" {
		t.Errorf("collection-1's evidence content changed: %q", data)
	}
}

func TestRemoveCollectionDir(t *testing.T) {
	root := t.TempDir()
	s := NewStore(root)
	if err := s.EnsureCollectionDir("case-1", "coll-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveCollectionDir("case-1", "coll-1"); err != nil {
		t.Fatalf("RemoveCollectionDir: %v", err)
	}
	if _, err := os.Stat(s.CollectionDir("case-1", "coll-1")); !os.IsNotExist(err) {
		t.Error("expected collection directory to be fully removed")
	}
}

func TestRemoveCollectionDir_LeavesSiblingsIntact(t *testing.T) {
	root := t.TempDir()
	s := NewStore(root)
	if err := s.EnsureCollectionDir("case-1", "coll-1"); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(s.EvidenceDir("case-1", "coll-1"), "keep-me.csv")
	if err := os.WriteFile(marker, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureCollectionDir("case-1", "coll-2"); err != nil {
		t.Fatal(err)
	}

	// Simulate collection-2 failing and being cleaned up.
	if err := s.RemoveCollectionDir("case-1", "coll-2"); err != nil {
		t.Fatalf("RemoveCollectionDir: %v", err)
	}

	if _, err := os.Stat(s.CollectionDir("case-1", "coll-2")); !os.IsNotExist(err) {
		t.Error("expected collection-2's directory to be removed")
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "keep" {
		t.Errorf("collection-1's evidence was affected by removing collection-2: err=%v data=%q", err, data)
	}
}

func TestRemoveCollectionDir_NonexistentIsNotAnError(t *testing.T) {
	s := NewStore(t.TempDir())
	if err := s.RemoveCollectionDir("case-1", "never-created"); err != nil {
		t.Errorf("RemoveCollectionDir on a collection that was never created should be a no-op, got: %v", err)
	}
}

func TestWriteMetadata(t *testing.T) {
	root := t.TempDir()
	s := NewStore(root)
	if err := s.EnsureCollectionDir("case-1", "coll-1"); err != nil {
		t.Fatal(err)
	}

	type sample struct {
		Foo string `json:"foo"`
	}
	if err := s.WriteMetadata("case-1", "coll-1", sample{Foo: "bar"}); err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}
	data, err := os.ReadFile(s.MetadataPath("case-1", "coll-1"))
	if err != nil {
		t.Fatalf("reading metadata.json: %v", err)
	}
	if !strings.Contains(string(data), `"foo": "bar"`) {
		t.Errorf("metadata.json content = %q, want it to contain the marshaled field", data)
	}
}
