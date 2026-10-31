package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
	"tracefall/internal/model"
)

func TestWMIBundleSourceIndexUpgradePreservesOrdinaryUniqueness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source-index.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	seedCaseAndSourceFile(t, s)
	if _, err = s.db.Exec(`DROP INDEX idx_source_files_collection_sha256_active; CREATE UNIQUE INDEX idx_source_files_collection_sha256_active ON source_files(collection_id,sha256) WHERE import_status='imported' AND deleted_at=''`); err != nil {
		t.Fatal(err)
	}
	rows := []model.SourceFile{}
	for _, id := range []string{"wmi01", "wmi02", "ordinary01", "ordinary02"} {
		artifact, sha := model.ArtifactWMIRepository, "literal-primary-sha"
		if id == "ordinary01" || id == "ordinary02" {
			artifact, sha = model.ArtifactWindowsEventLog, "ordinary-sha"
		}
		rows = append(rows, model.SourceFile{ID: id, CaseID: "case-1", CollectionID: "collection-1", Path: id, OriginalFilename: id, ArtifactType: artifact, SHA256: sha, ImportStatus: model.SourceFileDiscovered})
	}
	if err = s.SaveSourceFiles(rows); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, id := range []string{"wmi01", "wmi02", "ordinary01"} {
		if applied, err := s.MarkSourceFileImported(id, 0, time.Now()); err != nil || !applied {
			t.Fatalf("source index upgrade %s applied=%v err=%v", id, applied, err)
		}
	}
	if _, err := s.MarkSourceFileImported("ordinary02", 0, time.Now()); !errors.Is(err, ErrDuplicateSourceFile) {
		t.Fatalf("ordinary artifact dedup weakened: %v", err)
	}
	sf, err := s.GetSourceFile("wmi02")
	if err != nil || sf.SHA256 != "literal-primary-sha" {
		t.Fatal("migration rewrote source evidence hash")
	}
	if err := enforceSourceFileUniquenessPerCollection(s.db); err != nil {
		t.Fatal("source-index migration is not idempotent")
	}
	got, err := s.ListSourceFilesByCollection("collection-1")
	if err != nil || len(got) != 5 {
		t.Fatal("index upgrade lost catalog rows")
	}
}
