package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"tracefall/internal/model"
)

func TestPersistZeroEventSourceInvalidatesAnalysisAtomically(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("zero event source", "")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ERRORLOG"), []byte("2025-01-02 03:04:05.00 Server Microsoft SQL Server informational message\n"), 0600); err != nil {
		t.Fatal(err)
	}
	d, err := svc.DiscoverEvidenceFromPath(c.ID, root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := svc.store.ListSourceFilesByCollection(d.Collection.ID)
	if err != nil || len(files) != 1 {
		t.Fatalf("sources: %v", err)
	}
	if err := svc.store.UpdateCaseStatus(c.ID, model.CaseStatusAnalyzed); err != nil {
		t.Fatal(err)
	}
	n, applied, err := svc.persistSource(context.Background(), pendingImport{sourceFile: files[0]}, c.ID, d.Collection.ID, func() bool { return false })
	if err != nil || !applied || n != 0 {
		t.Fatalf("zero source: n=%d applied=%v err=%v", n, applied, err)
	}
	var status string
	if err := svc.store.DB().QueryRow(`SELECT status FROM cases WHERE id=?`, c.ID).Scan(&status); err != nil || status != model.CaseStatusIngested {
		t.Fatalf("zero-event source committed with stale analysis: %s %v", status, err)
	}
}
