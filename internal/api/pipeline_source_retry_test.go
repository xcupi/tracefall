package api

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/store"
)

func TestPipelineResumeRetriesEvidenceFreeFailedSource(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("failed source restart", "")
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
	analyze := false
	j, err := svc.EnqueueIngest(c.ID, IngestJobParams{LocalPath: root, Analyze: &analyze})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, _, err := svc.store.ClaimNextPipelineJob(now); err != nil {
		t.Fatal(err)
	}
	stage, col := model.StageImport, d.Collection.ID
	if err := svc.store.UpdatePipelineJob(j.ID, store.JobUpdate{Stage: &stage, CollectionID: &col}, now); err != nil {
		t.Fatal(err)
	}
	// The worker failed and status was stored, then the server died before the
	// pipeline could finalize. Recovery must not skip it and report empty success.
	if err := svc.store.MarkSourceFileFailed(files[0].ID); err != nil {
		t.Fatal(err)
	}
	if n, failed, err := svc.RecoverPipeline(); err != nil || n != 1 || failed != 0 {
		t.Fatalf("recover: %d/%d %v", n, failed, err)
	}
	startWorker(t, svc)
	done := waitPipelineJob(t, routerFor(svc), c.ID, j.ID)
	if done.Status != model.JobSucceeded || done.Attempts != 2 || num(done.Result, "events") != 1 || num(done.Result, "files_imported") != 1 {
		t.Fatalf("failed source omitted on resume: %+v", done)
	}
	sf, err := svc.store.GetSourceFile(files[0].ID)
	if err != nil || sf.ImportStatus != model.SourceFileImported || sf.EventCount != 1 {
		t.Fatalf("source after recovery: %s count=%d err=%v", sf.ImportStatus, sf.EventCount, err)
	}
}
