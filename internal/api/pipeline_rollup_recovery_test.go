package api

import (
	"os"
	"path/filepath"
	"testing"
	"time"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

func TestPipelineResumeReconcilesCommittedSourceRollups(t *testing.T) {
	testCommittedRollupRecovery(t, false)
}

func TestPipelineCancelledResumeReconcilesCommittedSourceRollups(t *testing.T) {
	testCommittedRollupRecovery(t, true)
}

func testCommittedRollupRecovery(t *testing.T, cancel bool) {
	svc := newTestService(t)
	c, err := svc.CreateCase("rollup recovery", "")
	if err != nil {
		t.Fatal(err)
	}
	other, err := svc.CreateCase("unrelated analysis", "")
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
		t.Fatalf("files: %v", err)
	}
	// Model the durable state immediately after source admission, before rollup.
	if _, err := svc.store.MarkSourceFileImported(files[0].ID, 3, time.Now().UTC(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.store.DB().Exec(`UPDATE cases SET analyzed_at=? WHERE id IN (?,?)`, time.Now().UTC().Format(time.RFC3339Nano), c.ID, other.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{c.ID, other.ID} {
		if err := svc.store.UpdateCaseStatus(id, model.CaseStatusAnalyzed); err != nil {
			t.Fatal(err)
		}
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
	if cancel {
		if err := svc.store.RequestPipelineJobCancel(j.ID, now); err != nil {
			t.Fatal(err)
		}
	}
	if n, f, err := svc.RecoverPipeline(); err != nil || n != 1 || f != 0 {
		t.Fatalf("recover: %d/%d %v", n, f, err)
	}
	startWorker(t, svc)
	done := waitPipelineJob(t, routerFor(svc), c.ID, j.ID)
	wantStatus := model.JobSucceeded
	if cancel {
		wantStatus = model.JobCancelled
	}
	if done.Status != wantStatus || done.Attempts != 2 || num(done.Result, "files_imported") != 0 {
		t.Fatalf("job: %+v", done)
	}
	got, err := svc.store.GetCollection(col)
	if err != nil || got.ImportedFileCount != 1 || got.ParsedEventCount != 3 || got.IngestionStatus != model.CollectionStatusIngested {
		t.Fatalf("unreconciled committed source: %+v err=%v", got, err)
	}
	state, err := svc.store.GetCase(c.ID)
	if err != nil || state.Status != model.CaseStatusIngested {
		t.Fatalf("stale analysis: %+v %v", state, err)
	}
	state, err = svc.store.GetCase(other.ID)
	if err != nil || state.Status != model.CaseStatusAnalyzed {
		t.Fatalf("unrelated analysis reset: %+v %v", state, err)
	}
	// A failure between rollup and invalidation must roll back BOTH writes.
	if _, err := svc.store.DB().Exec(`UPDATE collections SET imported_file_count=0,parsed_event_count=0 WHERE id=?`, col); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.store.DB().Exec(`CREATE TRIGGER reject_case_invalidation BEFORE UPDATE ON cases BEGIN SELECT RAISE(ABORT,'injected invalidation failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.ReconcileCollectionImports(c.ID, col); err == nil {
		t.Fatal("invalidation failure ignored")
	}
	got, err = svc.store.GetCollection(col)
	if err != nil || got.ImportedFileCount != 0 || got.ParsedEventCount != 0 {
		t.Fatalf("rollup committed without invalidation: %+v %v", got, err)
	}
	if _, err := svc.store.DB().Exec(`DROP TRIGGER reject_case_invalidation`); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.ReconcileCollectionImports(other.ID, col); err == nil {
		t.Fatal("cross-case reconciliation accepted")
	}
	if err := svc.store.ReconcileCollectionImports(c.ID, col); err != nil {
		t.Fatal(err)
	}
	// A no-op invocation must not stale a later analysis or add counts twice.
	if err := svc.store.UpdateCaseStatus(c.ID, model.CaseStatusAnalyzed); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := svc.ImportEvidence(c.ID, col, []string{files[0].ID}); err != nil {
			t.Fatal(err)
		}
		got, _ = svc.store.GetCollection(col)
		state, _ = svc.store.GetCase(c.ID)
		if got.ImportedFileCount != 1 || got.ParsedEventCount != 3 || state.Status != model.CaseStatusAnalyzed {
			t.Fatalf("non-idempotent retry: %+v %+v", got, state)
		}
	}
}
