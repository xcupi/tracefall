package store

import (
	"errors"
	"testing"
	"time"

	"tracefall/internal/model"
)

func seedCase(t *testing.T, s *Store, id string) {
	t.Helper()
	now := time.Now().UTC()
	if err := s.CreateCase(model.Case{ID: id, Name: "case " + id, Status: model.CaseStatusCreated, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
}

func newJob(id, caseID string, at time.Time) model.PipelineJob {
	return model.PipelineJob{
		ID: id, CaseID: caseID, Kind: model.JobKindIngest, Status: model.JobQueued, Stage: model.StageQueued,
		Params: `{"local_path":"/x"}`, CreatedBy: "local-user", CreatedAt: at, UpdatedAt: at,
	}
}

func TestPipelineJob_RoundTrip(t *testing.T) {
	s := openTest(t)
	seedCase(t, s, "c1")
	at := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.CreatePipelineJob(newJob("j1", "c1", at)); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPipelineJob("j1")
	if err != nil {
		t.Fatal(err)
	}
	if got.CaseID != "c1" || got.Status != model.JobQueued || got.Stage != model.StageQueued ||
		got.Params != `{"local_path":"/x"}` || got.Attempts != 0 || got.CreatedBy != "local-user" || !got.CreatedAt.Equal(at) {
		t.Errorf("round trip lost data: %+v", got)
	}
	if got.StartedAt != nil || got.FinishedAt != nil {
		t.Error("a queued job must not carry start or finish times")
	}
	if _, err := s.GetPipelineJob("nope"); !errors.Is(err, ErrJobNotFound) {
		t.Errorf("missing job error = %v, want ErrJobNotFound", err)
	}
}

func TestPipelineJob_ClaimIsOldestFirstAndExactlyOnce(t *testing.T) {
	s := openTest(t)
	seedCase(t, s, "c1")
	base := time.Now().UTC()
	_ = s.CreatePipelineJob(newJob("late", "c1", base.Add(2*time.Second)))
	_ = s.CreatePipelineJob(newJob("early", "c1", base))

	a, ok, err := s.ClaimNextPipelineJob(base.Add(time.Minute))
	if err != nil || !ok || a.ID != "early" {
		t.Fatalf("first claim = %+v ok=%v err=%v, want the oldest job", a, ok, err)
	}
	if a.Status != model.JobRunning || a.Attempts != 1 || a.StartedAt == nil {
		t.Errorf("a claimed job must be running with attempts=1 and a start time: %+v", a)
	}
	b, ok, _ := s.ClaimNextPipelineJob(base.Add(time.Minute))
	if !ok || b.ID != "late" {
		t.Fatalf("second claim = %+v ok=%v", b, ok)
	}
	if _, ok, _ := s.ClaimNextPipelineJob(base.Add(time.Minute)); ok {
		t.Error("a job was claimed twice")
	}
	stored, _ := s.GetPipelineJob("early")
	if stored.Status != model.JobRunning {
		t.Errorf("claim was not persisted: %q", stored.Status)
	}
}

func TestPipelineJob_UpdateAndFinish(t *testing.T) {
	s := openTest(t)
	seedCase(t, s, "c1")
	now := time.Now().UTC()
	_ = s.CreatePipelineJob(newJob("j1", "c1", now))
	_, _, _ = s.ClaimNextPipelineJob(now)

	stage, coll, prog := model.StageImport, "col-9", `{"files_parsed":3}`
	if err := s.UpdatePipelineJob("j1", JobUpdate{Stage: &stage, CollectionID: &coll, Progress: &prog}, now); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetPipelineJob("j1")
	if got.Stage != model.StageImport || got.CollectionID != "col-9" || got.Progress != `{"files_parsed":3}` {
		t.Errorf("update not stored: %+v", got)
	}

	// A partial update leaves the other fields alone.
	stage2 := model.StageAnalyze
	_ = s.UpdatePipelineJob("j1", JobUpdate{Stage: &stage2}, now)
	got, _ = s.GetPipelineJob("j1")
	if got.CollectionID != "col-9" || got.Progress != `{"files_parsed":3}` || got.Stage != model.StageAnalyze {
		t.Errorf("a partial update clobbered other fields: %+v", got)
	}

	if err := s.FinishPipelineJob("j1", model.JobSucceeded, model.StageComplete, `{"findings":2}`, "", now); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetPipelineJob("j1")
	if got.Status != model.JobSucceeded || got.Stage != model.StageComplete || got.Result != `{"findings":2}` || got.FinishedAt == nil {
		t.Errorf("finish not stored: %+v", got)
	}
	if _, ok, _ := s.ClaimNextPipelineJob(now); ok {
		t.Error("a finished job was claimed")
	}
}

func TestPipelineJob_UpdatesCannotReviveAFinishedJob(t *testing.T) {
	s := openTest(t)
	seedCase(t, s, "c1")
	now := time.Now().UTC()
	_ = s.CreatePipelineJob(newJob("j1", "c1", now))
	_, _, _ = s.ClaimNextPipelineJob(now)
	_ = s.FinishPipelineJob("j1", model.JobFailed, model.StageFailed, "", "boom", now)

	stage := model.StageImport
	_ = s.UpdatePipelineJob("j1", JobUpdate{Stage: &stage}, now)
	got, _ := s.GetPipelineJob("j1")
	if got.Stage != model.StageFailed || got.Status != model.JobFailed || got.Error != "boom" {
		t.Errorf("a late progress write overwrote a final state: %+v", got)
	}
}

func TestPipelineJob_RestartRequeuesRunningAndKeepsTheCheckpoint(t *testing.T) {
	s := openTest(t)
	seedCase(t, s, "c1")
	now := time.Now().UTC()
	_ = s.CreatePipelineJob(newJob("interrupted", "c1", now))
	_, _, _ = s.ClaimNextPipelineJob(now)
	stage, coll := model.StageImport, "col-1"
	_ = s.UpdatePipelineJob("interrupted", JobUpdate{Stage: &stage, CollectionID: &coll}, now)

	_ = s.CreatePipelineJob(newJob("waiting", "c1", now))
	_ = s.CreatePipelineJob(newJob("done", "c1", now))
	_ = s.FinishPipelineJob("done", model.JobSucceeded, model.StageComplete, "", "", now)

	requeued, failed, err := s.RequeueInterruptedPipelineJobs(3, now)
	if err != nil || requeued != 1 || failed != 0 {
		t.Fatalf("requeued=%d failed=%d err=%v, want 1/0", requeued, failed, err)
	}
	got, _ := s.GetPipelineJob("interrupted")
	if got.Status != model.JobQueued || got.Stage != model.StageImport || got.CollectionID != "col-1" {
		t.Errorf("an interrupted job must go back to queued WITH its stage and collection: %+v", got)
	}
	if done, _ := s.GetPipelineJob("done"); done.Status != model.JobSucceeded {
		t.Error("a finished job was disturbed by recovery")
	}
	// Claiming it again counts as a second attempt.
	var second model.PipelineJob
	for i := 0; i < 2; i++ {
		c, ok, _ := s.ClaimNextPipelineJob(now.Add(time.Second))
		if ok && c.ID == "interrupted" {
			second = c
		}
	}
	if second.Attempts != 2 {
		t.Errorf("attempts after resume = %d, want 2", second.Attempts)
	}
}

func TestPipelineJob_RestartGivesUpOnAJobThatKeepsDying(t *testing.T) {
	s := openTest(t)
	seedCase(t, s, "c1")
	now := time.Now().UTC()
	_ = s.CreatePipelineJob(newJob("poison", "c1", now))
	for i := 0; i < 3; i++ {
		if _, ok, _ := s.ClaimNextPipelineJob(now); !ok {
			t.Fatalf("claim %d found nothing", i)
		}
		if i < 2 {
			if _, _, err := s.RequeueInterruptedPipelineJobs(3, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	requeued, failed, _ := s.RequeueInterruptedPipelineJobs(3, now)
	if requeued != 0 || failed != 1 {
		t.Fatalf("requeued=%d failed=%d, want 0/1: a job that crashed the server three times must stop retrying", requeued, failed)
	}
	got, _ := s.GetPipelineJob("poison")
	if got.Status != model.JobFailed || got.Error == "" {
		t.Errorf("gave up without saying why: %+v", got)
	}
}

func TestPipelineJob_CancelIsRecordedAndASecondRequestIsHarmless(t *testing.T) {
	s := openTest(t)
	seedCase(t, s, "c1")
	now := time.Now().UTC()
	_ = s.CreatePipelineJob(newJob("j1", "c1", now))
	for i := 0; i < 2; i++ {
		if err := s.RequestPipelineJobCancel("j1", now); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := s.GetPipelineJob("j1")
	if !got.CancelRequested {
		t.Error("cancel request not stored")
	}
	if err := s.RequestPipelineJobCancel("missing", now); !errors.Is(err, ErrJobNotFound) {
		t.Errorf("cancelling a missing job = %v, want ErrJobNotFound", err)
	}
}

func TestPipelineJob_ListIsPerCaseNewestFirst(t *testing.T) {
	s := openTest(t)
	seedCase(t, s, "c1")
	seedCase(t, s, "c2")
	base := time.Now().UTC()
	_ = s.CreatePipelineJob(newJob("a", "c1", base))
	_ = s.CreatePipelineJob(newJob("b", "c1", base.Add(time.Second)))
	_ = s.CreatePipelineJob(newJob("other", "c2", base))
	got, err := s.ListPipelineJobs("c1")
	if err != nil || len(got) != 2 || got[0].ID != "b" || got[1].ID != "a" {
		t.Errorf("list = %+v err=%v", got, err)
	}
}

func TestPipelineJob_DeletingACaseRemovesItsJobsAndUploads(t *testing.T) {
	s := openTest(t)
	seedCase(t, s, "c1")
	now := time.Now().UTC()
	_ = s.CreatePipelineJob(newJob("j1", "c1", now))
	_ = s.CreateUploadSession(model.UploadSession{ID: "u1", CaseID: "c1", Filename: "a.zip", Size: 10, Status: model.UploadOpen, CreatedBy: "x", CreatedAt: now, UpdatedAt: now})
	if err := s.DeleteCase("c1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPipelineJob("j1"); !errors.Is(err, ErrJobNotFound) {
		t.Error("a deleted case left its jobs behind")
	}
	if _, err := s.GetUploadSession("u1"); !errors.Is(err, ErrUploadNotFound) {
		t.Error("a deleted case left its upload sessions behind")
	}
}

func TestUploadSession_AdvanceIsCompareAndSwap(t *testing.T) {
	s := openTest(t)
	seedCase(t, s, "c1")
	now := time.Now().UTC()
	_ = s.CreateUploadSession(model.UploadSession{ID: "u1", CaseID: "c1", Filename: "a.zip", Size: 100, Status: model.UploadOpen, CreatedBy: "x", CreatedAt: now, UpdatedAt: now})

	if err := s.AdvanceUpload("u1", 0, 40, now); err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceUpload("u1", 0, 40, now); !errors.Is(err, ErrUploadOffsetConflict) {
		t.Errorf("replaying an offset = %v, want ErrUploadOffsetConflict", err)
	}
	if err := s.AdvanceUpload("u1", 40, 100, now); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetUploadSession("u1")
	if got.Received != 100 || got.Size != 100 {
		t.Errorf("received = %d", got.Received)
	}
	if err := s.AdvanceUpload("ghost", 0, 1, now); !errors.Is(err, ErrUploadNotFound) {
		t.Errorf("advancing a missing session = %v", err)
	}
}

func TestUploadSession_AdvanceRefusesAClosedSession(t *testing.T) {
	s := openTest(t)
	seedCase(t, s, "c1")
	now := time.Now().UTC()
	_ = s.CreateUploadSession(model.UploadSession{ID: "u1", CaseID: "c1", Filename: "a.zip", Size: 100, Status: model.UploadOpen, CreatedBy: "x", CreatedAt: now, UpdatedAt: now})
	_ = s.SetUploadStatus("u1", model.UploadAborted, now)
	if err := s.AdvanceUpload("u1", 0, 10, now); err == nil {
		t.Error("bytes were accepted into an aborted upload")
	}
}

func TestUploadSession_StaleOpenSessionsAreListed(t *testing.T) {
	s := openTest(t)
	seedCase(t, s, "c1")
	old := time.Now().UTC().Add(-10 * 24 * time.Hour)
	fresh := time.Now().UTC()
	_ = s.CreateUploadSession(model.UploadSession{ID: "old", CaseID: "c1", Filename: "a", Size: 1, Status: model.UploadOpen, CreatedBy: "x", CreatedAt: old, UpdatedAt: old})
	_ = s.CreateUploadSession(model.UploadSession{ID: "new", CaseID: "c1", Filename: "b", Size: 1, Status: model.UploadOpen, CreatedBy: "x", CreatedAt: fresh, UpdatedAt: fresh})
	_ = s.CreateUploadSession(model.UploadSession{ID: "done", CaseID: "c1", Filename: "c", Size: 1, Status: model.UploadConsumed, CreatedBy: "x", CreatedAt: old, UpdatedAt: old})

	got, err := s.ListStaleOpenUploads(time.Now().UTC().Add(-7 * 24 * time.Hour))
	if err != nil || len(got) != 1 || got[0].ID != "old" {
		t.Errorf("stale = %+v err=%v, want only the idle open session", got, err)
	}
}
