package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"tracefall/internal/archive"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

// Server-side ingest pipeline (roadmap item 2).
//
// One job takes a piece of evidence from "bytes on the server" to
// "analysed case" with no analyst interaction and no browser attached:
//
//	discover -> import (everything supported) -> analyze
//
// # Why it is persisted
//
// The previous automatic flow lived in browser JavaScript and died with
// the tab. A job is a row in SQLite. Its (stage, collection_id) pair is a
// checkpoint, written as each stage begins, so after a restart the job
// continues instead of starting over.
//
// # Resume is idempotent by construction
//
//   - discover: skipped once a collection is recorded. If the server died
//     AFTER the collection was committed but BEFORE the checkpoint was
//     saved, the second attempt's discover reports a duplicate of that
//     very collection, and a resumed job (attempts > 1) adopts it. A
//     FIRST attempt that hits a duplicate is a user submitting the same
//     evidence twice, and fails with the duplicate message instead.
//   - import: only files still in the "discovered" state are selected,
//     and importing is already per-file idempotent.
//   - analyze: AnalyzeCase clears and recomputes, so repeating it yields
//     the same result.
//
// # Concurrency
//
// A single worker runs one job at a time. Import and analysis are heavy
// and already hold the case's data; overlapping them would trade
// predictability for throughput, and the host is one machine.
//
// Cancellation is checked between stages. A stage already running is
// allowed to finish, because stopping import mid-file would leave a
// partially parsed file, which the analyst-driven path goes out of its
// way to avoid.

// maxPipelineAttempts bounds how many times a job may be started. A job
// that has taken the server down this many times is failed, not retried.
const maxPipelineAttempts = 3

type pipelineManager struct {
	poll    time.Duration
	uploads uploadLocks
	wake    chan struct{}
}

func newPipelineManager() *pipelineManager {
	return &pipelineManager{poll: time.Second, wake: make(chan struct{}, 1)}
}

func (p *pipelineManager) kick() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// IngestJobParams describe what an ingest job should process. Exactly one
// of UploadID and LocalPath is set.
type IngestJobParams struct {
	UploadID  string `json:"upload_id,omitempty"`
	LocalPath string `json:"local_path,omitempty"`
	// Analyze defaults to true. A pointer so "absent" and "false" differ.
	Analyze *bool `json:"analyze,omitempty"`
}

func (p IngestJobParams) analyze() bool { return p.Analyze == nil || *p.Analyze }

// UploadInit is the body that opens a resumable upload.
type UploadInit struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256,omitempty"`
}

// PipelineProgress is what a running job reports.
type PipelineProgress struct {
	Stage         string `json:"stage"`
	FilesImported int    `json:"files_imported,omitempty"`
	FilesSkipped  int    `json:"files_skipped,omitempty"`
	FilesFailed   int    `json:"files_failed,omitempty"`
}

// PipelineResult is what a finished job reports.
type PipelineResult struct {
	CollectionID  string `json:"collection_id,omitempty"`
	FilesImported int    `json:"files_imported"`
	FilesSkipped  int    `json:"files_skipped"`
	FilesFailed   int    `json:"files_failed"`
	Events        int    `json:"events"`
	Analyzed      bool   `json:"analyzed"`
	Findings      int    `json:"findings"`
	Correlations  int    `json:"correlations"`
	Resumed       bool   `json:"resumed,omitempty"`
}

// EnqueueIngest validates a request and queues it. Everything that can be
// refused immediately is refused here, so the analyst hears it now rather
// than from a failed job later.
func (s *Service) EnqueueIngest(caseID string, p IngestJobParams) (model.PipelineJob, error) {
	if _, err := s.requireEvidenceMutable(caseID); err != nil {
		return model.PipelineJob{}, err
	}
	p.UploadID, p.LocalPath = strings.TrimSpace(p.UploadID), strings.TrimSpace(p.LocalPath)
	if (p.UploadID == "") == (p.LocalPath == "") {
		return model.PipelineJob{}, fmt.Errorf("%w: give exactly one of upload_id or local_path", ErrUploadInvalid)
	}
	if p.UploadID != "" {
		lock := s.pipe.uploads.get(p.UploadID)
		lock.Lock()
		defer lock.Unlock()
		u, err := s.loadUpload(caseID, p.UploadID)
		if err != nil {
			return model.PipelineJob{}, err
		}
		if u.Status != model.UploadComplete {
			return model.PipelineJob{}, fmt.Errorf("%w (status is %q)", ErrUploadNotReady, u.Status)
		}
	}
	params, _ := json.Marshal(p)
	now := time.Now().UTC()
	job := model.PipelineJob{
		ID: uuid.NewString(), CaseID: caseID, Kind: model.JobKindIngest, Status: model.JobQueued,
		Stage: model.StageQueued, Params: string(params), CreatedBy: s.auditActor(), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreatePipelineJob(job); err != nil {
		return model.PipelineJob{}, err
	}
	if p.UploadID != "" {
		// Claimed for this job so the same bytes cannot be queued twice.
		if err := s.store.SetUploadStatus(p.UploadID, model.UploadConsumed, now); err != nil {
			return model.PipelineJob{}, err
		}
	}
	s.audit(caseID, model.AuditPipelineQueued, "pipeline_job", job.ID, "ingest pipeline queued")
	s.pipe.kick()
	return job, nil
}

// GetPipelineJob returns a job that belongs to caseID.
func (s *Service) GetPipelineJob(caseID, jobID string) (model.PipelineJob, error) {
	j, err := s.store.GetPipelineJob(jobID)
	if err != nil {
		return model.PipelineJob{}, err
	}
	if j.CaseID != caseID {
		return model.PipelineJob{}, store.ErrJobNotFound
	}
	return j, nil
}

// ListPipelineJobs lists a case's jobs, newest first.
func (s *Service) ListPipelineJobs(caseID string) ([]model.PipelineJob, error) {
	if _, err := s.GetCase(caseID); err != nil {
		return nil, err
	}
	return s.store.ListPipelineJobs(caseID)
}

// CancelPipelineJob stops a queued job outright, or asks a running one to
// stop at its next stage boundary. Cancelling a finished job is a no-op.
func (s *Service) CancelPipelineJob(caseID, jobID string) error {
	j, err := s.GetPipelineJob(caseID, jobID)
	if err != nil {
		return err
	}
	if model.IsTerminalJobStatus(j.Status) {
		return nil
	}
	now := time.Now().UTC()
	if err := s.store.RequestPipelineJobCancel(jobID, now); err != nil {
		return err
	}
	if j.Status == model.JobQueued {
		if err := s.store.FinishPipelineJob(jobID, model.JobCancelled, model.StageCancelled, "", "cancelled before it started", now); err != nil {
			return err
		}
		s.releaseUpload(j)
		s.audit(caseID, model.AuditPipelineFinished, "pipeline_job", jobID, "ingest pipeline cancelled before it started")
	}
	return nil
}

// RecoverPipeline is called once at startup, before the worker: jobs a
// dead process left running go back to the queue (or fail if they keep
// killing the server).
func (s *Service) RecoverPipeline() (requeued, failed int, err error) {
	return s.store.RequeueInterruptedPipelineJobs(maxPipelineAttempts, time.Now().UTC())
}

// StartPipeline runs the worker until ctx is cancelled or the returned
// stop function is called, and waits for the current job's stage to end.
func (s *Service) StartPipeline(ctx context.Context) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		lastPurge := time.Time{}
		for {
			if ctx.Err() != nil {
				return
			}
			if time.Since(lastPurge) > time.Hour {
				lastPurge = time.Now()
				if n, err := s.PurgeStaleUploads(staleUploadAge); err == nil && n > 0 {
					slog.Info("discarded abandoned uploads", "count", n)
				}
			}
			job, ok, err := s.store.ClaimNextPipelineJob(time.Now().UTC())
			if err != nil {
				slog.Error("pipeline: claiming a job", "error", err)
			}
			if ok {
				s.runPipelineJob(job)
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-s.pipe.wake:
			case <-time.After(s.pipe.poll):
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { cancel(); wg.Wait() }) }
}

// pipelineStop is how a stage ends the job early.
type pipelineStop struct {
	status string
	msg    string
}

func (s *Service) runPipelineJob(job model.PipelineJob) {
	var res PipelineResult
	stop := func() (st *pipelineStop) {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("pipeline: panic", "job", job.ID, "panic", r)
				st = &pipelineStop{model.JobFailed, "the pipeline hit an internal error; see the server log"}
			}
		}()
		return s.executeIngest(job, &res)
	}()

	now := time.Now().UTC()
	status, stage, msg := model.JobSucceeded, model.StageComplete, ""
	if stop != nil {
		status, msg = stop.status, stop.msg
		stage = model.StageFailed
		if status == model.JobCancelled {
			stage = model.StageCancelled
		}
	}
	out, _ := json.Marshal(res)
	if err := s.store.FinishPipelineJob(job.ID, status, stage, string(out), msg, now); err != nil {
		slog.Error("pipeline: recording the outcome", "job", job.ID, "error", err)
	}
	s.releaseUpload(job)
	summary := "ingest pipeline " + status
	if msg != "" {
		summary += ": " + msg
	}
	s.WithActor(Principal{Username: job.CreatedBy}).audit(job.CaseID, model.AuditPipelineFinished, "pipeline_job", job.ID, summary)
}

// releaseUpload deletes a job's uploaded bytes. The evidence has by now
// been copied into the collection (or the job will never use it), so the
// staging copy would only waste disk. A failed job's upload is therefore
// also gone: retrying means uploading again.
func (s *Service) releaseUpload(job model.PipelineJob) {
	var p IngestJobParams
	if json.Unmarshal([]byte(job.Params), &p) != nil || p.UploadID == "" {
		return
	}
	_ = os.Remove(s.files.UploadSessionPath(job.CaseID, p.UploadID))
	s.pipe.uploads.forget(p.UploadID)
}

func (s *Service) cancelRequested(jobID string) bool {
	j, err := s.store.GetPipelineJob(jobID)
	return err == nil && j.CancelRequested
}

func (s *Service) setStage(jobID, stage string, collectionID *string, progress *PipelineProgress) {
	var prog *string
	if progress != nil {
		b, _ := json.Marshal(progress)
		str := string(b)
		prog = &str
	}
	_ = s.store.UpdatePipelineJob(jobID, store.JobUpdate{Stage: &stage, CollectionID: collectionID, Progress: prog}, time.Now().UTC())
}

// executeIngest runs the stages. It returns nil on success.
func (s *Service) executeIngest(job model.PipelineJob, res *PipelineResult) *pipelineStop {
	var p IngestJobParams
	if err := json.Unmarshal([]byte(job.Params), &p); err != nil {
		return &pipelineStop{model.JobFailed, "the job's parameters are unreadable"}
	}
	svc := s.WithActor(Principal{Username: job.CreatedBy})
	res.Resumed = job.Attempts > 1
	collectionID := job.CollectionID

	cancelled := func() *pipelineStop {
		if svc.cancelRequested(job.ID) {
			return &pipelineStop{model.JobCancelled, "cancelled by an analyst"}
		}
		return nil
	}
	fail := func(err error) *pipelineStop {
		return &pipelineStop{model.JobFailed, pipelineErrorMessage(err)}
	}

	// ---- discover
	if collectionID == "" {
		if st := cancelled(); st != nil {
			return st
		}
		svc.setStage(job.ID, model.StageDiscover, nil, &PipelineProgress{Stage: model.StageDiscover})
		var disc DiscoverResult
		var err error
		if p.UploadID != "" {
			disc, err = svc.discoverUploadSession(job.CaseID, p.UploadID)
		} else {
			disc, err = svc.DiscoverEvidenceFromPath(job.CaseID, p.LocalPath)
		}
		var dup *DuplicateEvidenceError
		switch {
		case err == nil:
			collectionID = disc.Collection.ID
		case errors.As(err, &dup) && job.Attempts > 1:
			collectionID = dup.CollectionID // committed before the crash
		default:
			slog.Warn("pipeline: discover failed", "job", job.ID, "error", err)
			return fail(err)
		}
		svc.setStage(job.ID, model.StageImport, &collectionID, nil)
	}
	res.CollectionID = collectionID

	// ---- import
	if st := cancelled(); st != nil {
		return st
	}
	svc.setStage(job.ID, model.StageImport, &collectionID, &PipelineProgress{Stage: model.StageImport})
	ids, err := svc.EvidenceFileIDs(job.CaseID, collectionID, EvidenceFilter{})
	if err != nil {
		return fail(err)
	}
	if len(ids) > 0 {
		imp, err := svc.ImportEvidence(job.CaseID, collectionID, ids)
		if err != nil {
			slog.Warn("pipeline: import failed", "job", job.ID, "error", err)
			return fail(err)
		}
		res.FilesImported, res.FilesSkipped = len(imp.Imported), len(imp.Skipped)
		res.FilesFailed = len(imp.ParseFailures)
	}
	if n, err := s.store.CountEvents(job.CaseID); err == nil {
		res.Events = n
	}
	svc.setStage(job.ID, model.StageImport, &collectionID,
		&PipelineProgress{Stage: model.StageImport, FilesImported: res.FilesImported, FilesSkipped: res.FilesSkipped, FilesFailed: res.FilesFailed})

	// ---- analyze
	if !p.analyze() {
		return nil
	}
	if st := cancelled(); st != nil {
		return st
	}
	svc.setStage(job.ID, model.StageAnalyze, &collectionID, &PipelineProgress{Stage: model.StageAnalyze})
	sum, err := svc.AnalyzeCase(job.CaseID)
	if err != nil {
		slog.Warn("pipeline: analysis failed", "job", job.ID, "error", err)
		return fail(err)
	}
	res.Analyzed, res.Findings, res.Correlations = true, len(sum.Findings), len(sum.Correlations)
	return nil
}

// discoverUploadSession verifies an uploaded file against the digest the
// client declared (if any) and feeds it to the same discovery code a
// single-request upload uses.
func (s *Service) discoverUploadSession(caseID, uploadID string) (DiscoverResult, error) {
	u, err := s.store.GetUploadSession(uploadID)
	if err != nil {
		return DiscoverResult{}, err
	}
	f, err := os.Open(s.files.UploadSessionPath(caseID, uploadID))
	if err != nil {
		return DiscoverResult{}, fmt.Errorf("the uploaded file is no longer on the server: %w", ErrUploadNotReady)
	}
	defer f.Close()
	if u.ClientSHA256 != "" {
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return DiscoverResult{}, err
		}
		if hex.EncodeToString(h.Sum(nil)) != u.ClientSHA256 {
			return DiscoverResult{}, ErrUploadHashMismatch
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return DiscoverResult{}, err
		}
	}
	return s.DiscoverEvidenceFromUpload(caseID, f, u.Filename)
}

// pipelineErrorMessage turns an error into text safe to show a client.
// Errors the analyst can act on are passed through; anything else is
// reduced to a generic sentence, with the detail left in the server log.
func pipelineErrorMessage(err error) string {
	var dup *DuplicateEvidenceError
	var locked *EvidenceLockedError
	switch {
	case errors.As(err, &dup), errors.As(err, &locked),
		errors.Is(err, ErrUploadHashMismatch), errors.Is(err, ErrUploadNotReady),
		errors.Is(err, ErrUploadTooLarge), errors.Is(err, ErrUnsupportedEvidence),
		errors.Is(err, ErrInvalidAD1), errors.Is(err, ErrInvalidDiskImage), errors.Is(err, ErrEvidencePathNotFound),
		errors.Is(err, ErrNoEvidenceFound), errors.Is(err, ErrNotIngested),
		errors.Is(err, ErrCaseNotFound), errors.Is(err, ErrCollectionNotFound):
		return err.Error()
	}
	if errors.Is(err, archive.ErrLimitExceeded) || errors.Is(err, archive.ErrInvalidArchive) || errors.Is(err, archive.ErrUnsafeEntry) {
		return err.Error()
	}
	return "the pipeline failed; see the server log for details"
}
