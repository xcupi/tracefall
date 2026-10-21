package api

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Import progress.
//
// Importing a large selection -- a few thousand files out of an AD1
// image -- takes long enough that a synchronous request tells an
// investigator nothing except that the browser is still waiting. This
// adds the smallest mechanism that fixes that honestly: the import runs
// in a goroutine, and its progress is published to an in-memory job
// record the dashboard polls.
//
// Two design constraints drove this shape:
//
//   - The store opens the database with SetMaxOpenConns(1). A running
//     import therefore holds the only connection for long stretches, so
//     a status poll MUST NOT touch the database or it would block behind
//     the very work it is reporting on. Job state is consequently held
//     in memory only, and reading it never queries anything.
//   - Progress must reflect real work (see below). Nothing here
//     animates, estimates, or interpolates.
//
// Job records are deliberately in-memory and process-lifetime only:
// they are transient UI state, not evidence. Losing them on restart
// costs nothing -- the import either committed its files or it did not,
// and that truth lives in the database where it belongs.

var (
	// ErrImportInProgress means this collection already has a running
	// import. Two concurrent imports of overlapping selections would
	// both "succeed" while each skipped the other's files as already
	// imported, which is confusing rather than harmful -- but there is
	// no reason to allow it, and refusing makes the UI's disabled-button
	// guarantee enforceable on the server too.
	ErrImportInProgress = errors.New("an import is already running for this collection")
	// ErrJobNotFound means the job ID is unknown or has been evicted.
	ErrJobNotFound = errors.New("import job not found")
)

// Import phases. These are the phases that ACTUALLY EXIST in
// Service.ImportEvidence -- no stage is reported that does not
// correspond to code that runs.
const (
	PhaseQueued     = "queued"     // waiting for another import to finish (see Service.SetImportLimit)
	PhasePreparing  = "preparing"  // resolving the selection, before any file is read
	PhaseParsing    = "parsing"    // ImportEvidence phase 1: parse every selected file
	PhaseEnriching  = "enriching"  // phase 2: resolve hosts across the whole batch
	PhasePersisting = "persisting" // phase 3: deduplicate and save
	PhaseFinalizing = "finalizing" // recompute counts, update case status, audit
	PhaseComplete   = "complete"
	PhaseFailed     = "failed"
	// PhaseCancelled is a COMPLETED import that an analyst stopped part
	// way. It is deliberately not PhaseFailed: nothing went wrong, and
	// the files that were imported before the stop are valid evidence.
	PhaseCancelled = "cancelled"
)

// ImportProgress is a point-in-time snapshot of a running import.
//
// Percent is computed from units of real work, never from elapsed time:
// each selected file contributes exactly two units, one when it has been
// parsed and one when it has been persisted. A file that fails to parse
// still consumes both units, because it is equally finished. There is
// therefore no case in which the bar advances without work having
// happened, and none in which it stalls at 99%.
type ImportProgress struct {
	JobID        string `json:"job_id"`
	CaseID       string `json:"case_id"`
	CollectionID string `json:"collection_id"`
	Phase        string `json:"phase"`

	FilesTotal     int `json:"files_total"`
	FilesParsed    int `json:"files_parsed"`
	FilesPersisted int `json:"files_persisted"`
	// Percent is 0-100 and derived only from completed work units. It is
	// omitted (-1) when the total is not yet known, so the UI shows an
	// indeterminate indicator rather than a made-up number.
	Percent int `json:"percent"`

	// CurrentFile is the path of the file being worked on, RELATIVE to
	// the evidence root. Absolute server paths are never published.
	CurrentFile string `json:"current_file,omitempty"`

	EventsParsed  int `json:"events_parsed"`
	EventsSkipped int `json:"events_skipped"`
	ParseErrors   int `json:"parse_errors"`

	// CancelRequested is set the moment cancellation is asked for, and
	// stays set. Cancelled is set only once the import goroutine has
	// actually stopped. The UI needs both: the first lets it show
	// "Cancelling..." immediately instead of leaving the button looking
	// inert, the second is the truth about whether work has ceased.
	CancelRequested bool `json:"cancel_requested"`
	Cancelled       bool `json:"cancelled"`

	StartedAt      time.Time `json:"started_at"`
	ElapsedSeconds int       `json:"elapsed_seconds"`
	Done           bool      `json:"done"`

	// Result is the completed import's outcome, present only once Done
	// and the import succeeded -- exactly what the synchronous endpoint
	// would have returned.
	Result *ImportResult `json:"result,omitempty"`
	// Error is a safe, human-readable failure message when the whole
	// import failed. Per-file parse failures are NOT here: those are
	// normal partial outcomes and appear in Result.ParseFailures.
	Error string `json:"error,omitempty"`
}

// importJob is the mutable state behind an ImportProgress.
//
// Cancellation is a context, not a flag, because the import goroutine
// already runs independently of the request that started it: the HTTP
// request returns as soon as the job exists, so there is no request
// context to inherit and nothing that would cancel this work implicitly.
// A dedicated context gives the running import one thing to check and
// gives cancel-twice the idempotency of context.CancelFunc for free.
type importJob struct {
	mu       sync.Mutex
	progress ImportProgress
	// cancel stops the running import at its next safe point. Calling it
	// more than once is harmless (context.CancelFunc is idempotent), so
	// a double-clicked Cancel button needs no extra guarding.
	cancel context.CancelFunc
	ctx    context.Context
}

// requestCancel asks the import to stop and records that it was asked.
// Idempotent: the second and later calls report that cancellation was
// already requested rather than erroring, because from the analyst's
// point of view clicking Cancel twice should mean the same thing as
// clicking it once.
func (j *importJob) requestCancel() {
	j.mu.Lock()
	alreadyDone := j.progress.Done
	j.progress.CancelRequested = true
	j.mu.Unlock()
	// Cancelling a finished job is a no-op rather than an error: the
	// import may well have completed while the click was in flight.
	if !alreadyDone {
		j.cancel()
	}
}

// cancelled reports whether this job has been asked to stop.
func (j *importJob) cancelled() bool {
	if j == nil || j.ctx == nil {
		return false
	}
	select {
	case <-j.ctx.Done():
		return true
	default:
		return false
	}
}

func (j *importJob) snapshot() ImportProgress {
	j.mu.Lock()
	defer j.mu.Unlock()
	p := j.progress
	if !p.Done {
		p.ElapsedSeconds = int(time.Since(p.StartedAt).Seconds())
	}
	return p
}

func (j *importJob) update(fn func(p *ImportProgress)) {
	j.mu.Lock()
	defer j.mu.Unlock()
	fn(&j.progress)
	j.progress.ElapsedSeconds = int(time.Since(j.progress.StartedAt).Seconds())
	j.progress.Percent = percentOf(j.progress)
}

// percentOf derives completion from work units actually finished. When
// nothing is selected there is no work and the import is trivially
// complete; when the total is unknown the caller gets -1 and shows an
// indeterminate indicator.
func percentOf(p ImportProgress) int {
	if p.Done {
		return 100
	}
	if p.FilesTotal <= 0 {
		return -1
	}
	total := p.FilesTotal * 2
	done := p.FilesParsed + p.FilesPersisted
	if done > total {
		done = total
	}
	pct := done * 100 / total
	// Never report 100 before the job is actually finished: finalizing
	// still has to run, and a bar that sits at 100% while work continues
	// is the same lie as a fake one.
	if pct >= 100 {
		pct = 99
	}
	return pct
}

// progressSink is how ImportEvidence reports what it is doing. It is an
// interface with a nil-safe wrapper so the synchronous code path stays
// exactly as it was -- one implementation of the import, two ways to
// call it.
type progressSink struct{ job *importJob }

// cancelled is how importEvidence asks whether it should stop. Nil-safe,
// so the synchronous import path (which has no job) simply never
// cancels.
func (s *progressSink) cancelled() bool {
	if s == nil || s.job == nil {
		return false
	}
	return s.job.cancelled()
}

// context is the context of the import this sink reports on: cancelling the
// job ends it. Nil-safe; the synchronous path has no job.
func (s *progressSink) context() context.Context {
	if s == nil || s.job == nil || s.job.ctx == nil {
		return nil
	}
	return s.job.ctx
}

func (s *progressSink) phase(name string) {
	if s == nil || s.job == nil {
		return
	}
	s.job.update(func(p *ImportProgress) { p.Phase = name; p.CurrentFile = "" })
}

func (s *progressSink) startFile(relPath string) {
	if s == nil || s.job == nil {
		return
	}
	s.job.update(func(p *ImportProgress) { p.CurrentFile = relPath })
}

func (s *progressSink) fileParsed(events int, failed bool) {
	if s == nil || s.job == nil {
		return
	}
	s.job.update(func(p *ImportProgress) {
		p.FilesParsed++
		p.EventsParsed += events
		if failed {
			p.ParseErrors++
			// A file that failed to parse never reaches the persist
			// phase, so its persist unit is consumed here -- otherwise
			// the bar could never reach 100% on a batch with failures.
			p.FilesPersisted++
		}
	})
}

func (s *progressSink) filePersisted(newEvents, duplicateEvents int) {
	if s == nil || s.job == nil {
		return
	}
	s.job.update(func(p *ImportProgress) {
		p.FilesPersisted++
		p.EventsSkipped += duplicateEvents
	})
}

// setTotal publishes how many files the import will actually work on,
// which is known only after the selection has been resolved.
func (s *progressSink) setTotal(n int) {
	if s == nil || s.job == nil {
		return
	}
	s.job.update(func(p *ImportProgress) { p.FilesTotal = n })
}

// ---------- job registry ----------

// importJobs holds running and recently-finished jobs.
type importJobs struct {
	mu     sync.Mutex
	byID   map[string]*importJob
	active map[string]string // collectionID -> jobID, for the one-at-a-time guarantee
}

func newImportJobs() *importJobs {
	return &importJobs{byID: map[string]*importJob{}, active: map[string]string{}}
}

// StartImport begins an import in the background and returns its job ID.
//
// Exactly one import may run per collection at a time; a second attempt
// returns ErrImportInProgress rather than racing. That is what makes the
// dashboard's disabled Import button a real guarantee instead of a
// client-side courtesy -- a double-submit, a second browser tab, or a
// replayed request all hit the same guard.
func (s *Service) StartImport(caseID, collectionID string, sourceFileIDs []string) (string, error) {
	// Validate before creating a job, so a bad request fails fast with a
	// proper status instead of producing a job that immediately fails.
	// The lock is checked here as well as inside importEvidence: without
	// it a locked case would accept the request, create a job, and only
	// then fail in the background, where the analyst would see it as a
	// mysterious failed import rather than a clear refusal.
	if _, err := s.requireEvidenceMutable(caseID); err != nil {
		return "", err
	}
	collection, err := s.store.GetCollection(collectionID)
	if err != nil || collection.CaseID != caseID {
		return "", ErrCollectionNotFound
	}

	s.jobs.mu.Lock()
	if existing, running := s.jobs.active[collectionID]; running {
		s.jobs.mu.Unlock()
		_ = existing
		return "", ErrImportInProgress
	}
	jobID := uuid.NewString()
	// context.Background, not the request's context: the import
	// deliberately outlives the HTTP request that started it, and
	// inheriting that context would cancel every import the instant its
	// starting request returned.
	ctx, cancel := context.WithCancel(context.Background())
	job := &importJob{
		ctx:    ctx,
		cancel: cancel,
		progress: ImportProgress{
			JobID: jobID, CaseID: caseID, CollectionID: collectionID,
			Phase: PhasePreparing, FilesTotal: len(sourceFileIDs),
			StartedAt: time.Now().UTC(), Percent: 0,
		}}
	s.jobs.byID[jobID] = job
	s.jobs.active[collectionID] = jobID
	s.jobs.mu.Unlock()

	go func() {
		defer func() {
			s.jobs.mu.Lock()
			delete(s.jobs.active, collectionID)
			s.jobs.mu.Unlock()
		}()
		// A panic in a background goroutine would take the whole server
		// down, unlike the synchronous path where it would only fail one
		// request. Recovering keeps a malformed-evidence bug contained
		// to the job that hit it.
		defer func() {
			if r := recover(); r != nil {
				job.update(func(p *ImportProgress) {
					p.Phase, p.Done, p.Error = PhaseFailed, true, "the import failed unexpectedly"
				})
			}
		}()

		res, err := s.importEvidence(caseID, collectionID, sourceFileIDs, &progressSink{job: job})
		// The context is released whatever happens, so a completed
		// import does not leak one.
		defer cancel()
		job.update(func(p *ImportProgress) {
			p.Done = true
			p.CurrentFile = ""
			if err != nil {
				p.Phase, p.Error = PhaseFailed, safeImportError(err)
				return
			}
			// A cancelled import still returns a real result: the files
			// it did import are evidence, and the counts describe what
			// actually happened. Reporting it as a failure would be a
			// lie about valid evidence.
			if res.Cancelled {
				p.Phase = PhaseCancelled
				p.Cancelled = true
			} else {
				p.Phase = PhaseComplete
			}
			p.Result = &res
		})
	}()

	return jobID, nil
}

// ImportJob returns a snapshot of one job's progress.
func (s *Service) ImportJob(caseID, jobID string) (ImportProgress, error) {
	s.jobs.mu.Lock()
	job, ok := s.jobs.byID[jobID]
	s.jobs.mu.Unlock()
	if !ok {
		return ImportProgress{}, ErrJobNotFound
	}
	p := job.snapshot()
	// Scope the job to its case, so a job ID from one case can never be
	// read through another.
	if p.CaseID != caseID {
		return ImportProgress{}, ErrJobNotFound
	}
	return p, nil
}

// CancelImport asks a running import to stop at its next safe point.
//
// IDEMPOTENT by construction, which matters because every realistic way
// this gets called twice is normal user behaviour: a double click, a
// retried request, a second browser tab. All of these return the current
// progress rather than an error.
//
// Cancelling an import that has already finished is likewise not an
// error -- the import may have completed while the click was in flight,
// which is a race the analyst cannot see and should not be punished for.
// The caller gets the final progress and can see for itself that the
// import completed.
func (s *Service) CancelImport(caseID, jobID string) (ImportProgress, error) {
	s.jobs.mu.Lock()
	job, ok := s.jobs.byID[jobID]
	s.jobs.mu.Unlock()
	if !ok {
		return ImportProgress{}, ErrJobNotFound
	}
	// Scope to the case, exactly as ImportJob does: a job ID from one
	// case must never be controllable through another.
	if job.snapshot().CaseID != caseID {
		return ImportProgress{}, ErrJobNotFound
	}
	job.requestCancel()
	return job.snapshot(), nil
}

// safeImportError renders a whole-import failure for the browser without
// leaking server internals. The detailed error is still returned to the
// caller of importEvidence and logged there; this is only what a user
// sees.
func safeImportError(err error) string {
	switch {
	case errors.Is(err, ErrCaseNotFound):
		return "case not found"
	case errors.Is(err, ErrCollectionNotFound):
		return "evidence collection not found"
	default:
		return "the import failed; see the server log for details"
	}
}
