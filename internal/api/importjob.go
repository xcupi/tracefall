package api

import (
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
	PhasePreparing  = "preparing"  // resolving the selection, before any file is read
	PhaseParsing    = "parsing"    // ImportEvidence phase 1: parse every selected file
	PhaseEnriching  = "enriching"  // phase 2: resolve hosts across the whole batch
	PhasePersisting = "persisting" // phase 3: deduplicate and save
	PhaseFinalizing = "finalizing" // recompute counts, update case status, audit
	PhaseComplete   = "complete"
	PhaseFailed     = "failed"
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
type importJob struct {
	mu       sync.Mutex
	progress ImportProgress
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
	if _, err := s.GetCase(caseID); err != nil {
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
	job := &importJob{progress: ImportProgress{
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
		job.update(func(p *ImportProgress) {
			p.Done = true
			p.CurrentFile = ""
			if err != nil {
				p.Phase, p.Error = PhaseFailed, safeImportError(err)
				return
			}
			p.Phase = PhaseComplete
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
