package api

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"tracefall/internal/store"
)

// Deletion progress.
//
// # What the backend can actually report, and why it is stages
//
// Case deletion is SYNCHRONOUS and TRANSACTIONAL. Every database row
// goes in ONE transaction of bulk `DELETE ... WHERE case_id = ?`
// statements; the evidence directory is then removed in one pass. There
// is no loop over records to count through.
//
// That rules out a per-record numerator. "1,205 of 2,319 events
// deleted" is never a true statement about this implementation: before
// the commit none are deleted, after it all are, and a partial figure
// would describe rows that could still roll back. Producing one would
// mean chunking the deletes into many transactions -- slower, and it
// would give up the atomicity that stops a failure leaving a
// half-deleted case. Neither is worth a nicer bar.
//
// What IS real, and free:
//
//   - the two phases are genuinely sequential and separately
//     confirmable: the transaction either commits or does not, and the
//     directory removal either returns or does not;
//   - once the transaction commits, the EXACT number of rows removed
//     from every table is known, because sql.Result already carries it.
//     No counting query is added to obtain it.
//
// So progress is reported as confirmed stages carrying confirmed counts,
// and the bar stays indeterminate. Nothing here interpolates, estimates
// or animates against elapsed time.
//
// # Why the state is in memory
//
// The store opens SQLite with SetMaxOpenConns(1). A deletion holds that
// connection for the whole transaction, so a progress poll that touched
// the database would block behind the very work it is reporting on --
// the same constraint internal/api/importjob.go documents. Reading this
// registry touches no database at all.
//
// The records are transient UI state, not evidence: they are dropped
// shortly after the deletion ends and are lost on restart, which costs
// nothing. Whether a case was deleted lives in the database and the
// security log, where it belongs.

// Deletion stages. Each corresponds to code that actually runs, and a
// stage is only ever reported as DONE once the backend has confirmed it.
const (
	// DeletionStagePreparing: the case is being resolved and checked,
	// before anything is removed.
	DeletionStagePreparing = "preparing"
	// DeletionStageRemovingRecords: the database transaction is running.
	// Nothing is removed yet -- a rollback here leaves the case intact.
	DeletionStageRemovingRecords = "removing_records"
	// DeletionStageRemovingFiles: the transaction has COMMITTED (so every
	// record is now confirmed gone) and the evidence directory is being
	// removed.
	DeletionStageRemovingFiles = "removing_evidence_files"
	// DeletionStageComplete: everything is gone and the server is about
	// to answer the request.
	DeletionStageComplete = "complete"
	// DeletionStageFailed: the deletion stopped. What had been confirmed
	// before that point is still reported, and nothing else is claimed.
	DeletionStageFailed = "failed"
)

// DeletionStageLabels are the analyst-facing wordings. One place, so the
// API and the dashboard cannot disagree about what a stage is called.
var DeletionStageLabels = map[string]string{
	DeletionStagePreparing:       "Preparing deletion",
	DeletionStageRemovingRecords: "Removing case records",
	DeletionStageRemovingFiles:   "Removing evidence files",
	DeletionStageComplete:        "Complete",
	DeletionStageFailed:          "Failed",
}

// DeletionProgress is a point-in-time snapshot of one case deletion.
type DeletionProgress struct {
	CaseID string `json:"case_id"`
	Stage  string `json:"stage"`
	Label  string `json:"stage_label"`

	StartedAt time.Time `json:"started_at"`
	// ElapsedMS is measured, not estimated. It is the one number here
	// that moves continuously, and it is never presented as a position.
	ElapsedMS int64 `json:"elapsed_ms"`

	// RecordsRemoved is populated only once the database transaction has
	// COMMITTED. Until then it is nil: reporting it earlier would claim
	// rows were deleted that a rollback could still restore.
	RecordsRemoved *store.DeletedCaseCounts `json:"records_removed,omitempty"`
	// RecordsConfirmed says the same thing in one boolean, so a UI does
	// not have to infer confirmation from a struct being present.
	RecordsConfirmed bool `json:"records_confirmed"`
	// FilesRemoved reports that the evidence directory removal returned
	// successfully.
	FilesRemoved bool `json:"evidence_files_removed"`

	// Done and Error close the record out. Done is true only for a
	// deletion that finished -- successfully or not -- and Error is
	// non-empty only when it failed.
	Done  bool   `json:"done"`
	Error string `json:"error,omitempty"`
}

// deletionProgressTTL is how long a finished record is kept so a poll
// that arrives just after the response can still read the final state.
// Short, because nothing here is evidence.
const deletionProgressTTL = 60 * time.Second

type deletionTracker struct {
	mu      sync.RWMutex
	entries map[string]*DeletionProgress
}

func newDeletionTracker() *deletionTracker {
	return &deletionTracker{entries: map[string]*DeletionProgress{}}
}

// begin starts tracking a deletion, replacing any stale record for the
// same case.
func (d *deletionTracker) begin(caseID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.entries[caseID] = &DeletionProgress{
		CaseID:    caseID,
		Stage:     DeletionStagePreparing,
		Label:     DeletionStageLabels[DeletionStagePreparing],
		StartedAt: time.Now().UTC(),
	}
}

// stage advances a tracked deletion. Unknown cases are ignored rather
// than created: progress is a side effect of a deletion that is running,
// never a thing that can be started on its own.
func (d *deletionTracker) stage(caseID, stage string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p, ok := d.entries[caseID]; ok {
		p.Stage = stage
		p.Label = DeletionStageLabels[stage]
	}
}

// recordsRemoved publishes the confirmed row counts. Called ONLY after
// the transaction commits.
func (d *deletionTracker) recordsRemoved(caseID string, counts store.DeletedCaseCounts) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p, ok := d.entries[caseID]; ok {
		c := counts
		p.RecordsRemoved = &c
		p.RecordsConfirmed = true
	}
}

func (d *deletionTracker) filesRemoved(caseID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p, ok := d.entries[caseID]; ok {
		p.FilesRemoved = true
	}
}

// finish closes a deletion out, successfully or otherwise, and schedules
// the record's removal.
func (d *deletionTracker) finish(caseID string, err error) {
	d.mu.Lock()
	p, ok := d.entries[caseID]
	if ok {
		p.Done = true
		if err != nil {
			p.Stage = DeletionStageFailed
			p.Label = DeletionStageLabels[DeletionStageFailed]
			p.Error = err.Error()
		} else {
			p.Stage = DeletionStageComplete
			p.Label = DeletionStageLabels[DeletionStageComplete]
		}
	}
	d.mu.Unlock()

	if !ok {
		return
	}
	time.AfterFunc(deletionProgressTTL, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if cur, ok := d.entries[caseID]; ok && cur == p {
			delete(d.entries, caseID)
		}
	})
}

// snapshot returns a copy of a deletion's current state. It reads memory
// only -- no database, so polling can never queue behind the deletion.
func (d *deletionTracker) snapshot(caseID string) (DeletionProgress, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	p, ok := d.entries[caseID]
	if !ok {
		return DeletionProgress{}, false
	}
	out := *p
	out.ElapsedMS = time.Since(p.StartedAt).Milliseconds()
	if p.RecordsRemoved != nil {
		c := *p.RecordsRemoved
		out.RecordsRemoved = &c
	}
	return out, true
}

// DeletionProgressFor reports how far a running (or just-finished) case
// deletion has got. Not found means no deletion is being tracked for
// this case, which is the normal answer for almost every case almost all
// of the time.
func (s *Service) DeletionProgressFor(caseID string) (DeletionProgress, bool) {
	return s.deletions.snapshot(caseID)
}

// EvidenceSize is how much of a case's evidence lives on disk under
// Tracefall's own storage.
//
// It answers one question for the deletion confirmation: how much is
// about to be removed. It is measured by walking the case directory,
// which is exactly the tree RemoveCaseDir deletes -- so the number
// describes what will actually go, not what the catalog says was once
// collected.
//
// Evidence a case merely POINTS at is not included and must not be:
// a local-path collection's files stay where the investigator put them
// and are never deleted (see Service.DeleteCollection). Those files are
// not under the case directory, so they are outside this walk by
// construction rather than by a rule that could drift.
type EvidenceSize struct {
	// Measured is false when the size could not be established -- no
	// case directory, or a tree larger than the walk is willing to
	// visit. A caller must then say nothing about size rather than
	// showing a number it does not have.
	Measured bool  `json:"measured"`
	Bytes    int64 `json:"bytes"`
	Files    int   `json:"files"`
}

// evidenceWalkLimit bounds the walk. A case directory of this many
// entries is already far past anything a triage collection produces, and
// an unbounded walk on a pathological tree would stall the request that
// asked for it.
const evidenceWalkLimit = 250_000

// EvidenceSizeFor measures a case's on-disk evidence.
//
// Deliberately NOT part of CaseSummary: that is loaded on every case
// page view, and a walk of 7,074 files costs ~22 ms which would be paid
// on every one of them. This is called once, while the deletion
// confirmation is being prepared, so the cost lands where the answer is
// wanted and never during the deletion itself.
func (s *Service) EvidenceSizeFor(caseID string) (EvidenceSize, error) {
	if _, err := s.GetCase(caseID); err != nil {
		return EvidenceSize{}, err
	}

	root := s.files.CaseDir(caseID)
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		// No directory: nothing of this case's evidence is stored by
		// Tracefall. Measured, and the answer is zero.
		return EvidenceSize{Measured: true}, nil
	}

	var out EvidenceSize
	var visited int
	walkErr := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable subtree makes the total wrong, and a wrong
			// total is worse than none.
			return err
		}
		visited++
		if visited > evidenceWalkLimit {
			return errEvidenceWalkTooLarge
		}
		if d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		out.Files++
		out.Bytes += fi.Size()
		return nil
	})
	if walkErr != nil {
		return EvidenceSize{Measured: false}, nil
	}
	out.Measured = true
	return out, nil
}

var errEvidenceWalkTooLarge = errors.New("evidence tree is larger than this build will walk")
