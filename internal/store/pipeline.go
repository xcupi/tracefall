package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"tracefall/internal/model"
)

// Pipeline jobs and resumable uploads (roadmap item 2).
//
// Every state transition here is one SQL statement whose WHERE clause
// states the state it expects, so a stale writer cannot move a row
// somewhere it should not be: a late progress write cannot revive a
// finished job, two chunks cannot both advance the same offset, and two
// workers cannot claim the same job.

var (
	// ErrJobNotFound means no pipeline job has that id.
	ErrJobNotFound = errors.New("pipeline job not found")
	// ErrUploadNotFound means no upload session has that id.
	ErrUploadNotFound = errors.New("upload session not found")
	// ErrUploadOffsetConflict means a chunk was written against an offset
	// that is no longer the session's received count.
	ErrUploadOffsetConflict = errors.New("upload offset does not match the bytes already received")
	// ErrUploadClosed means the session no longer accepts bytes.
	ErrUploadClosed = errors.New("upload session is not open")
)

// JobUpdate carries the fields a running job may change. A nil field is
// left alone.
type JobUpdate struct {
	Stage        *string
	CollectionID *string
	Progress     *string
}

const jobCols = `id, case_id, kind, status, stage, collection_id, params, progress, result, error,
	attempts, cancel_requested, created_by, created_at, started_at, finished_at, updated_at`

func scanJob(row interface{ Scan(...any) error }) (model.PipelineJob, error) {
	var j model.PipelineJob
	var cancel int
	var created, started, finished, updated string
	if err := row.Scan(&j.ID, &j.CaseID, &j.Kind, &j.Status, &j.Stage, &j.CollectionID, &j.Params, &j.Progress,
		&j.Result, &j.Error, &j.Attempts, &cancel, &j.CreatedBy, &created, &started, &finished, &updated); err != nil {
		return model.PipelineJob{}, err
	}
	j.CancelRequested = cancel != 0
	j.CreatedAt, j.UpdatedAt = parseTime(created), parseTime(updated)
	if started != "" {
		t := parseTime(started)
		j.StartedAt = &t
	}
	if finished != "" {
		t := parseTime(finished)
		j.FinishedAt = &t
	}
	return j, nil
}

// CreatePipelineJob stores a new job.
func (s *Store) CreatePipelineJob(j model.PipelineJob) error {
	params := j.Params
	if params == "" {
		params = "{}"
	}
	_, err := s.db.Exec(`INSERT INTO pipeline_jobs (id, case_id, kind, status, stage, collection_id, params, progress,
		result, error, attempts, cancel_requested, created_by, created_at, started_at, finished_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, '', '', ?)`,
		j.ID, j.CaseID, j.Kind, j.Status, j.Stage, j.CollectionID, params, j.Progress, j.Result, j.Error,
		j.Attempts, j.CreatedBy, fmtTime(j.CreatedAt), fmtTime(j.UpdatedAt))
	return err
}

// GetPipelineJob returns one job.
func (s *Store) GetPipelineJob(id string) (model.PipelineJob, error) {
	j, err := scanJob(s.db.QueryRow(`SELECT `+jobCols+` FROM pipeline_jobs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.PipelineJob{}, ErrJobNotFound
	}
	return j, err
}

// ListPipelineJobs returns a case's jobs, newest first.
func (s *Store) ListPipelineJobs(caseID string) ([]model.PipelineJob, error) {
	rows, err := s.db.Query(`SELECT `+jobCols+` FROM pipeline_jobs WHERE case_id = ? ORDER BY created_at DESC, id DESC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.PipelineJob
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// ClaimNextPipelineJob atomically takes the oldest queued job and marks
// it running. It reports false when nothing is queued. The single UPDATE
// both selects and claims, so two workers cannot take the same job.
func (s *Store) ClaimNextPipelineJob(now time.Time) (model.PipelineJob, bool, error) {
	j, err := scanJob(s.db.QueryRow(`UPDATE pipeline_jobs
		SET status = ?, attempts = attempts + 1, started_at = ?, updated_at = ?
		WHERE id = (SELECT id FROM pipeline_jobs WHERE status = ? ORDER BY created_at ASC, id ASC LIMIT 1)
		  AND status = ?
		RETURNING `+jobCols,
		model.JobRunning, fmtTime(now), fmtTime(now), model.JobQueued, model.JobQueued))
	if errors.Is(err, sql.ErrNoRows) {
		return model.PipelineJob{}, false, nil
	}
	if err != nil {
		return model.PipelineJob{}, false, err
	}
	return j, true, nil
}

// UpdatePipelineJob changes a RUNNING job's stage, collection or
// progress. A job that has already finished is left exactly as it is, so
// a late progress write can never revive it.
func (s *Store) UpdatePipelineJob(id string, u JobUpdate, now time.Time) error {
	_, err := s.db.Exec(`UPDATE pipeline_jobs SET
		stage         = COALESCE(?, stage),
		collection_id = COALESCE(?, collection_id),
		progress      = COALESCE(?, progress),
		updated_at    = ?
		WHERE id = ? AND status = ?`,
		u.Stage, u.CollectionID, u.Progress, fmtTime(now), id, model.JobRunning)
	return err
}

// FinishPipelineJob records a final status. Only a queued or running job
// can be finished; a finished one is never rewritten.
func (s *Store) FinishPipelineJob(id, status, stage, result, errMsg string, now time.Time) error {
	if !model.IsTerminalJobStatus(status) {
		return fmt.Errorf("store: %q is not a final job status", status)
	}
	_, err := s.db.Exec(`UPDATE pipeline_jobs SET status = ?, stage = ?, result = ?, error = ?, finished_at = ?, updated_at = ?
		WHERE id = ? AND status IN (?, ?)`,
		status, stage, result, errMsg, fmtTime(now), fmtTime(now), id, model.JobQueued, model.JobRunning)
	return err
}

// RequestPipelineJobCancel records that cancellation was asked for.
// Idempotent. Whether the job honours it, and when, is the worker's
// business; this only makes the request durable.
func (s *Store) RequestPipelineJobCancel(id string, now time.Time) error {
	res, err := s.db.Exec(`UPDATE pipeline_jobs SET cancel_requested = 1, updated_at = ? WHERE id = ?`, fmtTime(now), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrJobNotFound
	}
	return nil
}

// RequeueInterruptedPipelineJobs is run once at startup. A job left
// 'running' by a process that no longer exists is put back to 'queued'
// with its stage and collection intact, so it resumes rather than
// repeats. A job that has already been started maxAttempts times is
// failed instead: work that keeps killing the server must not be allowed
// to keep doing it.
func (s *Store) RequeueInterruptedPipelineJobs(maxAttempts int, now time.Time) (requeued, failed int, err error) {
	res, err := s.db.Exec(`UPDATE pipeline_jobs SET status = ?, finished_at = ?, updated_at = ?, stage = ?,
		error = ? WHERE status = ? AND attempts >= ?`,
		model.JobFailed, fmtTime(now), fmtTime(now), model.StageFailed,
		fmt.Sprintf("the server stopped %d times while running this job, so it was not retried again", maxAttempts),
		model.JobRunning, maxAttempts)
	if err != nil {
		return 0, 0, err
	}
	n, _ := res.RowsAffected()
	failed = int(n)

	res, err = s.db.Exec(`UPDATE pipeline_jobs SET status = ?, updated_at = ? WHERE status = ?`,
		model.JobQueued, fmtTime(now), model.JobRunning)
	if err != nil {
		return 0, failed, err
	}
	n, _ = res.RowsAffected()
	return int(n), failed, nil
}

// ---------------------------------------------------------------- uploads

const uploadCols = `id, case_id, filename, size, received, status, client_sha256, created_by, created_at, updated_at`

func scanUpload(row interface{ Scan(...any) error }) (model.UploadSession, error) {
	var u model.UploadSession
	var created, updated string
	if err := row.Scan(&u.ID, &u.CaseID, &u.Filename, &u.Size, &u.Received, &u.Status, &u.ClientSHA256,
		&u.CreatedBy, &created, &updated); err != nil {
		return model.UploadSession{}, err
	}
	u.CreatedAt, u.UpdatedAt = parseTime(created), parseTime(updated)
	return u, nil
}

// CreateUploadSession stores a new resumable upload.
func (s *Store) CreateUploadSession(u model.UploadSession) error {
	_, err := s.db.Exec(`INSERT INTO upload_sessions (`+uploadCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.CaseID, u.Filename, u.Size, u.Received, u.Status, u.ClientSHA256, u.CreatedBy,
		fmtTime(u.CreatedAt), fmtTime(u.UpdatedAt))
	return err
}

// GetUploadSession returns one upload session.
func (s *Store) GetUploadSession(id string) (model.UploadSession, error) {
	u, err := scanUpload(s.db.QueryRow(`SELECT `+uploadCols+` FROM upload_sessions WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.UploadSession{}, ErrUploadNotFound
	}
	return u, err
}

// AdvanceUpload moves an OPEN session's received count from `from` to
// `to`, and only if it is still `from`: a compare-and-swap. Two chunks
// aimed at the same offset cannot both succeed.
func (s *Store) AdvanceUpload(id string, from, to int64, now time.Time) error {
	res, err := s.db.Exec(`UPDATE upload_sessions SET received = ?, updated_at = ?
		WHERE id = ? AND received = ? AND status = ?`, to, fmtTime(now), id, from, model.UploadOpen)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	u, err := s.GetUploadSession(id)
	if err != nil {
		return err
	}
	if u.Status != model.UploadOpen {
		return ErrUploadClosed
	}
	return ErrUploadOffsetConflict
}

// SetUploadStatus changes a session's status.
func (s *Store) SetUploadStatus(id, status string, now time.Time) error {
	res, err := s.db.Exec(`UPDATE upload_sessions SET status = ?, updated_at = ? WHERE id = ?`, status, fmtTime(now), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUploadNotFound
	}
	return nil
}

// ListStaleOpenUploads returns open sessions untouched since `before`.
func (s *Store) ListStaleOpenUploads(before time.Time) ([]model.UploadSession, error) {
	rows, err := s.db.Query(`SELECT `+uploadCols+` FROM upload_sessions WHERE status = ? AND updated_at < ? ORDER BY updated_at`,
		model.UploadOpen, fmtTime(before))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.UploadSession
	for rows.Next() {
		u, err := scanUpload(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
