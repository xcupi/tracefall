package model

import "time"

// Pipeline job and upload session records (roadmap item 2).
//
// These are OPERATIONAL state, not evidence: they describe work Tracefall
// is doing or has done on a case. They are persisted so that work
// survives a restart, but nothing here is an input to detection,
// correlation or any finding, and deleting them changes no result.

// Pipeline job kinds.
const (
	// JobKindIngest runs discover, import, analyze for one evidence
	// source (an uploaded file or a local path), with no analyst
	// interaction in between.
	JobKindIngest = "ingest_pipeline"
)

// Pipeline job statuses. A job moves queued -> running -> one of
// succeeded / failed / cancelled. A restart moves a running job back to
// queued (it is resumed, not repeated from scratch).
const (
	JobQueued    = "queued"
	JobRunning   = "running"
	JobSucceeded = "succeeded"
	JobFailed    = "failed"
	JobCancelled = "cancelled"
)

// Pipeline stages, in order. A job's Stage names the stage it is IN, or
// the last one it reached; it is the resume point after a restart.
const (
	StageQueued    = "queued"
	StageDiscover  = "discover"
	StageImport    = "import"
	StageAnalyze   = "analyze"
	StageReport    = "report"
	StageComplete  = "complete"
	StageFailed    = "failed"
	StageCancelled = "cancelled"
)

// IsTerminal reports whether a job status is final.
func IsTerminalJobStatus(s string) bool {
	return s == JobSucceeded || s == JobFailed || s == JobCancelled
}

// PipelineJob is one persisted unit of server-side work.
type PipelineJob struct {
	ID     string `json:"job_id"`
	CaseID string `json:"case_id"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
	Stage  string `json:"stage"`

	// CollectionID is the collection this job created or adopted. It is
	// the job's checkpoint: once set, a resumed job does not discover
	// again.
	CollectionID string `json:"collection_id,omitempty"`

	// Params, Progress and Result are JSON documents. They are kept as
	// text so this package defines no schema for them; the API layer
	// owns their shape.
	Params   string `json:"params"`
	Progress string `json:"progress,omitempty"`
	Result   string `json:"result,omitempty"`

	// Error is a safe, human-readable failure reason.
	Error string `json:"error,omitempty"`

	// Attempts counts how many times a worker has started this job. More
	// than one means it was resumed after an interruption.
	Attempts        int  `json:"attempts"`
	CancelRequested bool `json:"cancel_requested"`

	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// Upload session statuses.
const (
	UploadOpen     = "open"     // accepting chunks
	UploadComplete = "complete" // every byte received and verified
	UploadConsumed = "consumed" // handed to a pipeline job
	UploadAborted  = "aborted"
)

// UploadSession is a resumable upload in progress. Received is the
// number of contiguous bytes from offset zero that are durably on disk;
// a client that lost its connection asks for it and continues from
// there.
type UploadSession struct {
	ID       string `json:"upload_id"`
	CaseID   string `json:"case_id"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	Received int64  `json:"received"`
	Status   string `json:"status"`
	// ClientSHA256 is the digest the client declared for the whole file,
	// if it declared one. It is checked at completion and never trusted
	// beyond that: Tracefall computes its own digests at ingestion.
	ClientSHA256 string    `json:"client_sha256,omitempty"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
