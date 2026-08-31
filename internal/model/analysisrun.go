package model

import "time"

// AnalysisRun records one execution of the detection and correlation
// engines over a case's events.
//
// # Why this exists
//
// Before Phase 11 a finding could be traced to its supporting events
// and from there to the evidence, but not to the ANALYSIS that produced
// it. Re-running analysis replaces every finding atomically (see
// store.ReplaceAnalysis), so the question "was this finding produced by
// the run I read last week, or by a later one?" had no answer beyond
// the case's single AnalyzedAt timestamp.
//
// A run row answers it, and records which build did the work -- which
// matters because detection rules and parsers change between builds.
//
// # What it deliberately does NOT do
//
// It does not change how analysis works. Re-analysis still recomputes
// findings from scratch and still replaces the previous set; runs are a
// record OF that process, not a new lifecycle around it. Superseded
// runs are retained as history, but the findings they produced are
// gone, exactly as before.
type AnalysisRun struct {
	ID     string `json:"analysis_run_id"`
	CaseID string `json:"case_id"`

	// StartedAt is when the run began. CompletedAt is nil until it
	// finishes -- a run that failed or was interrupted keeps a nil
	// CompletedAt rather than being stamped with a time it never
	// reached.
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// Status is one of the AnalysisRunStatus constants below.
	Status string `json:"status"`

	// ToolVersion is the build that performed the run, captured when the
	// run started. Never backfilled onto older rows: a run recorded
	// before this field existed genuinely does not know its build, and
	// guessing would be fabrication.
	ToolVersion string `json:"tool_version,omitempty"`

	// Counts of what the run produced. Zero for a run that failed.
	EventCount       int `json:"event_count"`
	FindingCount     int `json:"finding_count"`
	CorrelationCount int `json:"correlation_count"`

	// Error is the failure reason for a failed run, sanitized for
	// display. Empty for a successful one.
	Error string `json:"error,omitempty"`
}

// Analysis run statuses.
const (
	// AnalysisRunRunning is set when the run starts. A row left in this
	// state is a run whose process died before it could record an
	// outcome -- reported honestly as such rather than being silently
	// promoted to failed.
	AnalysisRunRunning   = "running"
	AnalysisRunCompleted = "completed"
	AnalysisRunFailed    = "failed"
)

// LegacyProvenanceUnavailable is the value provenance views use for a
// record that predates the provenance being captured.
//
// It exists so the distinction between "we know it was X" and "we do
// not know" is explicit everywhere it is displayed, rather than being
// implied by an empty string that could equally mean a bug.
const LegacyProvenanceUnavailable = "Legacy - provenance unavailable"
