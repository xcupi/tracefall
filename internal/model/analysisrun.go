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

	// InvalidatedAt is when this run stopped describing the case's
	// evidence -- set when the evidence it analyzed was deleted. Nil for
	// a run that still describes the current evidence set.
	//
	// The run row and everything it produced are KEPT; what changes is
	// that none of it is current any more. See InvalidationReason.
	InvalidatedAt *time.Time `json:"invalidated_at,omitempty"`

	// InvalidationReason states, in plain language, what happened to the
	// evidence. It is chain-of-custody information: an analyst reading
	// the history has to be able to see WHY a run's results stopped
	// counting, not merely that they did.
	InvalidationReason string `json:"invalidation_reason,omitempty"`
}

// IsCurrent reports whether this run's results may be presented as the
// case's current analysis.
//
// Only a completed run that has not been invalidated qualifies. A
// running, failed or invalidated run has produced nothing that describes
// the evidence the case holds now.
func (r AnalysisRun) IsCurrent() bool {
	return r.Status == AnalysisRunCompleted && r.InvalidatedAt == nil
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
	// AnalysisRunInvalidated is a run that COMPLETED and whose results
	// have since stopped describing the case, because the evidence they
	// were derived from was deleted.
	//
	// It is deliberately not "failed": the run did its job correctly at
	// the time, and saying otherwise would misrepresent the history. It
	// is also not a deletion -- the row, its counts and the findings it
	// produced are all retained for audit. What the status controls is
	// whether any of it is presented as CURRENT, and it never is.
	AnalysisRunInvalidated = "invalidated"
)

// LegacyProvenanceUnavailable is the value provenance views use for a
// record that predates the provenance being captured.
//
// It exists so the distinction between "we know it was X" and "we do
// not know" is explicit everywhere it is displayed, rather than being
// implied by an empty string that could equally mean a bug.
const LegacyProvenanceUnavailable = "Legacy - provenance unavailable"
