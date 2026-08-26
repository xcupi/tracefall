package model

import "time"

// Investigation categories (Phase 5). A small, fixed set of
// analyst-level groupings -- deliberately not one category per
// detection rule (there are 15 rules; there are 7 categories). See
// internal/investigate/category.go for the deterministic rule for
// assigning a group of findings to one of these.
const (
	InvestigationSuspiciousExecution = "suspicious_execution"
	InvestigationPersistence         = "persistence"
	InvestigationCredentialAttack    = "credential_attack"
	InvestigationSuspiciousNetwork   = "suspicious_network"
	InvestigationServicePersistence  = "service_persistence"
	InvestigationScriptBasedAttack   = "script_based_attack"
	InvestigationMultiStageAttack    = "multi_stage_attack"
)

// Investigation is a deterministic, evidence-backed grouping of related
// Findings and Correlations into one investigative story -- e.g. Office
// -> PowerShell -> payload -> persistence -> network reported as one
// Investigation instead of five findings an analyst would otherwise have
// to mentally stitch together.
//
// An Investigation is a derived VIEW, computed at read time from
// already-persisted Findings/Correlations/Events by
// internal/investigate -- it is never itself persisted (see that
// package's doc comment for why), never invents a finding, and never
// hides one: every Finding in an analyzed case belongs to exactly one
// Investigation. EventIDs/FindingIDs/CorrelationIDs are references into
// the existing case data, the same IDs the Timeline/Findings/Activity
// Chains tabs already resolve through GET .../events/{id} and
// .../findings/{id} -- an Investigation never duplicates the underlying
// record.
type Investigation struct {
	ID       string `json:"investigation_id"`
	CaseID   string `json:"case_id"`
	Category string `json:"category"`
	Title    string `json:"title"`

	// Summary is a deterministic, template-generated narrative -- see
	// internal/investigate/narrative.go. Never AI-generated. Every
	// statement in it is derived directly from the referenced events; it
	// never speculates about attacker intent.
	Summary string `json:"summary"`

	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`

	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`

	Hosts []string `json:"hosts"`
	Users []string `json:"users"`

	EventIDs       []string `json:"event_ids"`
	FindingIDs     []string `json:"finding_ids"`
	CorrelationIDs []string `json:"correlation_ids"`

	Techniques []string `json:"attack_techniques"` // ATT&CK technique IDs referenced by this investigation's findings
	Tactics    []string `json:"tactics"`           // MITRE tactics those techniques resolve to

	// CollectionIDs/SourceFileIDs are the evidence collections/files the
	// investigation's events were first observed in -- the basis for
	// "independently observed in N evidence collections" (see
	// internal/investigate/score.go's cross-collection scoring factor,
	// which is careful to count only genuinely distinct evidence, not a
	// re-observed duplicate of the same event).
	CollectionIDs []string `json:"collection_ids"`
	SourceFileIDs []string `json:"source_file_ids"`

	// Score is the 0-100 deterministic risk score; ScoreRationale is the
	// itemized, explainable breakdown of exactly how it was reached (see
	// internal/investigate/score.go). ConfidenceRationale is the
	// equivalent one-line explanation for Confidence, which is derived
	// independently of Score/Severity -- see
	// internal/investigate/confidence.go.
	Score               int      `json:"risk_score"`
	ScoreRationale      []string `json:"score_rationale"`
	ConfidenceRationale string   `json:"confidence_rationale"`
}
