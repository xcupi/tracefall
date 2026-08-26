package investigate

import (
	"fmt"
	"sort"

	"tracefall/internal/model"
)

// Scoring is a fixed, documented, additive point system -- never ML,
// never an LLM. Each factor is checked at most once per investigation
// (a boolean "is this facet/property present in the group", not "how
// many findings have it"), which is what keeps five findings that all
// stem from the same underlying persistence mechanism from inflating the
// score five times over ("avoid double-counting the same underlying
// event").
// Base-severity points and severityForScore's thresholds are calibrated
// together so a finding's own severity, taken alone with no
// corroboration at all, maps to that SAME Investigation severity -- per
// the task's own worked example ("a suspicious PowerShell command may be
// Severity: HIGH, Confidence: MEDIUM": a standalone high-severity
// finding stays high-severity at the investigation level; only
// confidence is what corroboration is short of). Corroborating factors
// then provide headroom to escalate a lower-severity finding upward
// (e.g. a medium finding that also establishes persistence reaches
// high), not to arbitrarily invent severity from nothing.
const (
	scoreBaseLow      = 15
	scoreBaseMedium   = 30
	scoreBaseHigh     = 50
	scoreBaseCritical = 70

	// Facet bonuses are deliberately modest relative to the base-severity
	// points above: a single finding-cluster commonly satisfies several
	// rules/facets from ONE or TWO underlying events (e.g. one encoded
	// PowerShell command that's also a suspicious parent/child pattern
	// and also makes a network connection) -- that's the SAME evidence
	// looked at from several rules' angles, not several independent
	// pieces of evidence, so facet presence alone must never be able to
	// carry a case across two full severity bands on its own. Genuine
	// escalation to CRITICAL comes from the corroboration factors below
	// (a real correlation, multiple artifact types, multiple evidence
	// collections) stacking on TOP of the facets, not from facet count
	// alone.
	scoreExecution         = 5
	scoreScriptInterpreter = 5
	scorePersistence       = 10
	scoreCredential        = 5
	scoreNetwork           = 5

	scoreChainCorrelation = 15 // a genuine multi-step narrative (activity/credential/service chain)
	scoreAnyCorrelation   = 5  // a weaker correlation (entity/process_chain) -- see mergeworthy in group.go for why temporal never even reaches here

	scoreTactics3Plus = 10
	scoreTactics2     = 5

	scoreArtifactDiversity = 5
	scoreCrossCollection   = 5
	maxScore               = 100
)

// scoreInput bundles everything computeScore needs, pre-extracted from
// the group so this file has no knowledge of union-find/grouping
// mechanics.
type scoreInput struct {
	highestSeverity  string
	facets           facet
	hasChainCorr     bool
	hasAnyCorr       bool
	distinctTactics  int
	distinctArtifact int
	distinctCollect  int
}

// computeScore returns the 0-100 score and its itemized, explainable
// rationale. Order matches the category the points are "about" (base
// severity, then behavior facets, then correlation strength, then
// diversity/corroboration) so the rationale reads as a coherent argument,
// not a shuffled list.
func computeScore(in scoreInput) (int, []string) {
	score := 0
	var reasons []string

	switch in.highestSeverity {
	case model.SeverityCritical:
		score += scoreBaseCritical
		reasons = append(reasons, fmt.Sprintf("+%d critical-severity finding present", scoreBaseCritical))
	case model.SeverityHigh:
		score += scoreBaseHigh
		reasons = append(reasons, fmt.Sprintf("+%d high-severity finding present", scoreBaseHigh))
	case model.SeverityMedium:
		score += scoreBaseMedium
		reasons = append(reasons, fmt.Sprintf("+%d medium-severity finding present", scoreBaseMedium))
	case model.SeverityLow:
		score += scoreBaseLow
		reasons = append(reasons, fmt.Sprintf("+%d low-severity indicator present", scoreBaseLow))
	}

	if in.facets.has(facetExecution) {
		score += scoreExecution
		reasons = append(reasons, fmt.Sprintf("+%d suspicious execution observed", scoreExecution))
	}
	if in.facets.has(facetScriptInterpreter) {
		score += scoreScriptInterpreter
		reasons = append(reasons, fmt.Sprintf("+%d scripting interpreter execution", scoreScriptInterpreter))
	}
	if in.facets.has(facetPersistence) {
		score += scorePersistence
		reasons = append(reasons, fmt.Sprintf("+%d persistence mechanism established", scorePersistence))
	}
	if in.facets.has(facetCredential) {
		score += scoreCredential
		reasons = append(reasons, fmt.Sprintf("+%d credential/authentication activity", scoreCredential))
	}
	if in.facets.has(facetNetwork) {
		score += scoreNetwork
		reasons = append(reasons, fmt.Sprintf("+%d outbound network activity", scoreNetwork))
	}

	switch {
	case in.hasChainCorr:
		score += scoreChainCorrelation
		reasons = append(reasons, fmt.Sprintf("+%d multi-step activity chain evidenced", scoreChainCorrelation))
	case in.hasAnyCorr:
		score += scoreAnyCorrelation
		reasons = append(reasons, fmt.Sprintf("+%d entity/process-chain correlation observed", scoreAnyCorrelation))
	}

	// Tactic diversity only counts as corroboration when it's backed by
	// SOME other independent signal (a correlation, multiple artifact
	// types, or multiple evidence collections) -- otherwise "spans 3
	// tactics" can be entirely an artifact of one or two events each
	// matching several rules that each map to a different tactic (e.g.
	// Execution + Defense Evasion + Command and Control from a single
	// encoded-PowerShell-then-network pair), which is the same
	// underlying evidence counted from multiple angles, not genuinely
	// diverse evidence.
	corroborated := in.hasAnyCorr || in.distinctArtifact >= 2 || in.distinctCollect >= 2
	switch {
	case corroborated && in.distinctTactics >= 3:
		score += scoreTactics3Plus
		reasons = append(reasons, fmt.Sprintf("+%d spans %d ATT&CK tactics", scoreTactics3Plus, in.distinctTactics))
	case corroborated && in.distinctTactics == 2:
		score += scoreTactics2
		reasons = append(reasons, fmt.Sprintf("+%d spans 2 ATT&CK tactics", scoreTactics2))
	}

	if in.distinctArtifact >= 2 {
		score += scoreArtifactDiversity
		reasons = append(reasons, fmt.Sprintf("+%d corroborated by %d independent artifact types", scoreArtifactDiversity, in.distinctArtifact))
	}

	// Cross-collection: only genuinely distinct evidence counts. A
	// single real-world event re-observed in two collections is still
	// ONE Event row with ONE (first-observation) CollectionID (see
	// internal/model.Event's dedup design), so this can only fire when
	// the group actually contains independently-sourced events, never
	// merely because the same artifact was collected twice.
	if in.distinctCollect >= 2 {
		score += scoreCrossCollection
		reasons = append(reasons, fmt.Sprintf("+%d independently observed across %d evidence collections", scoreCrossCollection, in.distinctCollect))
	}

	if score > maxScore {
		score = maxScore
	}
	return score, reasons
}

// severityForScore maps the 0-100 score back to a Severity label.
// Thresholds are deliberately round and documented here, not buried in
// a comparison chain elsewhere.
func severityForScore(score int) string {
	switch {
	case score >= 70:
		return model.SeverityCritical
	case score >= 50:
		return model.SeverityHigh
	case score >= 25:
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}

// highestSeverity returns the most severe Severity value among findings.
func highestSeverity(findings []model.Finding) string {
	rank := map[string]int{model.SeverityLow: 1, model.SeverityMedium: 2, model.SeverityHigh: 3, model.SeverityCritical: 4}
	best := model.SeverityLow
	for _, f := range findings {
		if rank[f.Severity] > rank[best] {
			best = f.Severity
		}
	}
	return best
}

// sortedUniqueStrings returns the sorted, deduplicated contents of vals,
// skipping empty strings -- used throughout this package for the
// Hosts/Users/CollectionIDs/SourceFileIDs/Techniques fields, which must
// be in a stable order for deterministic output.
// sortedUniqueStrings always returns a non-nil slice (empty rather than
// nil when vals has no non-empty values) -- Investigation's Hosts/Users/
// Techniques/Tactics/CollectionIDs/SourceFileIDs fields have no
// `omitempty` (see model/investigation.go), so a nil slice here would
// serialize as JSON `null` instead of `[]`. That's not just a style
// wart: an investigation whose supporting events have since been
// deleted (evidence deleted, analysis not yet re-run) can legitimately
// have zero hosts/users, and the frontend calls .length/.join on these
// fields unconditionally -- null reaching it crashes the case-detail
// page. See docs/analyst-workflow.md's stale-analysis section.
func sortedUniqueStrings(vals []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range vals {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
