package detect

import (
	"sort"

	"tracefall/internal/model"
)

// Run evaluates every registered rule against events (expected sorted by
// timestamp ascending, as store.ListEvents returns them) and returns all
// resulting findings, assigned IDs and sorted by first-seen time so
// output ordering is stable across runs given the same input evidence.
//
// Finding IDs are content-derived (model.StableID), not random: the same
// rule firing on the same supporting events -- across two separate
// /analyze calls on unchanged evidence -- must produce the SAME finding
// ID both times. This is what lets Phase 6's analyst workflow state
// (status/notes/tags, stored in tables separate from findings
// specifically so re-analysis doesn't wipe them) survive a re-analysis
// that didn't actually change this finding, instead of silently
// orphaning every analyst assessment on every re-run. See
// docs/analyst-workflow.md.
func Run(caseID string, events []model.Event) []model.Finding {
	var findings []model.Finding
	for _, rule := range All() {
		findings = append(findings, rule.Evaluate(events)...)
	}
	for i := range findings {
		if findings[i].CaseID == "" {
			findings[i].CaseID = caseID
		}
		idParts := append([]string{findings[i].CaseID, findings[i].RuleID}, findings[i].SupportingEvents...)
		findings[i].ID = model.StableID("finding", idParts...)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if !findings[i].FirstSeen.Equal(findings[j].FirstSeen) {
			return findings[i].FirstSeen.Before(findings[j].FirstSeen)
		}
		return findings[i].RuleID < findings[j].RuleID
	})
	return findings
}
