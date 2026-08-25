package detect

import (
	"sort"

	"github.com/google/uuid"

	"tracefall/internal/model"
)

// Run evaluates every registered rule against events (expected sorted by
// timestamp ascending, as store.ListEvents returns them) and returns all
// resulting findings, assigned IDs and sorted by first-seen time so
// output ordering is stable across runs given the same input evidence.
func Run(caseID string, events []model.Event) []model.Finding {
	var findings []model.Finding
	for _, rule := range All() {
		findings = append(findings, rule.Evaluate(events)...)
	}
	for i := range findings {
		findings[i].ID = uuid.NewString()
		if findings[i].CaseID == "" {
			findings[i].CaseID = caseID
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if !findings[i].FirstSeen.Equal(findings[j].FirstSeen) {
			return findings[i].FirstSeen.Before(findings[j].FirstSeen)
		}
		return findings[i].RuleID < findings[j].RuleID
	})
	return findings
}
