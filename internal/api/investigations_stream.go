package api

import (
	"tracefall/internal/investigate"
	"tracefall/internal/model"
)

// caseInvestigations computes a case's investigations from its findings and
// correlations, streaming the case's events from the store once. Only the
// events a group references are kept, and of those only the narrative's
// types are kept whole, so this does not hold the case's whole event set
// (see internal/investigate.RunStreamed).
func (s *Service) caseInvestigations(caseID string, findings []model.Finding, correlations []model.Correlation) ([]model.Investigation, error) {
	each := func(fn func(model.Event) error) error {
		return s.store.ForEachEventLazy(caseID, investigate.NeedsExtra, fn)
	}
	return investigate.RunStreamed(caseID, each, findings, correlations)
}

// findingEventIDs lists the events the findings cite, once each. The report
// resolves these by id to show the evidence behind each finding; the
// correlations' events are not needed for that, because the investigations
// are computed separately, from the stream.
func findingEventIDs(findings []model.Finding) []string {
	seen := map[string]bool{}
	var ids []string
	for _, f := range findings {
		for _, id := range f.SupportingEvents {
			if id != "" && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids
}
