package api

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/report"
)

// reportNarrative assembles Appendix E from the latest stored draft. It sends
// nothing: a report never causes a request to a model.
//
// Citations are shown with the report's own finding numbers (F-003) so that
// the reader can go straight to the finding.
func (s *Service) reportNarrative(caseID string, findings []report.Finding, current []model.Finding) (report.Narrative, error) {
	n, ok, err := s.store.LatestNarrative(caseID)
	if err != nil {
		return report.Narrative{}, err
	}
	if !ok {
		return report.Narrative{}, nil
	}
	v := viewOf(n, current)
	out := report.Narrative{Requested: true, RequestedAt: n.CreatedAt.UTC().Format(time.RFC3339), Destination: n.Destination, Local: n.Local, Model: n.Model,
		Rejected: n.Rejected, PayloadSHA256: n.PayloadSHA256, PromptTokens: n.PromptTokens, CompletionTokens: n.CompletionTokens, Stale: v.Stale}
	if n.Status != model.NarrativeOK {
		out.Error = oneLine(n.Error)
	}
	num := make(map[string]string, len(findings))
	for _, f := range findings {
		num[f.ID] = f.Number
	}
	for _, sn := range v.Sentences {
		var cites []string
		for _, c := range sn.Cites {
			switch c.Kind {
			case "finding":
				if lbl, ok := num[c.ID]; ok {
					cites = append(cites, lbl)
				} else {
					cites = append(cites, "finding "+c.ID)
				}
			default:
				cites = append(cites, "event "+c.ID)
			}
		}
		out.Sentences = append(out.Sentences, report.NarrativeSentence{Text: oneLineKeep(sn.Text), Cites: strings.Join(cites, "; ")})
	}
	out.Usable = len(out.Sentences) > 0
	reasons := make([]string, 0, len(v.Reasons))
	for r := range v.Reasons {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		out.Reasons = append(out.Reasons, report.KV{Key: r, Value: fmt.Sprint(v.Reasons[r])})
	}
	return out, nil
}

// oneLineKeep flattens whitespace without shortening: a draft sentence is
// shown whole.
func oneLineKeep(s string) string { return strings.Join(strings.Fields(s), " ") }
