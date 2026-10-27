package investigate

import (
	"testing"
	"tracefall/internal/model"
)

func TestReview2RecordedDomainContext(t *testing.T) {
	for _, domain := range []string{"domain-a.example", " DOMAIN-B.EXAMPLE "} {
		es := []model.Event{{ID: "short", CaseID: "case", CollectionID: "one", Host: "host01", EventType: model.EventProcessCreate}, {ID: "full", CaseID: "case", CollectionID: "one", Host: "host01.domain-b.example", EventType: model.EventProcessCreate}, {ID: "metadata", CaseID: "case", CollectionID: "one", Host: "host01", Extra: map[string]string{"domain": domain}}}
		fs := []model.Finding{{ID: "finding", SupportingEvents: []string{"full"}, Severity: model.SeverityLow, Confidence: model.ConfidenceLow}}
		cs := []model.Correlation{{ID: "context", Type: model.CorrelationServiceChain, Title: "Contextual service configuration", EventIDs: []string{"short", "full"}}}
		for i := 0; i < 2; i++ {
			got := Run("case", es, fs, cs)
			want := 2
			if domain == "domain-a.example" {
				want = 1
			}
			if len(got) != 1 || got[0].EventCount != want {
				t.Fatalf("domain=%q groups=%+v want %d", domain, got, want)
			}
			es[0], es[2] = es[2], es[0]
		}
	}
}
