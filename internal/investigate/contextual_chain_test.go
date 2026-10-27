package investigate

import (
	"strings"
	"testing"
	"time"
	"tracefall/internal/model"
)

func TestContextualChainsDoNotBecomeEvidencedCorroboration(t *testing.T) {
	base := time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)
	events := []model.Event{{ID: "a", Host: "host01", CollectionID: "one", EventType: model.EventProcessCreate, ProcessName: "worker.exe", Timestamp: base}, {ID: "b", Host: "host01", CollectionID: "one", EventType: model.EventServiceInstall, ProcessName: "worker.exe", Timestamp: base.Add(time.Minute)}}
	findings := []model.Finding{{ID: "finding", Severity: model.SeverityLow, Confidence: model.ConfidenceLow, SupportingEvents: []string{"a", "b"}}}
	for _, typ := range []string{model.CorrelationActivityChain, model.CorrelationServiceChain} {
		control := Run("case-1", events, findings, nil)
		corrs := []model.Correlation{{ID: "context", Type: typ, Title: "Contextual service chain", Description: "A contextual configuration association, not proof that the service launched this process.", EventIDs: []string{"a", "b"}}}
		got := Run("case-1", events, findings, corrs)
		if len(control) != 1 || len(got) != 1 {
			t.Fatalf("unexpected grouping: %+v %+v", control, got)
		}
		if got[0].Score != control[0].Score || got[0].Confidence != control[0].Confidence {
			t.Fatalf("weak context promoted to corroboration: control=%+v got=%+v", control, got)
		}
		if strings.Contains(got[0].ConfidenceRationale, "backed by a multi-step") || !strings.Contains(got[0].Summary, "contextual configuration") {
			t.Fatalf("weak basis lost: %+v", got[0])
		}
	}
}
