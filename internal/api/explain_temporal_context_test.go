package api

import (
	"testing"

	"tracefall/internal/detect"
	"tracefall/internal/model"
)

// Graded temporal context must not regress to the former fixed Critical
// explanation. This is separate from the fixed-level explanation invariant.
func TestExplain_TemporalContextUsesGradedLevels(t *testing.T) {
	doc, ok := detect.DocFor("execution-persistence-temporal")
	if !ok {
		t.Fatal("catalog is missing execution-persistence-temporal")
	}
	if doc.BaseSeverity != model.SeverityLow || doc.BaseConfidence != model.ConfidenceLow ||
		doc.MaxSeverity != model.SeverityMedium || doc.MaxConfidence != model.ConfidenceMedium || len(doc.Escalates) == 0 {
		t.Fatalf("temporal context must range from low/low to medium/medium: %+v", doc)
	}
	for _, tc := range []struct {
		name, severity, confidence string
		escalated                  bool
	}{
		{"basename-or-prefetch", model.SeverityLow, model.ConfidenceLow, false},
		{"full-path-process-start", model.SeverityMedium, model.ConfidenceMedium, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := explainFinding(model.Finding{RuleID: doc.ID, Severity: tc.severity, Confidence: tc.confidence}, []model.Event{evAt("1", 0, nil)})
			if x.Escalated != tc.escalated {
				t.Errorf("escalated=%v, want %v", x.Escalated, tc.escalated)
			}
			if x.Severity != tc.severity || x.Confidence != tc.confidence {
				t.Errorf("explanation changed recorded levels: %s/%s", x.Severity, x.Confidence)
			}
			if !hasFactorKind(x, FactorLevel) {
				t.Error("missing factor explaining the graded level")
			}
		})
	}
}
