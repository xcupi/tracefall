package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"tracefall/internal/detect"
	"tracefall/internal/model"
)

// Phase 9B: severity transparency.
//
// The contract these tests defend is narrow and important: the
// explanation must be TRUE. Every statement has to be checkable against
// either the producing rule's declared reasoning or the finding's own
// supporting events -- and explaining a finding must never change it.

func evAt(id string, offset time.Duration, mutate func(*model.Event)) model.Event {
	e := model.Event{
		ID:           id,
		Timestamp:    time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC).Add(offset),
		Host:         "WKSTN-042",
		User:         "jdoe",
		ArtifactType: model.ArtifactWindowsEventLog,
		CollectionID: "col-1",
	}
	if mutate != nil {
		mutate(&e)
	}
	return e
}

// The single most important property: explaining a finding must not
// alter its severity or confidence.
func TestExplain_DoesNotChangeTheFinding(t *testing.T) {
	f := model.Finding{
		RuleID: "new-registry-run-key", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium,
		Techniques: []string{"T1547.001"},
	}
	before := f
	x := explainFinding(f, []model.Event{evAt("1", 0, nil)})

	// Finding contains slices, so compare the fields that matter here.
	if f.Severity != before.Severity || f.Confidence != before.Confidence || f.RuleID != before.RuleID ||
		len(f.Techniques) != len(before.Techniques) {
		t.Errorf("explainFinding mutated the finding: %+v -> %+v", before, f)
	}
	if x.Severity != before.Severity || x.Confidence != before.Confidence {
		t.Errorf("explanation reports %s/%s, finding is %s/%s",
			x.Severity, x.Confidence, before.Severity, before.Confidence)
	}
}

// A finding above its rule's baseline must say so, and name the
// conditions that could have raised it.
func TestExplain_EscalatedFindingIsIdentified(t *testing.T) {
	doc, ok := detect.DocFor("new-registry-run-key")
	if !ok {
		t.Fatal("catalog is missing new-registry-run-key")
	}
	if doc.BaseSeverity != model.SeverityLow {
		t.Fatalf("fixture assumption broken: base severity is %q", doc.BaseSeverity)
	}

	escalated := explainFinding(model.Finding{
		RuleID: "new-registry-run-key", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium,
	}, []model.Event{evAt("1", 0, nil)})
	if !escalated.Escalated {
		t.Error("a high-severity finding from a low-baseline rule was not marked as escalated")
	}
	if !hasFactorKind(escalated, FactorLevel) {
		t.Error("no level factor explaining the escalation")
	}

	baseline := explainFinding(model.Finding{
		RuleID: "new-registry-run-key", Severity: model.SeverityLow, Confidence: model.ConfidenceLow,
	}, []model.Event{evAt("1", 0, nil)})
	if baseline.Escalated {
		t.Error("a finding at the rule's baseline was marked as escalated")
	}
}

// A fixed-severity rule must not claim escalating conditions it does not
// have.
func TestExplain_FixedSeverityRuleSaysSo(t *testing.T) {
	x := explainFinding(model.Finding{
		RuleID: "execution-persistence-temporal", Severity: model.SeverityCritical, Confidence: model.ConfidenceHigh,
	}, []model.Event{evAt("1", 0, nil)})

	if x.Escalated {
		t.Error("a rule whose base severity IS critical cannot be escalated above it")
	}
	var found bool
	for _, f := range x.Factors {
		if f.Kind == FactorLevel && strings.Contains(strings.ToLower(f.Detail), "no escalating conditions") {
			found = true
		}
	}
	if !found {
		t.Errorf("fixed-severity rule did not say it has no escalating conditions: %+v", x.Factors)
	}
}

// Corroboration must be reported only when it is real: two independently
// collected artifact types, or two separate evidence collections.
func TestExplain_CorroborationIsCountedNotAssumed(t *testing.T) {
	single := explainFinding(model.Finding{RuleID: "new-registry-run-key", Severity: model.SeverityLow},
		[]model.Event{
			evAt("1", 0, nil),
			evAt("2", time.Minute, nil), // same artifact type, same collection
		})
	if hasFactorKind(single, FactorCorroboration) {
		t.Error("corroboration claimed for two events from one artifact type in one collection")
	}

	multi := explainFinding(model.Finding{RuleID: "new-registry-run-key", Severity: model.SeverityLow},
		[]model.Event{
			evAt("1", 0, nil),
			evAt("2", time.Minute, func(e *model.Event) {
				e.ArtifactType = model.ArtifactRegistryHive
				e.CollectionID = "col-2"
			}),
		})
	if !hasFactorKind(multi, FactorCorroboration) {
		t.Error("no corroboration reported despite two artifact types and two collections")
	}
	// And it must name what corroborated, not just assert that something did.
	var named bool
	for _, f := range multi.Factors {
		if f.Kind == FactorCorroboration && strings.Contains(f.Detail, "Registry") {
			named = true
		}
	}
	if !named {
		t.Errorf("corroboration factor does not name the artifact types: %+v", multi.Factors)
	}
}

// Every evidence factor must be derived from the events actually passed
// in -- nothing invented, nothing about hosts or accounts not present.
func TestExplain_FactsComeFromTheSuppliedEvidenceOnly(t *testing.T) {
	x := explainFinding(model.Finding{RuleID: "new-registry-run-key", Severity: model.SeverityLow},
		[]model.Event{
			evAt("1", 0, func(e *model.Event) { e.Host = "SRV-DC01"; e.User = "CORP\\svc-backup" }),
		})

	joined := allDetails(x)
	if !strings.Contains(joined, "SRV-DC01") {
		t.Error("the host from the supporting evidence is not reported")
	}
	if !strings.Contains(joined, "svc-backup") {
		t.Error("the account from the supporting evidence is not reported")
	}
	if strings.Contains(joined, "WKSTN-042") {
		t.Error("a host that appears in no supporting event was reported")
	}
}

// With no supporting events, the explanation must fall back to the
// rule's reasoning rather than fabricating evidence facts.
func TestExplain_NoSupportingEventsStillExplainsTheRule(t *testing.T) {
	x := explainFinding(model.Finding{RuleID: "brute-force-then-success", Severity: model.SeverityHigh}, nil)
	if len(x.Factors) == 0 {
		t.Fatal("no factors at all")
	}
	if !hasFactorKind(x, FactorRule) {
		t.Error("the rule's reasoning is missing")
	}
	if hasFactorKind(x, FactorEvidence) {
		t.Error("evidence factors were produced with no supporting events")
	}
}

// A finding from a rule this build no longer has must be handled
// honestly rather than explained with an invented entry.
func TestExplain_UnknownRuleIsHandledHonestly(t *testing.T) {
	x := explainFinding(model.Finding{RuleID: "rule-from-a-future-build", Severity: model.SeverityHigh},
		[]model.Event{evAt("1", 0, nil)})
	if x.Rule != nil {
		t.Error("documentation was produced for a rule that does not exist")
	}
	if !strings.Contains(allDetails(x), "no longer has") {
		t.Errorf("the missing rule is not acknowledged: %+v", x.Factors)
	}
}

func TestExplain_IsDeterministic(t *testing.T) {
	f := model.Finding{RuleID: "new-registry-run-key", Severity: model.SeverityHigh, Techniques: []string{"T1547.001"}}
	events := []model.Event{
		evAt("1", 0, nil),
		evAt("2", time.Minute, func(e *model.Event) { e.ArtifactType = model.ArtifactRegistryHive }),
	}
	first := allDetails(explainFinding(f, events))
	for i := 0; i < 10; i++ {
		if got := allDetails(explainFinding(f, events)); got != first {
			t.Fatalf("explanation differed between runs:\n%s\n%s", first, got)
		}
	}
}

// ---------------- through the API ----------------

func TestFindingDetail_CarriesTheExplanation(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Severity explanation e2e")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Windows/System32/winevt/Logs/Security.evtx": attackEvtx(),
		"Users/jdoe/NTUSER.DAT":                      persistenceHive(),
	})
	importAllFrom(t, mux, c.ID, disc)
	analyze(t, mux, c.ID)

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings", nil, &findings)
	if len(findings) == 0 {
		t.Fatal("no findings to explain")
	}

	for _, f := range findings {
		var detail FindingDetail
		rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings/"+f.ID, nil, &detail)
		if rec.Code != http.StatusOK {
			t.Fatalf("finding detail: status %d", rec.Code)
		}
		x := detail.Explanation

		// The explanation must agree with the finding it explains.
		if x.Severity != f.Severity || x.Confidence != f.Confidence {
			t.Errorf("finding %s is %s/%s but its explanation says %s/%s",
				f.RuleID, f.Severity, f.Confidence, x.Severity, x.Confidence)
		}
		if len(x.Factors) == 0 {
			t.Errorf("finding %s has no explanation factors", f.RuleID)
		}
		for _, factor := range x.Factors {
			if factor.Label == "" || factor.Detail == "" {
				t.Errorf("finding %s has an empty factor: %+v", f.RuleID, factor)
			}
		}
		// The supporting-event count in the explanation must match the
		// evidence actually returned.
		if n := len(detail.SupportingEventDetails); n > 0 {
			want := plural(n, "supporting event", "supporting events")
			if !strings.Contains(allDetailsFromFactors(x.Factors, true), want) {
				t.Errorf("finding %s reports a different supporting-event count than it returns (%d)", f.RuleID, n)
			}
		}
	}
}

func TestSeverityModel_IsPublishedAndReadOnly(t *testing.T) {
	mux := newTestRouter(t)

	var sm SeverityModel
	rec := doJSON(t, mux, "GET", "/api/severity-model", nil, &sm)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if sm.Configurable {
		t.Error("the severity model advertises itself as configurable; it is not")
	}
	if sm.Note == "" {
		t.Error("no explanation of why the model is fixed")
	}
	if len(sm.Rules) != len(detect.All()) {
		t.Errorf("model publishes %d rules, %d are registered", len(sm.Rules), len(detect.All()))
	}
	if len(sm.Levels) != 4 || len(sm.Confidences) != 3 {
		t.Errorf("severity/confidence vocabularies are wrong: %d/%d", len(sm.Levels), len(sm.Confidences))
	}
}

// ---------------- helpers ----------------

func hasFactorKind(x SeverityExplanation, kind string) bool {
	for _, f := range x.Factors {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

func allDetails(x SeverityExplanation) string { return allDetailsFromFactors(x.Factors, false) }

func allDetailsFromFactors(factors []ExplanationFactor, includeLabels bool) string {
	var b strings.Builder
	for _, f := range factors {
		if includeLabels {
			b.WriteString(f.Label)
			b.WriteString(" ")
		}
		b.WriteString(f.Detail)
		b.WriteString("\n")
	}
	return b.String()
}
