package api

import (
	"net/http"
	"path/filepath"
	"testing"

	"tracefall/internal/model"
)

// ingestLocalPath drives the local-path discover step (mirroring
// duplicate_evidence_test.go's evidenceRoot pattern) and returns the
// decoded DiscoverResult, failing the test on a non-200 response.
func ingestLocalPath(t *testing.T, mux *http.ServeMux, caseID, path string) DiscoverResult {
	t.Helper()
	var disc DiscoverResult
	rec := doJSON(t, mux, "POST", "/api/cases/"+caseID+"/ingest", map[string]string{"path": path}, &disc)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest %s: status %d, body %s", path, rec.Code, rec.Body.String())
	}
	return disc
}

func analyze(t *testing.T, mux *http.ServeMux, caseID string) {
	t.Helper()
	rec := doJSON(t, mux, "POST", "/api/cases/"+caseID+"/analyze", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyze: status %d, body %s", rec.Code, rec.Body.String())
	}
}

func getFindings(t *testing.T, mux *http.ServeMux, caseID string) []model.Finding {
	t.Helper()
	var findings []model.Finding
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings)
	if rec.Code != http.StatusOK {
		t.Fatalf("get findings: status %d, body %s", rec.Code, rec.Body.String())
	}
	return findings
}

func getCorrelations(t *testing.T, mux *http.ServeMux, caseID string) []model.Correlation {
	t.Helper()
	var corr []model.Correlation
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/correlations", nil, &corr)
	if rec.Code != http.StatusOK {
		t.Fatalf("get correlations: status %d, body %s", rec.Code, rec.Body.String())
	}
	return corr
}

func findingRuleIDs(findings []model.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range findings {
		out[f.RuleID] = true
	}
	return out
}

func correlationTypes(corr []model.Correlation) map[string]bool {
	out := map[string]bool{}
	for _, c := range corr {
		out[c.Type] = true
	}
	return out
}

// runScenario ingests, imports, and analyzes one Phase 4G scenario
// directory end-to-end through the real HTTP API, exactly as a browser
// session driving local-path evidence discovery would.
func runScenario(t *testing.T, dirName string) (findings []model.Finding, corr []model.Correlation) {
	t.Helper()
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Phase 4 scenario: "+dirName)
	root := filepath.Join("..", "..", "testdata", "scenarios", dirName)

	disc := ingestLocalPath(t, mux, c.ID, root)
	if disc.SupportedCount == 0 {
		t.Fatalf("scenario %s: 0 supported files discovered", dirName)
	}
	if _, imp := importAll(t, mux, c.ID, disc); imp.EventCount == 0 {
		t.Fatalf("scenario %s: import produced 0 events", dirName)
	}
	analyze(t, mux, c.ID)
	return getFindings(t, mux, c.ID), getCorrelations(t, mux, c.ID)
}

func TestScenarioB_BruteForce(t *testing.T) {
	findings, corr := runScenario(t, "b_brute_force")
	rules := findingRuleIDs(findings)
	if !rules["brute-force-then-success"] {
		t.Errorf("expected a brute-force-then-success finding, got rules: %v", rules)
	}
	types := correlationTypes(corr)
	if !types[model.CorrelationCredentialChain] {
		t.Errorf("expected a credential_chain correlation, got types: %v", types)
	}
}

func TestScenarioC_ScheduledTaskPersistence(t *testing.T) {
	findings, _ := runScenario(t, "c_scheduled_task_persistence")
	var f *model.Finding
	for i := range findings {
		if findings[i].RuleID == "new-scheduled-task" {
			f = &findings[i]
		}
	}
	if f == nil {
		t.Fatalf("expected a new-scheduled-task finding, got rules: %v", findingRuleIDs(findings))
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity = %q, want high (HighestAvailable RunLevel + PowerShell LOLBin action)", f.Severity)
	}
}

func TestScenarioD_RegistryRunKeyPersistence(t *testing.T) {
	findings, _ := runScenario(t, "d_registry_run_key_persistence")
	var f *model.Finding
	for i := range findings {
		if findings[i].RuleID == "new-registry-run-key" {
			f = &findings[i]
		}
	}
	if f == nil {
		t.Fatalf("expected a new-registry-run-key finding, got rules: %v", findingRuleIDs(findings))
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity = %q, want high (AppData-staged target)", f.Severity)
	}
}

func TestScenarioE_SuspiciousService(t *testing.T) {
	findings, _ := runScenario(t, "e_suspicious_service")
	var f *model.Finding
	for i := range findings {
		if findings[i].RuleID == "service-persistence" {
			f = &findings[i]
		}
	}
	if f == nil {
		t.Fatalf("expected a service-persistence finding, got rules: %v", findingRuleIDs(findings))
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity = %q, want high (service binary under Users\\Public)", f.Severity)
	}
	if !containsTechnique(f.Techniques, "T1543.003") {
		t.Errorf("techniques = %v, want T1543.003", f.Techniques)
	}
}

func TestScenarioF_PowerShellDownload(t *testing.T) {
	findings, _ := runScenario(t, "f_powershell_download")
	rules := findingRuleIDs(findings)
	if !rules["powershell-encoded-command"] {
		t.Errorf("expected a powershell-encoded-command finding, got rules: %v", rules)
	}
	if !rules["network-after-execution"] {
		t.Errorf("expected a network-after-execution finding, got rules: %v", rules)
	}
}

// TestScenarioG_BenignAdministrativeActivity is Phase 4G's required
// negative case, exercised end-to-end through the real HTTP API (the unit
// -level equivalent is
// internal/detect.TestBenignAdministrativeActivity_DoesNotBecomeHighConfidence,
// which checks the rule logic directly; this test checks the same
// property survives the full parse -> normalize -> detect -> correlate ->
// API pipeline). A plausible day of ordinary IT administration must
// produce zero high-severity+high-confidence findings, while still
// showing that the evidence was genuinely processed (not silently
// dropped) via the low-confidence observational findings it's expected to
// produce.
func TestScenarioG_BenignAdministrativeActivity(t *testing.T) {
	findings, _ := runScenario(t, "g_benign_admin_activity")
	if len(findings) == 0 {
		t.Fatal("expected at least some low-confidence observational findings (proves the evidence was processed, not silently dropped)")
	}
	for _, f := range findings {
		if (f.Severity == model.SeverityHigh || f.Severity == model.SeverityCritical) && f.Confidence == model.ConfidenceHigh {
			t.Errorf("benign administrative scenario produced a high-severity/high-confidence finding: %s (%s): %s", f.RuleID, f.Title, f.Description)
		}
	}
	rules := findingRuleIDs(findings)
	for _, want := range []string{"privileged-logon-observed", "explicit-credential-use", "remote-logon-observed"} {
		if !rules[want] {
			t.Errorf("expected a low-confidence %q observation (evidence was present for it), got rules: %v", want, rules)
		}
	}
}

func containsTechnique(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}
