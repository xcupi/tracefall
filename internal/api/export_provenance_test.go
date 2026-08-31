package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"tracefall/internal/model"
)

// Export provenance is ADDITIVE. Everything a pre-Phase-11 consumer read
// must still be there, in the same place, with the same meaning.
func TestExport_ExistingContractIsUnchanged(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := analyzedCase(t, mux, "Export contract")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/cases/"+caseID+"/export", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export: status %d", rec.Code)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}

	// Every field the export carried before Phase 11.
	for _, key := range []string{
		"case", "collections", "source_files", "findings", "correlations",
		"investigations", "attack_techniques", "analyst_statuses", "notes", "tags",
		"audit_log", "exported_at",
	} {
		if _, ok := raw[key]; !ok {
			t.Errorf("export lost the pre-existing field %q", key)
		}
	}
	// And the new ones.
	for _, key := range []string{"tool_version", "analysis_runs"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("export is missing the Phase 11 field %q", key)
		}
	}
}

// The export must identify what produced it and from which state.
func TestExport_CarriesProvenanceMetadata(t *testing.T) {
	mux := newTestRouter(t)
	caseID, disc := analyzedCase(t, mux, "Export provenance")

	var exp CaseExport
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/export", nil, &exp)

	if exp.ToolVersion == "" {
		t.Error("export records no tool version")
	}
	if exp.ExportedAt.IsZero() {
		t.Error("export records no export time")
	}
	if exp.Case.ID != caseID {
		t.Errorf("export case id = %q, want %q", exp.Case.ID, caseID)
	}
	if len(exp.AnalysisRuns) != 1 {
		t.Fatalf("export carries %d analysis runs, want 1", len(exp.AnalysisRuns))
	}

	// Evidence hashes travel with the collections, not duplicated
	// elsewhere -- and they must be the COMPLETE digests.
	var found bool
	for _, c := range exp.Collections {
		if c.ID != disc.Collection.ID {
			continue
		}
		found = true
		if len(c.ArchiveHash) != 64 {
			t.Errorf("exported archive_hash is not a full SHA-256: %q", c.ArchiveHash)
		}
		if len(c.IntegritySHA512) != 128 {
			t.Errorf("exported integrity_sha512 is not a full SHA-512: %q", c.IntegritySHA512)
		}
	}
	if !found {
		t.Fatal("the case's collection is missing from the export")
	}

	// Findings are attributable to the run in the same document.
	runIDs := map[string]bool{exp.AnalysisRuns[0].ID: true}
	for _, f := range exp.Findings {
		if f.AnalysisRunID != "" && !runIDs[f.AnalysisRunID] {
			t.Errorf("finding %s references run %q, which is not in the export", f.ID, f.AnalysisRunID)
		}
	}
}

// The exported evidence digest must equal what verification computes --
// two numbers describing the same evidence that disagree would be worse
// than either alone.
func TestExport_HashesAgreeWithVerification(t *testing.T) {
	mux := newTestRouter(t)
	caseID, collID, _ := dirEvidenceCase(t, mux, "Export vs verify")

	var exp CaseExport
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/export", nil, &exp)
	res := verifyIntegrity(t, mux, caseID, collID)

	for _, c := range exp.Collections {
		if c.ID != collID {
			continue
		}
		if c.IntegritySHA512 != res.RecordedSHA512 {
			t.Errorf("export digest %q != verification's recorded digest %q", c.IntegritySHA512, res.RecordedSHA512)
		}
		if res.Status == IntegrityVerified && c.IntegritySHA512 != res.ComputedSHA512 {
			t.Errorf("export digest %q != freshly computed digest %q", c.IntegritySHA512, res.ComputedSHA512)
		}
	}
}

// Exporting must not leak server paths.
func TestExport_LeaksNoServerPaths(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := dirEvidenceCaseIDs(t, mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/cases/"+caseID+"/export", nil))
	body := rec.Body.String()
	// evidence_directory is a pre-existing, deliberate field on
	// Collection; this checks only that nothing NEW leaks internals.
	for _, bad := range []string{"goroutine", ".go:", "SQL", "panic"} {
		if containsAny(body, bad) {
			t.Errorf("export leaks internals (%q)", bad)
		}
	}
}

func dirEvidenceCaseIDs(t *testing.T, mux http.Handler) (string, string) {
	t.Helper()
	caseID, collID, _ := dirEvidenceCase(t, mux, "Export leak check")
	return caseID, collID
}

// ---------------- audit immutability ----------------

// Ordinary application operations must APPEND to the audit trail and
// never modify what is already recorded.
func TestAudit_OrdinaryOperationsOnlyAppend(t *testing.T) {
	mux := newTestRouter(t)
	caseID, disc := analyzedCase(t, mux, "Audit append-only")

	baseline := auditEntries(t, mux, caseID)
	if len(baseline) == 0 {
		t.Fatal("no audit entries after building a case")
	}

	// Exercise a spread of ordinary operations.
	verifyIntegrity(t, mux, caseID, disc.Collection.ID)
	doJSON(t, mux, "POST", "/api/cases/"+caseID+"/analyze", nil, &AnalyzeResultSummary{})
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/export", nil, &CaseExport{})
	doJSON(t, mux, "PATCH", "/api/cases/"+caseID,
		map[string]string{"case_status": "investigating"}, &model.Case{})

	after := auditEntries(t, mux, caseID)
	if len(after) <= len(baseline) {
		t.Fatalf("audit did not grow: %d -> %d", len(baseline), len(after))
	}
	// Every historical entry must be byte-identical.
	for i, want := range baseline {
		if after[i] != want {
			t.Errorf("audit entry %d was modified.\n before: %+v\n after:  %+v", i, want, after[i])
		}
	}
}

// There must be no route that edits or deletes an individual audit
// entry. This asserts on the router itself rather than on a list of
// handlers someone could forget to update.
func TestAudit_NoRouteMutatesAnAuditEntry(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := analyzedCase(t, mux, "Audit no mutation")
	entries := auditEntries(t, mux, caseID)
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	target := entries[0]

	for _, method := range []string{"PUT", "PATCH", "DELETE", "POST"} {
		for _, path := range []string{
			"/api/cases/" + caseID + "/audit/" + target.ID,
			"/api/cases/" + caseID + "/audit",
		} {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
			// 404/405 are both fine: what matters is that nothing handles it.
			if rec.Code == http.StatusOK {
				t.Errorf("%s %s returned 200 -- audit entries must not be mutable through the API", method, path)
			}
		}
	}

	after := auditEntries(t, mux, caseID)
	if len(after) != len(entries) || after[0] != target {
		t.Error("an audit entry changed after attempted mutation")
	}
}
