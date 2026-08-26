package api

import (
	"net/http"
	"path/filepath"
	"testing"

	"tracefall/internal/model"
)

// TestCaseIsolation_NotesTagsAuditDoNotLeakAcrossCases is a Phase 6
// security-audit test: two cases' analyst-workflow data (notes, tags,
// audit log) must never be visible through the other case's endpoints,
// even though all of it lives in shared tables (notes/tags/audit_log)
// keyed by case_id rather than one-table-per-case.
func TestCaseIsolation_NotesTagsAuditDoNotLeakAcrossCases(t *testing.T) {
	mux := newTestRouter(t)
	caseA := createTestCase(t, mux, "Isolation case A")
	caseB := createTestCase(t, mux, "Isolation case B")

	doJSON(t, mux, "POST", "/api/cases/"+caseA.ID+"/notes",
		map[string]string{"target_type": model.TargetCase, "target_id": caseA.ID, "note": "case A secret observation"}, nil)
	doJSON(t, mux, "POST", "/api/cases/"+caseB.ID+"/notes",
		map[string]string{"target_type": model.TargetCase, "target_id": caseB.ID, "note": "case B secret observation"}, nil)
	doJSON(t, mux, "POST", "/api/cases/"+caseA.ID+"/tags",
		map[string]string{"target_type": model.TargetCase, "target_id": caseA.ID, "tag": "case-a-only"}, nil)

	var notesA, notesB []model.Note
	doJSON(t, mux, "GET", "/api/cases/"+caseA.ID+"/notes", nil, &notesA)
	doJSON(t, mux, "GET", "/api/cases/"+caseB.ID+"/notes", nil, &notesB)

	if len(notesA) != 1 || notesA[0].Text != "case A secret observation" {
		t.Fatalf("case A notes = %+v, want exactly its own note", notesA)
	}
	if len(notesB) != 1 || notesB[0].Text != "case B secret observation" {
		t.Fatalf("case B notes = %+v, want exactly its own note", notesB)
	}
	for _, n := range notesB {
		if n.Text == "case A secret observation" {
			t.Error("case B's notes response leaked case A's note")
		}
	}

	var tagsB []model.Tag
	doJSON(t, mux, "GET", "/api/cases/"+caseB.ID+"/tags", nil, &tagsB)
	if len(tagsB) != 0 {
		t.Errorf("case B tags = %+v, want empty (the tag was added to case A only)", tagsB)
	}

	var auditA, auditB []model.AuditEvent
	doJSON(t, mux, "GET", "/api/cases/"+caseA.ID+"/audit", nil, &auditA)
	doJSON(t, mux, "GET", "/api/cases/"+caseB.ID+"/audit", nil, &auditB)
	for _, e := range auditA {
		if e.CaseID != caseA.ID {
			t.Errorf("case A's audit log contains an event for a different case: %+v", e)
		}
	}
	for _, e := range auditB {
		if e.CaseID != caseB.ID {
			t.Errorf("case B's audit log contains an event for a different case: %+v", e)
		}
	}
}

// TestCaseIsolation_EvidenceDeletionScopedToOwningCase confirms deleting
// evidence in one case can never affect another case's event/finding
// counts, even when both cases happen to contain byte-identical evidence
// content (a duplicate KAPE package legitimately collected for two
// different investigations -- see docs/data-model.md's "Duplicate
// evidence collections" section on why that's allowed across cases).
func TestCaseIsolation_EvidenceDeletionScopedToOwningCase(t *testing.T) {
	mux := newTestRouter(t)
	caseA := createTestCase(t, mux, "Isolation evidence case A")
	caseB := createTestCase(t, mux, "Isolation evidence case B")
	root := filepath.Join("..", "..", "testdata", "scenarios", "f_powershell_download")

	discA := ingestLocalPath(t, mux, caseA.ID, root)
	importAll(t, mux, caseA.ID, discA)
	discB := ingestLocalPath(t, mux, caseB.ID, root)
	importAll(t, mux, caseB.ID, discB)

	summaryB := func() Summary {
		var data struct {
			Summary Summary `json:"summary"`
		}
		doJSON(t, mux, "GET", "/api/cases/"+caseB.ID, nil, &data)
		return data.Summary
	}
	before := summaryB()
	if before.Events == 0 {
		t.Fatal("expected case B to have imported events")
	}

	// Delete ALL of case A's evidence files.
	var sourceFileID string
	for _, sf := range discA.SourceFiles {
		sourceFileID = sf.ID
	}
	rec := doJSON(t, mux, "DELETE", "/api/cases/"+caseA.ID+"/evidence/"+sourceFileID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete case A evidence: status %d, body %s", rec.Code, rec.Body.String())
	}

	after := summaryB()
	if after.Events != before.Events {
		t.Errorf("case B's event count changed (%d -> %d) after deleting case A's evidence -- cross-case leakage", before.Events, after.Events)
	}
}
