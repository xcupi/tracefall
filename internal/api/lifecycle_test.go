package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"tracefall/internal/model"
)

// Phase 13 gave the analyst lifecycle authority over the evidence set.
// These tests pin BOTH halves: that a locked case genuinely refuses
// mutations at the API (not merely in the UI), and that everything a
// locked case is still supposed to do keeps working.

func setStatus(t *testing.T, mux http.Handler, caseID, status string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, mux, "PATCH", "/api/cases/"+caseID, map[string]string{"case_status": status}, nil)
}

func setPriority(t *testing.T, mux http.Handler, caseID, priority string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, mux, "PATCH", "/api/cases/"+caseID, map[string]string{"priority": priority}, nil)
}

func caseNow(t *testing.T, mux http.Handler, caseID string) model.Case {
	t.Helper()
	var out struct {
		Case model.Case `json:"case"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+caseID, nil, &out)
	return out.Case
}

// ---------------- lifecycle ----------------

// All FOUR statuses exist and are settable. Investigating in particular
// must not be quietly lost.
func TestLifecycle_AllFourStatusesAreSupported(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Four statuses")

	if c.CaseStatus != model.CaseWorkflowOpen {
		t.Errorf("a new case starts as %q, want %q", c.CaseStatus, model.CaseWorkflowOpen)
	}
	for _, status := range []string{
		model.CaseWorkflowOpen,
		model.CaseWorkflowInvestigating,
		model.CaseWorkflowContained,
		model.CaseWorkflowClosed,
	} {
		if rec := setStatus(t, mux, c.ID, status); rec.Code != http.StatusOK {
			t.Fatalf("setting status %q: status %d, body %s", status, rec.Code, rec.Body.String())
		}
		if got := caseNow(t, mux, c.ID).CaseStatus; got != status {
			t.Errorf("case_status = %q, want %q", got, status)
		}
	}
}

// The transitions the phase names explicitly, walked in order.
func TestLifecycle_DocumentedTransitionsAllWork(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Transitions")

	for _, step := range []struct{ from, to string }{
		{model.CaseWorkflowOpen, model.CaseWorkflowInvestigating},
		{model.CaseWorkflowInvestigating, model.CaseWorkflowContained},
		{model.CaseWorkflowContained, model.CaseWorkflowClosed},
		{model.CaseWorkflowClosed, model.CaseWorkflowOpen}, // reopen
		{model.CaseWorkflowOpen, model.CaseWorkflowClosed}, // straight to closed
		{model.CaseWorkflowClosed, model.CaseWorkflowOpen}, // reopen again
	} {
		t.Run(step.from+"->"+step.to, func(t *testing.T) {
			if got := caseNow(t, mux, c.ID).CaseStatus; got != step.from {
				t.Fatalf("precondition: case is %q, expected %q", got, step.from)
			}
			if rec := setStatus(t, mux, c.ID, step.to); rec.Code != http.StatusOK {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
			}
			if got := caseNow(t, mux, c.ID).CaseStatus; got != step.to {
				t.Errorf("case_status = %q, want %q", got, step.to)
			}
		})
	}
}

// Closed is NOT terminal, and reopening uses the ordinary status update
// rather than any separate mechanism.
func TestLifecycle_ClosedCaseCanBeReopened(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Reopen")
	setStatus(t, mux, c.ID, model.CaseWorkflowClosed)

	if rec := setStatus(t, mux, c.ID, model.CaseWorkflowOpen); rec.Code != http.StatusOK {
		t.Fatalf("reopening a closed case: status %d, body %s", rec.Code, rec.Body.String())
	}
	after := caseNow(t, mux, c.ID)
	if after.CaseStatus != model.CaseWorkflowOpen {
		t.Errorf("case_status = %q, want open", after.CaseStatus)
	}
}

func TestLifecycle_InvalidStatusIsRejected(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Invalid status")
	for _, bad := range []string{"archived", "OPEN", "", "deleted"} {
		if rec := setStatus(t, mux, c.ID, bad); rec.Code == http.StatusOK {
			t.Errorf("status %q was accepted", bad)
		}
	}
	if got := caseNow(t, mux, c.ID).CaseStatus; got != model.CaseWorkflowOpen {
		t.Errorf("a rejected status change altered the case: %q", got)
	}
}

// ---------------- evidence locking ----------------

// evidenceMutationAttempts returns every API call that changes the
// evidence set, so the lock is tested across all of them rather than
// only the one that was convenient.
func evidenceMutationAttempts(mux http.Handler, caseID, sourceFileID, collectionID string) []struct {
	Name   string
	Do     func(t *testing.T) *httptest.ResponseRecorder
	Method string
} {
	return []struct {
		Name   string
		Do     func(t *testing.T) *httptest.ResponseRecorder
		Method string
	}{
		{"discover from path", func(t *testing.T) *httptest.ResponseRecorder {
			return discoverPath(t, mux, caseID, "../../testdata/synthetic_case")
		}, "POST"},
		{"import", func(t *testing.T) *httptest.ResponseRecorder {
			return doJSON(t, mux, "POST", "/api/cases/"+caseID+"/evidence/"+collectionID+"/import",
				map[string][]string{"source_file_ids": {sourceFileID}}, nil)
		}, "POST"},
		{"start background import", func(t *testing.T) *httptest.ResponseRecorder {
			return doJSON(t, mux, "POST", "/api/cases/"+caseID+"/evidence/"+collectionID+"/import/start",
				map[string][]string{"source_file_ids": {sourceFileID}}, nil)
		}, "POST"},
		{"delete one source file", func(t *testing.T) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest("DELETE", "/api/cases/"+caseID+"/evidence/"+sourceFileID, nil))
			return rec
		}, "DELETE"},
		{"bulk delete evidence", func(t *testing.T) *httptest.ResponseRecorder {
			return doJSON(t, mux, "DELETE", "/api/cases/"+caseID+"/evidence",
				map[string][]string{"source_file_ids": {sourceFileID}}, nil)
		}, "DELETE"},
	}
}

// lockedCase builds a case with real discovered evidence, then puts it
// into the given status.
func lockedCase(t *testing.T, status string) (http.Handler, string, string, string) {
	t.Helper()
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Lock "+status)
	rec := discoverPath(t, mux, c.ID, "../../testdata/synthetic_case")
	if rec.Code != http.StatusOK {
		t.Fatalf("seeding evidence: status %d", rec.Code)
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	if len(disc.SourceFiles) == 0 {
		t.Fatal("no source files discovered")
	}
	setStatus(t, mux, c.ID, status)
	return mux, c.ID, disc.SourceFiles[0].ID, disc.Collection.ID
}

func TestEvidenceLock_OpenAndInvestigatingAllowMutation(t *testing.T) {
	for _, status := range []string{model.CaseWorkflowOpen, model.CaseWorkflowInvestigating} {
		t.Run(status, func(t *testing.T) {
			mux, caseID, sfID, collID := lockedCase(t, status)

			// Import must work.
			rec := doJSON(t, mux, "POST", "/api/cases/"+caseID+"/evidence/"+collID+"/import",
				map[string][]string{"source_file_ids": {sfID}}, nil)
			if rec.Code != http.StatusOK {
				t.Errorf("import while %s: status %d, body %s", status, rec.Code, rec.Body.String())
			}
			// Deleting must work.
			del := httptest.NewRecorder()
			mux.ServeHTTP(del, httptest.NewRequest("DELETE", "/api/cases/"+caseID+"/evidence/"+sfID, nil))
			if del.Code != http.StatusOK {
				t.Errorf("delete while %s: status %d, body %s", status, del.Code, del.Body.String())
			}
		})
	}
}

// THE core requirement: a contained or closed case refuses every
// evidence mutation, through the API, and changes nothing.
func TestEvidenceLock_ContainedAndClosedRejectEveryMutation(t *testing.T) {
	for _, status := range []string{model.CaseWorkflowContained, model.CaseWorkflowClosed} {
		t.Run(status, func(t *testing.T) {
			mux, caseID, sfID, collID := lockedCase(t, status)

			before := sourcesSnapshot(t, mux, caseID)
			for _, attempt := range evidenceMutationAttempts(mux, caseID, sfID, collID) {
				rec := attempt.Do(t)
				if rec.Code != http.StatusConflict {
					t.Errorf("%s while %s: status %d, want 409", attempt.Name, status, rec.Code)
				}
				if !containsAny(rec.Body.String(), "locked") {
					t.Errorf("%s: refusal does not explain the lock: %s", attempt.Name, rec.Body.String())
				}
			}
			// Nothing changed.
			if after := sourcesSnapshot(t, mux, caseID); after != before {
				t.Errorf("a blocked mutation changed the evidence set:\n before: %s\n after:  %s", before, after)
			}
		})
	}
}

// Reopening restores mutability -- the lock is state, not a one-way door.
func TestEvidenceLock_ReopeningRestoresMutability(t *testing.T) {
	mux, caseID, sfID, collID := lockedCase(t, model.CaseWorkflowClosed)

	rec := doJSON(t, mux, "POST", "/api/cases/"+caseID+"/evidence/"+collID+"/import",
		map[string][]string{"source_file_ids": {sfID}}, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("precondition: import while closed returned %d, want 409", rec.Code)
	}

	if rec := setStatus(t, mux, caseID, model.CaseWorkflowOpen); rec.Code != http.StatusOK {
		t.Fatalf("reopen: %d", rec.Code)
	}
	rec = doJSON(t, mux, "POST", "/api/cases/"+caseID+"/evidence/"+collID+"/import",
		map[string][]string{"source_file_ids": {sfID}}, nil)
	if rec.Code != http.StatusOK {
		t.Errorf("import after reopening: status %d, body %s", rec.Code, rec.Body.String())
	}
}

// Locking freezes the evidence SET. It must not disable reading,
// analysing, exporting, investigating or verifying integrity.
func TestEvidenceLock_ReadAndInvestigationRemainAvailable(t *testing.T) {
	for _, status := range []string{model.CaseWorkflowContained, model.CaseWorkflowClosed} {
		t.Run(status, func(t *testing.T) {
			mux := newTestRouter(t)
			c := mustCreateCase(t, mux, "Readable "+status)
			discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
			doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, &AnalyzeResultSummary{})

			var collections []model.Collection
			doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence", nil, &collections)
			if len(collections) == 0 {
				t.Fatal("no collections")
			}
			setStatus(t, mux, c.ID, status)

			for _, tc := range []struct{ name, method, path string }{
				{"timeline", "GET", "/api/cases/" + c.ID + "/timeline"},
				{"findings", "GET", "/api/cases/" + c.ID + "/findings"},
				{"investigations", "GET", "/api/cases/" + c.ID + "/investigations"},
				{"attack", "GET", "/api/cases/" + c.ID + "/attack"},
				{"correlations", "GET", "/api/cases/" + c.ID + "/correlations"},
				{"provenance", "GET", "/api/cases/" + c.ID + "/provenance"},
				{"evidence list", "GET", "/api/cases/" + c.ID + "/evidence"},
				{"audit", "GET", "/api/cases/" + c.ID + "/audit"},
				{"export", "GET", "/api/cases/" + c.ID + "/export"},
			} {
				rec := doJSON(t, mux, tc.method, tc.path, nil, nil)
				if rec.Code != http.StatusOK {
					t.Errorf("%s while %s: status %d -- locking evidence must not disable reading", tc.name, status, rec.Code)
				}
			}

			// Re-analysis is not an evidence mutation.
			if rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil); rec.Code != http.StatusOK {
				t.Errorf("analyze while %s: status %d -- analysis reads evidence, it does not change it", status, rec.Code)
			}
			// Integrity verification is read-only (Phase 11) and must stay available.
			rec := doJSON(t, mux, "POST",
				"/api/cases/"+c.ID+"/evidence/"+collections[0].ID+"/verify-integrity", nil, nil)
			if rec.Code != http.StatusOK {
				t.Errorf("verify-integrity while %s: status %d -- verification is read-only", status, rec.Code)
			}
			// Analyst annotation is case metadata, not evidence.
			note := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/notes",
				map[string]string{"target_type": model.TargetCase, "target_id": c.ID, "note": "still annotating"}, nil)
			if note.Code != http.StatusCreated {
				t.Errorf("adding a note while %s: status %d", status, note.Code)
			}
		})
	}
}

// ---------------- priority locking ----------------

func TestPriorityLock_EditableUntilClosed(t *testing.T) {
	for _, status := range []string{
		model.CaseWorkflowOpen, model.CaseWorkflowInvestigating, model.CaseWorkflowContained,
	} {
		t.Run(status, func(t *testing.T) {
			mux := newTestRouter(t)
			c := mustCreateCase(t, mux, "Priority "+status)
			setStatus(t, mux, c.ID, status)

			if rec := setPriority(t, mux, c.ID, model.CasePriorityCritical); rec.Code != http.StatusOK {
				t.Fatalf("priority change while %s: status %d, body %s", status, rec.Code, rec.Body.String())
			}
			if got := caseNow(t, mux, c.ID).Priority; got != model.CasePriorityCritical {
				t.Errorf("priority = %q, want critical", got)
			}
		})
	}
}

func TestPriorityLock_ClosedRejectsPriorityChange(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Priority closed")
	setPriority(t, mux, c.ID, model.CasePriorityHigh)
	setStatus(t, mux, c.ID, model.CaseWorkflowClosed)

	rec := setPriority(t, mux, c.ID, model.CasePriorityLow)
	if rec.Code != http.StatusConflict {
		t.Fatalf("priority change on a closed case: status %d, want 409", rec.Code)
	}
	if got := caseNow(t, mux, c.ID).Priority; got != model.CasePriorityHigh {
		t.Errorf("priority = %q; a rejected change still mutated the case", got)
	}
}

// Re-submitting the SAME priority is not a change and must not be
// refused -- otherwise a plain "close this case" save would fail
// whenever the UI submits the unchanged priority alongside it.
func TestPriorityLock_ResubmittingTheSamePriorityIsNotAChange(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Priority no-op")
	setPriority(t, mux, c.ID, model.CasePriorityHigh)
	setStatus(t, mux, c.ID, model.CaseWorkflowClosed)

	rec := doJSON(t, mux, "PATCH", "/api/cases/"+c.ID,
		map[string]string{"priority": model.CasePriorityHigh}, nil)
	if rec.Code != http.StatusOK {
		t.Errorf("re-sending the current priority on a closed case: status %d, want 200", rec.Code)
	}
}

// Closing and re-prioritising at once is refused as a combination rather
// than silently applying one and dropping the other.
func TestPriorityLock_ClosingAndChangingPriorityTogetherIsRefused(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Combined close")
	setPriority(t, mux, c.ID, model.CasePriorityMedium)

	rec := doJSON(t, mux, "PATCH", "/api/cases/"+c.ID, map[string]string{
		"case_status": model.CaseWorkflowClosed,
		"priority":    model.CasePriorityCritical,
	}, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("closing while changing priority: status %d, want 409", rec.Code)
	}
	// NEITHER half was applied.
	after := caseNow(t, mux, c.ID)
	if after.CaseStatus == model.CaseWorkflowClosed {
		t.Error("the status was applied despite the request being refused")
	}
	if after.Priority != model.CasePriorityMedium {
		t.Errorf("priority = %q; the refused request still changed it", after.Priority)
	}
}

func TestPriorityLock_ReopeningRestoresPriorityEditing(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Priority reopen")
	setStatus(t, mux, c.ID, model.CaseWorkflowClosed)
	if rec := setPriority(t, mux, c.ID, model.CasePriorityLow); rec.Code != http.StatusConflict {
		t.Fatalf("precondition: %d", rec.Code)
	}

	setStatus(t, mux, c.ID, model.CaseWorkflowOpen)
	if rec := setPriority(t, mux, c.ID, model.CasePriorityLow); rec.Code != http.StatusOK {
		t.Errorf("priority change after reopening: status %d, body %s", rec.Code, rec.Body.String())
	}
}

// ---------------- lock state is published ----------------

func TestLifecycle_CaseEndpointPublishesLockState(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Lock flags")

	for _, tc := range []struct {
		status                 string
		wantEvidence, wantPrio bool
	}{
		{model.CaseWorkflowOpen, true, true},
		{model.CaseWorkflowInvestigating, true, true},
		{model.CaseWorkflowContained, false, true},
		{model.CaseWorkflowClosed, false, false},
	} {
		setStatus(t, mux, c.ID, tc.status)
		var out struct {
			EvidenceMutable  bool `json:"evidence_mutable"`
			PriorityEditable bool `json:"priority_editable"`
		}
		doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &out)
		if out.EvidenceMutable != tc.wantEvidence {
			t.Errorf("%s: evidence_mutable = %v, want %v", tc.status, out.EvidenceMutable, tc.wantEvidence)
		}
		if out.PriorityEditable != tc.wantPrio {
			t.Errorf("%s: priority_editable = %v, want %v", tc.status, out.PriorityEditable, tc.wantPrio)
		}
	}
}

// sourcesSnapshot captures the evidence set as a comparable string, so a
// blocked mutation can be shown to have changed nothing at all.
func sourcesSnapshot(t *testing.T, mux http.Handler, caseID string) string {
	t.Helper()
	var sources []model.SourceFile
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/sources", nil, &sources)
	out := ""
	for _, sf := range sources {
		out += fmt.Sprintf("%s|%s|%d;", sf.ID, sf.ImportStatus, sf.EventCount)
	}
	return out
}
