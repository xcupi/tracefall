package api

import (
	"net/http"
	"testing"

	"tracefall/internal/model"
)

// Derived analysis output must never outlive the evidence it came from.
//
// The defect: deleting the LAST source file resets Case.Status to
// "created", and AnalyzeCase refused to run in that state with 409
// ErrNotIngested. Re-analysis was therefore blocked exactly when it was
// most needed, so the previous run's findings, correlations and ATT&CK
// techniques stayed in the database and kept being served as current
// results for evidence that no longer existed. Investigations,
// recomputed on read from those rows, were stale for the same reason.
//
// Partial deletion always worked, because it leaves the status
// "ingested" -- which is why this only showed up when every file was
// removed.

type derived struct {
	Events, Findings, Correlations, Investigations, Techniques int
}

func derivedCounts(t *testing.T, mux http.Handler, caseID string) derived {
	t.Helper()
	var summary struct {
		Summary struct {
			Events         int `json:"events"`
			Findings       int `json:"findings"`
			Correlations   int `json:"correlations"`
			Investigations int `json:"investigations"`
			TechniqueCount int `json:"technique_count"`
		} `json:"summary"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+caseID, nil, &summary)

	// Cross-check the summary against the list endpoints the dashboard
	// actually renders, so a summary that disagreed with them would fail
	// here rather than looking correct.
	var findings []model.Finding
	var correlations []model.Correlation
	var investigations []model.Investigation
	var techniques []AttackTechnique
	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings)
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/correlations", nil, &correlations)
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/investigations", nil, &investigations)
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/attack", nil, &techniques)
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/timeline", nil, &events)

	got := derived{len(events), len(findings), len(correlations), len(investigations), len(techniques)}
	want := derived{summary.Summary.Events, summary.Summary.Findings, summary.Summary.Correlations,
		summary.Summary.Investigations, summary.Summary.TechniqueCount}
	if got != want {
		t.Errorf("the case summary disagrees with the list endpoints:\n summary: %+v\n lists:   %+v", want, got)
	}
	return got
}

func deleteAllEvidence(t *testing.T, mux http.Handler, caseID string) {
	t.Helper()
	var sources []model.SourceFile
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/sources", nil, &sources)
	ids := make([]string, 0, len(sources))
	for _, sf := range sources {
		ids = append(ids, sf.ID)
	}
	rec := doJSON(t, mux, "DELETE", "/api/cases/"+caseID+"/evidence",
		map[string][]string{"source_file_ids": ids}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("deleting evidence: status %d, body %s", rec.Code, rec.Body.String())
	}
}

// analyzeStatus runs analysis and returns the HTTP status, so a test can
// assert a REFUSAL as well as a success. The existing analyze() helper
// fails the test on any non-200, which is the wrong shape here.
func analyzeStatus(t *testing.T, mux http.Handler, caseID string) int {
	t.Helper()
	return doJSON(t, mux, "POST", "/api/cases/"+caseID+"/analyze", nil, nil).Code
}

// THE REGRESSION: delete every piece of evidence, rerun, and every
// derived number must be zero.
func TestStaleAnalysis_DeletingAllEvidenceThenRerunningClearsDerivedResults(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Delete all then rerun")
	discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	analyzeStatus(t, mux, c.ID)

	before := derivedCounts(t, mux, c.ID)
	if before.Findings == 0 || before.Events == 0 {
		t.Fatalf("baseline produced nothing to invalidate: %+v", before)
	}

	deleteAllEvidence(t, mux, c.ID)

	// Re-analysis must be PERMITTED here. It used to 409, which is what
	// left the orphaned results in place.
	if code := analyzeStatus(t, mux, c.ID); code != http.StatusOK {
		t.Fatalf("re-analysis after deleting all evidence: status %d, want 200 -- "+
			"refusing here is what leaves derived results orphaned", code)
	}

	after := derivedCounts(t, mux, c.ID)
	if after != (derived{}) {
		t.Errorf("derived results survived the removal of all evidence: %+v", after)
	}
}

// A case that has NEVER held evidence is still refused -- the fix must
// not turn the guard off entirely.
func TestStaleAnalysis_BrandNewCaseStillRefusesAnalysis(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Never ingested")

	if code := analyzeStatus(t, mux, c.ID); code != http.StatusConflict {
		t.Errorf("analysing a case that never had evidence: status %d, want 409", code)
	}
}

// Deleting one collection while another remains: results must come from
// the survivor only.
func TestStaleAnalysis_RerunReflectsOnlyRemainingEvidence(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Two collections")
	discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	disc2, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/native_samples")
	analyzeStatus(t, mux, c.ID)
	both := derivedCounts(t, mux, c.ID)

	// Remove every file belonging to the second collection only.
	var sources []model.SourceFile
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/sources", nil, &sources)
	ids := []string{}
	for _, sf := range sources {
		if sf.CollectionID == disc2.Collection.ID {
			ids = append(ids, sf.ID)
		}
	}
	if len(ids) == 0 {
		t.Fatal("no files found for the second collection")
	}
	doJSON(t, mux, "DELETE", "/api/cases/"+c.ID+"/evidence", map[string][]string{"source_file_ids": ids}, nil)

	if code := analyzeStatus(t, mux, c.ID); code != http.StatusOK {
		t.Fatalf("rerun: status %d", code)
	}
	after := derivedCounts(t, mux, c.ID)

	if after.Events >= both.Events {
		t.Errorf("events did not shrink after removing a collection: %d -> %d", both.Events, after.Events)
	}
	if after.Events == 0 {
		t.Error("removing one collection removed the other collection's events too")
	}
	// Every remaining event must belong to the surviving collection.
	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &events)
	for _, e := range events {
		if e.CollectionID == disc2.Collection.ID {
			t.Errorf("an event from the deleted collection survived: %s", e.ID)
		}
	}
}

// Import new evidence after a prior analysis: the rerun must reflect the
// current set, not the union with a stale one.
func TestStaleAnalysis_RerunAfterReimportReflectsCurrentEvidence(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Delete then reimport")
	discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	analyzeStatus(t, mux, c.ID)

	deleteAllEvidence(t, mux, c.ID)
	analyzeStatus(t, mux, c.ID)
	if empty := derivedCounts(t, mux, c.ID); empty != (derived{}) {
		t.Fatalf("expected an empty snapshot, got %+v", empty)
	}

	// Fresh evidence into the emptied case.
	discoverPathAndImportAll(t, mux, c.ID, "../../testdata/native_samples")
	if code := analyzeStatus(t, mux, c.ID); code != http.StatusOK {
		t.Fatalf("rerun after reimport: status %d", code)
	}
	after := derivedCounts(t, mux, c.ID)
	if after.Events == 0 || after.Findings == 0 {
		t.Errorf("re-imported evidence produced no results: %+v", after)
	}
}

// Repeated analysis with unchanged evidence must be deterministic and
// must not accumulate.
func TestStaleAnalysis_RepeatedRunsAreDeterministic(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Deterministic reruns")
	discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")

	analyzeStatus(t, mux, c.ID)
	first := derivedCounts(t, mux, c.ID)
	for i := 0; i < 3; i++ {
		analyzeStatus(t, mux, c.ID)
		if got := derivedCounts(t, mux, c.ID); got != first {
			t.Fatalf("rerun %d changed the results: %+v -> %+v", i+1, first, got)
		}
	}
}

// Deleting evidence must mark the case stale so the dashboard cannot
// present the old numbers as current without a rerun.
func TestStaleAnalysis_DeletionMarksTheCaseStale(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Deletion marks stale")
	discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	analyzeStatus(t, mux, c.ID)

	var before model.Case
	var wrapper struct {
		Case model.Case `json:"case"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &wrapper)
	before = wrapper.Case
	if before.Status != model.CaseStatusAnalyzed {
		t.Fatalf("case status = %q, want analyzed", before.Status)
	}

	deleteAllEvidence(t, mux, c.ID)
	doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &wrapper)
	if wrapper.Case.Status == model.CaseStatusAnalyzed {
		t.Error("the case still reports itself analyzed after its evidence was deleted")
	}
}
