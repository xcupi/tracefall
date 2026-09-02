package api

import (
	"net/http"
	"testing"

	"tracefall/internal/model"
)

// The evidence-deletion lifecycle.
//
// The bug this guards against was a case reporting 0 events and 0
// evidence beside 1,520 findings and 1,520 investigations. Every derived
// view is computed from stored findings/correlations, so deleting the
// evidence without invalidating the analysis left results that looked
// authoritative and described nothing the case still held.
//
// The rule enforced here: analysis describes an evidence set, and when
// that set changes by deletion the analysis stops being current --
// in the query layer, so no API response can return it.

// importedFileIDs lists a collection's imported evidence files.
func importedFileIDs(t *testing.T, mux http.Handler, caseID, collectionID string) []string {
	t.Helper()
	var page struct {
		Items []TriagedSourceFile `json:"items"`
	}
	doJSON(t, mux, "GET",
		"/api/cases/"+caseID+"/evidence/"+collectionID+"/files?page=1&page_size=250&status=imported", nil, &page)
	ids := make([]string, 0, len(page.Items))
	for _, f := range page.Items {
		ids = append(ids, f.ID)
	}
	return ids
}

// derivedState is every current derived count in one place.
type derivedState struct {
	Events         int
	Findings       int
	Correlations   int
	Investigations int
	Techniques     int
	Chains         int
}

func currentDerived(t *testing.T, mux http.Handler, caseID string) derivedState {
	t.Helper()
	summary := caseSummaryOf(t, mux, caseID)

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings)
	var corrs []model.Correlation
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/correlations", nil, &corrs)
	var invs []model.Investigation
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/investigations", nil, &invs)
	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/timeline", nil, &events)
	var attack []map[string]any
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/attack", nil, &attack)

	chains := 0
	for _, c := range corrs {
		if c.Type == model.CorrelationActivityChain {
			chains++
		}
	}
	// The endpoints and the summary must agree; a disagreement is the
	// exact class of bug this file exists to catch.
	if len(findings) != summary.Findings {
		t.Errorf("findings endpoint returned %d but the summary says %d", len(findings), summary.Findings)
	}
	if len(corrs) != summary.Correlations {
		t.Errorf("correlations endpoint returned %d but the summary says %d", len(corrs), summary.Correlations)
	}
	if len(invs) != summary.Investigations {
		t.Errorf("investigations endpoint returned %d but the summary says %d", len(invs), summary.Investigations)
	}
	if len(events) != summary.Events {
		t.Errorf("timeline returned %d events but the summary says %d", len(events), summary.Events)
	}
	return derivedState{
		Events: len(events), Findings: len(findings), Correlations: len(corrs),
		Investigations: len(invs), Techniques: summary.TechniqueCount, Chains: chains,
	}
}

// caseSummaryOf reads the summary the case detail endpoint returns
// alongside the case -- there is no separate /summary route.
func caseSummaryOf(t *testing.T, mux http.Handler, caseID string) Summary {
	t.Helper()
	var wrapper struct {
		Summary Summary `json:"summary"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+caseID, nil, &wrapper)
	return wrapper.Summary
}

// runsOf reads the analysis-run history from the case provenance view,
// which is where it is exposed.
func runsOf(t *testing.T, mux http.Handler, caseID string) []model.AnalysisRun {
	t.Helper()
	var prov CaseProvenance
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/provenance", nil, &prov)
	return prov.AnalysisRuns
}

func caseOf(t *testing.T, mux http.Handler, caseID string) model.Case {
	t.Helper()
	var wrapper struct {
		Case model.Case `json:"case"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+caseID, nil, &wrapper)
	return wrapper.Case
}

// 1. Evidence present and analyzed: findings and investigations exist.
func TestInvalidation_AnalyzedCaseShowsItsResults(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Analyzed case")
	discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	analyzeStatus(t, mux, c.ID)

	got := currentDerived(t, mux, c.ID)
	if got.Events == 0 {
		t.Fatal("no events; the fixture did not import")
	}
	if got.Findings == 0 || got.Investigations == 0 {
		t.Fatalf("analysis produced nothing to invalidate: %+v", got)
	}
	if caseOf(t, mux, c.ID).Status != model.CaseStatusAnalyzed {
		t.Error("the case does not report itself analyzed")
	}
	if caseSummaryOf(t, mux, c.ID).AnalysisInvalidated {
		t.Error("a freshly analyzed case reports invalidated analysis")
	}
}

// 2. Deleting all evidence zeroes every current derived count.
func TestInvalidation_DeletingAllEvidenceZeroesEveryDerivedCount(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Delete all evidence")
	disc, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	analyzeStatus(t, mux, c.ID)

	before := currentDerived(t, mux, c.ID)
	if before.Findings == 0 {
		t.Fatal("nothing to invalidate")
	}

	deleteCollection(t, mux, c.ID, disc.Collection.ID)

	after := currentDerived(t, mux, c.ID)
	if after != (derivedState{}) {
		t.Errorf("derived results survived evidence deletion: %+v", after)
	}
	// And the case's own counters agree.
	s := caseSummaryOf(t, mux, c.ID)
	if s.Events != 0 || s.Findings != 0 || s.Correlations != 0 ||
		s.Investigations != 0 || s.TechniqueCount != 0 {
		t.Errorf("summary still reports derived results: %+v", s)
	}
	for sev, n := range s.SeverityCounts {
		if n != 0 {
			t.Errorf("severity counter %q is %d after deletion", sev, n)
		}
	}
	for sev, n := range s.InvestigationSeverityCounts {
		if n != 0 {
			t.Errorf("investigation severity counter %q is %d after deletion", sev, n)
		}
	}
}

// 3. The case reports NOT ANALYZED, not STALE.
//
// Stale means "results still describe evidence that exists". After a
// deletion there is no valid analysis at all, and the two must not be
// conflated -- the whole point is that an analyst can tell them apart.
func TestInvalidation_CaseReportsNotAnalyzedRatherThanStale(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Not analyzed after deletion")
	disc, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	analyzeStatus(t, mux, c.ID)

	if caseOf(t, mux, c.ID).AnalyzedAt == nil {
		t.Fatal("an analyzed case has no analysis timestamp")
	}

	deleteCollection(t, mux, c.ID, disc.Collection.ID)

	got := caseOf(t, mux, c.ID)
	if got.Status == model.CaseStatusAnalyzed {
		t.Error("the case still reports itself analyzed")
	}
	// The analysis timestamp is cleared: there is no current analysis to
	// timestamp. The run history retains when it happened.
	if got.AnalyzedAt != nil {
		t.Errorf("the case still carries an analysis timestamp (%s); it has no valid analysis", got.AnalyzedAt)
	}
	// And the summary says explicitly WHY it is not analyzed, so the UI
	// can distinguish this from a case that never ran analysis.
	if !caseSummaryOf(t, mux, c.ID).AnalysisInvalidated {
		t.Error("the summary does not report that analysis was invalidated")
	}
}

// 4. Stale remains possible: evidence still exists but has changed.
func TestInvalidation_StaleStillHappensWhenEvidenceRemains(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Still stale")
	discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	analyzeStatus(t, mux, c.ID)

	// ADDING evidence changes the set without deleting anything.
	discoverPathAndImportAll(t, mux, c.ID, "../../testdata/native_samples")

	got := currentDerived(t, mux, c.ID)
	if got.Findings == 0 {
		t.Fatal("adding evidence destroyed the existing findings; only deletion invalidates")
	}
	s := caseSummaryOf(t, mux, c.ID)
	if s.AnalysisInvalidated {
		t.Error("adding evidence reported the analysis as invalidated; it is merely stale")
	}
	c2 := caseOf(t, mux, c.ID)
	if c2.Status == model.CaseStatusAnalyzed {
		t.Error("the case reports itself current after evidence changed")
	}
	if c2.AnalyzedAt == nil {
		t.Error("a stale case lost its analysis timestamp; stale results still have a run time")
	}
}

//  5. The invalidated run is retained as history and excluded from
//     current results.
func TestInvalidation_RunHistoryIsRetainedAndMarked(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Run history")
	disc, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	analyzeStatus(t, mux, c.ID)

	before := runsOf(t, mux, c.ID)
	if len(before) != 1 || before[0].Status != model.AnalysisRunCompleted {
		t.Fatalf("expected one completed run, got %+v", before)
	}
	producedFindings := before[0].FindingCount
	if producedFindings == 0 {
		t.Fatal("the run recorded no findings")
	}

	deleteCollection(t, mux, c.ID, disc.Collection.ID)

	after := runsOf(t, mux, c.ID)
	if len(after) != 1 {
		t.Fatalf("the run history was destroyed: %d rows", len(after))
	}
	run := after[0]
	if run.Status != model.AnalysisRunInvalidated {
		t.Errorf("run status = %q, want invalidated", run.Status)
	}
	if run.InvalidatedAt == nil {
		t.Error("the invalidated run records no invalidation time")
	}
	if run.InvalidationReason == "" {
		t.Error("the invalidated run does not say why it was invalidated")
	}
	// The historical record still shows what the run produced and which
	// run it was -- that is what makes it auditable.
	if run.FindingCount != producedFindings {
		t.Errorf("the run's finding count changed from %d to %d", producedFindings, run.FindingCount)
	}
	if run.ID == "" || run.CompletedAt == nil {
		t.Error("the run lost its identity or completion time")
	}
	if run.IsCurrent() {
		t.Error("an invalidated run reports itself current")
	}
}

// 6. Deletion is recorded in the audit log as its own event.
func TestInvalidation_IsAudited(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Audited invalidation")
	disc, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	analyzeStatus(t, mux, c.ID)
	deleteCollection(t, mux, c.ID, disc.Collection.ID)

	var entries []model.AuditEvent
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/audit", nil, &entries)
	var found bool
	for _, e := range entries {
		if e.Action == model.AuditAnalysisInvalidated {
			found = true
			if e.Summary == "" {
				t.Error("the invalidation audit entry has no summary")
			}
		}
	}
	if !found {
		t.Error("no audit entry records that the analysis was invalidated")
	}
}

// 7. Re-analysis after deletion works and produces a coherent snapshot.
func TestInvalidation_ReanalysisAfterDeletionProducesCurrentResults(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Reanalyze after deletion")
	disc, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	analyzeStatus(t, mux, c.ID)
	deleteCollection(t, mux, c.ID, disc.Collection.ID)

	if code := analyzeStatus(t, mux, c.ID); code != http.StatusOK {
		t.Fatalf("re-analysis after deletion returned %d", code)
	}
	if got := currentDerived(t, mux, c.ID); got != (derivedState{}) {
		t.Errorf("re-analysis of an empty case produced results: %+v", got)
	}
	// A new run is recorded beside the invalidated one, and the history
	// still shows both.
	runs := runsOf(t, mux, c.ID)
	if len(runs) != 2 {
		t.Fatalf("got %d runs, want the invalidated one plus the new one", len(runs))
	}
	var invalidated, completed int
	for _, r := range runs {
		switch r.Status {
		case model.AnalysisRunInvalidated:
			invalidated++
		case model.AnalysisRunCompleted:
			completed++
		}
	}
	if invalidated != 1 || completed != 1 {
		t.Errorf("run statuses = %d invalidated / %d completed, want 1 and 1", invalidated, completed)
	}
}

//  8. Deleting SOME evidence invalidates the analysis, and re-running it
//     produces results for the surviving evidence only.
//
// The unit of invalidation is the run, because correlations, activity
// chains and investigations are derived from the event set as a whole --
// a cluster computed over events that have since been deleted is not
// "partly correct". Per-evidence precision comes from re-analysis, which
// sees only what survived.
func TestInvalidation_PartialDeletionInvalidatesThenRecomputes(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Partial deletion")
	keep, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	drop, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/native_samples")
	analyzeStatus(t, mux, c.ID)

	both := currentDerived(t, mux, c.ID)
	if both.Events == 0 || both.Findings == 0 {
		t.Fatal("the two-collection fixture produced nothing")
	}

	deleteCollection(t, mux, c.ID, drop.Collection.ID)

	// Immediately after: nothing current, because the analysis covered
	// evidence that no longer exists.
	if got := currentDerived(t, mux, c.ID); got.Findings != 0 || got.Correlations != 0 || got.Investigations != 0 {
		t.Errorf("results derived from the deleted collection are still current: %+v", got)
	}
	// Events from the SURVIVING collection are untouched -- only the
	// analysis was invalidated, not the evidence.
	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &events)
	if len(events) == 0 {
		t.Fatal("deleting one collection removed the other collection's events")
	}
	for _, e := range events {
		if e.CollectionID == drop.Collection.ID {
			t.Errorf("an event still attributed to the deleted collection: %s", e.ID)
		}
	}

	// Re-running produces findings for what survived.
	if code := analyzeStatus(t, mux, c.ID); code != http.StatusOK {
		t.Fatalf("re-analysis returned %d", code)
	}
	after := currentDerived(t, mux, c.ID)
	if after.Events != len(events) {
		t.Errorf("re-analysis sees %d events, timeline has %d", after.Events, len(events))
	}
	if after.Events == 0 {
		t.Fatal("the surviving collection contributed no events")
	}
	if caseSummaryOf(t, mux, c.ID).AnalysisInvalidated {
		t.Error("the case still reports invalidated analysis after a successful re-run")
	}
	if caseOf(t, mux, c.ID).Status != model.CaseStatusAnalyzed {
		t.Error("the case is not analyzed after a successful re-run")
	}
	_ = keep
}

//  9. No orphans anywhere: every current finding's supporting events, and
//     every current correlation's events, must still exist.
func TestInvalidation_NoOrphanedResultsRemain(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "No orphans")
	keep, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	drop, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/native_samples")
	analyzeStatus(t, mux, c.ID)
	deleteCollection(t, mux, c.ID, drop.Collection.ID)
	analyzeStatus(t, mux, c.ID)
	_ = keep

	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &events)
	live := map[string]bool{}
	for _, e := range events {
		live[e.ID] = true
	}

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings", nil, &findings)
	for _, f := range findings {
		for _, id := range f.SupportingEvents {
			if !live[id] {
				t.Errorf("finding %q cites event %s, which no longer exists", f.Title, id)
			}
		}
	}
	var corrs []model.Correlation
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/correlations", nil, &corrs)
	for _, cr := range corrs {
		for _, id := range cr.EventIDs {
			if !live[id] {
				t.Errorf("correlation %q cites event %s, which no longer exists", cr.Title, id)
			}
		}
	}
	var invs []model.Investigation
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/investigations", nil, &invs)
	for _, inv := range invs {
		if len(inv.FindingIDs)+len(inv.CorrelationIDs) == 0 {
			t.Errorf("investigation %q rests on no findings or correlations", inv.Title)
		}
	}
}

//  10. Deleting individual evidence files invalidates too -- not only
//     whole-collection deletion.
func TestInvalidation_SourceFileDeletionInvalidates(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "File deletion invalidates")
	disc, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	analyzeStatus(t, mux, c.ID)
	if currentDerived(t, mux, c.ID).Findings == 0 {
		t.Fatal("nothing to invalidate")
	}

	// One IMPORTED file, not the whole collection. getEvidenceIDs
	// returns the selectable (not yet imported) set, which is empty
	// after importing everything.
	ids := importedFileIDs(t, mux, c.ID, disc.Collection.ID)
	if len(ids) == 0 {
		t.Fatal("no imported evidence files")
	}
	var res DeletedEvidenceResult
	rec := doJSON(t, mux, "DELETE", "/api/cases/"+c.ID+"/evidence/"+ids[0], nil, &res)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete returned %d: %s", rec.Code, rec.Body.String())
	}
	if res.AnalysisInvalidated == nil {
		t.Fatal("the deletion did not report an invalidation")
	}
	if res.AnalysisInvalidated.Findings == 0 || res.AnalysisInvalidated.Runs == 0 {
		t.Errorf("the invalidation reports nothing: %+v", res.AnalysisInvalidated)
	}
	if res.AnalysisInvalidated.Reason == "" {
		t.Error("the invalidation carries no reason")
	}
	if got := currentDerived(t, mux, c.ID); got.Findings != 0 || got.Investigations != 0 || got.Correlations != 0 {
		t.Errorf("results survived a single-file deletion: %+v", got)
	}
	if !caseSummaryOf(t, mux, c.ID).AnalysisInvalidated {
		t.Error("the summary does not report the invalidation")
	}
}

//  11. Deleting evidence from a never-analyzed case is a no-op for
//     analysis -- there was nothing to invalidate, and nothing is
//     invented to say otherwise.
func TestInvalidation_NeverAnalyzedCaseReportsNoInvalidation(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Never analyzed")
	disc, _ := discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")

	ids := importedFileIDs(t, mux, c.ID, disc.Collection.ID)
	var res DeletedEvidenceResult
	doJSON(t, mux, "DELETE", "/api/cases/"+c.ID+"/evidence/"+ids[0], nil, &res)
	if res.AnalysisInvalidated != nil {
		t.Errorf("a never-analyzed case reported an invalidation: %+v", res.AnalysisInvalidated)
	}
	if caseSummaryOf(t, mux, c.ID).AnalysisInvalidated {
		t.Error("a never-analyzed case reports invalidated analysis")
	}
	runs := runsOf(t, mux, c.ID)
	if len(runs) != 0 {
		t.Errorf("got %d analysis runs for a case that was never analyzed", len(runs))
	}
}
