package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"tracefall/internal/casefiles"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

const testMaxUploadBytes = 64 << 20 // 64 MiB, plenty for test fixtures

func newTestService(t *testing.T) *Service {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("opening test store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	files := casefiles.NewStore(t.TempDir())
	return NewService(db, files)
}

func routerFor(svc *Service) http.Handler {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	return dashboardLike(NewRouter(svc, logger, testMaxUploadBytes, false))
}

// dashboardLike makes a test request look like the dashboard's own
// same-origin request: a loopback Host, and the X-Tracefall-Client header on
// every write. Without it, httptest's default Host (example.com) and missing
// client header would be refused by the request-source checks, which have
// their own dedicated tests in crossorigin_test.go that use the raw router.
func dashboardLike(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHostHeader(r.Host) {
			r.Host = "127.0.0.1:8080"
		}
		if !safeMethod(r.Method) && r.Header.Get(clientHeaderName) == "" {
			r.Header.Set(clientHeaderName, "dashboard")
		}
		next.ServeHTTP(w, r)
	})
}

func newTestRouter(t *testing.T) http.Handler {
	t.Helper()
	return routerFor(newTestService(t))
}

func TestHealthz_ReportsLANExposure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	for _, lanExposed := range []bool{false, true} {
		mux := dashboardLike(NewRouter(newTestService(t), logger, testMaxUploadBytes, lanExposed))
		var resp map[string]any
		doJSON(t, mux, "GET", "/api/healthz", nil, &resp)
		if resp["lan_exposed"] != lanExposed {
			t.Errorf("lanExposed=%v: healthz lan_exposed = %v, want %v", lanExposed, resp["lan_exposed"], lanExposed)
		}
	}
}

func doJSON(t *testing.T, mux http.Handler, method, path string, body any, out any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if out != nil && rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("decoding response from %s %s: %v\nbody: %s", method, path, err, rec.Body.String())
		}
	}
	return rec
}

// discoverPath POSTs a local-path discovery request to
// /api/cases/{id}/ingest and returns the response recorder, mirroring
// uploadZip for the upload path.
func discoverPath(t *testing.T, mux http.Handler, caseID, path string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, mux, "POST", "/api/cases/"+caseID+"/ingest", map[string]string{"path": path}, nil)
}

// discoverPathAndImportAll performs the full two-phase evidence-adding
// flow for a local path (discover, then import every supported file
// discovered) as one call -- the local-path-ingest counterpart of
// uploadAndImportAll in upload_test.go.
func discoverPathAndImportAll(t *testing.T, mux http.Handler, caseID, path string) (DiscoverResult, ImportResult) {
	t.Helper()
	rec := doJSON(t, mux, "POST", "/api/cases/"+caseID+"/ingest", map[string]string{"path": path}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("discover from path %s: status %d, body %s", path, rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	_, imp := importAll(t, mux, caseID, disc)
	return disc, imp
}

// TestEndToEnd_SyntheticCase is Tracefall's required end-to-end test: it
// drives the synthetic dataset through the real API surface --
// ingestion -> normalization -> detection -> correlation -> ATT&CK
// mapping -> API result -- exactly as an investigator using the
// dashboard would.
func TestEndToEnd_SyntheticCase(t *testing.T) {
	mux := newTestRouter(t)

	// 1. Create a case.
	var c model.Case
	rec := doJSON(t, mux, "POST", "/api/cases", map[string]string{
		"name":        "E2E synthetic case",
		"description": "driven by TestEndToEnd_SyntheticCase",
	}, &c)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create case: got status %d, body %s", rec.Code, rec.Body.String())
	}
	if c.Status != model.CaseStatusCreated {
		t.Fatalf("new case status = %q, want %q", c.Status, model.CaseStatusCreated)
	}

	// 2. Discover, then import, the synthetic evidence package (discovery
	// -> selection -> parsing -> normalization). Every supported file
	// discovered is selected, reproducing the old one-shot ingest's net
	// effect end to end.
	evidenceRoot := filepath.Join("..", "..", "testdata", "synthetic_case")
	disc, ingestRes := discoverPathAndImportAll(t, mux, c.ID, evidenceRoot)
	if disc.SupportedCount != 5 {
		t.Fatalf("got %d supported files discovered, want 5", disc.SupportedCount)
	}
	if ingestRes.EventCount == 0 {
		t.Fatal("import produced 0 events")
	}
	if len(ingestRes.Imported) != 5 {
		t.Errorf("got %d imported files, want 5", len(ingestRes.Imported))
	}

	// Discovering the exact same evidence a second time (as a new
	// collection) must be rejected as a duplicate collection -- see
	// TestDuplicateEvidence_EndToEnd for the dedicated test of this
	// behavior (collection count, event count, and the existing
	// collection all unaffected).
	rec = discoverPath(t, mux, c.ID, evidenceRoot)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second identical discovery: got status %d, want %d, body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}

	// 3. Run analysis (detection -> correlation).
	var analyzeRes AnalyzeResultSummary
	rec = doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, &analyzeRes)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyze: got status %d, body %s", rec.Code, rec.Body.String())
	}
	if len(analyzeRes.Findings) == 0 {
		t.Fatal("analyze produced 0 findings")
	}
	if len(analyzeRes.Correlations) == 0 {
		t.Fatal("analyze produced 0 correlations")
	}

	// Re-running analysis must be idempotent (same finding count, not
	// accumulating duplicates).
	var reanalyzeRes AnalyzeResultSummary
	rec = doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, &reanalyzeRes)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-analyze: got status %d, body %s", rec.Code, rec.Body.String())
	}
	if len(reanalyzeRes.Findings) != len(analyzeRes.Findings) {
		t.Errorf("re-analyze produced %d findings, want %d (analysis must be idempotent)", len(reanalyzeRes.Findings), len(analyzeRes.Findings))
	}

	// 4. GET the case, verify the summary rollup.
	var caseDetail struct {
		Case    model.Case `json:"case"`
		Summary Summary    `json:"summary"`
	}
	rec = doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &caseDetail)
	if rec.Code != http.StatusOK {
		t.Fatalf("get case: got status %d", rec.Code)
	}
	if caseDetail.Case.Status != model.CaseStatusAnalyzed {
		t.Errorf("case status = %q, want %q", caseDetail.Case.Status, model.CaseStatusAnalyzed)
	}
	if caseDetail.Summary.Findings != len(analyzeRes.Findings) {
		t.Errorf("summary.findings = %d, want %d", caseDetail.Summary.Findings, len(analyzeRes.Findings))
	}

	// 5. GET the timeline: must be chronologically sorted.
	var timeline []model.Event
	rec = doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
	if rec.Code != http.StatusOK {
		t.Fatalf("get timeline: got status %d", rec.Code)
	}
	for i := 1; i < len(timeline); i++ {
		if timeline[i].Timestamp.Before(timeline[i-1].Timestamp) {
			t.Fatalf("timeline not sorted at index %d: %v before %v", i, timeline[i].Timestamp, timeline[i-1].Timestamp)
		}
	}
	if len(timeline) != ingestRes.EventCount {
		t.Errorf("timeline has %d events, want %d", len(timeline), ingestRes.EventCount)
	}

	// 6. GET findings, then drill into one finding's supporting evidence.
	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings", nil, &findings)
	if len(findings) == 0 {
		t.Fatal("no findings returned")
	}
	var officeFinding *model.Finding
	for i, f := range findings {
		if f.RuleID == "office-spawns-powershell" {
			officeFinding = &findings[i]
		}
	}
	if officeFinding == nil {
		t.Fatal("expected an office-spawns-powershell finding in the synthetic dataset")
	}

	var detail FindingDetail
	rec = doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings/"+officeFinding.ID, nil, &detail)
	if rec.Code != http.StatusOK {
		t.Fatalf("get finding detail: got status %d, body %s", rec.Code, rec.Body.String())
	}
	if len(detail.SupportingEventDetails) == 0 {
		t.Fatal("finding detail has no resolved supporting events")
	}
	if len(detail.TechniqueDetails) == 0 {
		t.Fatal("finding detail has no resolved ATT&CK technique metadata")
	}

	// 7. Follow provenance from the supporting event down to raw evidence.
	ev := detail.SupportingEventDetails[0]
	var prov EventProvenance
	rec = doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/"+ev.ID, nil, &prov)
	if rec.Code != http.StatusOK {
		t.Fatalf("get event provenance: got status %d, body %s", rec.Code, rec.Body.String())
	}
	if prov.RawEvidence.Raw == "" {
		t.Error("raw evidence is empty -- provenance chain broken")
	}
	if prov.SourceFile.Path == "" {
		t.Error("source file path is empty -- provenance chain broken")
	}
	if len(prov.Observations) == 0 {
		t.Error("expected at least one observation for a valid event")
	}

	// 8. GET the ATT&CK summary (mapping layer) and confirm known
	// techniques for this dataset are present.
	var techniques []AttackTechnique
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/attack", nil, &techniques)
	wantTechniques := map[string]bool{"T1059.001": false, "T1547.001": false, "T1053.005": false, "T1110": false}
	for _, tech := range techniques {
		if _, ok := wantTechniques[tech.ID]; ok {
			wantTechniques[tech.ID] = true
		}
		if len(tech.Findings) == 0 {
			t.Errorf("technique %s has no findings attached", tech.ID)
		}
	}
	for id, found := range wantTechniques {
		if !found {
			t.Errorf("expected technique %s to be present in ATT&CK summary", id)
		}
	}

	// 9. GET correlations and confirm the full activity chain was reconstructed.
	var correlations []model.Correlation
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/correlations", nil, &correlations)
	var sawActivityChain bool
	for _, corr := range correlations {
		if corr.Type == model.CorrelationActivityChain {
			sawActivityChain = true
			if len(corr.EventIDs) < 3 {
				t.Errorf("activity chain has only %d events, want >= 3", len(corr.EventIDs))
			}
		}
	}
	if !sawActivityChain {
		t.Error("expected at least one activity_chain correlation")
	}

	// 10. GET sources (every cataloged source file, across all
	// collections -- imported and merely-discovered/unsupported alike).
	// The synthetic package has 5 supported (all imported above) plus its
	// own README.md, which is discovered but unsupported.
	var sources []model.SourceFile
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/sources", nil, &sources)
	if len(sources) != 6 {
		t.Errorf("got %d source files, want 6 (5 imported + 1 unsupported README.md)", len(sources))
	}
	var importedCount int
	for _, sf := range sources {
		if sf.SHA256 == "" {
			t.Errorf("source file %s missing SHA-256", sf.Path)
		}
		if sf.CollectionID == "" {
			t.Errorf("source file %s missing collection ID", sf.Path)
		}
		if sf.ImportStatus == model.SourceFileImported {
			importedCount++
		}
	}
	if importedCount != 5 {
		t.Errorf("got %d imported source files, want 5", importedCount)
	}

	// 11. GET evidence (the list of collections) and confirm the rejected
	// duplicate did not create a second one.
	var collections []model.Collection
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence", nil, &collections)
	if len(collections) != 1 {
		t.Fatalf("got %d collections, want 1 (the duplicate ingest must not have created a second)", len(collections))
	}
	for _, col := range collections {
		if col.IngestionStatus != model.CollectionStatusIngested {
			t.Errorf("collection %s status = %q, want %q", col.ID, col.IngestionStatus, model.CollectionStatusIngested)
		}
		if col.SupportedFileCount != 5 {
			t.Errorf("collection %s supported_file_count = %d, want 5", col.ID, col.SupportedFileCount)
		}
		if col.ImportedFileCount != 5 {
			t.Errorf("collection %s imported_file_count = %d, want 5", col.ID, col.ImportedFileCount)
		}
		if col.ArchiveHash == "" {
			t.Errorf("collection %s has no archive_hash recorded", col.ID)
		}
	}

	// 12. GET the collection's detail: every cataloged file, imported or
	// not (5 imported + 1 unsupported README.md).
	var collDetail CollectionDetail
	rec = doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+collections[0].ID, nil, &collDetail)
	if rec.Code != http.StatusOK {
		t.Fatalf("get collection detail: status %d, body %s", rec.Code, rec.Body.String())
	}
	if len(collDetail.SourceFiles) != 6 {
		t.Errorf("collection detail source files = %d, want 6", len(collDetail.SourceFiles))
	}
}

func TestCreateCase_RequiresName(t *testing.T) {
	mux := newTestRouter(t)
	rec := doJSON(t, mux, "POST", "/api/cases", map[string]string{"description": "no name"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestGetCase_NotFound(t *testing.T) {
	mux := newTestRouter(t)
	rec := doJSON(t, mux, "GET", "/api/cases/does-not-exist", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestAnalyze_RequiresIngestFirst(t *testing.T) {
	mux := newTestRouter(t)
	var c model.Case
	doJSON(t, mux, "POST", "/api/cases", map[string]string{"name": "no evidence yet"}, &c)

	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil)
	if rec.Code != http.StatusConflict {
		t.Errorf("got status %d, want %d (analyze before ingest should be rejected)", rec.Code, http.StatusConflict)
	}
}

func TestListCases(t *testing.T) {
	mux := newTestRouter(t)
	doJSON(t, mux, "POST", "/api/cases", map[string]string{"name": "case A"}, nil)
	doJSON(t, mux, "POST", "/api/cases", map[string]string{"name": "case B"}, nil)

	var cases []model.Case
	rec := doJSON(t, mux, "GET", "/api/cases", nil, &cases)
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d", rec.Code)
	}
	if len(cases) != 2 {
		t.Errorf("got %d cases, want 2", len(cases))
	}
}
