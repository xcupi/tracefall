package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"tracefall/internal/model"
)

func getJSON[T any](t *testing.T, mux http.Handler, path string) T {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d, body %s", path, rec.Code, rec.Body.String())
	}
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	return out
}

// analyzedCase builds a case with real evidence, imports it and runs
// analysis, so the whole chain exists to be walked.
func analyzedCase(t *testing.T, mux http.Handler, name string) (caseID string, disc DiscoverResult) {
	t.Helper()
	c := mustCreateCase(t, mux, name)
	disc, _ = discoverPathAndImportAll(t, mux, c.ID, "../../testdata/synthetic_case")
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, &AnalyzeResultSummary{})
	return c.ID, disc
}

// ---------------- the full chain ----------------

// The phase's central claim: a finding can be walked back to the
// evidence object and its hash, without inventing anything.
func TestProvenance_FindingWalksBackToEvidence(t *testing.T) {
	mux := newTestRouter(t)
	caseID, disc := analyzedCase(t, mux, "Chain")

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings)
	if len(findings) == 0 {
		t.Fatal("no findings produced; the chain cannot be tested")
	}
	f := findings[0]

	prov := getJSON[FindingProvenance](t, mux, "/api/cases/"+caseID+"/findings/"+f.ID+"/provenance")

	if prov.FindingID != f.ID || prov.RuleID != f.RuleID {
		t.Errorf("provenance describes the wrong finding: %+v", prov)
	}
	if prov.SupportingEventCount != len(f.SupportingEvents) {
		t.Errorf("supporting_event_count = %d, want %d", prov.SupportingEventCount, len(f.SupportingEvents))
	}
	if prov.ResolvedEventCount == 0 {
		t.Fatal("no supporting events resolved; the finding->event link is broken")
	}
	if len(prov.SourceFiles) == 0 {
		t.Fatal("no source files resolved; the event->source-file link is broken")
	}
	if len(prov.Collections) == 0 {
		t.Fatal("no collections resolved; the source-file->collection link is broken")
	}

	// Collection -> evidence hashes. Both must be complete.
	col := prov.Collections[0]
	if col.CollectionID != disc.Collection.ID {
		t.Errorf("collection_id = %q, want %q", col.CollectionID, disc.Collection.ID)
	}
	if len(col.ArchiveSHA256) != 64 {
		t.Errorf("archive_sha256 is not a full SHA-256: %q", col.ArchiveSHA256)
	}
	if len(col.IntegritySHA512) != 128 {
		t.Errorf("integrity_sha512 is not a full SHA-512: %q", col.IntegritySHA512)
	}
	if !col.IntegrityRecorded {
		t.Error("integrity_recorded is false despite a digest being present")
	}

	// Every named source file must really exist and be reachable on its
	// own provenance endpoint.
	for _, sf := range prov.SourceFiles {
		if sf.SourceFileID == "" {
			t.Fatal("a source file was reported with no ID")
		}
		sfProv := getJSON[SourceFileProvenance](t, mux,
			"/api/cases/"+caseID+"/sources/"+sf.SourceFileID+"/provenance")
		if sfProv.SourceFile.SourceFileID != sf.SourceFileID {
			t.Errorf("source file provenance returned the wrong file")
		}
		if sfProv.Collection == nil {
			t.Errorf("source file %s resolves to no collection", sf.Path)
		}
		if sfProv.EventCount == 0 {
			t.Errorf("source file %s reports 0 events but produced a finding's evidence", sf.Path)
		}
	}
}

// Event provenance must reach the collection, not stop at the source
// file, and must state the timestamp situation explicitly.
func TestProvenance_EventReachesCollectionAndStatesTimestamp(t *testing.T) {
	mux := newTestRouter(t)
	caseID, disc := analyzedCase(t, mux, "Event chain")

	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/timeline", nil, &events)
	if len(events) == 0 {
		t.Fatal("no events")
	}

	prov := getJSON[EventProvenance](t, mux, "/api/cases/"+caseID+"/events/"+events[0].ID)
	if prov.Collection == nil {
		t.Fatal("event provenance does not resolve a collection")
	}
	if prov.Collection.CollectionID != disc.Collection.ID {
		t.Errorf("collection_id = %q, want %q", prov.Collection.CollectionID, disc.Collection.ID)
	}
	if prov.SourceFile.ID == "" {
		t.Error("event provenance resolves no source file")
	}
	if prov.TimestampKnown != !events[0].Timestamp.IsZero() {
		t.Errorf("timestamp_known = %v but the event's timestamp zero-ness says otherwise", prov.TimestampKnown)
	}
	if len(prov.Observations) == 0 {
		t.Error("no observations; provenance cannot show which collections saw this event")
	}
}

// Counts must be DERIVED from live relationships, never a stored
// counter that can drift.
func TestProvenance_SourceFileCountsAreDerived(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := analyzedCase(t, mux, "Derived counts")

	var sources []model.SourceFile
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/sources", nil, &sources)
	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/timeline", nil, &events)

	eventsPerFile := map[string]int{}
	for _, e := range events {
		eventsPerFile[e.SourceFileID]++
	}

	checked := 0
	for _, sf := range sources {
		if sf.ImportStatus != model.SourceFileImported {
			continue
		}
		prov := getJSON[SourceFileProvenance](t, mux,
			"/api/cases/"+caseID+"/sources/"+sf.ID+"/provenance")
		if prov.EventCount != eventsPerFile[sf.ID] {
			t.Errorf("%s: event_count = %d, but %d events actually reference it",
				sf.Path, prov.EventCount, eventsPerFile[sf.ID])
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no imported source files to check")
	}
}

// ---------------- analysis runs ----------------

func TestProvenance_AnalysisRunIsRecordedAndFindingsAttributed(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := analyzedCase(t, mux, "Runs")

	prov := getJSON[CaseProvenance](t, mux, "/api/cases/"+caseID+"/provenance")
	if len(prov.AnalysisRuns) != 1 {
		t.Fatalf("got %d analysis runs, want 1", len(prov.AnalysisRuns))
	}
	run := prov.AnalysisRuns[0]
	if run.Status != model.AnalysisRunCompleted {
		t.Errorf("status = %q, want %q", run.Status, model.AnalysisRunCompleted)
	}
	if run.CompletedAt == nil {
		t.Error("a completed run has no completed_at")
	}
	if run.ToolVersion == "" {
		t.Error("run records no tool version")
	}
	if run.FindingCount == 0 {
		t.Error("run recorded 0 findings but the case has some")
	}
	if prov.LegacyFindingCount != 0 {
		t.Errorf("%d findings lack a run id despite being produced by this run", prov.LegacyFindingCount)
	}

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings)
	for _, f := range findings {
		if f.AnalysisRunID != run.ID {
			t.Errorf("finding %s attributed to run %q, want %q", f.ID, f.AnalysisRunID, run.ID)
		}
	}
}

// Re-analysis must be distinguishable from the earlier run, and the
// superseded run must survive as history even though its findings are
// replaced.
func TestProvenance_ReanalysisIsDistinguishable(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := analyzedCase(t, mux, "Re-analysis")

	first := getJSON[CaseProvenance](t, mux, "/api/cases/"+caseID+"/provenance").AnalysisRuns[0]

	doJSON(t, mux, "POST", "/api/cases/"+caseID+"/analyze", nil, &AnalyzeResultSummary{})
	after := getJSON[CaseProvenance](t, mux, "/api/cases/"+caseID+"/provenance")

	if len(after.AnalysisRuns) != 2 {
		t.Fatalf("got %d runs after re-analysis, want 2 (the earlier run is history and must be kept)", len(after.AnalysisRuns))
	}
	second := after.AnalysisRuns[0] // most recent first
	if second.ID == first.ID {
		t.Fatal("re-analysis reused the earlier run id; the two runs are indistinguishable")
	}
	// The superseded run is retained unchanged.
	var kept *model.AnalysisRun
	for i := range after.AnalysisRuns {
		if after.AnalysisRuns[i].ID == first.ID {
			kept = &after.AnalysisRuns[i]
		}
	}
	if kept == nil {
		t.Fatal("the earlier run was deleted by re-analysis")
	}
	if kept.Status != first.Status || !kept.StartedAt.Equal(first.StartedAt) {
		t.Error("the earlier run was modified by re-analysis")
	}

	// Findings now belong to the NEW run.
	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings)
	for _, f := range findings {
		if f.AnalysisRunID != second.ID {
			t.Errorf("finding %s still attributed to the superseded run", f.ID)
		}
	}
}

// A finding written before run tracking must be reported as legacy, not
// retrofitted to an invented run.
func TestProvenance_LegacyFindingIsNotGivenAnInventedRun(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	caseID, _ := analyzedCase(t, mux, "Legacy finding")

	if err := svc.store.ClearFindingRunIDsForTest(caseID); err != nil {
		t.Fatal(err)
	}

	prov := getJSON[CaseProvenance](t, mux, "/api/cases/"+caseID+"/provenance")
	if prov.LegacyFindingCount == 0 {
		t.Fatal("legacy findings were not reported as legacy")
	}

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings)
	fp := getJSON[FindingProvenance](t, mux,
		"/api/cases/"+caseID+"/findings/"+findings[0].ID+"/provenance")
	if fp.AnalysisRunAvailable {
		t.Error("a legacy finding reports an available analysis run")
	}
	if fp.AnalysisRun != nil {
		t.Errorf("a run was fabricated for a legacy finding: %+v", fp.AnalysisRun)
	}
	// The rest of the chain must still work.
	if len(fp.SourceFiles) == 0 || len(fp.Collections) == 0 {
		t.Error("missing run provenance broke the evidence chain, which does not depend on it")
	}
}

// ---------------- deletion honesty ----------------

// Deleted evidence must be represented as deleted, not omitted.
func TestProvenance_DeletedSourceFileIsShownAsDeletedNotHidden(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := analyzedCase(t, mux, "Deleted provenance")

	var sources []model.SourceFile
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/sources", nil, &sources)
	var target model.SourceFile
	for _, sf := range sources {
		if sf.ImportStatus == model.SourceFileImported {
			target = sf
			break
		}
	}
	if target.ID == "" {
		t.Fatal("no imported source file to delete")
	}

	before := getJSON[CaseProvenance](t, mux, "/api/cases/"+caseID+"/provenance")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("DELETE", "/api/cases/"+caseID+"/evidence/"+target.ID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: status %d, body %s", rec.Code, rec.Body.String())
	}

	// The file's own provenance still resolves and says it was deleted.
	prov := getJSON[SourceFileProvenance](t, mux,
		"/api/cases/"+caseID+"/sources/"+target.ID+"/provenance")
	if !prov.SourceFile.Deleted {
		t.Error("a deleted source file does not report itself as deleted")
	}
	if prov.SourceFile.DeletedAt == "" {
		t.Error("a deleted source file records no deletion time")
	}
	if prov.SourceFile.Path == "" {
		t.Error("a deleted source file lost its path; provenance must still say what it WAS")
	}

	after := getJSON[CaseProvenance](t, mux, "/api/cases/"+caseID+"/provenance")
	if after.DeletedSourceFileCount != before.DeletedSourceFileCount+1 {
		t.Errorf("deleted_source_file_count = %d, want %d",
			after.DeletedSourceFileCount, before.DeletedSourceFileCount+1)
	}

	// And the deletion is in the audit trail.
	found := false
	for _, e := range auditEntries(t, mux, caseID) {
		if e.Action == model.AuditEvidenceDeleted {
			found = true
		}
	}
	if !found {
		t.Error("evidence deletion left no audit record")
	}
}

// ---------------- no fabrication ----------------

// Provenance must never invent an acquisition time or an actor.
func TestProvenance_NeverFabricatesActorOrAcquisitionTime(t *testing.T) {
	mux := newTestRouter(t)
	caseID, _ := analyzedCase(t, mux, "No fabrication")

	body := func(path string) string {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec.Body.String()
	}
	prov := body("/api/cases/" + caseID + "/provenance")

	// Tracefall did not acquire this evidence and must not claim to know
	// when it was collected from the source machine.
	for _, forbidden := range []string{"acquisition_time", "acquired_at", "collected_at"} {
		if containsAny(prov, forbidden) {
			t.Errorf("case provenance claims %q, which Tracefall cannot know", forbidden)
		}
	}

	for _, e := range auditEntries(t, mux, caseID) {
		if e.Actor != model.ActorLocalUser {
			t.Errorf("audit entry %q has actor %q; the only honest value without authentication is %q",
				e.Action, e.Actor, model.ActorLocalUser)
		}
	}
}

// Provenance responses must not leak server filesystem paths.
func TestProvenance_LeaksNoServerPaths(t *testing.T) {
	mux := newTestRouter(t)
	caseID, disc := analyzedCase(t, mux, "No path leak")

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings)

	paths := []string{
		"/api/cases/" + caseID + "/provenance",
		"/api/cases/" + caseID + "/findings/" + findings[0].ID + "/provenance",
	}
	for _, p := range paths {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		body := rec.Body.String()
		if containsAny(body, "/tmp/", "TempDir", "\\Users\\runner", "goroutine", ".go:") {
			t.Errorf("%s leaks server internals: %s", p, body[:min(len(body), 300)])
		}
	}
	_ = disc
}

// The previous test used a RELATIVE evidence path, so it could never
// have caught an absolute server path leaking through provenance. This
// one ingests from an absolute temp directory -- the shape a real
// local-path ingestion has -- and asserts that the provenance responses
// introduce no path field beyond the analyst-supplied name that the
// pre-existing evidence endpoint already returns.
func TestProvenance_IntroducesNoNewPathExposure(t *testing.T) {
	mux := newTestRouter(t)
	caseID, collID, dir := dirEvidenceCase(t, mux, "Absolute path provenance")

	body := func(path string) string {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: %d", path, rec.Code)
		}
		return rec.Body.String()
	}

	// Baseline: what the PRE-EXISTING evidence endpoint already exposes.
	// evidence_directory and original_filename are long-standing fields
	// (a local-path collection's original_filename is the path the
	// analyst themselves supplied).
	if !containsAny(body("/api/cases/"+caseID+"/evidence"), dir) {
		t.Skip("evidence endpoint does not echo the ingest path in this configuration")
	}

	// Provenance must NOT introduce evidence_directory, which is a pure
	// server-side location with no forensic meaning to the reader.
	for _, p := range []string{
		"/api/cases/" + caseID + "/provenance",
		"/api/cases/" + caseID + "/evidence/" + collID + "/files?page_size=25",
	} {
		if containsAny(body(p), "evidence_directory") {
			t.Errorf("%s exposes evidence_directory; provenance must not widen path exposure", p)
		}
	}

	// And verification results must never carry a path at all.
	res := verifyIntegrity(t, mux, caseID, collID)
	blob, _ := json.Marshal(res)
	if containsAny(string(blob), dir, "evidence_directory") {
		t.Errorf("verification result leaks a server path: %s", blob)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Provenance must DEDUPLICATE the evidence it reports.
//
// A finding's supporting events frequently come from the same source
// file, so a naive walk would list that file (and its collection, and
// its hash) once per event. The chain must name each piece of evidence
// once.
//
// The related N+1 hazard is structural rather than testable here:
// FindingProvenanceFor loads events, source files and collections once
// each and indexes them, so its supporting-event loop issues no queries
// at all. Moving a lookup into that loop would turn one request into
// hundreds.
func TestProvenance_EvidenceIsDeduplicatedAcrossSupportingEvents(t *testing.T) {
	mux := newTestRouter(t)
	caseID, disc := analyzedCase(t, mux, "Provenance dedup")

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings)
	if len(findings) == 0 {
		t.Fatal("no findings")
	}
	// The finding resting on the most events is the one most likely to
	// repeat a source file.
	widest := findings[0]
	for _, f := range findings {
		if len(f.SupportingEvents) > len(widest.SupportingEvents) {
			widest = f
		}
	}

	prov := getJSON[FindingProvenance](t, mux,
		"/api/cases/"+caseID+"/findings/"+widest.ID+"/provenance")

	if prov.ResolvedEventCount != len(widest.SupportingEvents) {
		t.Errorf("resolved %d of %d supporting events", prov.ResolvedEventCount, len(widest.SupportingEvents))
	}
	seen := map[string]bool{}
	for _, sf := range prov.SourceFiles {
		if seen[sf.SourceFileID] {
			t.Errorf("source file %s reported more than once", sf.SourceFileID)
		}
		seen[sf.SourceFileID] = true
	}
	seenCol := map[string]bool{}
	for _, c := range prov.Collections {
		if seenCol[c.CollectionID] {
			t.Errorf("collection %s reported more than once", c.CollectionID)
		}
		seenCol[c.CollectionID] = true
	}
	if len(prov.Collections) != 1 || prov.Collections[0].CollectionID != disc.Collection.ID {
		t.Errorf("expected exactly the case's one collection, got %d", len(prov.Collections))
	}
}
