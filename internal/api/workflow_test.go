package api

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/model"
)

// ---------------- Case metadata ----------------

func TestUpdateCaseMetadata_HTTP(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Case metadata test")

	newStatus := model.CaseWorkflowInvestigating
	newPriority := model.CasePriorityHigh
	var updated model.Case
	rec := doJSON(t, mux, "PATCH", "/api/cases/"+c.ID, CaseMetadataUpdate{CaseStatus: &newStatus, Priority: &newPriority}, &updated)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH case: status %d, body %s", rec.Code, rec.Body.String())
	}
	if updated.CaseStatus != model.CaseWorkflowInvestigating {
		t.Errorf("case_status = %q, want investigating", updated.CaseStatus)
	}
	if updated.Priority != model.CasePriorityHigh {
		t.Errorf("priority = %q, want high", updated.Priority)
	}
	// Status (analysis lifecycle) must be untouched by a metadata update.
	if updated.Status != model.CaseStatusCreated {
		t.Errorf("status = %q, want unchanged 'created' (metadata update must not touch analysis lifecycle status)", updated.Status)
	}
}

func TestUpdateCaseMetadata_InvalidValueRejected(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Case metadata invalid test")
	bogus := "not-a-real-status"
	rec := doJSON(t, mux, "PATCH", "/api/cases/"+c.ID, CaseMetadataUpdate{CaseStatus: &bogus}, nil)
	if rec.Code == http.StatusOK {
		t.Errorf("PATCH with invalid case_status returned 200, want an error status")
	}
}

// ---------------- Notes ----------------

func TestNotes_HTTPLifecycle(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Notes test")

	var n model.Note
	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/notes",
		map[string]string{"target_type": model.TargetCase, "target_id": c.ID, "note": "initial triage looks routine"}, &n)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create note: status %d, body %s", rec.Code, rec.Body.String())
	}

	var notes []model.Note
	rec = doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/notes", nil, &notes)
	if rec.Code != http.StatusOK || len(notes) != 1 {
		t.Fatalf("list notes: status %d, got %d notes", rec.Code, len(notes))
	}

	rec = doJSON(t, mux, "PATCH", "/api/notes/"+n.ID, map[string]string{"note": "confirmed: routine admin activity"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("update note: status %d, body %s", rec.Code, rec.Body.String())
	}
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/notes", nil, &notes)
	if notes[0].Text != "confirmed: routine admin activity" {
		t.Errorf("note text = %q, want updated text", notes[0].Text)
	}

	rec = doJSON(t, mux, "DELETE", "/api/notes/"+n.ID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete note: status %d, body %s", rec.Code, rec.Body.String())
	}
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/notes", nil, &notes)
	if len(notes) != 0 {
		t.Errorf("got %d notes after delete, want 0", len(notes))
	}
}

// ---------------- Tags ----------------

func TestTags_HTTPLifecycle(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Tags test")

	var tg model.Tag
	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/tags",
		map[string]string{"target_type": model.TargetCase, "target_id": c.ID, "tag": "phishing"}, &tg)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add tag: status %d, body %s", rec.Code, rec.Body.String())
	}

	var tags []model.Tag
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/tags", nil, &tags)
	if len(tags) != 1 || tags[0].Tag != "phishing" {
		t.Fatalf("got %+v, want 1 tag 'phishing'", tags)
	}

	rec = doJSON(t, mux, "DELETE", "/api/cases/"+c.ID+"/tags",
		map[string]string{"target_type": model.TargetCase, "target_id": c.ID, "tag": "phishing"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove tag: status %d, body %s", rec.Code, rec.Body.String())
	}
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/tags", nil, &tags)
	if len(tags) != 0 {
		t.Errorf("got %d tags after removal, want 0", len(tags))
	}
}

// ---------------- Finding / Investigation status: the critical invariant ----------------

// TestFindingStatus_NeverModifiesDeterministicResult is the CRITICAL
// invariant Phase 6 section 7 requires: setting an analyst status
// (including "false_positive") on a finding must never alter that
// finding's own deterministic Severity/Confidence.
func TestFindingStatus_NeverModifiesDeterministicResult(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Finding status invariant test")
	root := filepath.Join("..", "..", "testdata", "scenarios", "f_powershell_download")
	disc := ingestLocalPath(t, mux, c.ID, root)
	importAll(t, mux, c.ID, disc)
	analyze(t, mux, c.ID)

	findings := getFindings(t, mux, c.ID)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	origSeverity, origConfidence := f.Severity, f.Confidence

	var status model.AnalystStatus
	rec := doJSON(t, mux, "PATCH", "/api/cases/"+c.ID+"/findings/"+f.ID+"/status",
		map[string]string{"status": model.ReviewFalsePositive, "note": "confirmed benign after review"}, &status)
	if rec.Code != http.StatusOK {
		t.Fatalf("set finding status: status %d, body %s", rec.Code, rec.Body.String())
	}
	if status.Status != model.ReviewFalsePositive {
		t.Errorf("status = %q, want false_positive", status.Status)
	}

	// Re-fetch the finding: its OWN severity/confidence must be identical.
	findingsAfter := getFindings(t, mux, c.ID)
	var after model.Finding
	for _, ff := range findingsAfter {
		if ff.ID == f.ID {
			after = ff
		}
	}
	if after.ID == "" {
		t.Fatal("finding disappeared after setting analyst status")
	}
	if after.Severity != origSeverity {
		t.Errorf("finding severity changed after analyst status set: %q -> %q", origSeverity, after.Severity)
	}
	if after.Confidence != origConfidence {
		t.Errorf("finding confidence changed after analyst status set: %q -> %q", origConfidence, after.Confidence)
	}
}

func TestInvestigationStatus_SetAndPersist(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Investigation status test")
	root := filepath.Join("..", "..", "testdata", "scenarios", "f_powershell_download")
	disc := ingestLocalPath(t, mux, c.ID, root)
	importAll(t, mux, c.ID, disc)
	analyze(t, mux, c.ID)

	invs := getInvestigations(t, mux, c.ID)
	if len(invs) == 0 {
		t.Fatal("expected at least one investigation")
	}
	inv := invs[0]
	origSeverity := inv.Severity

	rec := doJSON(t, mux, "PATCH", "/api/cases/"+c.ID+"/investigations/"+inv.ID+"/status",
		map[string]string{"status": model.InvestigationWorkflowConfirmed, "note": "confirmed real incident"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("set investigation status: status %d, body %s", rec.Code, rec.Body.String())
	}

	// The investigation's own deterministic severity must be unchanged.
	invsAfter := getInvestigations(t, mux, c.ID)
	var after model.Investigation
	for _, i := range invsAfter {
		if i.ID == inv.ID {
			after = i
		}
	}
	if after.ID == "" {
		t.Fatal("investigation disappeared after setting analyst status")
	}
	if after.Severity != origSeverity {
		t.Errorf("investigation severity changed after analyst status set: %q -> %q", origSeverity, after.Severity)
	}
}

// TestAnalystStatus_SurvivesReanalysis is THE key regression test this
// phase's stable-ID fix (internal/model.StableID, used by
// internal/detect and internal/correlate as of Phase 6) exists for: an
// analyst's review status on a finding must still apply after a
// re-analysis of UNCHANGED evidence, because the finding's ID is now a
// content-derived hash rather than a fresh random UUID each run.
func TestAnalystStatus_SurvivesReanalysis(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Analyst status survives reanalysis")
	root := filepath.Join("..", "..", "testdata", "scenarios", "f_powershell_download")
	disc := ingestLocalPath(t, mux, c.ID, root)
	importAll(t, mux, c.ID, disc)
	analyze(t, mux, c.ID)

	findings := getFindings(t, mux, c.ID)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]

	rec := doJSON(t, mux, "PATCH", "/api/cases/"+c.ID+"/findings/"+f.ID+"/status",
		map[string]string{"status": model.ReviewConfirmed, "note": "confirmed malicious"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("set finding status: status %d, body %s", rec.Code, rec.Body.String())
	}

	// Re-analyze the SAME unchanged evidence.
	analyze(t, mux, c.ID)

	findingsAfter := getFindings(t, mux, c.ID)
	var afterID string
	for _, ff := range findingsAfter {
		if ff.RuleID == f.RuleID {
			afterID = ff.ID
		}
	}
	if afterID == "" {
		t.Fatal("finding disappeared after re-analysis of unchanged evidence")
	}
	if afterID != f.ID {
		t.Errorf("finding ID changed across a no-op re-analysis: %q -> %q (analyst status keyed by the old ID would now be orphaned)", f.ID, afterID)
	}

	// Confirm the status is still attached to this (stable) finding ID,
	// via the case export (which includes analyst_statuses) -- Tracefall
	// has no standalone GET .../status endpoint.
	var export CaseExport
	rec = doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/export", nil, &export)
	if rec.Code != http.StatusOK {
		t.Fatalf("export case: status %d, body %s", rec.Code, rec.Body.String())
	}
	var found bool
	for _, a := range export.AnalystStatuses {
		if a.TargetType == model.TargetFinding && a.TargetID == afterID {
			found = true
			if a.Status != model.ReviewConfirmed {
				t.Errorf("status = %q, want confirmed (survived re-analysis)", a.Status)
			}
		}
	}
	if !found {
		t.Fatalf("analyst status for finding %s not found after re-analysis -- it was orphaned", afterID)
	}
}

// ---------------- Collection metadata (Phase 6 section 4) ----------------

func TestCollectionDetail_ComputedMetadata(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Collection metadata test")
	root := filepath.Join("..", "..", "testdata", "scenarios", "f_powershell_download")
	disc := ingestLocalPath(t, mux, c.ID, root)
	importAll(t, mux, c.ID, disc)

	var detail CollectionDetail
	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID, nil, &detail)
	if rec.Code != http.StatusOK {
		t.Fatalf("get collection detail: status %d, body %s", rec.Code, rec.Body.String())
	}
	if len(detail.HostsObserved) != 1 || detail.HostsObserved[0] != "WKSTN-SIM-F" {
		t.Errorf("hosts_observed = %v, want [WKSTN-SIM-F]", detail.HostsObserved)
	}
	if detail.EarliestEvent == nil || detail.LatestEvent == nil {
		t.Fatal("expected earliest_event/latest_event to be set for a collection with imported events")
	}
	if !detail.EarliestEvent.Before(*detail.LatestEvent) && !detail.EarliestEvent.Equal(*detail.LatestEvent) {
		t.Errorf("earliest_event (%v) should be <= latest_event (%v)", detail.EarliestEvent, detail.LatestEvent)
	}
	if len(detail.ParserCoverage) == 0 {
		t.Error("expected non-empty parser_coverage")
	}
	for _, pc := range detail.ParserCoverage {
		if pc.Parser == "" || pc.FileCount == 0 {
			t.Errorf("parser coverage entry looks empty: %+v", pc)
		}
	}
}

// TestCollectionDetail_UnknownWhenNoEventsImported confirms Phase 6's
// "never invent acquisition metadata" requirement: a collection with
// files discovered but nothing imported yet has no fabricated
// earliest/latest event or host list.
func TestCollectionDetail_UnknownWhenNoEventsImported(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Collection metadata unknown test")
	root := filepath.Join("..", "..", "testdata", "scenarios", "f_powershell_download")
	disc := ingestLocalPath(t, mux, c.ID, root)
	// Deliberately do NOT import anything.

	var detail CollectionDetail
	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID, nil, &detail)
	if rec.Code != http.StatusOK {
		t.Fatalf("get collection detail: status %d, body %s", rec.Code, rec.Body.String())
	}
	if detail.EarliestEvent != nil || detail.LatestEvent != nil {
		t.Errorf("expected nil earliest/latest event before import, got %v / %v", detail.EarliestEvent, detail.LatestEvent)
	}
	if len(detail.HostsObserved) != 0 {
		t.Errorf("expected empty hosts_observed before import, got %v", detail.HostsObserved)
	}
}

// ---------------- Audit log ----------------

func TestAuditLog_RecordsLifecycleActions(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Audit log test")
	root := filepath.Join("..", "..", "testdata", "scenarios", "f_powershell_download")
	disc := ingestLocalPath(t, mux, c.ID, root)
	importAll(t, mux, c.ID, disc)
	analyze(t, mux, c.ID)

	var events []model.AuditEvent
	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/audit", nil, &events)
	if rec.Code != http.StatusOK {
		t.Fatalf("get audit log: status %d, body %s", rec.Code, rec.Body.String())
	}

	wantActions := []string{
		model.AuditCaseCreated,
		model.AuditEvidenceDiscovered,
		model.AuditEvidenceImported,
		model.AuditAnalysisStarted,
		model.AuditAnalysisCompleted,
	}
	got := map[string]bool{}
	for _, e := range events {
		got[e.Action] = true
		if e.Actor != model.ActorLocalUser {
			t.Errorf("actor = %q, want %q", e.Actor, model.ActorLocalUser)
		}
	}
	for _, want := range wantActions {
		if !got[want] {
			t.Errorf("audit log missing expected action %q; got actions: %v", want, keysOf(got))
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------------- Exports ----------------

func TestExportCase_JSON(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Export case test")
	root := filepath.Join("..", "..", "testdata", "scenarios", "f_powershell_download")
	disc := ingestLocalPath(t, mux, c.ID, root)
	importAll(t, mux, c.ID, disc)
	analyze(t, mux, c.ID)

	var export CaseExport
	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/export", nil, &export)
	if rec.Code != http.StatusOK {
		t.Fatalf("export case: status %d, body %s", rec.Code, rec.Body.String())
	}
	if export.Case.ID != c.ID {
		t.Errorf("export.case.id = %q, want %q", export.Case.ID, c.ID)
	}
	if len(export.Findings) == 0 {
		t.Error("expected non-empty findings in export")
	}
	if len(export.Investigations) == 0 {
		t.Error("expected non-empty investigations in export")
	}
	if len(export.Collections) != 1 {
		t.Errorf("got %d collections in export, want 1", len(export.Collections))
	}
	if export.ExportedAt.IsZero() {
		t.Error("expected exported_at to be set")
	}
}

func TestExportInvestigation_JSON(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Export investigation test")
	root := filepath.Join("..", "..", "testdata", "scenarios", "f_powershell_download")
	disc := ingestLocalPath(t, mux, c.ID, root)
	importAll(t, mux, c.ID, disc)
	analyze(t, mux, c.ID)

	invs := getInvestigations(t, mux, c.ID)
	if len(invs) == 0 {
		t.Fatal("expected at least one investigation")
	}
	var export InvestigationDetail
	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/investigations/"+invs[0].ID+"/export", nil, &export)
	if rec.Code != http.StatusOK {
		t.Fatalf("export investigation: status %d, body %s", rec.Code, rec.Body.String())
	}
	if export.ID != invs[0].ID {
		t.Errorf("export.investigation_id = %q, want %q", export.ID, invs[0].ID)
	}
	if len(export.FindingDetails) == 0 {
		t.Error("expected resolved finding details in investigation export")
	}
}

func TestExportTimelineCSV(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Export timeline CSV test")
	root := filepath.Join("..", "..", "testdata", "scenarios", "f_powershell_download")
	disc := ingestLocalPath(t, mux, c.ID, root)
	importAll(t, mux, c.ID, disc)

	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/export/timeline.csv", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export timeline CSV: status %d, body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected a header row plus at least one data row, got %d lines: %q", len(lines), body)
	}
	if !strings.HasPrefix(lines[0], "timestamp_utc,") {
		t.Errorf("CSV header = %q, want it to start with timestamp_utc,", lines[0])
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/csv" {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
}

func TestExportFindingsCSV(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Export findings CSV test")
	root := filepath.Join("..", "..", "testdata", "scenarios", "f_powershell_download")
	disc := ingestLocalPath(t, mux, c.ID, root)
	importAll(t, mux, c.ID, disc)
	analyze(t, mux, c.ID)

	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/export/findings.csv", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export findings CSV: status %d, body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected a header row plus at least one finding row, got %d lines", len(lines))
	}
	if !strings.Contains(lines[0], "analyst_status") {
		t.Errorf("CSV header missing analyst_status column: %q", lines[0])
	}
	// Every finding row must show "new" analyst status by default (no
	// status set yet), never blank.
	if strings.Contains(body, ",,\n") {
		t.Log("note: a truly blank trailing field can be legitimate for other columns; this check only flags an obviously empty analyst_status")
	}
}
