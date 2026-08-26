package store

import (
	"testing"
	"time"

	"tracefall/internal/model"
)

// ---------------- Case metadata (Phase 6) ----------------

func TestCreateCase_DefaultsCaseStatusAndPriority(t *testing.T) {
	s := openTest(t)
	now := time.Now().UTC()
	if err := s.CreateCase(model.Case{ID: "c1", Name: "case", Status: model.CaseStatusCreated, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("CreateCase: %v", err)
	}
	c, err := s.GetCase("c1")
	if err != nil {
		t.Fatalf("GetCase: %v", err)
	}
	if c.CaseStatus != model.CaseWorkflowOpen {
		t.Errorf("case_status = %q, want %q (default)", c.CaseStatus, model.CaseWorkflowOpen)
	}
	if c.Priority != model.CasePriorityMedium {
		t.Errorf("priority = %q, want %q (default)", c.Priority, model.CasePriorityMedium)
	}
	if c.AnalyzedAt != nil {
		t.Errorf("analyzed_at = %v, want nil (never analyzed)", *c.AnalyzedAt)
	}
}

func TestUpdateCaseMetadata_PartialUpdate(t *testing.T) {
	s := openTest(t)
	now := time.Now().UTC()
	if err := s.CreateCase(model.Case{ID: "c1", Name: "case", Description: "orig desc", Status: model.CaseStatusCreated, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("CreateCase: %v", err)
	}

	newStatus := model.CaseWorkflowInvestigating
	if err := s.UpdateCaseMetadata("c1", CaseMetadataUpdate{CaseStatus: &newStatus}); err != nil {
		t.Fatalf("UpdateCaseMetadata: %v", err)
	}
	c, err := s.GetCase("c1")
	if err != nil {
		t.Fatalf("GetCase: %v", err)
	}
	if c.CaseStatus != model.CaseWorkflowInvestigating {
		t.Errorf("case_status = %q, want investigating", c.CaseStatus)
	}
	// Fields not passed must be left unchanged.
	if c.Description != "orig desc" {
		t.Errorf("description = %q, want unchanged 'orig desc'", c.Description)
	}
	if c.Priority != model.CasePriorityMedium {
		t.Errorf("priority = %q, want unchanged default medium", c.Priority)
	}
}

func TestUpdateCaseMetadata_NameCollisionStillEnforced(t *testing.T) {
	s := openTest(t)
	now := time.Now().UTC()
	if err := s.CreateCase(model.Case{ID: "c1", Name: "Case One", Status: model.CaseStatusCreated, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("CreateCase c1: %v", err)
	}
	if err := s.CreateCase(model.Case{ID: "c2", Name: "Case Two", Status: model.CaseStatusCreated, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("CreateCase c2: %v", err)
	}
	collidingName := "case one" // case-insensitive collision with c1
	err := s.UpdateCaseMetadata("c2", CaseMetadataUpdate{Name: &collidingName})
	if err != ErrDuplicateCase {
		t.Fatalf("UpdateCaseMetadata with colliding name: got %v, want ErrDuplicateCase", err)
	}
}

func TestReplaceAnalysis_SetsAnalyzedAt(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	before, err := s.GetCase("case-1")
	if err != nil {
		t.Fatalf("GetCase: %v", err)
	}
	if before.AnalyzedAt != nil {
		t.Fatalf("expected analyzed_at nil before ReplaceAnalysis")
	}

	if err := s.ReplaceAnalysis("case-1", nil, nil); err != nil {
		t.Fatalf("ReplaceAnalysis: %v", err)
	}
	after, err := s.GetCase("case-1")
	if err != nil {
		t.Fatalf("GetCase: %v", err)
	}
	if after.AnalyzedAt == nil {
		t.Error("expected analyzed_at to be set after ReplaceAnalysis")
	}
	if after.Status != model.CaseStatusAnalyzed {
		t.Errorf("status = %q, want analyzed", after.Status)
	}
}

// ---------------- Notes ----------------

func TestNotes_CreateListUpdateDelete(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	now := time.Now().UTC()

	n := model.Note{ID: "note-1", CaseID: "case-1", TargetType: model.TargetFinding, TargetID: "finding-x", Text: "looks suspicious", CreatedAt: now, UpdatedAt: now}
	if err := s.CreateNote(n); err != nil {
		t.Fatalf("CreateNote: %v", err)
	}

	notes, err := s.ListNotes("case-1", model.TargetFinding, "finding-x")
	if err != nil {
		t.Fatalf("ListNotes: %v", err)
	}
	if len(notes) != 1 || notes[0].Text != "looks suspicious" {
		t.Fatalf("got %+v, want 1 note with the expected text", notes)
	}

	if err := s.UpdateNote("note-1", "actually confirmed malicious"); err != nil {
		t.Fatalf("UpdateNote: %v", err)
	}
	notes, _ = s.ListNotes("case-1", "", "")
	if len(notes) != 1 || notes[0].Text != "actually confirmed malicious" {
		t.Fatalf("got %+v, want updated text", notes)
	}

	if err := s.DeleteNote("note-1"); err != nil {
		t.Fatalf("DeleteNote: %v", err)
	}
	notes, _ = s.ListNotes("case-1", "", "")
	if len(notes) != 0 {
		t.Fatalf("got %d notes after delete, want 0", len(notes))
	}
}

// TestNotes_SurviveTargetDeletion is the explicit behavior Phase 6
// requires documented and tested: a note attached to a target (e.g. a
// source file) that later gets deleted must NOT be silently deleted
// along with it -- only a full case deletion removes notes.
func TestNotes_SurviveTargetDeletion(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	now := time.Now().UTC()
	if err := s.CreateNote(model.Note{ID: "note-1", CaseID: "case-1", TargetType: model.TargetSourceFile, TargetID: "sf-1", Text: "re-check this file", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("CreateNote: %v", err)
	}
	if err := s.SoftDeleteSourceFile("sf-1", time.Now().UTC()); err != nil {
		t.Fatalf("SoftDeleteSourceFile: %v", err)
	}
	notes, err := s.ListNotes("case-1", "", "")
	if err != nil {
		t.Fatalf("ListNotes: %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("got %d notes after deleting the note's target source file, want 1 (notes are not cascade-deleted with their target)", len(notes))
	}
}

func TestNotes_DeletedWithCase(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	now := time.Now().UTC()
	if err := s.CreateNote(model.Note{ID: "note-1", CaseID: "case-1", TargetType: model.TargetCase, TargetID: "case-1", Text: "case-level note", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("CreateNote: %v", err)
	}
	if err := s.DeleteCase("case-1"); err != nil {
		t.Fatalf("DeleteCase: %v", err)
	}
	notes, err := s.ListNotes("case-1", "", "")
	if err != nil {
		t.Fatalf("ListNotes: %v", err)
	}
	if len(notes) != 0 {
		t.Errorf("got %d notes after deleting the whole case, want 0", len(notes))
	}
}

// ---------------- Tags ----------------

func TestTags_CreateListDeleteAndUniqueness(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	now := time.Now().UTC()

	if err := s.CreateTag(model.Tag{ID: "tag-1", CaseID: "case-1", TargetType: model.TargetInvestigation, TargetID: "inv-x", Tag: "phishing", CreatedAt: now}); err != nil {
		t.Fatalf("CreateTag: %v", err)
	}
	// Duplicate (same target+tag) must not error and must not create a
	// second row -- idx_tags_unique backstops this.
	if err := s.CreateTag(model.Tag{ID: "tag-2", CaseID: "case-1", TargetType: model.TargetInvestigation, TargetID: "inv-x", Tag: "phishing", CreatedAt: now}); err != nil {
		t.Fatalf("CreateTag (duplicate): %v", err)
	}
	tags, err := s.ListTags("case-1", model.TargetInvestigation, "inv-x")
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if len(tags) != 1 {
		t.Fatalf("got %d tags, want 1 (duplicate must not create a second row)", len(tags))
	}

	if err := s.DeleteTag("case-1", model.TargetInvestigation, "inv-x", "phishing"); err != nil {
		t.Fatalf("DeleteTag: %v", err)
	}
	tags, _ = s.ListTags("case-1", model.TargetInvestigation, "inv-x")
	if len(tags) != 0 {
		t.Fatalf("got %d tags after delete, want 0", len(tags))
	}
}

// ---------------- Analyst status ----------------

func TestAnalystStatus_SetAndGet(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	now := time.Now().UTC()

	if err := s.SetAnalystStatus(model.AnalystStatus{CaseID: "case-1", TargetType: model.TargetFinding, TargetID: "finding-x", Status: model.ReviewNew, UpdatedAt: now}); err != nil {
		t.Fatalf("SetAnalystStatus: %v", err)
	}
	a, found, err := s.GetAnalystStatus(model.TargetFinding, "finding-x")
	if err != nil {
		t.Fatalf("GetAnalystStatus: %v", err)
	}
	if !found || a.Status != model.ReviewNew {
		t.Fatalf("got found=%v status=%q, want found=true status=new", found, a.Status)
	}

	// Setting again (a status change) must UPSERT, not create a second row.
	if err := s.SetAnalystStatus(model.AnalystStatus{CaseID: "case-1", TargetType: model.TargetFinding, TargetID: "finding-x", Status: model.ReviewFalsePositive, Note: "confirmed benign", UpdatedAt: now}); err != nil {
		t.Fatalf("SetAnalystStatus (update): %v", err)
	}
	a, found, err = s.GetAnalystStatus(model.TargetFinding, "finding-x")
	if err != nil {
		t.Fatalf("GetAnalystStatus: %v", err)
	}
	if !found || a.Status != model.ReviewFalsePositive || a.Note != "confirmed benign" {
		t.Fatalf("got %+v, want status=false_positive note='confirmed benign'", a)
	}

	all, err := s.ListAnalystStatusForCase("case-1")
	if err != nil {
		t.Fatalf("ListAnalystStatusForCase: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("got %d statuses, want 1 (upsert, not append)", len(all))
	}
}

func TestAnalystStatus_NotFound(t *testing.T) {
	s := openTest(t)
	_, found, err := s.GetAnalystStatus(model.TargetFinding, "does-not-exist")
	if err != nil {
		t.Fatalf("GetAnalystStatus: %v", err)
	}
	if found {
		t.Error("expected found=false for a target with no status set")
	}
}

// CRITICAL invariant: analyst status must never be able to alter a
// Finding's own deterministic Severity/Confidence -- verified here by
// confirming the two live in entirely separate tables reachable only
// through separate store methods, so there is no code path from
// SetAnalystStatus back into the findings table at all.
func TestAnalystStatus_DoesNotTouchFindingsTable(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	now := time.Now().UTC()
	f := model.Finding{ID: "finding-x", CaseID: "case-1", RuleID: "r1", Title: "t", Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, SupportingEvents: []string{"ev-1"}, FirstSeen: now, LastSeen: now, CreatedAt: now}
	if err := s.SaveFindings([]model.Finding{f}); err != nil {
		t.Fatalf("SaveFindings: %v", err)
	}
	if err := s.SetAnalystStatus(model.AnalystStatus{CaseID: "case-1", TargetType: model.TargetFinding, TargetID: "finding-x", Status: model.ReviewFalsePositive, UpdatedAt: now}); err != nil {
		t.Fatalf("SetAnalystStatus: %v", err)
	}
	got, err := s.GetFinding("finding-x")
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if got.Severity != model.SeverityHigh || got.Confidence != model.ConfidenceHigh {
		t.Errorf("finding severity/confidence changed after SetAnalystStatus: got %s/%s, want unchanged high/high", got.Severity, got.Confidence)
	}
}

// ---------------- Audit log ----------------

func TestAuditLog_CreateAndList(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	now := time.Now().UTC()

	events := []model.AuditEvent{
		{ID: "a1", CaseID: "case-1", Timestamp: now, Action: model.AuditCaseCreated, Actor: model.ActorLocalUser, Summary: "Case created"},
		{ID: "a2", CaseID: "case-1", Timestamp: now.Add(time.Minute), Action: model.AuditAnalysisCompleted, Actor: model.ActorLocalUser, Summary: "Analysis completed: 3 findings"},
	}
	for _, e := range events {
		if err := s.CreateAuditEvent(e); err != nil {
			t.Fatalf("CreateAuditEvent: %v", err)
		}
	}
	got, err := s.ListAuditLog("case-1")
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d audit events, want 2", len(got))
	}
	if got[0].Action != model.AuditCaseCreated || got[1].Action != model.AuditAnalysisCompleted {
		t.Errorf("audit log not in chronological order: %+v", got)
	}
}

func TestAuditLog_DeletedWithCase(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	now := time.Now().UTC()
	if err := s.CreateAuditEvent(model.AuditEvent{ID: "a1", CaseID: "case-1", Timestamp: now, Action: model.AuditCaseCreated, Actor: model.ActorLocalUser, Summary: "Case created"}); err != nil {
		t.Fatalf("CreateAuditEvent: %v", err)
	}
	if err := s.DeleteCase("case-1"); err != nil {
		t.Fatalf("DeleteCase: %v", err)
	}
	got, err := s.ListAuditLog("case-1")
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d audit events after case deletion, want 0", len(got))
	}
}
