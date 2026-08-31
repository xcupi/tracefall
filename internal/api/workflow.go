// Phase 6 ("Forensic Hardening & Analyst Workflow") service methods:
// case metadata, notes, tags, finding/investigation review status, and
// the audit trail. None of this is forensic evidence and none of it can
// reach the deterministic findings/correlations/investigations
// themselves -- see internal/model/workflow.go's package doc comment
// and docs/analyst-workflow.md for the full model.
package api

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"tracefall/internal/model"
	"tracefall/internal/store"
)

// ---------------- Case metadata ----------------

// CaseMetadataUpdate is the API-layer request shape for
// PATCH /cases/{id} -- a pointer per field so a request can update just
// one of name/description/case_status/priority without needing the
// others (nil means "leave unchanged"). Deliberately does not include
// Status (the analysis lifecycle) or CreatedAt/AnalyzedAt (both
// system-set) -- see model.Case's doc comment on why those are never
// analyst-editable.
type CaseMetadataUpdate struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	CaseStatus  *string `json:"case_status"`
	Priority    *string `json:"priority"`
}

var validCaseWorkflowStatuses = set(model.CaseWorkflowOpen, model.CaseWorkflowInvestigating, model.CaseWorkflowContained, model.CaseWorkflowClosed)
var validCasePriorities = set(model.CasePriorityLow, model.CasePriorityMedium, model.CasePriorityHigh, model.CasePriorityCritical)

func set(vals ...string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}

// UpdateCaseMetadata applies a partial update to a case's analyst-facing
// metadata (name, description, investigative workflow status,
// priority). Name uniqueness is enforced the same way CreateCase's is.
func (s *Service) UpdateCaseMetadata(caseID string, u CaseMetadataUpdate) (model.Case, error) {
	if u.Name != nil {
		trimmed := strings.TrimSpace(*u.Name)
		if trimmed == "" {
			return model.Case{}, ErrCaseNameRequired
		}
		u.Name = &trimmed
	}
	if u.CaseStatus != nil && !validCaseWorkflowStatuses[*u.CaseStatus] {
		return model.Case{}, fmt.Errorf("invalid case_status %q", *u.CaseStatus)
	}
	if u.Priority != nil && !validCasePriorities[*u.Priority] {
		return model.Case{}, fmt.Errorf("invalid priority %q", *u.Priority)
	}

	storeUpdate := store.CaseMetadataUpdate{Name: u.Name, Description: u.Description, CaseStatus: u.CaseStatus, Priority: u.Priority}
	err := s.store.UpdateCaseMetadata(caseID, storeUpdate)
	if err != nil {
		if errors.Is(err, store.ErrDuplicateCase) {
			if u.Name != nil {
				if existing, found, ferr := s.store.FindCaseByName(*u.Name); ferr == nil && found && existing.ID != caseID {
					return model.Case{}, &DuplicateCaseError{CaseID: existing.ID, CaseName: existing.Name}
				}
			}
			return model.Case{}, ErrDuplicateCase
		}
		return model.Case{}, err
	}

	c, err := s.GetCase(caseID)
	if err != nil {
		return model.Case{}, err
	}
	s.audit(caseID, model.AuditCaseMetadataUpdated, model.TargetCase, caseID, "Case metadata updated")
	return c, nil
}

// ---------------- Notes ----------------

func (s *Service) CreateNote(caseID, targetType, targetID, text string) (model.Note, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return model.Note{}, fmt.Errorf("note text is required")
	}
	if !validTargetType(targetType) {
		return model.Note{}, fmt.Errorf("invalid target_type %q", targetType)
	}
	now := time.Now().UTC()
	n := model.Note{ID: uuid.NewString(), CaseID: caseID, TargetType: targetType, TargetID: targetID, Text: text, CreatedAt: now, UpdatedAt: now}
	if err := s.store.CreateNote(n); err != nil {
		return model.Note{}, err
	}
	s.audit(caseID, model.AuditNoteAdded, targetType, targetID, "Note added")
	return n, nil
}

// ListNotes returns a case's notes, optionally scoped to one target
// (pass targetType="" for every note in the case -- used by case export).
func (s *Service) ListNotes(caseID, targetType, targetID string) ([]model.Note, error) {
	return s.store.ListNotes(caseID, targetType, targetID)
}

// UpdateNote edits one note within caseID.
//
// caseID is REQUIRED and is enforced in the store's WHERE clause. Before
// Phase 12 this took a bare note id, so any caller who knew or guessed
// an id could edit a note in any case -- an authorization bypass by id.
func (s *Service) UpdateNote(caseID, id, text string) (model.Note, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return model.Note{}, fmt.Errorf("note text is required")
	}
	if err := s.store.UpdateNote(caseID, id, text); err != nil {
		return model.Note{}, err
	}
	return model.Note{}, nil
}

// DeleteNote removes one note within caseID. Scoped for the same reason
// as UpdateNote.
func (s *Service) DeleteNote(caseID, id string) error {
	return s.store.DeleteNote(caseID, id)
}

// ---------------- Tags ----------------

func (s *Service) AddTag(caseID, targetType, targetID, tag string) (model.Tag, error) {
	tag = strings.TrimSpace(strings.ToLower(tag))
	if tag == "" {
		return model.Tag{}, fmt.Errorf("tag is required")
	}
	if !validTargetType(targetType) {
		return model.Tag{}, fmt.Errorf("invalid target_type %q", targetType)
	}
	t := model.Tag{ID: uuid.NewString(), CaseID: caseID, TargetType: targetType, TargetID: targetID, Tag: tag, CreatedAt: time.Now().UTC()}
	if err := s.store.CreateTag(t); err != nil {
		return model.Tag{}, err
	}
	s.audit(caseID, model.AuditTagAdded, targetType, targetID, fmt.Sprintf("Tag %q added", tag))
	return t, nil
}

func (s *Service) RemoveTag(caseID, targetType, targetID, tag string) error {
	if err := s.store.DeleteTag(caseID, targetType, targetID, tag); err != nil {
		return err
	}
	s.audit(caseID, model.AuditTagRemoved, targetType, targetID, fmt.Sprintf("Tag %q removed", tag))
	return nil
}

func (s *Service) ListTags(caseID, targetType, targetID string) ([]model.Tag, error) {
	return s.store.ListTags(caseID, targetType, targetID)
}

// ---------------- Finding / Investigation review status ----------------

var validReviewStatuses = set(model.ReviewNew, model.ReviewReviewing, model.ReviewConfirmed, model.ReviewDismissed, model.ReviewFalsePositive)
var validInvestigationStatuses = set(model.InvestigationWorkflowOpen, model.InvestigationWorkflowInvestigating, model.InvestigationWorkflowConfirmed, model.InvestigationWorkflowDismissed, model.InvestigationWorkflowClosed)

// SetFindingStatus records the analyst's review status for one finding.
// This NEVER touches the finding's own deterministic Severity/Confidence
// (internal/model.Finding, produced by internal/detect and stored in the
// findings table) -- status lives entirely in the separate
// analyst_status table. See model.AnalystStatus's doc comment.
func (s *Service) SetFindingStatus(caseID, findingID, status, note string) (model.AnalystStatus, error) {
	if !validReviewStatuses[status] {
		return model.AnalystStatus{}, fmt.Errorf("invalid finding status %q", status)
	}
	a := model.AnalystStatus{CaseID: caseID, TargetType: model.TargetFinding, TargetID: findingID, Status: status, Note: note, UpdatedAt: time.Now().UTC()}
	if err := s.store.SetAnalystStatus(a); err != nil {
		return model.AnalystStatus{}, err
	}
	s.audit(caseID, model.AuditFindingStatusChanged, model.TargetFinding, findingID, fmt.Sprintf("Finding status changed to %q", status))
	return a, nil
}

// SetInvestigationStatus is SetFindingStatus's counterpart for
// investigations, with its own status vocabulary (see
// model.InvestigationWorkflow* -- a whole story progresses differently
// than a single indicator does).
func (s *Service) SetInvestigationStatus(caseID, investigationID, status, note string) (model.AnalystStatus, error) {
	if !validInvestigationStatuses[status] {
		return model.AnalystStatus{}, fmt.Errorf("invalid investigation status %q", status)
	}
	a := model.AnalystStatus{CaseID: caseID, TargetType: model.TargetInvestigation, TargetID: investigationID, Status: status, Note: note, UpdatedAt: time.Now().UTC()}
	if err := s.store.SetAnalystStatus(a); err != nil {
		return model.AnalystStatus{}, err
	}
	s.audit(caseID, model.AuditInvestigationStatusChanged, model.TargetInvestigation, investigationID, fmt.Sprintf("Investigation status changed to %q", status))
	return a, nil
}

// ListAnalystStatus returns every target's current review status in a
// case, one query -- the HTTP-facing counterpart to AnalystStatusIndex,
// used by the dashboard to render every finding/investigation's Analyst
// Assessment box without an N+1 request per card.
func (s *Service) ListAnalystStatus(caseID string) ([]model.AnalystStatus, error) {
	return s.store.ListAnalystStatusForCase(caseID)
}

// GetAnalystStatus returns one target's current review status, and
// whether it has ever been set (found=false + the zero value means
// "still New/Open" by convention -- see the handlers, which default the
// displayed status accordingly rather than treating "not found" as an
// error).
func (s *Service) GetAnalystStatus(targetType, targetID string) (model.AnalystStatus, bool, error) {
	return s.store.GetAnalystStatus(targetType, targetID)
}

// AnalystStatusIndex builds target_id -> AnalystStatus for a whole case
// in one query -- used to enrich the Findings/Investigations list
// responses without an N+1 query per row.
func (s *Service) AnalystStatusIndex(caseID string) (map[string]model.AnalystStatus, error) {
	all, err := s.store.ListAnalystStatusForCase(caseID)
	if err != nil {
		return nil, err
	}
	idx := make(map[string]model.AnalystStatus, len(all))
	for _, a := range all {
		idx[a.TargetID] = a
	}
	return idx, nil
}

// ---------------- Audit log ----------------

func (s *Service) AuditLog(caseID string) ([]model.AuditEvent, error) {
	return s.store.ListAuditLog(caseID)
}

// ---------------- shared helpers ----------------

func validTargetType(t string) bool {
	switch t {
	case model.TargetCase, model.TargetCollection, model.TargetSourceFile, model.TargetEvent, model.TargetFinding, model.TargetInvestigation:
		return true
	default:
		return false
	}
}
