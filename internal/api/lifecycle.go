package api

import (
	"errors"
	"fmt"

	"tracefall/internal/model"
)

// Case lifecycle enforcement (Phase 13).
//
// The lifecycle governs two things independently:
//
//	EVIDENCE   mutable while open/investigating, frozen once contained
//	PRIORITY   editable until the case is closed
//
// Both are enforced HERE, in the service layer, and never only in the
// UI. A disabled button is a courtesy to the analyst; the guard is what
// actually stops a direct API call from changing a contained case's
// evidence.
//
// The guard runs BEFORE any work: nothing is staged, hashed, extracted,
// written or deleted before the lock is checked, so a blocked request
// leaves the database and the evidence directory exactly as they were.

var (
	// ErrEvidenceLocked means the case's evidence set is frozen because
	// the case has been contained or closed.
	ErrEvidenceLocked = errors.New("this case's evidence is locked")
	// ErrPriorityLocked means the case is closed, so its triage priority
	// can no longer be changed.
	ErrPriorityLocked = errors.New("this case is closed, so its priority can no longer be changed")
)

// EvidenceLockedError explains a refused evidence mutation, naming the
// status responsible and what to do about it.
//
// A structured error rather than a bare sentinel because "you cannot do
// that" without saying WHY, or how to proceed, is the kind of message
// that makes an investigator think the tool is broken.
type EvidenceLockedError struct {
	CaseID     string
	CaseStatus string
}

func (e *EvidenceLockedError) Error() string {
	return fmt.Sprintf(
		"this case is %s, so its evidence set is locked and cannot be added to, imported or deleted. "+
			"Reopen the case (set its status back to Open or Investigating) if evidence genuinely still needs to change.",
		e.CaseStatus)
}

// Unwrap lets callers match the sentinel with errors.Is while still
// being able to read the status with errors.As.
func (e *EvidenceLockedError) Unwrap() error { return ErrEvidenceLocked }

// requireEvidenceMutable refuses an evidence mutation on a contained or
// closed case.
//
// It returns the case on success, so callers that need it do not pay for
// a second read -- every one of them was already loading the case to
// validate it exists.
func (s *Service) requireEvidenceMutable(caseID string) (model.Case, error) {
	c, err := s.GetCase(caseID)
	if err != nil {
		return model.Case{}, err
	}
	if !model.EvidenceMutable(c.CaseStatus) {
		return model.Case{}, &EvidenceLockedError{CaseID: caseID, CaseStatus: c.CaseStatus}
	}
	return c, nil
}
