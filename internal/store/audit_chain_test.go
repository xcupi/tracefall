package store

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// chainCase creates one case and returns its ID.
func chainCase(t *testing.T, s *Store, id string) string {
	t.Helper()
	now := time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)
	if err := s.CreateCase(model.Case{ID: id, Name: "chain " + id, Status: model.CaseStatusCreated, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("CreateCase: %v", err)
	}
	return id
}

func appendAudit(t *testing.T, s *Store, caseID string, n int) {
	t.Helper()
	base := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		e := model.AuditEvent{
			ID: caseID + "-a" + string(rune('a'+i)), CaseID: caseID,
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Action:    "test_action", Actor: "alice", TargetType: "case", TargetID: caseID,
			Summary: "entry " + string(rune('a'+i)),
		}
		if err := s.CreateAuditEvent(e); err != nil {
			t.Fatalf("CreateAuditEvent %d: %v", i, err)
		}
	}
}

func TestAuditChain_AppendedRowsVerify(t *testing.T) {
	s := openTest(t)
	id := chainCase(t, s, "c-verify")
	appendAudit(t, s, id, 4)

	st, err := s.VerifyAuditChain(id)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Valid || st.Chained != 4 || st.Unchained != 0 || st.Head == "" {
		t.Fatalf("status = %+v; four chained rows must verify with a head", st)
	}
}

func TestAuditChain_EditedSummaryIsDetected(t *testing.T) {
	s := openTest(t)
	id := chainCase(t, s, "c-edit")
	appendAudit(t, s, id, 3)

	if _, err := s.db.Exec(`UPDATE audit_log SET summary = 'nothing happened' WHERE id = ?`, id+"-ab"); err != nil {
		t.Fatal(err)
	}
	st, _ := s.VerifyAuditChain(id)
	if st.Valid || st.BrokenAt != id+"-ab" || !strings.Contains(st.Reason, "edited") {
		t.Fatalf("status = %+v; an edited summary must fail at that row", st)
	}
}

func TestAuditChain_DeletedMiddleRowIsDetected(t *testing.T) {
	s := openTest(t)
	id := chainCase(t, s, "c-delete")
	appendAudit(t, s, id, 4)

	if _, err := s.db.Exec(`DELETE FROM audit_log WHERE id = ?`, id+"-ab"); err != nil {
		t.Fatal(err)
	}
	st, _ := s.VerifyAuditChain(id)
	if st.Valid || st.BrokenAt != id+"-ac" {
		t.Fatalf("status = %+v; removing a middle row must fail at the row after it", st)
	}
}

func TestAuditChain_BlankedHashAfterTheChainBeganIsDetected(t *testing.T) {
	s := openTest(t)
	id := chainCase(t, s, "c-strip")
	appendAudit(t, s, id, 3)

	// Stripping a hash to pass the row off as legacy must not work once the
	// chain has started.
	if _, err := s.db.Exec(`UPDATE audit_log SET entry_hash = '' WHERE id = ?`, id+"-ab"); err != nil {
		t.Fatal(err)
	}
	st, _ := s.VerifyAuditChain(id)
	if st.Valid || !strings.Contains(st.Reason, "after the chain began") {
		t.Fatalf("status = %+v; a blanked hash after the chain began must fail", st)
	}
}

func TestAuditChain_LegacyRowsAreReportedNotVerified(t *testing.T) {
	s := openTest(t)
	id := chainCase(t, s, "c-legacy")
	// A row written before the chain existed: no hash, no link.
	if _, err := s.db.Exec(`INSERT INTO audit_log (id, case_id, timestamp, action, actor, summary)
		VALUES ('old-1', ?, '2026-10-01T00:00:00Z', 'legacy_action', 'alice', 'before the chain')`, id); err != nil {
		t.Fatal(err)
	}
	appendAudit(t, s, id, 2)

	st, err := s.VerifyAuditChain(id)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Valid || st.Unchained != 1 || st.Chained != 2 {
		t.Fatalf("status = %+v; the legacy row must be counted as unchained and the new rows must verify", st)
	}
}

func TestAuditChain_OnlyLegacyRowsIsValidWithNothingToVerify(t *testing.T) {
	s := openTest(t)
	id := chainCase(t, s, "c-only-legacy")
	if _, err := s.db.Exec(`INSERT INTO audit_log (id, case_id, timestamp, action, actor, summary)
		VALUES ('old-2', ?, '2026-10-01T00:00:00Z', 'legacy_action', 'alice', 'x')`, id); err != nil {
		t.Fatal(err)
	}
	st, _ := s.VerifyAuditChain(id)
	if !st.Valid || st.Chained != 0 || st.Unchained != 1 || st.Head != "" {
		t.Fatalf("status = %+v; a case with only legacy rows has nothing verified, and must say so", st)
	}
}

func TestAuditChain_EachCaseHasItsOwnChain(t *testing.T) {
	s := openTest(t)
	a := chainCase(t, s, "c-one")
	b := chainCase(t, s, "c-two")
	appendAudit(t, s, a, 2)
	appendAudit(t, s, b, 3)

	for _, id := range []string{a, b} {
		st, _ := s.VerifyAuditChain(id)
		if !st.Valid {
			t.Fatalf("case %s: %+v; interleaved writes to two cases must not break either chain", id, st)
		}
	}
}
