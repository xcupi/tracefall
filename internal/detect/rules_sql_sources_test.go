package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// Login evidence also reaches Tracefall as Server Audit rows (LGIF / LGIS) and
// as Extended Events error_reported 18456. The shapes below are those a real
// engine produced: no host, the client in sql_client_ip, the login in
// sql_principal, the reason inside the statement text, and a real UTC instant.

func auditLogin(id string, ts time.Time, action, principal, client, reason string) model.Event {
	stmt := failMsg(principal, reason, client)
	outcome := "login_failed"
	if action == "LGIS" {
		stmt = "-- network protocol: TCP/IP\r\nset quoted_identifier on\r\n"
		outcome = "login_success"
	}
	return model.Event{
		ID: id, CaseID: "case1", Timestamp: ts, SourceFileID: "audit-file",
		EventType: model.EventMSSQLAudit, ArtifactType: model.ArtifactMSSQLAudit,
		Extra: map[string]string{
			"sql_evidence_form": "native_sqlaudit_experimental_NOT_VERIFIED",
			"sql_action":        action, "sql_outcome": outcome, "sql_principal": principal,
			"sql_client_ip": client, "sql_instance": "inst01", "sql_statement": stmt,
		},
	}
}

func xeError(id string, ts time.Time, number, msg string) model.Event {
	return model.Event{
		ID: id, CaseID: "case1", Timestamp: ts, SourceFileID: "xe-file",
		EventType: model.EventMSSQLXE, ArtifactType: model.ArtifactMSSQLExtendedEvents,
		Extra: map[string]string{
			"sql_evidence_form": "native_xel", "sql_field_event_name": "error_reported",
			"sql_field_error_number": number, "sql_field_message": msg, "sql_field_category": "LOGON",
		},
	}
}

func auditBurst(prefix string, n int, base time.Time, principal, client, reason string) []model.Event {
	var out []model.Event
	for i := 0; i < n; i++ {
		out = append(out, auditLogin(fmt.Sprintf("%s%02d", prefix, i), base.Add(time.Duration(i)*time.Second), "LGIF", principal, client, reason))
	}
	return out
}

func TestSQLLoginBurst_ServerAuditRowsFire(t *testing.T) {
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	got := sqlFindings(sqlBurstRule, auditBurst("a", 5, base, "user01", "203.0.113.5", reasonNoLogin))
	if len(got) != 1 {
		t.Fatalf("want 1 finding from 5 audit login failures, got %d", len(got))
	}
	f := got[0]
	for _, w := range []string{"5 failed", "203.0.113.5", "user01", "Server Audit", "2026-03-01T09:00:00Z"} {
		if !strings.Contains(f.Title+" "+f.Description, w) {
			t.Errorf("finding lacks %q: %s", w, f.Description)
		}
	}
	if !f.FirstSeen.Equal(base) {
		t.Errorf("first seen = %v", f.FirstSeen)
	}
	noZeroTime(t, f)
}

func TestSQLLoginBurst_ServerAuditIgnoresOtherActionsAndSuccessesAlone(t *testing.T) {
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	var ev []model.Event
	for i := 0; i < 8; i++ {
		ev = append(ev, auditLogin(fmt.Sprintf("s%d", i), base.Add(time.Duration(i)*time.Second), "LGIS", "user01", "203.0.113.5", ""))
		other := auditLogin(fmt.Sprintf("o%d", i), base.Add(time.Duration(i)*time.Second), "AUSC", "user01", "203.0.113.5", reasonBadPass)
		other.Extra["sql_outcome"] = "permission_check_allowed"
		ev = append(ev, other)
	}
	if got := sqlFindings(sqlBurstRule, ev); len(got) != 0 {
		t.Fatalf("successful logins and other audit actions made %d findings", len(got))
	}
}

func TestSQLLoginBurst_ServerAuditSuccessFromSameClientRaisesSeverity(t *testing.T) {
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	ev := auditBurst("a", 5, base, "user01", "203.0.113.5", reasonBadPass)
	same := append(append([]model.Event{}, ev...), auditLogin("ok", base.Add(10*time.Minute), "LGIS", "user01", "203.0.113.5", ""))
	got := sqlFindings(sqlBurstRule, same)
	if len(got) != 1 || got[0].Severity != model.SeverityHigh || !strings.Contains(got[0].Description, "a successful login from the same client follows") {
		t.Fatalf("same-login success not recognised: %+v", got)
	}
	// A different login from that client is not the guessed name.
	other := append(append([]model.Event{}, ev...), auditLogin("ok", base.Add(10*time.Minute), "LGIS", "admin01", "203.0.113.5", ""))
	got = sqlFindings(sqlBurstRule, other)
	if len(got) != 1 || got[0].Severity != model.SeverityMedium {
		t.Fatalf("a different login raised severity: %+v", got)
	}
}

func TestSQLLoginBurst_ExtendedEventsError18456Fires(t *testing.T) {
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	var ev []model.Event
	for i := 0; i < 5; i++ {
		ev = append(ev, xeError(fmt.Sprintf("x%d", i), base.Add(time.Duration(i)*time.Second), "18456", failMsg("user01", reasonBadPass, "203.0.113.5")))
	}
	// Unrelated errors, including one with a client-looking message, never count.
	for i := 0; i < 6; i++ {
		ev = append(ev, xeError(fmt.Sprintf("n%d", i), base.Add(time.Duration(i)*time.Second), "5701", "Changed database context to 'master'."))
	}
	got := sqlFindings(sqlBurstRule, ev)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	for _, w := range []string{"5 failed", "203.0.113.5", "user01", "Extended Events"} {
		if !strings.Contains(got[0].Title+" "+got[0].Description, w) {
			t.Errorf("finding lacks %q: %s", w, got[0].Description)
		}
	}
}

// The same attempts are often recorded by the text log, the audit and the XE
// session. Counting them together would invent a burst; counting each source on
// its own is honest, and the finding must say the counts are not additive.
func TestSQLLoginBurst_SourcesAreNeverSummed(t *testing.T) {
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	var ev []model.Event
	ev = append(ev, auditBurst("a", 3, base, "user01", "203.0.113.5", reasonBadPass)...)
	for i := 0; i < 3; i++ {
		ev = append(ev, xeError(fmt.Sprintf("x%d", i), base.Add(time.Duration(i)*time.Second), "18456", failMsg("user01", reasonBadPass, "203.0.113.5")))
	}
	ev = append(ev, burstEvents("log1", 3, 0, "user01", "203.0.113.5", reasonBadPass)...)
	if got := sqlFindings(sqlBurstRule, ev); len(got) != 0 {
		t.Fatalf("3+3+3 across three sources made %d findings", len(got))
	}
	ev = append(auditBurst("b", 5, base, "user01", "203.0.113.5", reasonBadPass), burstEvents("log1", 5, 0, "user01", "203.0.113.5", reasonBadPass)...)
	got := sqlFindings(sqlBurstRule, ev)
	if len(got) != 2 {
		t.Fatalf("want one finding per source, got %d", len(got))
	}
	for _, f := range got {
		if !strings.Contains(f.Description, "may also record the same attempts") {
			t.Errorf("no note that sources overlap: %s", f.Description)
		}
	}
}

func TestSQLLoginBurst_ServerAuditAndXEAreOrderIndependent(t *testing.T) {
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	ev := auditBurst("a", 6, base, "user01", "203.0.113.5", reasonBadPass)
	ev = append(ev, auditLogin("ok", base.Add(5*time.Minute), "LGIS", "user01", "203.0.113.5", ""))
	for i := 0; i < 5; i++ {
		ev = append(ev, xeError(fmt.Sprintf("x%d", i), base.Add(time.Duration(i)*time.Second), "18456", failMsg("user02", reasonNoLogin, "203.0.113.9")))
	}
	sameFindings(t, sqlBurstRule, ev)
}
