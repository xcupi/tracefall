package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// The config-change, blocked-component and audit-stopped rules also read the
// same messages when they arrive as Extended Events error_reported records, and
// the audit rule reads Server Audit rows that record an audit being turned off.
// Shapes follow what a real engine wrote: XE records carry the message in
// sql_field_message, a real instant, no host; a blocked-component attempt is
// reported twice at the same instant (severity 10 for the log, 16 for the
// client).

func xeMsg(id string, ts time.Time, number, severity, msg string) model.Event {
	e := xeError(id, ts, number, msg)
	e.Extra["sql_field_severity"] = severity
	delete(e.Extra, "sql_field_category")
	return e
}

func auditAL(id string, ts time.Time, principal, object, stmt string) model.Event {
	return model.Event{
		ID: id, CaseID: "case1", Timestamp: ts, SourceFileID: "audit-file",
		EventType: model.EventMSSQLAudit, ArtifactType: model.ArtifactMSSQLAudit,
		Extra: map[string]string{
			"sql_evidence_form": "native_sqlaudit_experimental_NOT_VERIFIED",
			"sql_action":        "AL", "sql_outcome": "permission_check_allowed", "sql_principal": principal,
			"sql_client_ip": "203.0.113.5", "sql_client_application": "SQLCMD", "sql_instance": "inst01",
			"sql_object": object, "sql_statement": stmt,
		},
	}
}

var t0 = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

// ---------- config ----------

func TestSQLRiskyConfig_ExtendedEventsMessageFires(t *testing.T) {
	ev := []model.Event{xeMsg("c1", t0, "15457", "0", configMsg("xp_cmdshell", 0, 1))}
	got := sqlFindings(sqlConfigRule, ev)
	if len(got) != 1 || got[0].Severity != model.SeverityMedium || got[0].Confidence != model.ConfidenceHigh {
		t.Fatalf("want one medium/high finding, got %+v", got)
	}
	for _, w := range []string{"Extended Events", "2026-03-01T09:00:00Z", "does not show who made the change"} {
		if !strings.Contains(got[0].Description, w) {
			t.Errorf("description lacks %q: %s", w, got[0].Description)
		}
	}
	noZeroTime(t, got[0])
}

func TestSQLRiskyConfig_ExtendedEventsRoutineHardeningAndOtherEventsAreNotFindings(t *testing.T) {
	routine := xeMsg("r1", t0, "15457", "0", configMsg("show advanced options", 0, 1))
	harden := xeMsg("r2", t0.Add(time.Second), "15457", "0", configMsg("xp_cmdshell", 1, 0))
	// The same words inside a batch record are not a recorded change.
	batch := xeMsg("r3", t0.Add(2*time.Second), "", "", configMsg("xp_cmdshell", 0, 1))
	batch.Extra["sql_field_event_name"] = "sql_batch_completed"
	if got := sqlFindings(sqlConfigRule, []model.Event{routine, harden, batch}); len(got) != 0 {
		t.Fatalf("made %d findings", len(got))
	}
}

func TestSQLRiskyConfig_SameMessageAtSameInstantIsOneChange(t *testing.T) {
	m := configMsg("clr enabled", 0, 1)
	ev := []model.Event{xeMsg("d1", t0, "15457", "0", m), xeMsg("d2", t0, "15457", "0", m)}
	if got := sqlFindings(sqlConfigRule, ev); len(got) != 1 {
		t.Fatalf("one change reported twice made %d findings", len(got))
	}
	// A second change at a later instant is a second change.
	ev = append(ev, xeMsg("d3", t0.Add(time.Minute), "15457", "0", m))
	if got := sqlFindings(sqlConfigRule, ev); len(got) != 2 {
		t.Fatalf("two changes made %d findings", len(got))
	}
}

// ---------- blocked component ----------

func TestSQLDisabledComponent_ExtendedEventsTwinsAreOneAttempt(t *testing.T) {
	m := blockedMsg("sys.xp_cmdshell", "xp_cmdshell")
	var ev []model.Event
	for i := 0; i < 2; i++ {
		at := t0.Add(time.Duration(i) * time.Minute)
		ev = append(ev, xeMsg(fmt.Sprintf("a%d", i), at, "15281", "10", m), xeMsg(fmt.Sprintf("b%d", i), at, "15281", "16", m))
	}
	got := sqlFindings(sqlBlockRule, ev)
	if len(got) != 1 {
		t.Fatalf("want one finding for the procedure, got %d", len(got))
	}
	if !strings.Contains(got[0].Title, "2 attempts") {
		t.Errorf("4 records for 2 attempts were counted as 4: %s", got[0].Title)
	}
	if !strings.Contains(got[0].Description, "Extended Events") {
		t.Errorf("source not named: %s", got[0].Description)
	}
	noZeroTime(t, got[0])
}

func TestSQLDisabledComponent_TextLogAndExtendedEventsAreNotMerged(t *testing.T) {
	m := blockedMsg("sys.xp_cmdshell", "xp_cmdshell")
	ev := []model.Event{
		undatedMsg("t1", "log1", 10, localAt(5, 0), m),
		xeMsg("x1", t0, "15281", "10", m),
	}
	if got := sqlFindings(sqlBlockRule, ev); len(got) != 2 {
		t.Fatalf("want one finding per source, got %d", len(got))
	}
}

// ---------- audit stopped ----------

func TestSQLAuditStopped_ExtendedEventsStopLineFollowedByActivityFires(t *testing.T) {
	ev := []model.Event{
		xeMsg("s1", t0, "-1", "0", auditStopLine),
		xeMsg("s2", t0.Add(time.Second), "-1", "0", "Audit: Server Audit: 65536 Session has been closed"),
		xeMsg("s3", t0.Add(2*time.Second), "5701", "10", "Changed database context to 'db01'."),
	}
	got := sqlFindings(sqlAuditRule, ev)
	if len(got) != 1 || got[0].Severity != model.SeverityLow || got[0].Confidence != model.ConfidenceLow {
		t.Fatalf("want one low/low finding, got %+v", got)
	}
	if !strings.Contains(got[0].Description, "Extended Events") {
		t.Errorf("source not named: %s", got[0].Description)
	}
	// Only audit lines and shutdown text afterwards: a normal stop.
	quiet := ev[:2]
	if got := sqlFindings(sqlAuditRule, quiet); len(got) != 0 {
		t.Fatalf("audit-only tail made %d findings", len(got))
	}
}

func TestSQLAuditStopped_ServerAuditRowRecordsTheCommand(t *testing.T) {
	// A deliberate command needs no activity after it: nothing about it is
	// ambiguous with a shutdown.
	ev := []model.Event{auditAL("a1", t0, "admin01", "audit01", "ALTER SERVER AUDIT audit01 WITH (STATE=OFF)")}
	got := sqlFindings(sqlAuditRule, ev)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.Severity != model.SeverityMedium || f.Confidence != model.ConfidenceMedium {
		t.Errorf("severity/confidence = %s/%s", f.Severity, f.Confidence)
	}
	for _, w := range []string{"admin01", "203.0.113.5", "SQLCMD", "2026-03-01T09:00:00Z", "does not show why"} {
		if !strings.Contains(f.Description, w) {
			t.Errorf("description lacks %q: %s", w, f.Description)
		}
	}
	if strings.Contains(f.Description, "STATE=OFF") {
		t.Errorf("statement text was quoted: %s", f.Description)
	}
	noZeroTime(t, f)
}

func TestSQLAuditStopped_ServerAuditRowVariants(t *testing.T) {
	cases := []struct {
		stmt string
		want bool
	}{
		{"ALTER SERVER AUDIT audit01 WITH (STATE=OFF)", true},
		{"alter server audit [audit01] with ( state = off )", true},
		{"ALTER SERVER AUDIT SPECIFICATION spec01 WITH (STATE = OFF)", true},
		{"ALTER DATABASE AUDIT SPECIFICATION spec01 WITH (STATE = OFF)", true},
		{"DROP SERVER AUDIT audit01", true},
		{"ALTER SERVER AUDIT audit01 WITH (STATE=ON)", false},
		{"ALTER SERVER AUDIT audit01 MODIFY NAME = audit02", false},
		{"ALTER LOGIN alice WITH PASSWORD='x'", false},
		{"SELECT 'STATE=OFF' -- ALTER SERVER AUDIT", false},
	}
	for _, c := range cases {
		got := sqlFindings(sqlAuditRule, []model.Event{auditAL("v", t0, "admin01", "audit01", c.stmt)})
		if (len(got) == 1) != c.want {
			t.Errorf("%q: findings=%d, want fire=%v", c.stmt, len(got), c.want)
		}
	}
}

func TestSQLAuditStopped_ServerAuditAndXEAreOrderIndependent(t *testing.T) {
	ev := []model.Event{
		auditAL("a1", t0, "admin01", "audit01", "ALTER SERVER AUDIT audit01 WITH (STATE=OFF)"),
		auditAL("a2", t0.Add(time.Hour), "admin02", "audit02", "DROP SERVER AUDIT audit02"),
		xeMsg("s1", t0, "-1", "0", auditStopLine),
		xeMsg("s3", t0.Add(2*time.Second), "5701", "10", "Changed database context to 'db01'."),
		xeMsg("c1", t0, "15457", "0", configMsg("xp_cmdshell", 0, 1)),
	}
	for _, rule := range []string{sqlAuditRule, sqlConfigRule} {
		sameFindings(t, rule, ev)
	}
}
