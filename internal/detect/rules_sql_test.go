package detect

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers/mssql"
)

const (
	sqlBurstRule  = "sql-login-failure-burst"
	sqlConfigRule = "sql-risky-config-enabled"
	sqlBlockRule  = "sql-disabled-component-attempt"
	sqlAuditRule  = "sql-audit-stopped-while-running"

	reasonNoLogin  = "Could not find a login matching the name provided."
	reasonBadPass  = "Password did not match that for the login provided."
	localBasis     = "local time; offset not recorded"
	auditStopLine  = "Audit: Server Audit: 65536, State changed from: STARTED to: SHUTTING_DOWN"
	laterEngineMsg = "Setting database option RECOVERY to SIMPLE for database 'db01'."
)

// ---------- fixtures ----------

// errorlogLine is one ERRORLOG record in the shape the engine writes it.
func errorlogLine(local, source, msg string) string {
	return fmt.Sprintf("%s %-11s %s\n", local, source, msg)
}

func failMsg(login, reason, client string) string {
	return fmt.Sprintf("Login failed for user '%s'. Reason: %s [CLIENT: %s]", login, reason, client)
}

// localAt renders second s of a fixed local day as the engine writes it.
func localAt(s int, centi int) string {
	base := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC).Add(time.Duration(s) * time.Second)
	return fmt.Sprintf("%s.%02d", base.Format("2006-01-02 15:04:05"), centi)
}

// undatedFail is a failed-login event as the text-log parser leaves it:
// zero Timestamp, local reading in Extra.
func undatedFail(id, file string, line int, local, login, client, reason string) model.Event {
	msg := failMsg(login, reason, client)
	return model.Event{
		ID: id, CaseID: "case1", Host: "host01", SourceFileID: file,
		SourceReference: fmt.Sprintf("line:%d", line),
		EventType:       model.EventSQLLoginFailed, ArtifactType: model.ArtifactMSSQLLog,
		User: login, NetworkSource: client,
		Extra: map[string]string{
			"timestamp_local": local, "timestamp_basis": localBasis,
			"message": msg, "login": login, "client": client, "outcome": "failed", "sql_source": "Logon",
		},
	}
}

func undatedSuccess(id, file string, line int, local, login, client string) model.Event {
	return model.Event{
		ID: id, CaseID: "case1", Host: "host01", SourceFileID: file,
		SourceReference: fmt.Sprintf("line:%d", line),
		EventType:       model.EventSQLLoginSuccess, ArtifactType: model.ArtifactMSSQLLog,
		User: login, NetworkSource: client,
		Extra: map[string]string{
			"timestamp_local": local, "timestamp_basis": localBasis,
			"message": fmt.Sprintf("Login succeeded for user '%s'. [CLIENT: %s]", login, client),
			"login":   login, "client": client, "outcome": "success",
		},
	}
}

// datedFail is a failed login from the Windows Application log.
func datedFail(id string, ts time.Time, login, client, reason string) model.Event {
	return model.Event{
		ID: id, CaseID: "case1", Host: "host01", Timestamp: ts, SourceFileID: "app-evtx",
		EventType: model.EventSQLLoginFailed, ArtifactType: model.ArtifactWindowsEventLog,
		User: login, NetworkSource: client,
		Extra: map[string]string{
			"instance": "MSSQLSERVER", "sql_data.Message": failMsg(login, reason, client),
			"login": login, "client": client, "outcome": "failed", "error_number": "18456",
		},
	}
}

func datedSuccess(id string, ts time.Time, login, client string) model.Event {
	e := datedFail(id, ts, login, client, "")
	e.EventType = model.EventSQLLoginSuccess
	e.Extra["outcome"] = "success"
	e.Extra["sql_data.Message"] = fmt.Sprintf("Login succeeded for user '%s'. [CLIENT: %s]", login, client)
	delete(e.Extra, "error_number")
	return e
}

// undatedMsg is a sql_message from a text log.
func undatedMsg(id, file string, line int, local, msg string) model.Event {
	return model.Event{
		ID: id, CaseID: "case1", Host: "host01", SourceFileID: file,
		SourceReference: fmt.Sprintf("line:%d", line),
		EventType:       model.EventSQLMessage, ArtifactType: model.ArtifactMSSQLLog,
		Extra: map[string]string{"timestamp_local": local, "timestamp_basis": localBasis, "message": msg, "sql_source": "spid1"},
	}
}

// datedMsg is a sql_message from the Application log.
func datedMsg(id string, ts time.Time, msg string) model.Event {
	return model.Event{
		ID: id, CaseID: "case1", Host: "host01", Timestamp: ts, SourceFileID: "app-evtx",
		EventType: model.EventSQLMessage, ArtifactType: model.ArtifactWindowsEventLog,
		Extra: map[string]string{"instance": "MSSQLSERVER", "sql_data.Message": msg},
	}
}

func configMsg(option string, from, to int) string {
	return fmt.Sprintf("Configuration option '%s' changed from %d to %d. Run the RECONFIGURE statement to install.", option, from, to)
}

func blockedMsg(proc, component string) string {
	return fmt.Sprintf("SQL Server blocked access to procedure '%s' of component '%s' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of '%s' by using sp_configure. For more information about enabling '%s', search for '%s' in SQL Server Books Online.", proc, component, component, component, component)
}

func burstEvents(file string, n int, startSec int, login, client, reason string) []model.Event {
	var out []model.Event
	for i := 0; i < n; i++ {
		out = append(out, undatedFail(fmt.Sprintf("%s-f%02d", file, i), file, 10+i, localAt(startSec+i, 51), login, client, reason))
	}
	return out
}

func shuffled(ev []model.Event, seed int64) []model.Event {
	out := append([]model.Event{}, ev...)
	rand.New(rand.NewSource(seed)).Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func sqlFindings(rule string, ev []model.Event) []model.Finding {
	for _, r := range All() {
		if r.ID() == rule {
			return r.Evaluate(ev)
		}
	}
	panic("rule not registered: " + rule)
}

func noZeroTime(t *testing.T, f model.Finding) {
	t.Helper()
	for _, bad := range []string{"0001-01-01", "year 0001", "UTC"} {
		if strings.Contains(f.Title+" "+f.Description, bad) {
			t.Errorf("finding text contains %q: %s", bad, f.Description)
		}
	}
}

func sameFindings(t *testing.T, rule string, ev []model.Event) {
	t.Helper()
	want := mustJSON(t, withoutCreatedAt(sqlFindings(rule, ev)))
	for seed := int64(1); seed <= 6; seed++ {
		got := mustJSON(t, withoutCreatedAt(sqlFindings(rule, shuffled(ev, seed))))
		if got != want {
			t.Fatalf("%s: shuffled input (seed %d) changed the output\nwant %s\ngot  %s", rule, seed, want, got)
		}
	}
}

// ---------- sql-login-failure-burst ----------

func TestSQLLoginBurst_RealErrorlogShapeFires(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 12; i++ {
		body.WriteString(errorlogLine(localAt(158+i/6, 10+i), "Logon", failMsg("user01", reasonBadPass, "172.17.0.2")))
	}
	ev := load(t, mssql.New(), "log1", "ERRORLOG", body.String())
	if len(ev) != 12 || ev[0].EventType != model.EventSQLLoginFailed {
		t.Fatalf("fixture did not parse as expected: %d events", len(ev))
	}
	got := sqlFindings(sqlBurstRule, ev)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.Severity != model.SeverityMedium || f.Confidence != model.ConfidenceMedium {
		t.Errorf("severity/confidence = %s/%s, want medium/medium", f.Severity, f.Confidence)
	}
	for _, want := range []string{"12 failed", "172.17.0.2", "1 distinct login", "user01", strings.TrimRight(reasonBadPass, "."), localBasis,
		"does not record successful logins by default", "proxy or container gateway", "failed attempts recorded by the engine"} {
		if !strings.Contains(f.Description, want) {
			t.Errorf("description lacks %q:\n%s", want, f.Description)
		}
	}
	if !strings.Contains(f.Description, "2026-10-22 00:02:38.10") || !strings.Contains(f.Description, "2026-10-22 00:02:39.21") {
		t.Errorf("window should be the local readings:\n%s", f.Description)
	}
	noZeroTime(t, f)
	if !f.FirstSeen.IsZero() || !f.LastSeen.IsZero() {
		t.Errorf("undated finding must not carry a time window: %v %v", f.FirstSeen, f.LastSeen)
	}
}

func TestSQLLoginBurst_BelowThresholdAndWideGapsDoNotFire(t *testing.T) {
	if got := sqlFindings(sqlBurstRule, burstEvents("log1", 4, 0, "user01", "203.0.113.5", reasonBadPass)); len(got) != 0 {
		t.Errorf("4 failures fired: %d", len(got))
	}
	// 3 + 3 failures separated by a 3 minute gap: neither run reaches 5.
	ev := burstEvents("log1", 3, 0, "user01", "203.0.113.5", reasonBadPass)
	for i, e := range burstEvents("log1", 3, 183, "user01", "203.0.113.5", reasonBadPass) {
		e.ID = fmt.Sprintf("late%d", i)
		e.SourceReference = fmt.Sprintf("line:%d", 50+i)
		ev = append(ev, e)
	}
	if got := sqlFindings(sqlBurstRule, ev); len(got) != 0 {
		t.Errorf("runs split by a gap over 2 minutes fired: %d", len(got))
	}
	// Exactly 2 minutes between each failure still chains.
	var chained []model.Event
	for i := 0; i < 5; i++ {
		chained = append(chained, undatedFail(fmt.Sprintf("c%d", i), "log1", 10+i, localAt(i*120, 0), "user01", "203.0.113.5", reasonBadPass))
	}
	if got := sqlFindings(sqlBurstRule, chained); len(got) != 1 {
		t.Errorf("gaps of exactly 2 minutes should chain: %d findings", len(got))
	}
}

func TestSQLLoginBurst_ConfidenceRisesOnlyForGuessing(t *testing.T) {
	one := sqlFindings(sqlBurstRule, burstEvents("log1", 6, 0, "user01", "203.0.113.5", reasonNoLogin))
	if len(one) != 1 || one[0].Confidence != model.ConfidenceMedium {
		t.Fatalf("one missing login name repeated must stay medium: %+v", one)
	}
	var two []model.Event
	for i := 0; i < 6; i++ {
		two = append(two, undatedFail(fmt.Sprintf("t%d", i), "log1", 10+i, localAt(i, 0), []string{"user01", "user02"}[i%2], "203.0.113.5", reasonBadPass))
	}
	got := sqlFindings(sqlBurstRule, two)
	if len(got) != 1 || got[0].Confidence != model.ConfidenceHigh || got[0].Severity != model.SeverityMedium {
		t.Fatalf("2 distinct logins: want medium severity, high confidence: %+v", got)
	}
	if !strings.Contains(got[0].Description, "2 distinct login") {
		t.Errorf("description lacks the distinct login count: %s", got[0].Description)
	}
	var names []model.Event
	for i := 0; i < 6; i++ {
		names = append(names, undatedFail(fmt.Sprintf("n%d", i), "log1", 10+i, localAt(i, 0), fmt.Sprintf("name%02d", i%3), "203.0.113.5", reasonNoLogin))
	}
	got = sqlFindings(sqlBurstRule, names)
	if len(got) != 1 || got[0].Confidence != model.ConfidenceHigh {
		t.Fatalf("3 distinct missing names: want high confidence: %+v", got)
	}
	if !strings.Contains(got[0].Description, reasonNoLogin[:len(reasonNoLogin)-1]+" (6)") {
		t.Errorf("reason breakdown missing: %s", got[0].Description)
	}
}

func TestSQLLoginBurst_ListsAtMostTenNamesAndCapsCitations(t *testing.T) {
	var ev []model.Event
	for i := 0; i < 30; i++ {
		ev = append(ev, undatedFail(fmt.Sprintf("n%02d", i), "log1", 10+i, localAt(i, 0), fmt.Sprintf("name%02d", i%12), "203.0.113.5", reasonNoLogin))
	}
	got := sqlFindings(sqlBurstRule, ev)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	d := got[0].Description
	if !strings.Contains(d, "30 failed") || !strings.Contains(d, "12 distinct login") {
		t.Errorf("true counts missing: %s", d)
	}
	listed := 0
	for i := 0; i < 12; i++ {
		if strings.Contains(d, fmt.Sprintf("name%02d", i)) {
			listed++
		}
	}
	if listed != 10 {
		t.Errorf("want exactly 10 names listed, got %d: %s", listed, d)
	}
	if len(got[0].SupportingEvents) != supportingCap {
		t.Errorf("want %d cited events, got %d", supportingCap, len(got[0].SupportingEvents))
	}
}

func TestSQLLoginBurst_SuccessFromSameClientRaisesSeverity(t *testing.T) {
	ev := burstEvents("log1", 6, 0, "user01", "203.0.113.5", reasonBadPass)
	ev = append(ev, undatedSuccess("s1", "log1", 40, localAt(20*60, 0), "user01", "203.0.113.5"))
	got := sqlFindings(sqlBurstRule, ev)
	if len(got) != 1 || got[0].Severity != model.SeverityHigh {
		t.Fatalf("want 1 high finding: %+v", got)
	}
	if !strings.Contains(got[0].Description, "a successful login from the same client follows") {
		t.Errorf("description lacks the success statement: %s", got[0].Description)
	}
	found := false
	for _, id := range got[0].SupportingEvents {
		found = found || id == "s1"
	}
	if !found {
		t.Errorf("the success event is not cited: %v", got[0].SupportingEvents)
	}
	noZeroTime(t, got[0])

	cases := map[string]model.Event{
		"too late (45 minutes)":      undatedSuccess("s2", "log1", 40, localAt(45*60, 0), "user01", "203.0.113.5"),
		"other client":               undatedSuccess("s3", "log1", 40, localAt(20*60, 0), "user01", "203.0.113.99"),
		"login not among the failed": undatedSuccess("s4", "log1", 40, localAt(20*60, 0), "user77", "203.0.113.5"),
		"other source file":          undatedSuccess("s5", "log2", 40, localAt(20*60, 0), "user01", "203.0.113.5"),
		"before the burst":           undatedSuccess("s6", "log1", 5, localAt(-60, 0), "user01", "203.0.113.5"),
	}
	for name, s := range cases {
		g := sqlFindings(sqlBurstRule, append(burstEvents("log1", 6, 0, "user01", "203.0.113.5", reasonBadPass), s))
		if len(g) != 1 || g[0].Severity != model.SeverityMedium || strings.Contains(g[0].Description, "follows") {
			t.Errorf("%s: must not count as a following success: %+v", name, g)
		}
	}
}

func TestSQLLoginBurst_UndatedOrderComesFromTheLocalReading(t *testing.T) {
	// No line numbers, input reversed: only timestamp_local can order these.
	// The run crosses local midnight.
	stamps := []string{"2026-10-22 23:59:58.00", "2026-10-22 23:59:59.40", "2026-10-23 00:00:01.00", "2026-10-23 00:00:02.00", "2026-10-23 00:00:03.50"}
	var ev []model.Event
	for i := len(stamps) - 1; i >= 0; i-- {
		e := undatedFail(fmt.Sprintf("m%d", i), "log1", 0, stamps[i], "user01", "203.0.113.5", reasonBadPass)
		e.SourceReference = ""
		ev = append(ev, e)
	}
	got := sqlFindings(sqlBurstRule, ev)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if !strings.Contains(got[0].Description, "2026-10-22 23:59:58.00") || !strings.Contains(got[0].Description, "2026-10-23 00:00:03.50") {
		t.Errorf("window should run first to last local reading: %s", got[0].Description)
	}
	if got[0].SupportingEvents[0] != "m0" {
		t.Errorf("citations must start with the earliest reading, got %v", got[0].SupportingEvents)
	}
}

func TestSQLLoginBurst_TwoSourceFilesNeverMerge(t *testing.T) {
	a := burstEvents("logA", 3, 0, "user01", "203.0.113.5", reasonBadPass)
	b := burstEvents("logB", 3, 0, "user01", "203.0.113.5", reasonBadPass)
	if got := sqlFindings(sqlBurstRule, append(a, b...)); len(got) != 0 {
		t.Fatalf("3+3 failures in two files merged into %d findings", len(got))
	}
	a = burstEvents("logA", 5, 0, "user01", "203.0.113.5", reasonBadPass)
	b = burstEvents("logB", 6, 0, "user01", "203.0.113.5", reasonBadPass)
	got := sqlFindings(sqlBurstRule, append(a, b...))
	if len(got) != 2 {
		t.Fatalf("want one finding per file, got %d", len(got))
	}
	for _, f := range got {
		prefix := f.SupportingEvents[0][:4]
		for _, id := range f.SupportingEvents {
			if !strings.HasPrefix(id, prefix) {
				t.Errorf("finding mixes files: %v", f.SupportingEvents)
			}
		}
	}
}

func TestSQLLoginBurst_DatedApplicationLogEvents(t *testing.T) {
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	var ev []model.Event
	for i := 0; i < 5; i++ {
		ev = append(ev, datedFail(fmt.Sprintf("d%d", i), base.Add(time.Duration(i*90)*time.Second), "user01", "203.0.113.5", reasonBadPass))
	}
	got := sqlFindings(sqlBurstRule, ev)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if !got[0].FirstSeen.Equal(base) || !got[0].LastSeen.Equal(base.Add(360*time.Second)) {
		t.Errorf("window = %v..%v", got[0].FirstSeen, got[0].LastSeen)
	}
	if !strings.Contains(got[0].Description, "2026-03-01T09:00:00Z") {
		t.Errorf("dated window missing: %s", got[0].Description)
	}
	// A dated success within 30 minutes for the same client and login.
	ev = append(ev, datedSuccess("ds", base.Add(20*time.Minute), "user01", "203.0.113.5"))
	got = sqlFindings(sqlBurstRule, ev)
	if len(got) != 1 || got[0].Severity != model.SeverityHigh || !strings.Contains(got[0].Description, "a successful login from the same client follows") {
		t.Errorf("dated success not recognised: %+v", got)
	}
	// Dated and undated events never combine: 3 + 3 is not a burst.
	mixed := append(ev[:3:3], burstEvents("log1", 3, 0, "user01", "203.0.113.5", reasonBadPass)...)
	if got := sqlFindings(sqlBurstRule, mixed); len(got) != 0 {
		t.Errorf("dated and undated events were combined: %d", len(got))
	}
}

func TestSQLLoginBurst_OutputIsOrderIndependent(t *testing.T) {
	var ev []model.Event
	ev = append(ev, burstEvents("logA", 6, 0, "user01", "203.0.113.5", reasonBadPass)...)
	ev = append(ev, burstEvents("logB", 5, 0, "user02", "203.0.113.6", reasonNoLogin)...)
	ev = append(ev, burstEvents("logB", 5, 1000, "user03", "203.0.113.7", reasonNoLogin)...)
	ev = append(ev, undatedSuccess("s1", "logA", 99, localAt(600, 0), "user01", "203.0.113.5"))
	if n := len(sqlFindings(sqlBurstRule, ev)); n != 3 {
		t.Fatalf("fixture should give 3 findings, got %d", n)
	}
	sameFindings(t, sqlBurstRule, ev)
}

func TestSQLLoginBurst_TiedReadingsKeepADeterministicOrder(t *testing.T) {
	var ev []model.Event
	for i := 0; i < 6; i++ {
		e := undatedFail(fmt.Sprintf("t%d", i), "log1", 0, localAt(5, 0), "user01", "203.0.113.5", reasonBadPass)
		e.SourceReference = ""
		ev = append(ev, e)
	}
	sameFindings(t, sqlBurstRule, ev)
}

func TestSQLLoginBurst_NamesAreRedacted(t *testing.T) {
	ev := burstEvents("log1", 5, 0, "net user bob Hunter2secret /add", "203.0.113.5", reasonNoLogin)
	got := sqlFindings(sqlBurstRule, ev)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if strings.Contains(got[0].Title+got[0].Description, "Hunter2secret") {
		t.Errorf("secret reached the finding: %s", got[0].Description)
	}
}

// ---------- sql-risky-config-enabled ----------

func TestSQLRiskyConfig_RealErrorlogLines(t *testing.T) {
	body := errorlogLine(localAt(10, 51), "spid55", configMsg("show advanced options", 0, 1)) +
		errorlogLine(localAt(12, 3), "spid55", configMsg("xp_cmdshell", 0, 1)) +
		errorlogLine(localAt(13, 3), "spid55", configMsg("Agent XPs", 0, 1))
	ev := load(t, mssql.New(), "log1", "ERRORLOG", body)
	got := sqlFindings(sqlConfigRule, ev)
	if len(got) != 1 {
		t.Fatalf("want 1 finding (xp_cmdshell only), got %d", len(got))
	}
	f := got[0]
	if f.Severity != model.SeverityMedium || f.Confidence != model.ConfidenceHigh {
		t.Errorf("severity/confidence = %s/%s", f.Severity, f.Confidence)
	}
	for _, want := range []string{"xp_cmdshell", "changed from 0 to 1", "does not show who made the change", "whether the feature was used afterwards", localBasis, "2026-10-22 00:00:12.03"} {
		if !strings.Contains(f.Description, want) {
			t.Errorf("description lacks %q:\n%s", want, f.Description)
		}
	}
	noZeroTime(t, f)
	if len(f.SupportingEvents) != 1 {
		t.Errorf("want exactly the change event cited, got %v", f.SupportingEvents)
	}
}

func TestSQLRiskyConfig_OptionsAndSeverities(t *testing.T) {
	medium := []string{"xp_cmdshell", "Ole Automation Procedures", "external scripts enabled", "Ad Hoc Distributed Queries"}
	low := []string{"clr enabled", "Database Mail XPs", "cross db ownership chaining", "remote admin connections", "scan for startup procs"}
	check := func(opt, sev string) {
		got := sqlFindings(sqlConfigRule, []model.Event{undatedMsg("e1", "log1", 3, localAt(1, 0), configMsg(opt, 0, 1))})
		if len(got) != 1 || got[0].Severity != sev || got[0].Confidence != model.ConfidenceHigh {
			t.Errorf("%s: want %s/high, got %+v", opt, sev, got)
		}
	}
	for _, o := range medium {
		check(o, model.SeverityMedium)
	}
	for _, o := range low {
		check(o, model.SeverityLow)
	}
	check("XP_CMDSHELL", model.SeverityMedium) // option names are case-insensitive
}

func TestSQLRiskyConfig_RoutineHardeningAndUnlistedOptionsAreNotFindings(t *testing.T) {
	for name, msg := range map[string]string{
		"show advanced options": configMsg("show advanced options", 0, 1),
		"Agent XPs":             configMsg("Agent XPs", 0, 1),
		"hardening 1 to 0":      configMsg("xp_cmdshell", 1, 0),
		"unchanged value":       configMsg("xp_cmdshell", 1, 1),
		"unlisted option":       configMsg("max server memory (MB)", 0, 2048),
		"strict security on":    configMsg("clr strict security", 0, 1),
		"unrelated text":        "Configuration option parsing completed.",
	} {
		if got := sqlFindings(sqlConfigRule, []model.Event{undatedMsg("e1", "log1", 3, localAt(1, 0), msg)}); len(got) != 0 {
			t.Errorf("%s: unexpected finding: %s", name, got[0].Description)
		}
	}
}

func TestSQLRiskyConfig_DisablingClrStrictSecurityIsTheRisk(t *testing.T) {
	got := sqlFindings(sqlConfigRule, []model.Event{undatedMsg("e1", "log1", 3, localAt(1, 0), configMsg("clr strict security", 1, 0))})
	if len(got) != 1 || got[0].Severity != model.SeverityLow {
		t.Fatalf("want 1 low finding: %+v", got)
	}
	if !strings.Contains(got[0].Description, "changed from 1 to 0") || !strings.Contains(got[0].Description, "disabled") {
		t.Errorf("description should say strict security was turned off: %s", got[0].Description)
	}
}

func TestSQLRiskyConfig_DatedApplicationEvent(t *testing.T) {
	ts := time.Date(2026, 3, 1, 9, 30, 0, 0, time.UTC)
	got := sqlFindings(sqlConfigRule, []model.Event{datedMsg("a1", ts, configMsg("Ole Automation Procedures", 0, 1))})
	if len(got) != 1 || !got[0].FirstSeen.Equal(ts) || !strings.Contains(got[0].Description, "2026-03-01T09:30:00Z") {
		t.Fatalf("dated application event not reported with its time: %+v", got)
	}
}

func TestSQLRiskyConfig_FilesStaySeparateAndOrderIsStable(t *testing.T) {
	ev := []model.Event{
		undatedMsg("a1", "logA", 3, localAt(1, 0), configMsg("xp_cmdshell", 0, 1)),
		undatedMsg("b1", "logB", 3, localAt(1, 0), configMsg("xp_cmdshell", 0, 1)),
		undatedMsg("a2", "logA", 9, localAt(5, 0), configMsg("clr enabled", 0, 1)),
		datedMsg("d1", time.Date(2026, 3, 1, 9, 30, 0, 0, time.UTC), configMsg("Database Mail XPs", 0, 1)),
	}
	if got := sqlFindings(sqlConfigRule, ev); len(got) != 4 {
		t.Fatalf("want 4 findings, got %d", len(got))
	}
	sameFindings(t, sqlConfigRule, ev)
}

// ---------- sql-disabled-component-attempt ----------

func TestSQLDisabledComponent_RealErrorlogLine(t *testing.T) {
	body := errorlogLine(localAt(20, 51), "spid55", blockedMsg("sys.xp_cmdshell", "xp_cmdshell")) +
		errorlogLine(localAt(25, 7), "spid55", blockedMsg("sys.xp_cmdshell", "xp_cmdshell")) +
		errorlogLine(localAt(26, 7), "spid55", blockedMsg("sys.sp_OACreate", "Ole Automation Procedures"))
	ev := load(t, mssql.New(), "log1", "ERRORLOG", body)
	got := sqlFindings(sqlBlockRule, ev)
	if len(got) != 2 {
		t.Fatalf("want one finding per procedure, got %d", len(got))
	}
	var cmd model.Finding
	for _, f := range got {
		if strings.Contains(f.Description, "sys.xp_cmdshell") {
			cmd = f
		}
	}
	if cmd.RuleID == "" {
		t.Fatalf("no finding for sys.xp_cmdshell")
	}
	if cmd.Severity != model.SeverityLow || cmd.Confidence != model.ConfidenceMedium {
		t.Errorf("severity/confidence = %s/%s", cmd.Severity, cmd.Confidence)
	}
	for _, want := range []string{"2 time", "was blocked", "says nothing about who", "did not run on this instance at that time", localBasis, "2026-10-22 00:00:20.51", "2026-10-22 00:00:25.07"} {
		if !strings.Contains(cmd.Description, want) {
			t.Errorf("description lacks %q:\n%s", want, cmd.Description)
		}
	}
	noZeroTime(t, cmd)
	if len(cmd.SupportingEvents) != 2 {
		t.Errorf("want the two blocked records cited, got %v", cmd.SupportingEvents)
	}
}

func TestSQLDisabledComponent_GroupsByFileAndProcedure(t *testing.T) {
	ev := []model.Event{
		undatedMsg("a1", "logA", 3, localAt(1, 0), blockedMsg("sys.xp_cmdshell", "xp_cmdshell")),
		undatedMsg("b1", "logB", 3, localAt(1, 0), blockedMsg("sys.xp_cmdshell", "xp_cmdshell")),
		undatedMsg("a2", "logA", 4, localAt(2, 0), blockedMsg("sys.xp_cmdshell", "xp_cmdshell")),
		datedMsg("d1", time.Date(2026, 3, 1, 9, 30, 0, 0, time.UTC), blockedMsg("sys.xp_cmdshell", "xp_cmdshell")),
		datedMsg("d2", time.Date(2026, 3, 1, 9, 31, 0, 0, time.UTC), blockedMsg("sys.xp_cmdshell", "xp_cmdshell")),
	}
	got := sqlFindings(sqlBlockRule, ev)
	if len(got) != 3 {
		t.Fatalf("want 3 findings (logA, logB, dated), got %d", len(got))
	}
	sameFindings(t, sqlBlockRule, ev)
	var dated *model.Finding
	for i := range got {
		if !got[i].FirstSeen.IsZero() {
			dated = &got[i]
		}
	}
	if dated == nil || len(dated.SupportingEvents) != 2 || !strings.Contains(dated.Description, "2026-03-01T09:30:00Z") {
		t.Errorf("dated group wrong: %+v", dated)
	}
}

func TestSQLDisabledComponent_IgnoresOtherMessages(t *testing.T) {
	ev := []model.Event{undatedMsg("a1", "logA", 3, localAt(1, 0), "SQL Server blocked access to a file.")}
	if got := sqlFindings(sqlBlockRule, ev); len(got) != 0 {
		t.Errorf("unexpected finding: %d", len(got))
	}
}

// ---------- sql-audit-stopped-while-running ----------

func TestSQLAuditStopped_RealErrorlogLines(t *testing.T) {
	body := errorlogLine(localAt(30, 1), "Server", auditStopLine) +
		errorlogLine(localAt(30, 2), "Server", "Audit: Server Audit: 65536 Session is being closed. Audit Guid: 00000000-0000-0000-0000-000000000000") +
		errorlogLine(localAt(40, 9), "spid55", laterEngineMsg)
	ev := load(t, mssql.New(), "log1", "ERRORLOG", body)
	got := sqlFindings(sqlAuditRule, ev)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.Severity != model.SeverityLow || f.Confidence != model.ConfidenceLow {
		t.Errorf("severity/confidence = %s/%s", f.Severity, f.Confidence)
	}
	for _, want := range []string{"normal instance shutdown also stops audits", "continues afterwards", localBasis, "2026-10-22 00:00:30.01", "1 later", "does not show who"} {
		if !strings.Contains(f.Description, want) {
			t.Errorf("description lacks %q:\n%s", want, f.Description)
		}
	}
	noZeroTime(t, f)
}

func TestSQLAuditStopped_DoesNotFireWhenTheLogEndsOrOnlyShutsDown(t *testing.T) {
	stop := undatedMsg("s1", "log1", 5, localAt(30, 0), auditStopLine)
	closed := undatedMsg("s2", "log1", 6, localAt(30, 1), "Audit: Server Audit: 65536 Session is being closed. Audit Guid: 00000000-0000-0000-0000-000000000000")
	audStarted := undatedMsg("s3", "log1", 7, localAt(31, 0), "SQL Server Audit has started the audits. This is an informational message. No user action is required.")
	term := undatedMsg("s4", "log1", 8, localAt(32, 0), "SQL Server is terminating in response to a 'stop' request from Service Control Manager. This is an informational message only. No user action is required.")
	for name, ev := range map[string][]model.Event{
		"nothing follows":         {stop},
		"only audit lines follow": {stop, closed, audStarted},
		"only termination":        {stop, closed, term},
		"record is earlier":       {undatedMsg("p1", "log1", 2, localAt(10, 0), laterEngineMsg), stop},
		"record in another file":  {stop, undatedMsg("o1", "log2", 9, localAt(40, 0), laterEngineMsg)},
		"started to started":      {undatedMsg("x1", "log1", 5, localAt(30, 0), "Audit: Server Audit: 65536, State changed from: STOPPED to: STARTED"), undatedMsg("x2", "log1", 6, localAt(40, 0), laterEngineMsg)},
	} {
		if got := sqlFindings(sqlAuditRule, ev); len(got) != 0 {
			t.Errorf("%s: unexpected finding: %s", name, got[0].Description)
		}
	}
}

func TestSQLAuditStopped_StoppedVariantAndLocalOrdering(t *testing.T) {
	// No line numbers, shuffled: ordering has to come from timestamp_local.
	stop := undatedMsg("s1", "log1", 0, localAt(30, 0), "Audit: Server Audit: 65536, State changed from: STARTED to: STOPPED")
	stop.SourceReference = ""
	later := undatedMsg("l1", "log1", 0, localAt(90, 0), laterEngineMsg)
	later.SourceReference = ""
	earlier := undatedMsg("e1", "log1", 0, localAt(10, 0), laterEngineMsg)
	earlier.SourceReference = ""
	ev := []model.Event{later, stop, earlier}
	got := sqlFindings(sqlAuditRule, ev)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	ids := strings.Join(got[0].SupportingEvents, ",")
	if !strings.Contains(ids, "s1") || !strings.Contains(ids, "l1") || strings.Contains(ids, "e1") {
		t.Errorf("citations should be the stop and the later record only: %s", ids)
	}
	sameFindings(t, sqlAuditRule, ev)
	// Same stop, but the only other record is from before it.
	if got := sqlFindings(sqlAuditRule, []model.Event{stop, earlier}); len(got) != 0 {
		t.Errorf("an earlier record must not count: %d", len(got))
	}
}

func TestSQLAuditStopped_DatedApplicationEvents(t *testing.T) {
	t0 := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	stop := datedMsg("s1", t0, auditStopLine)
	later := datedMsg("l1", t0.Add(time.Minute), laterEngineMsg)
	got := sqlFindings(sqlAuditRule, []model.Event{later, stop})
	if len(got) != 1 || !got[0].FirstSeen.Equal(t0) || !got[0].LastSeen.Equal(t0.Add(time.Minute)) {
		t.Fatalf("dated stop not reported: %+v", got)
	}
	if !strings.Contains(got[0].Description, "2026-03-01T09:00:00Z") {
		t.Errorf("dated time missing: %s", got[0].Description)
	}
	// Equal timestamps carry no order.
	tie := datedMsg("l2", t0, laterEngineMsg)
	if got := sqlFindings(sqlAuditRule, []model.Event{stop, tie}); len(got) != 0 {
		t.Errorf("a tie must not count as later: %d", len(got))
	}
}

// ---------- shared ----------

// Every SQL rule must give the same findings from the full event set and from
// only the types it declares.
func TestSQLRules_InputsAreASupersetOfWhatTheyRead(t *testing.T) {
	var ev []model.Event
	ev = append(ev, burstEvents("logA", 6, 0, "user01", "203.0.113.5", reasonBadPass)...)
	ev = append(ev, undatedSuccess("s1", "logA", 99, localAt(600, 0), "user01", "203.0.113.5"))
	ev = append(ev,
		undatedMsg("m1", "logA", 100, localAt(700, 0), configMsg("xp_cmdshell", 0, 1)),
		undatedMsg("m2", "logA", 101, localAt(701, 0), blockedMsg("sys.xp_cmdshell", "xp_cmdshell")),
		undatedMsg("m3", "logA", 102, localAt(702, 0), auditStopLine),
		undatedMsg("m4", "logA", 103, localAt(703, 0), laterEngineMsg),
		datedMsg("m5", time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC), configMsg("clr enabled", 0, 1)),
		model.Event{ID: "x1", CaseID: "case1", EventType: model.EventSQLAgentMessage, SourceFileID: "logA", Extra: map[string]string{"message": laterEngineMsg}},
		model.Event{ID: "x2", CaseID: "case1", EventType: model.EventMSSQLAudit, SourceFileID: "logA"},
		model.Event{ID: "x3", CaseID: "case1", EventType: "unrelated_event"},
	)
	src := model.SliceSource(ev)
	for _, id := range []string{sqlBurstRule, sqlConfigRule, sqlBlockRule, sqlAuditRule} {
		for _, r := range All() {
			if r.ID() != id {
				continue
			}
			in, ok := r.(interface{ Inputs() model.EventFilter })
			if !ok {
				t.Fatalf("%s declares no Inputs", id)
			}
			full, _ := src.Load(model.EventFilter{All: true})
			typed, _ := src.Load(in.Inputs())
			if len(r.Evaluate(full)) == 0 {
				t.Errorf("%s: fixture does not trigger the rule", id)
			}
			if mustJSON(t, withoutCreatedAt(r.Evaluate(full))) != mustJSON(t, withoutCreatedAt(r.Evaluate(typed))) {
				t.Errorf("%s: declared inputs change the findings", id)
			}
		}
	}
}
