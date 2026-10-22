package correlate

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
	"tracefall/internal/model"
)

func sqlFixture() []model.Event {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	base := func(id, host, typ, artifact string, offset time.Duration) model.Event {
		return model.Event{ID: id, CaseID: "case01", CollectionID: "collection01", Host: host, EventType: typ, ArtifactType: artifact, Timestamp: at.Add(offset), SourceFileID: id + "-source", SourceReference: "record:1", Extra: map[string]string{}}
	}
	sql := base("sql", "server01", "mssql_xe_event", "mssql_extended_events", 0)
	sql.Extra = map[string]string{"sql_instance": "instance01", "sql_client_connection_id": "11111111-2222-3333-4444-55555555555a", "sql_client_pid": "999", "sql_client_hostname": "untrusted"}
	diag := base("diag", "client01", "mssql_client_diagnostic", "windows_sql_client_diagnostic", time.Second)
	diag.PID = 42
	diag.Extra = map[string]string{"sql_instance": "instance01", "sql_server_host": "server01", "sql_client_connection_id": sql.Extra["sql_client_connection_id"], "process_guid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
	proc := base("client-process", "client01", model.EventProcessCreate, model.ArtifactWindowsEventLog, -time.Minute)
	proc.PID = 42
	proc.ProcessName = "client.exe"
	proc.Extra = map[string]string{"process_guid": diag.Extra["process_guid"], "exit_time": at.Add(time.Hour).Format(time.RFC3339Nano)}
	return []model.Event{sql, diag, proc}
}

func sqlCorrelations(es []model.Event) []model.Correlation {
	var out []model.Correlation
	for _, c := range Run("case01", es) {
		if c.Type == "sql_client_connection" || c.Type == "sql_os_execution" {
			out = append(out, c)
		}
	}
	return out
}

func TestSQLClientConnectionLifetimeContradictions(t *testing.T) {
	for _, kind := range []string{"creation tie", "same GUID different PID", "overlap at SQL time"} {
		t.Run(kind, func(t *testing.T) {
			es := sqlFixture()
			q := es[2]
			q.ID = "competing-process"
			q.Extra = map[string]string{"process_guid": es[2].Extra["process_guid"], "exit_time": es[2].Extra["exit_time"]}
			switch kind {
			case "creation tie":
				q.Timestamp = es[1].Timestamp
			case "same GUID different PID":
				q.PID = 43
			case "overlap at SQL time":
				q.Extra["exit_time"] = es[0].Timestamp.Add(500 * time.Millisecond).Format(time.RFC3339Nano)
			}
			if cs := sqlCorrelations(append(es, q)); len(cs) != 0 {
				t.Fatalf("contradictory lifetime must abstain: %+v", cs)
			}
		})
	}
}

func TestSQLClientConnectionAmbiguity(t *testing.T) {
	for _, kind := range []string{"second process", "reused PID", "second client", "conflicting duplicate ID"} {
		t.Run(kind, func(t *testing.T) {
			es := sqlFixture()
			p := es[2]
			p.ID = "other-process"
			p.Extra = map[string]string{"process_guid": es[2].Extra["process_guid"], "exit_time": es[2].Extra["exit_time"]}
			switch kind {
			case "reused PID":
				p.Extra["process_guid"] = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
				p.Timestamp = es[0].Timestamp.Add(-time.Second)
			case "second client":
				p = es[1]
				p.ID = "other-diagnostic"
				p.Host = "other-client"
			case "conflicting duplicate ID":
				p.ID = es[2].ID
				p.PID = 99
			}
			es = append(es, p)
			if cs := sqlCorrelations(es); len(cs) != 0 {
				t.Fatalf("ambiguous identity must abstain: %+v", cs)
			}
		})
	}
}

func TestSQLClientConnectionDuplicateDeterminism(t *testing.T) {
	es := sqlFixture()
	want := sqlCorrelations(es)
	es = append(es, es...)
	for i, j := 0, len(es)-1; i < j; i, j = i+1, j-1 {
		es[i], es[j] = es[j], es[i]
	}
	got := sqlCorrelations(es)
	if len(got) != 1 || len(want) != 1 || got[0].ID != want[0].ID {
		t.Fatalf("duplicate/reversed input changed correlations: %+v / %+v", got, want)
	}
}

func sqlOSFixture() []model.Event {
	es := sqlFixture()
	s := es[0]
	p := es[2]
	c := es[1]
	delete(s.Extra, "sql_client_connection_id")
	s.Extra["sql_server_pid"] = "100"
	s.Extra["sql_statement"] = "EXEC xp_cmdshell N'whoami';"
	s.Extra["sql_outcome"] = "permission_allowed"
	s.Extra["sql_outcome_basis"] = "permission_check"
	p.ID = "server-process"
	p.Host = s.Host
	p.PID = 100
	p.ProcessName = "sqlservr.exe"
	p.Extra["sql_instance"] = "instance01"
	c.ID = "child-process"
	c.Host = s.Host
	c.EventType = model.EventProcessCreate
	c.ArtifactType = model.ArtifactWindowsEventLog
	c.PID = 200
	c.PPID = 100
	c.ProcessName = "cmd.exe"
	c.ParentProcessName = "sqlservr.exe"
	c.CommandLine = "cmd.exe /c whoami"
	c.Extra = map[string]string{"parent_process_guid": p.Extra["process_guid"], "process_guid": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"}
	return []model.Event{s, p, c}
}

func TestSQLOSExecutionGUIDParent(t *testing.T) {
	es := sqlOSFixture()
	es[2].PPID = 0
	if cs := sqlCorrelations(es); len(cs) != 1 {
		t.Fatalf("recorded parent GUID should identify bounded parent: %+v", cs)
	}
	es[2].PPID = 999
	if cs := sqlCorrelations(es); len(cs) != 0 {
		t.Fatalf("contradictory PPID must override GUID: %+v", cs)
	}
}

func TestSQLOSExecutionStrongIdentity(t *testing.T) {
	cs := sqlCorrelations(sqlOSFixture())
	if len(cs) != 1 || cs[0].Type != "sql_os_execution" || len(cs[0].EventIDs) != 3 {
		t.Fatalf("want SQL + server lifetime + real child evidence: %+v", cs)
	}
}

func TestSQLClientConnectionStrongIdentity(t *testing.T) {
	cs := sqlCorrelations(sqlFixture())
	if len(cs) != 1 {
		t.Fatalf("want one evidence-linked SQL client correlation, got %v", cs)
	}
	if cs[0].Type != "sql_client_connection" || len(cs[0].EventIDs) != 3 {
		t.Fatalf("missing connection/process citations: %+v", cs[0])
	}
}
func TestSQLClientConnectionIdentityGates(t *testing.T) {
	tests := []struct {
		name   string
		change func([]model.Event)
	}{
		{"opposite client host", func(e []model.Event) { e[2].Host = "other" }},
		{"opposite server host", func(e []model.Event) { e[0].Host = "other" }},
		{"collection", func(e []model.Event) { e[1].CollectionID = "other" }},
		{"case", func(e []model.Event) { e[1].CaseID = "other" }},
		{"missing scope", func(e []model.Event) { e[0].CollectionID = "" }},
		{"instance", func(e []model.Event) { e[1].Extra["sql_instance"] = "other" }},
		{"missing instance", func(e []model.Event) { delete(e[0].Extra, "sql_instance") }},
		{"wrong diagnostic schema", func(e []model.Event) { e[1].ArtifactType = model.ArtifactWindowsEventLog }},
		{"wrong SQL schema", func(e []model.Event) { e[0].ArtifactType = "mssql_errorlog" }},
		{"definition GUID not connection", func(e []model.Event) {
			delete(e[0].Extra, "sql_client_connection_id")
			e[0].Extra["event_uuid"] = e[1].Extra["sql_client_connection_id"]
		}},
		{"zero GUID", func(e []model.Event) {
			for _, i := range []int{0, 1} {
				e[i].Extra["sql_client_connection_id"] = "00000000-0000-0000-0000-000000000000"
			}
		}},
		{"malformed GUID", func(e []model.Event) {
			for _, i := range []int{0, 1} {
				e[i].Extra["sql_client_connection_id"] = "not-a-guid"
			}
		}},
		{"missing process GUID", func(e []model.Event) { delete(e[1].Extra, "process_guid"); delete(e[2].Extra, "process_guid") }},
		{"unknown time", func(e []model.Event) { e[0].Timestamp = time.Time{} }},
		{"no lifetime end", func(e []model.Event) { delete(e[2].Extra, "exit_time") }},
		{"outside lifetime", func(e []model.Event) { e[2].Extra["exit_time"] = e[0].Timestamp.Format(time.RFC3339Nano) }},
		{"memory", func(e []model.Event) { e[2].ArtifactType = model.ArtifactMemoryAnalysis }},
		{"same source is not independent", func(e []model.Event) { e[1].SourceFileID = e[0].SourceFileID }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			es := sqlFixture()
			tt.change(es)
			if cs := sqlCorrelations(es); len(cs) != 0 {
				t.Fatalf("identity contradiction must abstain: %+v", cs)
			}
		})
	}
}
func TestSQLOSExecutionGates(t *testing.T) {
	tests := []struct {
		name   string
		change func([]model.Event) []model.Event
	}{
		{"permission allowed without Windows", func(e []model.Event) []model.Event { return e[:1] }},
		{"no server PID client PID is not server", func(e []model.Event) []model.Event {
			delete(e[0].Extra, "sql_server_pid")
			e[0].Extra["sql_client_pid"] = "100"
			return e
		}},
		{"wrong server PID", func(e []model.Event) []model.Event { e[0].Extra["sql_server_pid"] = "999"; return e }},
		{"denied", func(e []model.Event) []model.Event { e[0].Extra["sql_outcome"] = "denied"; return e }},
		{"permission denied", func(e []model.Event) []model.Event { e[0].Extra["sql_outcome"] = "permission_denied"; return e }},
		{"failed", func(e []model.Event) []model.Event { e[0].Extra["sql_outcome"] = "failure"; return e }},
		{"opposite host", func(e []model.Event) []model.Event { e[2].Host = "client01"; return e }},
		{"opposite parent host", func(e []model.Event) []model.Event { e[1].Host = "client01"; return e }},
		{"opposite collection", func(e []model.Event) []model.Event { e[2].CollectionID = "other"; return e }},
		{"opposite case", func(e []model.Event) []model.Event { e[0].CaseID = "other"; return e }},
		{"instance mismatch", func(e []model.Event) []model.Event { e[1].Extra["sql_instance"] = "other"; return e }},
		{"instance missing", func(e []model.Event) []model.Event { delete(e[0].Extra, "sql_instance"); return e }},
		{"parent unknown time", func(e []model.Event) []model.Event { e[1].Timestamp = time.Time{}; return e }},
		{"SQL unknown time", func(e []model.Event) []model.Event { e[0].Timestamp = time.Time{}; return e }},
		{"child unknown time", func(e []model.Event) []model.Event { e[2].Timestamp = time.Time{}; return e }},
		{"SQL after child", func(e []model.Event) []model.Event { e[0].Timestamp = e[2].Timestamp.Add(time.Second); return e }},
		{"SQL timestamp tie", func(e []model.Event) []model.Event { e[0].Timestamp = e[2].Timestamp; return e }},
		{"parent exit missing", func(e []model.Event) []model.Event { delete(e[1].Extra, "exit_time"); return e }},
		{"parent ended", func(e []model.Event) []model.Event {
			e[1].Extra["exit_time"] = e[0].Timestamp.Format(time.RFC3339Nano)
			return e
		}},
		{"GUID contradiction", func(e []model.Event) []model.Event {
			e[2].Extra["parent_process_guid"] = "cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa"
			return e
		}},
		{"name contradiction", func(e []model.Event) []model.Event { e[2].ParentProcessName = "other.exe"; return e }},
		{"memory parent", func(e []model.Event) []model.Event { e[1].ArtifactType = model.ArtifactMemoryAnalysis; return e }},
		{"wrong child schema", func(e []model.Event) []model.Event { e[2].ArtifactType = "mssql_agent_log"; return e }},
		{"mere timewindow arbitrary statement", func(e []model.Event) []model.Event { e[0].Extra["sql_statement"] = "SELECT 1"; return e }},
		{"different command", func(e []model.Event) []model.Event { e[2].CommandLine = "cmd.exe /c hostname"; return e }},
		{"command case difference is content difference", func(e []model.Event) []model.Event { e[2].CommandLine = "cmd.exe /c WHOAMI"; return e }},
		{"statement mention", func(e []model.Event) []model.Event {
			e[0].Extra["sql_statement"] = "SELECT 'EXEC xp_cmdshell N''whoami'';'"
			return e
		}},
		{"reused parent PID", func(e []model.Event) []model.Event {
			p := e[1]
			p.ID = "other-parent"
			p.Timestamp = p.Timestamp.Add(time.Second)
			p.Extra = map[string]string{"sql_instance": "instance01", "exit_time": e[1].Extra["exit_time"], "process_guid": "cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa"}
			return append(e, p)
		}},
		{"ambiguous parent", func(e []model.Event) []model.Event { p := e[1]; p.ID = "other-parent"; return append(e, p) }},
		{"ambiguous request", func(e []model.Event) []model.Event { s := e[0]; s.ID = "other-sql"; return append(e, s) }},
		{"ambiguous child", func(e []model.Event) []model.Event { c := e[2]; c.ID = "other-child"; c.PID = 201; return append(e, c) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if cs := sqlCorrelations(tt.change(sqlOSFixture())); len(cs) != 0 {
				t.Fatalf("must abstain: %+v", cs)
			}
		})
	}
}
func TestSQLDeclaredInputParity(t *testing.T) {
	for _, fixture := range []func() []model.Event{sqlFixture, sqlOSFixture} {
		es := fixture()
		unrelated := es[0]
		unrelated.ID = "unrelated"
		unrelated.EventType = model.EventLogoff
		conflicting := unrelated
		conflicting.Host = "other"
		es = append(es, unrelated, conflicting)
		loaded, err := model.SliceSource(es).Load(model.EventFilter{Types: typedInputTypes, Artifacts: webArtifactNames()})
		if err != nil {
			t.Fatal(err)
		}
		full := buildSQLWindows("case01", es)
		filtered := buildSQLWindows("case01", loaded)
		if len(full) != 1 || !reflect.DeepEqual(full, filtered) {
			t.Fatalf("declared input differs: full=%+v filtered=%+v", full, filtered)
		}
	}
}

func TestSQLSummaryPrivacyAndDeterminism(t *testing.T) {
	es := sqlOSFixture()
	const secret = "SyntheticSecret42"
	es[0].Extra["sql_statement"] = "EXEC xp_cmdshell N'net user alice " + secret + " /add';"
	es[2].CommandLine = "cmd.exe /c net user alice " + secret + " /add"
	rawBefore, _ := json.Marshal(es)
	want := sqlCorrelations(es)
	if len(want) != 1 {
		t.Fatalf("missing command correspondence: %+v", want)
	}
	text, _ := json.Marshal(want)
	if strings.Contains(string(text), secret) || strings.Contains(string(text), "net user") {
		t.Fatal("command credentials leaked in derived summary")
	}
	if !strings.Contains(want[0].Description, "not proof") {
		t.Fatal("missing causal qualification")
	}
	rawAfter, _ := json.Marshal(es)
	if string(rawBefore) != string(rawAfter) {
		t.Fatal("raw event mutated")
	}
	es = append(es, es...)
	for i, j := 0, len(es)-1; i < j; i, j = i+1, j-1 {
		es[i], es[j] = es[j], es[i]
	}
	if got := sqlCorrelations(es); !reflect.DeepEqual(want, got) {
		t.Fatalf("unstable citations or IDs: %+v / %+v", want, got)
	}
}

func TestSQLActivityAloneNeverTransfersIdentity(t *testing.T) {
	es := sqlFixture()
	for _, i := range []int{0, 1} {
		delete(es[i].Extra, "sql_client_connection_id")
		es[i].Extra["sql_activity_id"] = "11111111-2222-3333-4444-55555555555a"
		es[i].Extra["sql_activity_sequence"] = "1"
	}
	if got := sqlCorrelations(es); len(got) != 0 {
		t.Fatalf("activity text without proven transfer must abstain: %+v", got)
	}
}
func TestSQLAuditInputAndPIDOnlyParent(t *testing.T) {
	es := sqlOSFixture()
	es[0].ArtifactType = "mssql_audit"
	es[0].EventType = "mssql_audit_event"
	delete(es[1].Extra, "process_guid")
	delete(es[2].Extra, "parent_process_guid")
	if got := sqlCorrelations(es); len(got) != 1 {
		t.Fatalf("bounded unique PID lineage with Audit request should correlate: %+v", got)
	}
	es[2].PPID = 0
	if got := sqlCorrelations(es); len(got) != 0 {
		t.Fatalf("no recorded parent identity must abstain: %+v", got)
	}
}

func TestSQLMultipleInstancesAndReusedSession(t *testing.T) {
	a, b := sqlOSFixture(), sqlOSFixture()
	for i := range b {
		b[i].ID = "instance02-" + b[i].ID
		b[i].SourceFileID = "instance02-" + b[i].SourceFileID
	}
	b[0].Extra["sql_server_pid"] = "300"
	b[0].Extra["sql_instance"] = "instance02"
	b[1].PID = 300
	b[1].Extra["sql_instance"] = "instance02"
	b[1].Extra["process_guid"] = "cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa"
	b[2].PID = 400
	b[2].PPID = 300
	b[2].Extra["parent_process_guid"] = b[1].Extra["process_guid"]
	for _, e := range [][]model.Event{a, b} {
		e[0].Extra["sql_session_id"] = "51"
		e[0].Extra["sql_client_pid"] = "100"
	}
	es := append(a, b...)
	want := sqlCorrelations(es)
	if len(want) != 2 {
		t.Fatalf("separate server PIDs/instances must not merge reused SQL sessions: %+v", want)
	}
	for _, c := range want {
		if strings.HasPrefix(c.EventIDs[0], "instance02-") != strings.HasPrefix(c.EventIDs[1], "instance02-") || strings.HasPrefix(c.EventIDs[0], "instance02-") != strings.HasPrefix(c.EventIDs[2], "instance02-") {
			t.Fatalf("cross-instance citation: %+v", c)
		}
	}
	for i, j := 0, len(es)-1; i < j; i, j = i+1, j-1 {
		es[i], es[j] = es[j], es[i]
	}
	if got := sqlCorrelations(es); !reflect.DeepEqual(want, got) {
		t.Fatalf("multi-instance citations/order unstable: %+v / %+v", want, got)
	}
}

func TestSQLClientTraceTimesDoNotImplyOrder(t *testing.T) {
	es := sqlFixture()
	es[0].Timestamp = es[1].Timestamp.Add(time.Second)
	es[0].Extra["sql_client_connection_id"] = strings.ToUpper(es[0].Extra["sql_client_connection_id"])
	if got := sqlCorrelations(es); len(got) != 1 || !got[0].LastSeen.Equal(es[0].Timestamp) {
		t.Fatalf("SQL trace after diagnostic is not execution ordering: %+v", got)
	}
}
