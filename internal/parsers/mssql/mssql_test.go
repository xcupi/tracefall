package mssql

import (
	"os"
	"path/filepath"
	"testing"
	"tracefall/internal/parsers"
)

func TestDetectionEncodingAgent(t *testing.T) {
	engine := "2026-01-15 09:15:30.12 Server      Microsoft SQL Server 2022\r\n"
	agent := "2026-01-15 09:15:30 - ? [100] Microsoft SQLServerAgent version 16.0\r\n2026-01-15 09:15:31 - ! [298] SQLServer Error: 18456, Login failed for user 'alice'. [SQLSTATE 28000]\r\n"
	for _, tc := range []struct {
		p          *Parser
		name, text string
		count      int
	}{{New(), `data\ERRORLOG.2`, engine, 1}, {NewAgent(), "SQLAGENT.OUT.1", agent, 2}} {
		if !tc.p.Detect(tc.name) || tc.p.ConfirmContent([]byte("unrelated error text")) || !tc.p.ConfirmContent([]byte(tc.text)) {
			t.Fatal("name/content gate", tc.name)
		}
		for _, wide := range []bool{false, true} {
			b := []byte(tc.text)
			if wide {
				b = []byte{255, 254}
				for _, c := range tc.text {
					b = append(b, byte(c), byte(c>>8))
				}
			}
			if !tc.p.ConfirmContent(b) {
				t.Fatal("UTF16 sniff")
			}
			path := filepath.Join(t.TempDir(), "evidence")
			os.WriteFile(path, b, 0600)
			r, err := tc.p.Parse(path)
			if err != nil || len(r.Events) != tc.count {
				t.Fatalf("%s wide=%v count=%d err=%v", tc.name, wide, len(r.Events), err)
			}
			if tc.p.Agent && (r.Events[0].EventType != "sql_agent_message" || r.Events[1].Extra["agent_message_id"] != "298") {
				t.Fatal(r.Events)
			}
		}
	}
	if New().Detect("ERRORLOG.zip") || NewAgent().Detect("SQLAGENT.OUT.bad") {
		t.Fatal("arbitrary suffix")
	}
}

func TestTiedRecordsAndRecollectionIdentity(t *testing.T) {
	text := "2026-01-15T09:15:30Z Server      SQL Server is ready\n2026-01-15T09:15:30Z Server      SQL Server is ready\n"
	path := filepath.Join(t.TempDir(), "ERRORLOG")
	os.WriteFile(path, []byte(text), 0600)
	a, err := New().ParseWithContext(path, parsers.ParseContext{EvidencePath: "SQL/ERRORLOG"})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Events) != 2 {
		t.Fatal(a)
	}
	if a.Events[0].ComputeDedupHash() == a.Events[1].ComputeDedupHash() {
		t.Fatal("tied distinct records collapsed")
	}
	b, _ := New().ParseWithContext(path, parsers.ParseContext{EvidencePath: "SQL/ERRORLOG"})
	if a.Events[0].ComputeDedupHash() != b.Events[0].ComputeDedupHash() {
		t.Fatal("recollection inflated")
	}
	if a.Events[0].FilePath != "SQL/ERRORLOG" {
		t.Fatal("missing evidence-relative path")
	}
}

func TestRecordedInstanceAndOutcomeHonesty(t *testing.T) {
	text := "2026-01-15 09:15:30.12 Server      Server name is 'host01\\LAB'. This is an informational message only.\n2026-01-15 09:15:30.12 Logon       Login for user 'alice'.\n2026-01-15 09:15:30.12 Logon       Login succeeded for user 'alice'.\n"
	path := filepath.Join(t.TempDir(), "ERRORLOG")
	os.WriteFile(path, []byte(text), 0600)
	r, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Events) != 3 {
		t.Fatal(r)
	}
	for _, e := range r.Events {
		if e.Extra["instance"] != "LAB" || e.Extra["instance_basis"] != "recorded server name" {
			t.Fatal("lost recorded instance", e)
		}
	}
	if r.Events[1].EventType != "sql_message" || r.Events[1].Extra["outcome"] != "" || r.Events[2].EventType != "sql_login_success" {
		t.Fatal("invented outcome", r.Events)
	}
}

func TestContinuationFieldsAndAgentError(t *testing.T) {
	for _, tc := range []struct {
		p    *Parser
		text string
	}{{New(), "2026-01-15 09:15:30.12 Logon       Login failed for user 'alice'.\r\n [CLIENT: 203.0.113.5]\r\n"}, {NewAgent(), "2026-01-15 09:15:30 - ! [298] SQLServer Error: 18456, Login failed for user 'alice'. [SQLSTATE 28000]\r\n [CLIENT: 203.0.113.5]\r\n"}} {
		path := filepath.Join(t.TempDir(), "log")
		os.WriteFile(path, []byte(tc.text), 0600)
		r, err := tc.p.Parse(path)
		if err != nil || len(r.Events) != 1 {
			t.Fatal(r, err)
		}
		e := r.Events[0]
		if e.NetworkSource != "203.0.113.5" {
			t.Fatal("continuation client lost", e.Extra)
		}
		if tc.p.Agent && (e.Extra["error_number"] != "18456" || e.Extra["sqlstate"] != "28000") {
			t.Fatal("Agent error fields lost", e.Extra)
		}
		if r.Raw[0].Raw != tc.text {
			t.Fatal("raw modified")
		}
	}
}

func TestMalformedEncodingAndBound(t *testing.T) {
	for _, b := range [][]byte{{255, 254, 0}, {255}, {255, 254, 0, 216}} {
		path := filepath.Join(t.TempDir(), "ERRORLOG")
		os.WriteFile(path, b, 0600)
		if _, err := New().Parse(path); err == nil {
			t.Fatalf("accepted malformed encoding %x", b)
		}
	}
	path := filepath.Join(t.TempDir(), "ERRORLOG")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(maxBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := New().Parse(path); err == nil {
		t.Fatal("unbounded input accepted")
	}
}

func TestInstanceTextInsideStatementIsNotAttribution(t *testing.T) {
	text := "2026-01-15 09:15:30.12 spid51      Statement contains: Server name is 'host01\\LAB'.\n"
	path := filepath.Join(t.TempDir(), "ERRORLOG")
	os.WriteFile(path, []byte(text), 0600)
	r, err := New().Parse(path)
	if err != nil || len(r.Events) != 1 {
		t.Fatal(r, err)
	}
	if r.Events[0].Extra["instance"] != "" {
		t.Fatal("statement text invented instance attribution", r.Events[0])
	}
}

func TestQuotedLoginTextDoesNotEstablishOutcome(t *testing.T) {
	text := "2026-01-15 09:15:30.12 spid51      Statement: SELECT 'Login succeeded for user ''alice''.'\n"
	path := filepath.Join(t.TempDir(), "ERRORLOG")
	os.WriteFile(path, []byte(text), 0600)
	r, _ := New().Parse(path)
	if len(r.Events) != 1 || r.Events[0].EventType != "sql_message" {
		t.Fatal("quoted text invented outcome", r.Events)
	}
}

func TestErrorLogLocalEvidence(t *testing.T) {
	text := "2026-01-15 09:15:30.12 Logon       Error: 18456, Severity: 14, State: 8.\r\n2026-01-15 09:15:30.12 Logon       Login failed for user 'alice'. [CLIENT: 203.0.113.5]\r\n\tReason: authentication rejected.\r\n"
	p := filepath.Join(t.TempDir(), "ERRORLOG.1")
	if err := os.WriteFile(p, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := New().ParseWithContext(p, parsers.ParseContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Events) != 2 {
		t.Fatalf("events=%d want 2", len(r.Events))
	}
	a, b := r.Events[0], r.Events[1]
	if !a.Timestamp.IsZero() || a.Extra["timestamp_local"] != "2026-01-15 09:15:30.12" {
		t.Fatalf("invented instant: %+v", a)
	}
	if a.Extra["error_number"] != "18456" || a.Extra["severity"] != "14" || a.Extra["state"] != "8" {
		t.Fatal(a.Extra)
	}
	if b.EventType != "sql_login_failed" || b.User != "alice" || b.NetworkSource != "203.0.113.5" || b.Extra["instance"] != "" {
		t.Fatal(b)
	}
	if r.Raw[1].Raw != "2026-01-15 09:15:30.12 Logon       Login failed for user 'alice'. [CLIENT: 203.0.113.5]\r\n\tReason: authentication rejected.\r\n" {
		t.Fatalf("raw altered: %q", r.Raw[1].Raw)
	}
	if a.SourceReference == b.SourceReference {
		t.Fatal("duplicate references")
	}
}
