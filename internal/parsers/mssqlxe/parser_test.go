package mssqlxe

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"tracefall/internal/parsers"
)

func fixture(t *testing.T, name, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestAuditExportPermissionAndRaw(t *testing.T) {
	raw := "event_time,action_id,succeeded,session_id,server_instance_name,client_ip,statement,sequence_number\n2026-01-02 03:04:05.1234567,SL,1,52,host01\\INST,203.0.113.5,SELECT secret,2\n"
	p := NewAudit()
	path := fixture(t, "capture.sqlaudit.csv", raw)
	r, err := p.ParseWithContext(path, parsers.ParseContext{EvidencePath: "capture.sqlaudit.csv"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Events) != 1 {
		t.Fatalf("events=%d want 1", len(r.Events))
	}
	e := r.Events[0]
	if e.Extra["sql_outcome"] != "permission_check_allowed" || e.Extra["sql_outcome_basis"] != "audit succeeded; non-login permission check only" {
		t.Fatalf("outcome: %#v", e.Extra)
	}
	if e.Timestamp.IsZero() || e.Timestamp.UTC().Format("2006-01-02T15:04:05.9999999Z") != "2026-01-02T03:04:05.1234567Z" {
		t.Fatal(e.Timestamp)
	}
	if e.Host != "" || e.PID != 0 || e.Extra["sql_session_id"] != "52" || e.Extra["sql_statement"] != "SELECT secret" {
		t.Fatalf("attribution %#v", e)
	}
	if !strings.Contains(r.Raw[0].Raw, "SELECT secret") || !strings.Contains(e.Extra["sql_fragment_note"], "not reconstructed") {
		t.Fatal(r)
	}
	if r.Coverage == nil || r.Coverage.RecordsRead != 1 {
		t.Fatal("missing coverage")
	}
}

func TestXEExplicitExports(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"capture.xel.xml", `<RingBufferTarget><event name="sql_batch_starting" timestamp="2026-01-02T03:04:05Z"><data name="statement"><value>SELECT secret</value></data><action name="session_id"><value>52</value></action><action name="client_hostname"><value>remote01</value></action></event></RingBufferTarget>`},
		{"capture.xel.jsonl", `{"name":"sql_batch_starting","timestamp":"2026-01-02 03:04:05","fields":{"statement":"SELECT secret"},"actions":{"session_id":52,"client_hostname":"remote01"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := New()
			if !p.Detect(tc.name) {
				t.Fatal("explicit export not detected")
			}
			r, err := p.Parse(fixture(t, tc.name, tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Events) != 1 {
				t.Fatalf("events %d", len(r.Events))
			}
			e := r.Events[0]
			if e.Host != "" || e.PID != 0 || e.Extra["sql_session_id"] != "52" || e.Extra["sql_statement"] != "SELECT secret" {
				t.Fatal(e)
			}
			if strings.HasSuffix(tc.name, "jsonl") && !e.Timestamp.IsZero() {
				t.Fatal("local date invented UTC")
			}
			if r.Raw[0].Raw != tc.raw && !strings.Contains(tc.raw, r.Raw[0].Raw) {
				t.Fatal("raw changed")
			}
		})
	}
}

func TestExportRejectsWrongFormatAndCaps(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"x.sqlaudit.csv", "foo,bar\na,b\n"}, {"x.xel.xml", "<unrelated/>"}, {"x.xel.jsonl", `{"foo":"bar"}`},
		{"x.sqlaudit.csv", "event_time,action_id\n" + strings.Repeat("2026-01-01,SL\n", maxRecords+1)},
		{"x.xel.xml", `<event name="x"><data name="statement"><value>` + strings.Repeat("a", maxLine) + `</value></data></event>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := New()
			if strings.Contains(tc.name, "sqlaudit") {
				p = NewAudit()
			}
			if _, err := p.Parse(fixture(t, tc.name, tc.raw)); err == nil {
				t.Fatal("accepted invalid/capped export")
			}
		})
	}
}
func TestMissingAuditOutcomeStaysUnknown(t *testing.T) {
	r, err := NewAudit().Parse(fixture(t, "x.sqlaudit.csv", "event_time,action_id,statement\n2026-01-02 03:04:05,SL,SELECT 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Events) != 1 || r.Events[0].Extra["sql_outcome"] != "unknown" {
		t.Fatal(r)
	}
}

func TestRealXEL(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_MSSQL_XEL")
	if path == "" {
		t.Skip("TRACEFALL_REAL_MSSQL_XEL not set")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(before)) != "79aad08f9efc149d96f89282a3eea9431aadb63845219e02bb45dfa4e2c11d75" {
		t.Fatal("fixture hash mismatch")
	}
	r, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Events) != 149 {
		t.Fatalf("events=%d want authoritative 149", len(r.Events))
	}
	e := r.Events[0]
	if e.Extra["sql_session_id"] != "182" || e.Extra["sql_client_pid"] != "4956" || e.Extra["sql_activity_id"] != "329b2676-060b-4760-8698-46a43e0b1603" || e.Extra["sql_activity_sequence"] != "1" {
		t.Fatal(e.Extra)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("input mutated")
	}
}
func TestBinaryMissingReaderFailsClosed(t *testing.T) {
	t.Setenv("TRACEFALL_MSSQL_READER", "")
	_, err := New().Parse(fixture(t, "x.xel", "not xel"))
	if err == nil || !strings.Contains(err.Error(), "reader unavailable") {
		t.Fatalf("want unavailable; got %v", err)
	}
}

func TestTiedRecordsAndRecollections(t *testing.T) {
	r, err := NewAudit().Parse(fixture(t, "x.sqlaudit.csv", "event_time,action_id,statement\n2026-01-02 03:04:05,SL,SELECT 1\n2026-01-02 03:04:05,SL,SELECT 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	a, b := r.Events[0], r.Events[1]
	if a.ComputeDedupHash() == b.ComputeDedupHash() {
		t.Fatal("tied rows collapsed")
	}
	originalHash := a.ComputeDedupHash()
	a.CollectionID = "new"
	copyExtra := map[string]string{}
	for k, v := range a.Extra {
		copyExtra[k] = v
	}
	a.Extra = copyExtra
	a.Extra["sql_isolation"] = "different renderer note"
	if a.ComputeDedupHash() != originalHash {
		t.Fatal("recollection split")
	}
}
func TestBinaryProtocolNegativeControls(t *testing.T) {
	header := `{"kind":"header","schema":1,"reader":"XELite/2024.2.5.1","checksum":true,"source_sha256":"hash","source_size":"10"}` + "\n"
	event := `{"kind":"event","ordinal":"1","name":"x","timestamp":"2026-01-02T03:04:05Z","start_offset":"0","end_offset":"10","size":"10"}` + "\n"
	final := `{"kind":"final","status":"complete","records":1}` + "\n"
	for _, raw := range []string{event + final, header + event, header + event + strings.Replace(final, `"records":1`, `"records":2`, 1), header + strings.Replace(event, `"end_offset":"10"`, `"end_offset":"9223372036854775808"`, 1) + final, header + event + final + event, header + strings.Repeat("x", maxLine+1)} {
		if _, err := New().decode(strings.NewReader(raw), 10, "hash", parsers.ParseContext{}); err == nil {
			t.Fatal("accepted invalid protocol")
		}
	}
}

func TestAuditLoginOutcome(t *testing.T) {
	for _, tc := range []struct{ action, value, want string }{{"LGIS", "1", "login_success"}, {"LGIF", "0", "login_failed"}} {
		r, err := NewAudit().Parse(fixture(t, "x.sqlaudit.csv", "event_time,action_id,succeeded\n2026-01-02 03:04:05,"+tc.action+","+tc.value+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if r.Events[0].Extra["sql_outcome"] != tc.want {
			t.Fatal(r.Events[0].Extra)
		}
	}
}
func TestZeroExportSourceCaveat(t *testing.T) {
	r, err := NewAudit().Parse(fixture(t, "x.sqlaudit.csv", "event_time,action_id\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Coverage == nil || len(r.Raw) != 1 || !strings.Contains(r.Raw[0].Raw, "PARTIAL") {
		t.Fatal("zero export lost source caveat")
	}
}

func TestAuditPackedActionAndXEActivity(t *testing.T) {
	r, err := NewAudit().Parse(fixture(t, "x.sqlaudit.csv", "event_time,action_id,succeeded\n2026-01-02 03:04:05,538987603,1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Events[0].Extra["sql_action"] != "SL" || r.Events[0].Extra["sql_field_action_id"] != "538987603" {
		t.Fatal(r.Events[0].Extra)
	}
	x, err := New().Parse(fixture(t, "x.xel.jsonl", `{"name":"x","timestamp":"2026-01-02T03:04:05Z","actions":{"attach_activity_id":"329b2676-060b-4760-8698-46a43e0b1603:7"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if x.Events[0].Extra["sql_activity_sequence"] != "7" {
		t.Fatal(x.Events[0].Extra)
	}
}
func TestXMLTruncationDisclosed(t *testing.T) {
	_, err := New().Parse(fixture(t, "x.xel.xml", `<RingBufferTarget truncated="1"/>`))
	if err == nil {
		t.Fatal("truncated XML accepted as complete")
	}
}

func TestSourceCoverageCarriesExportCaveat(t *testing.T) {
	r, err := NewAudit().Parse(fixture(t, "x.sqlaudit.csv", "event_time,action_id\n"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r.Coverage)
	if !strings.Contains(string(b), "PARTIAL") {
		t.Fatal(string(b))
	}
}

func TestReaderSourceBinding(t *testing.T) {
	raw := `{"kind":"header","schema":1,"reader":"XELite/2024.2.5.1","checksum":true,"source_sha256":"different","source_size":"10"}` + "\n" + `{"kind":"final","status":"complete","records":0}` + "\n"
	if _, err := New().decode(strings.NewReader(raw), 10, "expected", parsers.ParseContext{}); err == nil {
		t.Fatal("reader decoded a different source")
	}
}

func TestBinaryAuditRequiresExperimentalOptIn(t *testing.T) {
	t.Setenv("TRACEFALL_MSSQL_AUDIT_EXPERIMENTAL", "")
	_, err := NewAudit().Parse(fixture(t, "x.sqlaudit", "not audit"))
	if err == nil || !strings.Contains(err.Error(), "NOT-VERIFIED") {
		t.Fatalf("missing audit validation gate: %v", err)
	}
}

func TestXEDocumentedActionAliases(t *testing.T) {
	r, err := New().Parse(fixture(t, "x.xel.jsonl", `{"name":"x","timestamp":"2026-01-02T03:04:05Z","actions":{"sql_text":"SELECT 1","client_app_name":"app01","server_instance_name":"host01"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if r.Events[0].Extra["sql_statement"] != "SELECT 1" || r.Events[0].Extra["sql_client_application"] != "app01" {
		t.Fatal(r.Events[0].Extra)
	}
}

func TestRealXELCorruptAndSymlinkControls(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_MSSQL_XEL")
	if path == "" {
		t.Skip("TRACEFALL_REAL_MSSQL_XEL not set")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(b)) != "79aad08f9efc149d96f89282a3eea9431aadb63845219e02bb45dfa4e2c11d75" {
		t.Fatal("fixture hash mismatch")
	}
	b[0] ^= 255
	bad := fixture(t, "corrupt.xel", string(b))
	r, err := New().Parse(bad)
	if err == nil || len(r.Events) != 0 {
		t.Fatal("corrupt native accepted")
	}
	link := filepath.Join(t.TempDir(), "link.xel")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = New().Parse(link); err == nil {
		t.Fatal("symlink accepted")
	}
}
func TestBinaryProtocolValidEmptyHasCoverage(t *testing.T) {
	raw := `{"kind":"header","schema":1,"reader":"XELite/2024.2.5.1","checksum":true,"source_sha256":"hash","source_size":"10"}` + "\n" + `{"kind":"final","status":"complete","records":0}` + "\n"
	r, err := New().decode(strings.NewReader(raw), 10, "hash", parsers.ParseContext{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Coverage == nil || len(r.Coverage.Notes) == 0 || len(r.Raw) != 1 {
		t.Fatal("empty source lost diagnostics")
	}
}
