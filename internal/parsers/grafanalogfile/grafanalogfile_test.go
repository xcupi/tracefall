package grafanalogfile

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const (
	lStart  = `logger=settings t=2026-10-22T08:21:00.941928132Z level=info msg="Starting Grafana" version=11.3.0`
	lFailed = `logger=context userId=0 orgId=0 uname= t=2026-10-22T08:21:07.910446864Z level=info msg="Request Completed" method=POST path=/login status=401 remote_addr=203.0.113.9 time_ms=0 duration=649.459µs size=107 referer= handler=/login status_source=server`
	lAdmin  = `logger=context userId=2 orgId=1 uname=alice01 t=2026-10-22T08:21:08.233632176Z level=info msg="Request Completed" method=POST path=/api/users status=200 remote_addr=203.0.113.10 time_ms=80 duration=80ms size=116 referer= handler=/api/users status_source=server`
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDetect_Names(t *testing.T) {
	p := New()
	for _, n := range []string{"grafana.log", "var/log/grafana/grafana.log", "Grafana.LOG", "grafana.log.1", "grafana.log.2026-10-21", "grafana-2026-10-21.log", `x\grafana.log.12`} {
		if !p.Detect(n) {
			t.Errorf("%q not detected", n)
		}
	}
	for _, n := range []string{"grafana.db", "grafana.log.gz", "grafana.logx", "mygrafana.log", "grafana-2026.log", "grafana.log.abc", "grafana.ini", "log"} {
		if p.Detect(n) {
			t.Errorf("%q detected", n)
		}
	}
}

func TestDetectContent_FirstLine(t *testing.T) {
	p := New()
	if !p.DetectContent([]byte(lStart + "\n" + lFailed + "\n")) {
		t.Error("grafana first line not detected")
	}
	if !p.DetectContent([]byte(lStart)) {
		t.Error("single line without newline not detected")
	}
	if p.DetectContent([]byte("hello\n" + lStart + "\n")) {
		t.Error("non-grafana first line detected")
	}
	if p.DetectContent(nil) {
		t.Error("empty detected")
	}
	// a first line longer than the sniff window is cut mid-value
	long := `logger=settings t=2026-10-22T08:21:00Z level=info msg="x" extra="` + strings.Repeat("a", 900) + `"` + "\n"
	if !p.DetectContent([]byte(long)[:parsers.SniffLength]) {
		t.Error("truncated first line not detected")
	}
}

func TestParse_EventsAndProvenance(t *testing.T) {
	path := write(t, "grafana.log", lStart+"\n"+lFailed+"\n"+lAdmin+"\n")
	res, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 3 || len(res.Raw) != 3 {
		t.Fatalf("events=%d raw=%d", len(res.Events), len(res.Raw))
	}
	e := res.Events[1]
	if e.EventType != model.EventWebRequest || e.ArtifactType != model.ArtifactGrafanaLog || e.Parser != "grafanalogfile@1" ||
		e.FilePath != "grafana.log" || e.SourceReference != "line:2" || e.Extra["line_number"] != "2" || e.Confidence != 0.95 {
		t.Errorf("%+v", e)
	}
	if res.Events[0].EventType != model.EventGrafanaLog || res.Events[0].SourceReference != "line:1" {
		t.Errorf("%+v", res.Events[0])
	}
	if res.Raw[1].SourceReference != "line:2" || res.Raw[1].Raw != lFailed {
		t.Errorf("raw %+v", res.Raw[1])
	}
	if _, has := res.Events[0].Extra["unparsed_lines"]; has {
		t.Error("unparsed_lines set though every line parsed")
	}
	if res.Coverage == nil || res.Coverage.RecordsRead != 3 || res.Coverage.Mapped != 3 {
		t.Errorf("coverage %+v", res.Coverage)
	}
}

func TestParse_UnparsedLinesAreCounted(t *testing.T) {
	path := write(t, "grafana.log.1", "garbage line\n"+lStart+"\n\n  \nlogger=x level=info msg=nope\n"+lFailed+"\n")
	res, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 2 {
		t.Fatalf("events=%d", len(res.Events))
	}
	if res.Events[0].Extra["unparsed_lines"] != "2" {
		t.Errorf("unparsed_lines = %q", res.Events[0].Extra["unparsed_lines"])
	}
	if res.Events[0].SourceReference != "line:2" || res.Events[1].SourceReference != "line:6" {
		t.Errorf("refs %s %s", res.Events[0].SourceReference, res.Events[1].SourceReference)
	}
	if _, has := res.Events[1].Extra["unparsed_lines"]; has {
		t.Error("only the first event carries unparsed_lines")
	}
	if res.Coverage.Unmapped != 2 || !strings.Contains(strings.Join(res.Coverage.Notes, "|"), "2 line(s) are not Grafana records") {
		t.Errorf("coverage %+v", res.Coverage)
	}
}

func TestParse_NoRecognisedLineIsAnError(t *testing.T) {
	path := write(t, "grafana.log", "just text\nmore text\n")
	_, err := New().Parse(path)
	if !errors.Is(err, ErrNoGrafanaRecords) {
		t.Fatalf("err = %v", err)
	}
	if _, err := New().Parse(write(t, "grafana.log", "")); !errors.Is(err, ErrNoGrafanaRecords) {
		t.Fatalf("empty err = %v", err)
	}
}

func TestParse_OversizedLineCountedAndNextLineSurvives(t *testing.T) {
	big := `logger=x t=2026-10-22T08:21:00Z level=info msg="` + strings.Repeat("a", 1<<20+10) + `"`
	path := write(t, "grafana.log", lStart+"\n"+big+"\n"+lFailed+"\n")
	res, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 2 || res.Events[1].SourceReference != "line:3" {
		t.Fatalf("events=%d", len(res.Events))
	}
	if res.Events[0].Extra["unparsed_lines"] != "1" || !strings.Contains(strings.Join(res.Coverage.Notes, "|"), "1 line(s) longer than") {
		t.Errorf("%v %v", res.Events[0].Extra["unparsed_lines"], res.Coverage.Notes)
	}
}

func TestParse_LineJustUnderOneMiBIsParsed(t *testing.T) {
	line := `logger=x t=2026-10-22T08:21:00Z level=info msg="` + strings.Repeat("a", 1<<20-200) + `"`
	res, err := New().Parse(write(t, "grafana.log", line+"\n"))
	if err != nil || len(res.Events) != 1 {
		t.Fatalf("err=%v", err)
	}
}

func TestParse_EventCapIsExplicit(t *testing.T) {
	old := maxEvents
	maxEvents = 5
	defer func() { maxEvents = old }()
	var b strings.Builder
	for i := 0; i < 9; i++ {
		fmt.Fprintf(&b, "%s\n", lAdmin)
	}
	res, err := New().Parse(write(t, "grafana.log", b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 5 || !res.Coverage.LimitReached || !strings.Contains(strings.Join(res.Coverage.Notes, "|"), "event limit of 5") {
		t.Errorf("events=%d cov=%+v", len(res.Events), res.Coverage)
	}
}

func TestParse_DoesNotModifyEvidenceAndIsDeterministic(t *testing.T) {
	path := write(t, "grafana.log", lStart+"\n"+lFailed+"\n")
	before := sum(t, path)
	a, _ := New().Parse(path)
	b, _ := New().Parse(path)
	if sum(t, path) != before {
		t.Fatal("evidence changed")
	}
	if fmt.Sprint(a.Events) != fmt.Sprint(b.Events) {
		t.Error("not deterministic")
	}
}

func sum(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

const realLogSHA = "8837956b4c012962ce0e26e8081e853153f045090417c297589d3404459f1b84"

func TestReal_GrafanaLog(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_GRAFANA_LOG")
	if path == "" {
		t.Skip("TRACEFALL_REAL_GRAFANA_LOG not set")
	}
	if got := sum(t, path); got != realLogSHA {
		t.Skipf("sample hash %s is not the pinned one", got)
	}
	raw, _ := os.ReadFile(path)
	wantReq := strings.Count(string(raw), `msg="Request Completed"`)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if sum(t, path) != realLogSHA {
		t.Fatal("evidence changed")
	}
	req, failed := 0, 0
	for _, e := range res.Events {
		if e.EventType == model.EventWebRequest {
			req++
			if e.Extra["uri"] == "/login" && e.Extra["status"] == "401" {
				failed++
			}
		}
	}
	t.Logf("events=%d web_request=%d independent=%d failed_login_401=%d unparsed=%d", len(res.Events), req, wantReq, failed, res.Coverage.Unmapped)
	if req != wantReq {
		t.Errorf("web_request %d != independent %d", req, wantReq)
	}
	if failed != 7 {
		t.Errorf("failed login 401 = %d, want 7", failed)
	}
}
