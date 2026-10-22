package iislog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const hdr = "#Software: Microsoft Internet Information Services 10.0\r\n#Version: 1.0\r\n#Date: 2026-01-05 00:00:03\r\n" +
	"#Fields: date time s-sitename s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status sc-bytes time-taken\r\n"

func TestDetect_ByNameAndPath(t *testing.T) {
	p := New()
	for _, ok := range []string{"u_ex260105.log", "U_EX260105.LOG", "u_ex26010512.log", "u_extend1.log", `C:\inetpub\logs\LogFiles\W3SVC1\u_ex260105.log`} {
		if !p.Detect(ok) {
			t.Errorf("Detect(%q) = false", ok)
		}
	}
	for _, no := range []string{"u_ex260105.log.gz", "ex260105.log", "error.log", "u_ex.txt", `inetpub\logs\LogFiles\FTPSVC2\u_ex260105.log`, `LogFiles\HTTPERR\httperr1.log`} {
		if p.Detect(no) {
			t.Errorf("Detect(%q) = true", no)
		}
	}
}

func TestDetectContent_NeedsTheDirectivesAndAWholeFieldsLine(t *testing.T) {
	p := New()
	if !p.DetectContent([]byte(hdr)) {
		t.Error("a real IIS header should be recognised")
	}
	if p.DetectContent([]byte(hdr[:len(hdr)-40])) {
		t.Error("a Fields line cut mid-way must not be judged")
	}
	if p.DetectContent([]byte("#Software: Microsoft Firewall\r\n#Version: 1.5\r\n#Fields: date time action protocol src-ip dst-ip\r\n")) {
		t.Error("the Windows Firewall log is not a web log")
	}
	if p.DetectContent([]byte("just text\n")) {
		t.Error("plain text")
	}
}

func TestDetectContent_FTPSiteLogsAreNotWebLogs(t *testing.T) {
	ftp := "#Software: Microsoft Internet Information Services 10.0\r\n#Version: 1.0\r\n" +
		"#Fields: date time c-ip cs-username s-ip s-port cs-method cs-uri-stem cs-uri-query sc-status sc-win32-status sc-substatus x-session x-fullpath\r\n"
	p := New()
	if p.DetectContent([]byte(ftp)) || p.ConfirmContent([]byte(ftp)) {
		t.Error("an FTP site log shares the column names but is not a web log")
	}
	// A web log with its columns cut down is still confirmed when named like
	// one, but is not claimed from content alone.
	min := "#Fields: date time c-ip cs-method cs-uri-stem sc-status\r\n"
	if p.DetectContent([]byte(min)) {
		t.Error("without any HTTP-specific column the content alone does not prove a web log")
	}
	if !p.ConfirmContent([]byte(min)) {
		t.Error("a log named like an IIS log with the web columns should be confirmed")
	}
}

func TestParse_FieldsByNameNotPosition(t *testing.T) {
	body := hdr +
		"2026-01-05 13:04:05 W3SVC1 WEB01 192.0.2.10 POST /upload/shell.aspx cmd=whoami+/all 443 alice 203.0.113.9 Mozilla/5.0+(X11) http://ref.example/ 200 0 0 1234 87\r\n"
	res, err := New().Parse(write(t, "u_ex260105.log", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 || len(res.Raw) != 1 {
		t.Fatalf("events %d raw %d", len(res.Events), len(res.Raw))
	}
	e := res.Events[0]
	if !e.Timestamp.Equal(time.Date(2026, 1, 5, 13, 4, 5, 0, time.UTC)) {
		t.Errorf("timestamp %v", e.Timestamp)
	}
	if e.EventType != model.EventWebRequest || e.ArtifactType != model.ArtifactIISLog {
		t.Errorf("types %s %s", e.EventType, e.ArtifactType)
	}
	if e.NetworkSource != "203.0.113.9" || e.User != "alice" {
		t.Errorf("source %q user %q", e.NetworkSource, e.User)
	}
	for k, want := range map[string]string{
		"method": "POST", "uri_stem": "/upload/shell.aspx", "uri_query": "cmd=whoami+/all",
		"uri": "/upload/shell.aspx?cmd=whoami+/all", "status": "200", "substatus": "0",
		"win32_status": "0", "bytes": "1234", "time_taken_ms": "87", "server_ip": "192.0.2.10",
		"server_port": "443", "site": "W3SVC1", "server_name": "WEB01", "user_agent": "Mozilla/5.0+(X11)",
		"referrer": "http://ref.example/", "line_number": "5",
	} {
		if e.Extra[k] != want {
			t.Errorf("Extra[%s] = %q, want %q", k, e.Extra[k], want)
		}
	}
	if e.SourceReference != "line:5" || res.Raw[0].SourceReference != "line:5" {
		t.Errorf("reference %q", e.SourceReference)
	}
}

func TestParse_DashIsEmptyAndAnonymousUserIsNoUser(t *testing.T) {
	body := hdr + "2026-01-05 13:04:05 W3SVC1 WEB01 192.0.2.10 GET /index.html - 80 - 203.0.113.9 - - 404 0 2 100 3\r\n"
	res, _ := New().Parse(write(t, "u_ex260105.log", body))
	e := res.Events[0]
	if e.User != "" || e.Extra["uri_query"] != "" || e.Extra["uri"] != "/index.html" || e.Extra["status"] != "404" || e.Extra["win32_status"] != "2" {
		t.Errorf("%+v", e)
	}
	if _, ok := e.Extra["user_agent"]; ok && e.Extra["user_agent"] != "" {
		t.Errorf("a dash user agent is empty, got %q", e.Extra["user_agent"])
	}
}

func TestParse_FieldsDirectiveCanChangeMidFile(t *testing.T) {
	body := hdr + "2026-01-05 13:04:05 W3SVC1 WEB01 192.0.2.10 GET /a - 80 - 203.0.113.9 - - 200 0 0 1 1\r\n" +
		"#Fields: date time c-ip cs-method cs-uri-stem sc-status\r\n" +
		"2026-01-05 13:05:00 203.0.113.10 GET /b 500\r\n"
	res, _ := New().Parse(write(t, "u_ex260105.log", body))
	if len(res.Events) != 2 {
		t.Fatalf("events %d", len(res.Events))
	}
	b := res.Events[1]
	if b.NetworkSource != "203.0.113.10" || b.Extra["uri"] != "/b" || b.Extra["status"] != "500" || b.SourceReference != "line:7" {
		t.Errorf("%+v", b)
	}
}

func TestParse_BadLinesAreCountedNotGuessed(t *testing.T) {
	body := hdr + "2026-01-05 13:04:05 W3SVC1 WEB01 192.0.2.10 GET /a - 80 - 203.0.113.9 - - 200 0 0 1 1\r\n" +
		"2026-01-05 13:04:06 W3SVC1 WEB01 192.0.2.10 GET /trunc\r\n" + // truncated while being written
		"not-a-date 13:04:07 W3SVC1 WEB01 192.0.2.10 GET /x - 80 - 203.0.113.9 - - 200 0 0 1 1\r\n"
	res, _ := New().Parse(write(t, "u_ex260105.log", body))
	if len(res.Events) != 1 {
		t.Fatalf("events %d", len(res.Events))
	}
	if res.Events[0].Extra["unparsed_lines"] != "2" {
		t.Errorf("unparsed = %q", res.Events[0].Extra["unparsed_lines"])
	}
}

func TestParse_NoDateOrTimeFieldMeansUndated(t *testing.T) {
	body := "#Fields: time c-ip cs-method cs-uri-stem sc-status\n13:04:05 203.0.113.9 GET /a 200\n"
	res, _ := New().Parse(write(t, "u_ex260105.log", body))
	if len(res.Events) != 1 || !res.Events[0].Timestamp.IsZero() || res.Events[0].Extra["timestamp_known"] != "false" {
		t.Fatalf("%+v", res.Events)
	}
}

func TestParse_RowsBeforeAnyFieldsDirectiveAreNotInterpreted(t *testing.T) {
	body := "2026-01-05 13:04:05 203.0.113.9 GET /a 200\n"
	res, _ := New().Parse(write(t, "u_ex260105.log", body))
	if len(res.Events) != 0 {
		t.Fatalf("a row with no Fields directive was guessed at: %+v", res.Events)
	}
}

func TestParse_BOMAndLongLineAndInvalidUTF8(t *testing.T) {
	long := strings.Repeat("A", 200000)
	body := "\xef\xbb\xbf" + hdr +
		"2026-01-05 13:04:05 W3SVC1 WEB01 192.0.2.10 GET /a " + long + " 80 - 203.0.113.9 - - 200 0 0 1 1\r\n" +
		"2026-01-05 13:04:06 W3SVC1 WEB01 192.0.2.10 GET /\xff\xfe - 80 - 203.0.113.9 - - 200 0 0 1 1\r\n"
	res, err := New().Parse(write(t, "u_ex260105.log", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("events %d (the oversized line is dropped and counted, the next line still parses)", len(res.Events))
	}
	if !strings.Contains(res.Events[0].Extra["uri"], "\uFFFD") {
		t.Errorf("uri %q", res.Events[0].Extra["uri"])
	}
	if res.Events[0].Extra["unparsed_lines"] != "1" {
		t.Errorf("unparsed %q", res.Events[0].Extra["unparsed_lines"])
	}
}
