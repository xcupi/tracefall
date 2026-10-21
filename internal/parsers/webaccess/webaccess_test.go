package webaccess

import (
	"os"
	"path/filepath"
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

func TestDetect_ByName(t *testing.T) {
	p := New()
	for _, ok := range []string{"access.log", "access_log", "site-access.log", "other_vhosts_access.log", "access.log.1", "ACCESS.LOG", `[root]\var\log\apache2\access.log`} {
		if !p.Detect(ok) {
			t.Errorf("Detect(%q) = false", ok)
		}
	}
	for _, no := range []string{"access", "access.log.gz", "error.log", "accessibility.log", "access.log.bak", "auth.log"} {
		if p.Detect(no) {
			t.Errorf("Detect(%q) = true", no)
		}
	}
}

func TestDetectContent_NeedsAWholeFirstLineInTheLayout(t *testing.T) {
	p := New()
	good := "198.51.100.4 - - [19/Apr/2010:06:36:15 -0700] \"GET / HTTP/1.1\" 200 12\nrest"
	if !p.DetectContent([]byte(good)) {
		t.Error("a Common Log Format first line should be recognised")
	}
	if p.DetectContent([]byte("198.51.100.4 - - [19/Apr/2010:06:36:15 -0700] \"GET / HTTP/1.1\" 200 12")) {
		t.Error("a header with no line end may be cut mid-line; do not judge it")
	}
	if p.DetectContent([]byte("Mar 20 11:26:22 host01 sshd[1]: Failed password for alice\nrest")) {
		t.Error("syslog is not an access log")
	}
}

func TestParse_CombinedWithTrailingFields(t *testing.T) {
	body := `203.0.113.7 - alice [19/Apr/2010:06:36:15 -0700] "GET /feed/?a=1 HTTP/1.1" 200 16605 "http://ref.example/" "Agent/1.0 (x)" C4nE4goAAQ4 3822005` + "\n"
	res, err := New().Parse(write(t, "access.log", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 || len(res.Raw) != 1 {
		t.Fatalf("events %d raw %d", len(res.Events), len(res.Raw))
	}
	e := res.Events[0]
	want := time.Date(2010, 4, 19, 13, 36, 15, 0, time.UTC)
	if !e.Timestamp.Equal(want) {
		t.Errorf("timestamp %v, want %v (06:36:15 at -0700 is 13:36:15 UTC)", e.Timestamp, want)
	}
	if e.EventType != model.EventWebRequest || e.NetworkSource != "203.0.113.7" || e.User != "alice" {
		t.Errorf("event %+v", e)
	}
	for k, v := range map[string]string{
		"method": "GET", "uri": "/feed/?a=1", "protocol": "HTTP/1.1", "status": "200", "bytes": "16605",
		"referrer": "http://ref.example/", "user_agent": "Agent/1.0 (x)", "trailing_fields": "C4nE4goAAQ4 3822005",
		"log_utc_offset": "-0700",
	} {
		if e.Extra[k] != v {
			t.Errorf("Extra[%s] = %q, want %q", k, e.Extra[k], v)
		}
	}
	if e.SourceReference != "line:1" {
		t.Errorf("reference %q", e.SourceReference)
	}
}

func TestParse_CommonFormatMalformedRequestAndUnparsedLines(t *testing.T) {
	body := "" +
		"198.51.100.4 - - [02/Jan/2020:00:00:01 +0000] \"-\" 408 -\n" +
		"not a log line at all\n" +
		"198.51.100.4 - - [02/Jan/2020:00:00:02 +0000] \"GET /a\\\"b HTTP/1.0\" 404 209\n" +
		"198.51.100.4 - - [31/Feb/2020:00:00:02 +0000] \"GET / HTTP/1.0\" 200 1\n"
	res, err := New().Parse(write(t, "access.log", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2 (a non-log line and an impossible date are not events)", len(res.Events))
	}
	if res.Events[0].Extra["uri"] != "-" || res.Events[0].Extra["status"] != "408" || res.Events[0].Extra["bytes"] != "" {
		t.Errorf("garbage request kept as text: %v", res.Events[0].Extra)
	}
	if res.Events[1].Extra["uri"] != `/a"b` {
		t.Errorf("escaped quote: %q", res.Events[1].Extra["uri"])
	}
	if res.Events[0].Extra["unparsed_lines"] != "2" {
		t.Errorf("unparsed_lines = %q, want 2", res.Events[0].Extra["unparsed_lines"])
	}
}

func TestParse_AFileOfAnotherFormatYieldsNothing(t *testing.T) {
	res, err := New().Parse(write(t, "access.log", "[Tue Apr 20 00:00:35 2010] [error] [client 203.0.113.9] request failed\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		t.Fatalf("an error-log line must not become a request: %d events", len(res.Events))
	}
}
