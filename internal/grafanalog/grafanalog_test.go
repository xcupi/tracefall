package grafanalog

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

const (
	failedLogin = `logger=context userId=0 orgId=0 uname= t=2026-10-22T08:21:07.910446864Z level=info msg="Request Completed" method=POST path=/login status=401 remote_addr=203.0.113.9 time_ms=0 duration=649.459µs size=107 referer= handler=/login status_source=server`
	adminCall   = `logger=context userId=1 orgId=1 uname=admin t=2026-10-22T08:21:08.233632176Z level=info msg="Request Completed" method=POST path=/api/serviceaccounts status=201 remote_addr=203.0.113.9 time_ms=80 duration=80.755953ms size=116 referer= handler=/api/serviceaccounts/ status_source=server`
	traversal   = `logger=context userId=0 orgId=0 uname= t=2026-10-22T08:21:08.291061407Z level=info msg="Request Completed" method=GET path=/public/plugins/alertlist/../../../../../../../../etc/passwd status=404 remote_addr=203.0.113.9 time_ms=0 duration=77.556µs size=36 referer= handler=public-assets status_source=server`
	startup     = `logger=settings t=2026-10-22T08:21:00.941928132Z level=info msg="Starting Grafana" version=11.3.0 commit=d9455ff7db73b694db7d412e49a68bec767f2b5a branch=HEAD compiled=2026-10-22T08:21:00Z`
)

func TestParseLine_RequestBecomesAWebRequest(t *testing.T) {
	e, ok := ParseLine(failedLogin)
	if !ok {
		t.Fatal("not recognised")
	}
	if e.EventType != model.EventWebRequest {
		t.Fatalf("type = %s", e.EventType)
	}
	if !e.Timestamp.Equal(time.Date(2026, 10, 22, 8, 21, 7, 910446864, time.UTC)) {
		t.Errorf("timestamp = %v", e.Timestamp)
	}
	if e.NetworkSource != "203.0.113.9" || e.User != "" {
		t.Errorf("source/user = %q/%q (an anonymous request has no user)", e.NetworkSource, e.User)
	}
	for k, want := range map[string]string{"method": "POST", "uri": "/login", "status": "401", "bytes": "107", "grafana_handler": "/login", "grafana_user_id": "0"} {
		if e.Extra[k] != want {
			t.Errorf("Extra[%s] = %q, want %q", k, e.Extra[k], want)
		}
	}
	if !strings.Contains(e.Extra["records_outcome"], "status the server returned") {
		t.Errorf("no outcome caveat: %q", e.Extra["records_outcome"])
	}
}

func TestParseLine_AuthenticatedRequestKeepsTheUser(t *testing.T) {
	e, ok := ParseLine(adminCall)
	if !ok || e.User != "admin" || e.Extra["grafana_user_id"] != "1" || e.Extra["status"] != "201" {
		t.Fatalf("%+v ok=%v", e, ok)
	}
}

func TestParseLine_TraversalPathIsKeptRaw(t *testing.T) {
	e, ok := ParseLine(traversal)
	if !ok || e.Extra["uri"] != "/public/plugins/alertlist/../../../../../../../../etc/passwd" || e.Extra["status"] != "404" {
		t.Fatalf("%+v", e.Extra)
	}
}

func TestParseLine_OtherLinesAreGrafanaLog(t *testing.T) {
	e, ok := ParseLine(startup)
	if !ok || e.EventType != model.EventGrafanaLog {
		t.Fatalf("%+v ok=%v", e, ok)
	}
	if e.Extra["message"] != "Starting Grafana" || e.Extra["grafana_level"] != "info" || e.Extra["grafana_logger"] != "settings" || e.Extra["grafana_version"] != "11.3.0" {
		t.Errorf("%v", e.Extra)
	}
}

func TestParseLine_RejectsLinesThatAreNotGrafana(t *testing.T) {
	for _, s := range []string{
		"", "plain text", `level=info msg="no logger or time"`,
		`logger=x level=info msg=hi`, // no t=
		`logger=x t=not-a-time level=info msg=hi`,
		`logger=x t=2026-10-22T08:21:00Z level=info`, // no msg
	} {
		if _, ok := ParseLine(s); ok {
			t.Errorf("%q recognised", s)
		}
	}
}

func TestParseLine_SecretsInTheMessageAreRedacted(t *testing.T) {
	e, ok := ParseLine(`logger=x t=2026-10-22T08:21:00Z level=warn msg="connect failed" dsn="Server=db01;User Id=app;Password=P@ssw0rdX;" error="bad password=hunter22x"`)
	if !ok {
		t.Fatal("rejected")
	}
	for k, v := range e.Extra {
		if strings.Contains(v, "P@ssw0rdX") || strings.Contains(v, "hunter22x") {
			t.Errorf("Extra[%s] leaks a secret: %q", k, v)
		}
	}
}

func TestParseLine_IsDeterministic(t *testing.T) {
	a, _ := ParseLine(startup)
	b, _ := ParseLine(startup)
	if len(a.Extra) != len(b.Extra) {
		t.Fatal("differs")
	}
	for k, v := range a.Extra {
		if b.Extra[k] != v {
			t.Fatal("differs")
		}
	}
}
