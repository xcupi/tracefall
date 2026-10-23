package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"tracefall/internal/model"

	"tracefall/internal/enrich/llm"
)

func TestChatGPTSettingsNotConnectedAndExplicitConsent(t *testing.T) {
	mux, _ := newTestRouterWithService(t)
	var st map[string]any
	r := doJSON(t, mux, "GET", "/api/admin/integrations/chatgpt", nil, nil)
	if r.Code != 200 {
		t.Fatalf("integration endpoint missing: %d", r.Code)
	}
	json.Unmarshal(r.Body.Bytes(), &st)
	if r.Code != 200 || st["state"] != "not_connected" || st["request_verified"] != false {
		t.Fatalf("status=%d %s", r.Code, r.Body.String())
	}
	r = doJSON(t, mux, "POST", "/api/admin/integrations/chatgpt/verify", map[string]any{"acknowledge": false}, nil)
	if r.Code != 403 {
		t.Fatalf("verification consent=%d", r.Code)
	}
}

const settingsCodex = `#!/bin/sh
printf '%s\n' "$CODEX_HOME|$*" >> "$(dirname "$0")/calls"
while [ "$1" = "-c" ]; do shift 2; done
case "$1 $2" in
 "login status") if [ -e "$CODEX_HOME/synthetic-signed-in" ]; then echo 'Logged in using ChatGPT' >&2; else echo 'Not logged in' >&2; exit 1; fi ;;
 "login --device-auth") if [ -e "$(dirname "$0")/fail-auth" ]; then echo "SECRET-RAW-AUTH-OUTPUT <script>" >&2; exit 1; fi; printf 'https://auth.openai.com/codex/device\n2. Enter this one-time code (expires in 15 minutes)\nABCD-12345\n'; while [ ! -e "$(dirname "$0")/approve" ]; do sleep .02; done; touch "$CODEX_HOME/synthetic-signed-in"; printf '{}' > "$CODEX_HOME/auth.json" ;;
 "logout ") rm -f "$CODEX_HOME/synthetic-signed-in" "$CODEX_HOME/auth.json" ;;
 "exec "*) if [ -e "$(dirname "$0")/fail-request" ]; then echo "SECRET-RAW-MODEL-OUTPUT" >&2; exit 3; fi; input="$(cat)"; printf '%s' "$input" > "$(dirname "$0")/prompt"; while [ $# -gt 0 ]; do if [ "$1" = "-o" ]; then shift; out="$1"; fi; shift; done; echo 'TRACEFALL_TEST_OK' > "$out" ;;
 *) exit 2 ;;
esac
`

func setupChatGPT(t *testing.T, svc *Service, env string) (string, string) {
	t.Helper()
	d := t.TempDir()
	bin := filepath.Join(d, "codex")
	if err := os.WriteFile(bin, []byte(settingsCodex), 0700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(d, "data")
	if err := svc.ConfigureChatGPT(data, bin, "", env, llm.None{}); err != nil {
		t.Fatal(err)
	}
	return d, data
}
func chatStatus(t *testing.T, mux http.Handler) map[string]any {
	t.Helper()
	var st map[string]any
	r := doJSON(t, mux, "GET", "/api/admin/integrations/chatgpt", nil, &st)
	if r.Code != 200 {
		t.Fatalf("status: %d", r.Code)
	}
	return st
}
func waitChat(t *testing.T, mux http.Handler, state string) map[string]any {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		st := chatStatus(t, mux)
		if st["state"] == state {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("never reached %s: %v", state, chatStatus(t, mux))
	return nil
}
func TestChatGPTAdminSourceAndCSRFGates(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "reader", "a-long-test-password", model.RoleAnalyst)
	user, _ := f.login(t, "reader", "a-long-test-password")
	for _, route := range []struct {
		method, path string
		body         any
	}{{"GET", "", nil}, {"PUT", "", map[string]any{"provider": "codex-cli"}}, {"DELETE", "", nil}, {"POST", "/authorize", nil}, {"POST", "/cancel", nil}, {"POST", "/verify", map[string]any{"acknowledge": true}}} {
		if rec := user.do(route.method, "/api/admin/integrations/chatgpt"+route.path, route.body); rec.Code != 403 {
			t.Fatalf("analyst allowed %s %s: %d", route.method, route.path, rec.Code)
		}
	}
	f.mustCreateUser(t, "operator", "a-long-test-password", model.RoleAdmin)
	admin, _ := f.login(t, "operator", "a-long-test-password")
	if rec := admin.do("GET", "/api/admin/integrations/chatgpt", nil); rec.Code != 200 {
		t.Fatal("admin status denied", rec.Code)
	}
	req := httptest.NewRequest("POST", "/api/admin/integrations/chatgpt/authorize", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: admin.session})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: admin.csrf})
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatal("missing CSRF allowed", rec.Code)
	}
	mux := NewRouter(newTestService(t), slog.Default(), testMaxUploadBytes, false)
	for _, tc := range []struct{ host, origin, fetch, client string }{{"127.0.0.1", "https://foreign.invalid", "", "dashboard"}, {"foreign.invalid", "", "", "dashboard"}, {"127.0.0.1", "", "cross-site", "dashboard"}, {"127.0.0.1", "", "", ""}} {
		req := httptest.NewRequest("POST", "http://"+tc.host+"/api/admin/integrations/chatgpt/authorize", nil)
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("Sec-Fetch-Site", tc.fetch)
		req.Header.Set("X-Tracefall-Client", tc.client)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Fatalf("source bypass: %+v %d", tc, rec.Code)
		}
	}
}
func TestChatGPTAuthorizationFailureNeverReflectsOutput(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	d, _ := setupChatGPT(t, svc, "")
	os.WriteFile(filepath.Join(d, "fail-auth"), nil, 0600)
	r := doJSON(t, mux, "POST", "/api/admin/integrations/chatgpt/authorize", nil, nil)
	if r.Code != 202 {
		t.Fatal(r.Code)
	}
	st := waitChat(t, mux, "failed")
	raw, _ := json.Marshal(st)
	if strings.Contains(string(raw), "SECRET") || strings.Contains(string(raw), "script") || st["request_verified"] != false {
		t.Fatal("raw failure exposed")
	}
}
func TestChatGPTPendingAuthorizationRefusesNewSummaryAsConflict(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	setupChatGPT(t, svc, "")
	id := caseWithFindings(t, svc, mux, nil)
	doJSON(t, mux, "POST", "/api/admin/integrations/chatgpt/authorize", nil, nil)
	waitChat(t, mux, "waiting")
	defer doJSON(t, mux, "POST", "/api/admin/integrations/chatgpt/cancel", nil, nil)
	r := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/narrative", map[string]any{"acknowledge": true}, nil)
	if r.Code != 409 {
		t.Fatalf("pending configuration should be a conflict, not internal failure: %d %s", r.Code, r.Body.String())
	}
}
func TestChatGPTCancelClearsTransientCodeAndSendsNoModelRequest(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	d, _ := setupChatGPT(t, svc, "")
	ep := "/api/admin/integrations/chatgpt"
	doJSON(t, mux, "POST", ep+"/authorize", nil, nil)
	waitChat(t, mux, "waiting")
	r := doJSON(t, mux, "POST", ep+"/cancel", nil, nil)
	if r.Code != 204 {
		t.Fatal(r.Code)
	}
	st := chatStatus(t, mux)
	if st["state"] != "cancelled" || st["user_code"] != nil || st["busy"] != false {
		t.Fatal(st)
	}
	calls, _ := os.ReadFile(filepath.Join(d, "calls"))
	if strings.Contains(string(calls), "exec ") {
		t.Fatal("cancel sent model request")
	}
}
func TestChatGPTRelativeDataDirectoryUsesAbsoluteIsolatedHome(t *testing.T) {
	_, svc := newTestRouterWithService(t)
	d, data := setupChatGPT(t, svc, "")
	cwd, _ := os.Getwd()
	rel, err := filepath.Rel(cwd, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ConfigureChatGPT(rel, filepath.Join(d, "codex"), "", "", llm.None{}); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(svc.llm.codex.CodexHome) {
		t.Fatal("relative CODEX_HOME will resolve against child working directory")
	}
}
func TestChatGPTUnavailableBinaryIsNotAdvertised(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	setupChatGPT(t, svc, "")
	svc.llm.codex.Binary = "/missing/codex"
	if chatStatus(t, mux)["available"] != false {
		t.Fatal("missing CLI advertised as available")
	}
	r := doJSON(t, mux, "POST", "/api/admin/integrations/chatgpt/authorize", nil, nil)
	if r.Code != 503 {
		t.Fatal("missing binary accepted", r.Code)
	}
}
func TestChatGPTAuthorizationDeadlineClearsCode(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	setupChatGPT(t, svc, "")
	svc.llm.authorizationTimeout = 100 * time.Millisecond
	r := doJSON(t, mux, "POST", "/api/admin/integrations/chatgpt/authorize", nil, nil)
	if r.Code != 202 {
		t.Fatal(r.Code)
	}
	t.Cleanup(func() { doJSON(t, mux, "POST", "/api/admin/integrations/chatgpt/cancel", nil, nil) })
	st := waitChat(t, mux, "expired")
	if st["user_code"] != nil || st["request_verified"] != false {
		t.Fatal(st)
	}
}
func TestChatGPTRuntimePinsProviderDuringNarrative(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	setupChatGPT(t, svc, "")
	stub := newLLMStub(t, svc, true)
	started, release := make(chan struct{}), make(chan struct{})
	stub.answer = func(user string) (int, string) { close(started); <-release; return goodAnswer(user) }
	id := caseWithFindings(t, svc, mux, nil)
	defer func() { close(release); waitNarr(t, svc, id) }()
	if _, err := svc.StartNarrative(id, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request not started")
	}
	for _, route := range []struct {
		method, path string
		body         any
	}{{"PUT", "", map[string]any{"provider": "none"}}, {"DELETE", "", nil}, {"POST", "/authorize", nil}} {
		r := doJSON(t, mux, route.method, "/api/admin/integrations/chatgpt"+route.path, route.body, nil)
		if r.Code != 409 {
			t.Fatalf("provider/account change during active request allowed: %s %d", route.method, r.Code)
		}
	}
}

func TestChatGPTEnvironmentPrecedenceAndSharedCopies(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	setupChatGPT(t, svc, "openai-compatible")
	r := doJSON(t, mux, "PUT", "/api/admin/integrations/chatgpt", map[string]any{"provider": "codex-cli"}, nil)
	if r.Code != 409 {
		t.Fatal("environment override ignored", r.Code)
	}
	st := chatStatus(t, mux)
	if st["environment_managed"] != true || st["effective_provider"] != "openai-compatible" {
		t.Fatal(st)
	}
	mux2, svc2 := newTestRouterWithService(t)
	setupChatGPT(t, svc2, "")
	newLLMStub(t, svc2, true)
	before := svc2.WithActor(Principal{})
	r = doJSON(t, mux2, "PUT", "/api/admin/integrations/chatgpt", map[string]any{"provider": "none"}, nil)
	if r.Code != 200 || before.llm.snapshot().Configured() {
		t.Fatal("request copy did not share selection")
	}
}

func TestChatGPTAuthorizeSelectVerifyDisconnect(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	d, data := setupChatGPT(t, svc, "")
	ep := "/api/admin/integrations/chatgpt"
	r := doJSON(t, mux, "POST", ep+"/authorize", nil, nil)
	if r.Code != 202 {
		t.Fatalf("authorize=%d %s", r.Code, r.Body.String())
	}
	st := waitChat(t, mux, "waiting")
	if st["authorization_url"] != "https://auth.openai.com/codex/device" || st["user_code"] != "ABCD-12345" {
		t.Fatalf("waiting: %v", st)
	}
	calls, _ := os.ReadFile(filepath.Join(d, "calls"))
	if strings.Contains(string(calls), "exec ") {
		t.Fatal("authorize sent model request")
	}
	os.WriteFile(filepath.Join(d, "approve"), nil, 0600)
	st = waitChat(t, mux, "signed_in")
	if st["request_verified"] != false || st["user_code"] != nil {
		t.Fatalf("authorization mistaken for verification or code retained: %v", st)
	}
	r = doJSON(t, mux, "PUT", ep, map[string]any{"provider": "codex-cli"}, nil)
	if r.Code != 200 {
		t.Fatalf("select: %d %s", r.Code, r.Body.String())
	}
	if st = chatStatus(t, mux); st["effective_provider"] != "codex-cli" {
		t.Fatal(st)
	}
	r = doJSON(t, mux, "POST", ep+"/verify", map[string]any{"acknowledge": true}, nil)
	if r.Code != 200 {
		t.Fatalf("verify: %d %s", r.Code, r.Body.String())
	}
	if chatStatus(t, mux)["request_verified"] != true {
		t.Fatal("successful request not verified")
	}
	prompt, _ := os.ReadFile(filepath.Join(d, "prompt"))
	if !strings.Contains(string(prompt), "TRACEFALL_TEST_OK") || strings.Contains(string(prompt), "FACTS") {
		t.Fatalf("not fixed synthetic prompt: %s", prompt)
	}
	os.WriteFile(filepath.Join(d, "fail-request"), nil, 0600)
	r = doJSON(t, mux, "POST", ep+"/verify", map[string]any{"acknowledge": true}, nil)
	if r.Code != 502 || strings.Contains(r.Body.String(), "SECRET") || chatStatus(t, mux)["request_verified"] != false {
		t.Fatal("failed request retained verification or leaked stderr")
	}
	os.Remove(filepath.Join(d, "fail-request"))
	// Restart loads only the non-secret preference; request verification is deliberately ephemeral.
	otherMux, other := newTestRouterWithService(t)
	if err := other.ConfigureChatGPT(data, filepath.Join(d, "codex"), "", "", llm.None{}); err != nil {
		t.Fatal(err)
	}
	if restarted := chatStatus(t, otherMux); restarted["effective_provider"] != "codex-cli" || restarted["request_verified"] != false {
		t.Fatalf("restart preference/verification: %v", restarted)
	}
	r = doJSON(t, mux, "POST", ep+"/verify", map[string]any{"acknowledge": true}, nil)
	if r.Code != 200 || chatStatus(t, mux)["request_verified"] != true {
		t.Fatal("synthetic verification recovery failed")
	}
	r = doJSON(t, mux, "POST", ep+"/authorize", nil, nil)
	if r.Code != 202 {
		t.Fatal(r.Code)
	}
	waitChat(t, mux, "signed_in")
	if chatStatus(t, mux)["request_verified"] != false {
		t.Fatal("authorization change retained verification")
	}
	r = doJSON(t, mux, "DELETE", ep, nil, nil)
	if r.Code != 200 {
		t.Fatalf("disconnect=%d %s", r.Code, r.Body.String())
	}
	st = chatStatus(t, mux)
	if st["state"] != "not_connected" || st["request_verified"] != false {
		t.Fatal(st)
	}
	calls, _ = os.ReadFile(filepath.Join(d, "calls"))
	prefPath := filepath.Join(data, ".integrations", "llm-provider")
	pref, err := os.ReadFile(prefPath)
	if err != nil || string(pref) != "codex-cli" {
		t.Fatal("non-secret preference not saved")
	}
	for _, p := range []string{filepath.Join(data, ".integrations"), filepath.Join(data, ".integrations", "codex"), prefPath} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0700)
		if !info.IsDir() {
			want = 0600
		}
		if info.Mode().Perm() != want {
			t.Fatalf("unsafe integration mode: %o", info.Mode().Perm())
		}
	}
	audit, err := svc.store.ListSecurityLog(1000)
	if err != nil {
		t.Fatal(err)
	}
	auditJSON, _ := json.Marshal(audit)
	for _, secret := range []string{"ABCD-12345", "SECRET-RAW", "TRACEFALL_TEST_OK"} {
		if strings.Contains(string(auditJSON), secret) {
			t.Fatalf("authorization/request value entered security database: %s", secret)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
		if !strings.HasPrefix(line, filepath.Join(data, ".integrations", "codex")+"|") {
			t.Fatalf("not isolated: %s", line)
		}
	}
}
