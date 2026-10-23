package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"tracefall/internal/model"
)

func TestVTIntegrationTestRequiresConsentAndUsesOneFixedHashAndQuota(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newVTStub(t, svc)
	stub.answers[hA] = ok(vtKnown)
	endpoint := "/api/admin/integrations/virustotal/test"
	if rec := doJSON(t, mux, "POST", endpoint, map[string]any{"acknowledge": false}, nil); rec.Code != 403 {
		t.Fatalf("consent: %d %s", rec.Code, rec.Body.String())
	}
	if stub.count() != 0 {
		t.Fatal("refused test sent a request")
	}
	old := vtDailyLimit
	vtDailyLimit = 1
	t.Cleanup(func() { vtDailyLimit = old })
	rec := doJSON(t, mux, "POST", endpoint, map[string]any{"acknowledge": true}, nil)
	if rec.Code != 200 {
		t.Fatalf("connection test: %d %s", rec.Code, rec.Body.String())
	}
	if stub.count() != 1 || stub.hits[0] != "GET /api/v3/files/"+hA {
		t.Fatalf("test sent something other than fixed public hash: %+v", stub.hits)
	}
	n, _ := svc.store.CountProviderRequestsSince(model.EnrichmentVirusTotal, time.Time{})
	if n != 1 {
		t.Fatalf("test not counted: %d", n)
	}
	rec = doJSON(t, mux, "POST", endpoint, map[string]any{"acknowledge": true}, nil)
	if rec.Code != 429 || stub.count() != 1 {
		t.Fatalf("quota bypass: %d hits=%d", rec.Code, stub.count())
	}
}

func TestVTIntegrationEnvironmentAndInvalidInput(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	p := filepath.Join(t.TempDir(), ".integrations", "virustotal.key")
	key := strings.Repeat("cd", 32)
	if err := svc.ConfigureVirusTotalStorage(p, key); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"PUT", "DELETE"} {
		body := any(nil)
		if method == "PUT" {
			body = map[string]any{"api_key": strings.Repeat("ef", 32)}
		}
		rec := doJSON(t, mux, method, "/api/admin/integrations/virustotal", body, nil)
		if rec.Code != 409 {
			t.Fatalf("env override allowed: %d %s", rec.Code, rec.Body.String())
		}
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("environment key written to disk")
	}
	mux2, svc2 := newTestRouterWithService(t)
	svc2.ConfigureVirusTotalStorage(filepath.Join(t.TempDir(), "key"), "")
	for _, bad := range []any{map[string]any{"api_key": "bad-secret-value"}, map[string]any{"api_key": 12345}, map[string]any{"api_key": strings.Repeat("ab", 32), "unexpected": "secret"}} {
		rec := doJSON(t, mux2, "PUT", "/api/admin/integrations/virustotal", bad, nil)
		if rec.Code != 400 || strings.Contains(rec.Body.String(), "bad-secret-value") {
			t.Fatalf("validation: %d %s", rec.Code, rec.Body.String())
		}
	}
}

func TestVTIntegrationAdminAndRequestSourceGuards(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "reader", "a-long-test-password", model.RoleAnalyst)
	user, _ := f.login(t, "reader", "a-long-test-password")
	for _, route := range []struct {
		method, path string
		body         any
	}{{"GET", "/api/admin/integrations/virustotal", nil}, {"PUT", "/api/admin/integrations/virustotal", map[string]any{"api_key": strings.Repeat("ab", 32)}}, {"DELETE", "/api/admin/integrations/virustotal", nil}, {"POST", "/api/admin/integrations/virustotal/test", map[string]any{"acknowledge": true}}} {
		if rec := user.do(route.method, route.path, route.body); rec.Code != 403 {
			t.Fatalf("analyst allowed %s: %d", route.method, rec.Code)
		}
	}
	mux, _ := newTestRouterWithService(t)
	for _, origin := range []string{"https://foreign.invalid", "null"} {
		req := httptest.NewRequest("PUT", "http://127.0.0.1/api/admin/integrations/virustotal", strings.NewReader(`{"api_key":"`+strings.Repeat("ab", 32)+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		req.Header.Set("X-Tracefall-Client", "dashboard")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatal("foreign origin allowed", rec.Code)
		}
	}
}

func TestVTIntegrationChangesDoNotRaceAnInflightRequest(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	p := filepath.Join(t.TempDir(), ".integrations", "virustotal.key")
	if err := svc.ConfigureVirusTotalStorage(p, ""); err != nil {
		t.Fatal(err)
	}
	stub := newVTStub(t, svc)
	started, release := make(chan struct{}), make(chan struct{})
	stub.answers[hA] = func(w http.ResponseWriter) { close(started); <-release; w.Write([]byte(vtKnown)) }
	done := make(chan int, 1)
	go func() {
		rec := doJSON(t, mux, "POST", "/api/admin/integrations/virustotal/test", map[string]any{"acknowledge": true}, nil)
		done <- rec.Code
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not start")
	}
	rec := doJSON(t, mux, "DELETE", "/api/admin/integrations/virustotal", nil, nil)
	if rec.Code != 409 {
		t.Errorf("key changed during request: %d", rec.Code)
	}
	close(release)
	if code := <-done; code != 200 {
		t.Fatal("test request failed", code)
	}
	copy := svc.WithActor(LocalPrincipal())
	rec = doJSON(t, mux, "PUT", "/api/admin/integrations/virustotal", map[string]any{"api_key": strings.Repeat("ef", 32)}, nil)
	if rec.Code != 200 || !copy.vt.Configured() {
		t.Fatal("request copies did not see new config")
	}
	rec = doJSON(t, mux, "DELETE", "/api/admin/integrations/virustotal", nil, nil)
	if rec.Code != 200 || copy.vt.Configured() {
		t.Fatal("request copies did not see removed config")
	}
}

func TestVTIntegrationRefusedKeyAndStrictRequests(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newVTStub(t, svc)
	stub.answers[hA] = status(401, "DO-NOT-REFLECT-PROVIDER-BODY", nil)
	rec := doJSON(t, mux, "POST", "/api/admin/integrations/virustotal/test", map[string]any{"acknowledge": true}, nil)
	if rec.Code != 400 || strings.Contains(rec.Body.String(), "DO-NOT-REFLECT") {
		t.Fatalf("unsafe refused-key response: %d %s", rec.Code, rec.Body.String())
	}
	raw := NewRouter(svc, nil, testMaxUploadBytes, false)
	for _, tc := range []struct {
		host, origin, ctype, body, header string
		want                              int
	}{
		{"foreign.invalid", "", "application/json", `{}`, "dashboard", 403},
		{"127.0.0.1", "", "application/json", `{}`, "", 403},
		{"127.0.0.1", "", "text/plain", `{}`, "dashboard", 415},
		{"127.0.0.1", "", "application/json", `{"api_key":"` + strings.Repeat("ab", 32) + `"} {}`, "dashboard", 400},
	} {
		req := httptest.NewRequest("PUT", "http://"+tc.host+"/api/admin/integrations/virustotal", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", tc.ctype)
		if tc.header != "" {
			req.Header.Set("X-Tracefall-Client", tc.header)
		}
		result := httptest.NewRecorder()
		raw.ServeHTTP(result, req)
		if result.Code != tc.want {
			t.Errorf("strict request: got %d want %d", result.Code, tc.want)
		}
	}
}

func TestVTIntegrationSaveRestoreAndRemoveNeverReturnsKey(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	p := filepath.Join(t.TempDir(), ".integrations", "virustotal.key")
	if err := svc.ConfigureVirusTotalStorage(p, ""); err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("ab", 32)
	rec := doJSON(t, mux, "PUT", "/api/admin/integrations/virustotal", map[string]any{"api_key": key}, nil)
	if rec.Code != 200 {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), key) {
		t.Fatal("save returned key")
	}
	if !svc.vt.Configured() {
		t.Fatal("saved key not active without restart")
	}
	var st map[string]any
	rec = doJSON(t, mux, "GET", "/api/admin/integrations/virustotal", nil, &st)
	if rec.Code != 200 || st["configured"] != true || st["source"] != "saved" || strings.Contains(rec.Body.String(), key) {
		t.Fatalf("status: %d %s", rec.Code, rec.Body.String())
	}
	// Emulate a fresh process loading the same on-disk credential.
	_, fresh := newTestRouterWithService(t)
	if err := fresh.ConfigureVirusTotalStorage(p, ""); err != nil {
		t.Fatal(err)
	}
	if !fresh.vt.Configured() {
		t.Fatal("key not restored after restart")
	}
	// No network call or quota use merely by saving or reading configuration.
	if n, err := svc.store.CountProviderRequestsSince("virustotal", time.Time{}); err != nil || n != 0 {
		t.Fatalf("save spent quota: %d %v", n, err)
	}
	rec = doJSON(t, mux, "DELETE", "/api/admin/integrations/virustotal", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body.String())
	}
	if svc.vt.Configured() {
		t.Fatal("removed key still active")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("removed key still on disk")
	}
}
