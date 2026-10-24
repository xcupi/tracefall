package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

func TestReviewBatchesCentralRequestSourceAndSessionGuards(t *testing.T) {
	mux := rawNoAuthRouter(t)
	path := "/api/cases/synthetic/enrich/case-review/batches/plan"
	for _, test := range []struct{ host, origin, client string }{{"foreign.invalid", "", "dashboard"}, {"127.0.0.1", "https://foreign.invalid", "dashboard"}, {"127.0.0.1", "", ""}} {
		req := httptest.NewRequest("POST", "http://127.0.0.1"+path, strings.NewReader(`{}`))
		req.Host = test.host
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", test.origin)
		req.Header.Set("X-Tracefall-Client", test.client)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("source checks bypassed: %+v got %d", test, rec.Code)
		}
	}
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "analyst01", "synthetic-long-password", model.RoleAnalyst)
	req := httptest.NewRequest("GET", "http://127.0.0.1"+strings.TrimSuffix(path, "/plan"), nil)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("batch read bypassed session: %d", rec.Code)
	}
	user, login := f.login(t, "analyst01", "synthetic-long-password")
	if login.Code != 200 {
		t.Fatalf("synthetic login: %d", login.Code)
	}
	user.csrf = ""
	rec = user.do("POST", path, map[string]any{})
	if rec.Code != 403 || !strings.Contains(strings.ToLower(rec.Body.String()), "csrf") {
		t.Fatalf("batch plan bypassed CSRF: %d %s", rec.Code, rec.Body.String())
	}
	for _, method := range []string{"GET", "POST"} {
		role, ok := requiredRole(method, path)
		if !ok || role != "analyst" {
			t.Fatalf("batch route role not centrally guarded: %s %q %t", method, role, ok)
		}
	}
}
