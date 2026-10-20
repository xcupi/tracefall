package api

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A JSON body past the limit is refused with 413, on the public login route
// as on any other, instead of being read whole into memory.
func TestDecodeJSON_RefusesAnOversizedBody(t *testing.T) {
	body := `{"username":"` + strings.Repeat("a", maxJSONBodyBytes+10) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	var v struct{ Username string }
	if decodeJSON(rec, req, &v) {
		t.Fatal("an oversized body was accepted")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", rec.Code)
	}
}

// The throttle table stays bounded under a flood of distinct usernames, and
// entries that expired are swept.
func TestLoginThrottle_TableIsBounded(t *testing.T) {
	th := newLoginThrottle()
	now := time.Now()
	for i := 0; i < maxThrottleEntries*3; i++ {
		th.recordFailure("user-"+strconv.Itoa(i), now)
	}
	if n := len(th.failures); n > maxThrottleEntries {
		t.Fatalf("table holds %d entries, limit %d", n, maxThrottleEntries)
	}
	// After the window every entry is expired, so a new name is recorded again.
	later := now.Add(th.window + time.Minute)
	th.recordFailure("fresh", later)
	if _, ok := th.failures["fresh"]; !ok {
		t.Fatal("a new username was not recorded after expired entries were swept")
	}
	if n := len(th.failures); n > 1 {
		t.Fatalf("expired entries were not swept: %d left", n)
	}
}

// HSTS is sent on a TLS connection and only there.
func TestSecurityHeaders_HSTSOnlyOverTLS(t *testing.T) {
	h := SecurityHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), true)
	plain := httptest.NewRecorder()
	h.ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "/", nil))
	if v := plain.Header().Get("Strict-Transport-Security"); v != "" {
		t.Errorf("HSTS sent over plain HTTP: %q", v)
	}
	req := httptest.NewRequest(http.MethodGet, "https://localhost/", nil)
	req.TLS = &tls.ConnectionState{}
	secure := httptest.NewRecorder()
	h.ServeHTTP(secure, req)
	if secure.Header().Get("Strict-Transport-Security") == "" {
		t.Error("no HSTS over TLS")
	}
}
