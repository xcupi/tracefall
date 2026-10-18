package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/store"
)

// authFixture is an authenticated deployment plus a way to act as a
// given user.
type authFixture struct {
	svc *Service
	mux http.Handler
}

func newAuthFixture(t *testing.T, ttl time.Duration) *authFixture {
	t.Helper()
	svc := newTestService(t)
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	mux := dashboardLike(NewRouterWithAuth(svc, logger, testMaxUploadBytes, false, AuthConfig{
		Enabled: true, SessionTTL: ttl,
	}))
	return &authFixture{svc: svc, mux: mux}
}

func (f *authFixture) mustCreateUser(t *testing.T, username, password, role string) PublicUser {
	t.Helper()
	u, err := f.svc.CreateUser(Principal{Username: "test-setup", Role: model.RoleAdmin}, username, password, role)
	if err != nil {
		t.Fatalf("creating %s: %v", username, err)
	}
	return u
}

// client is a logged-in caller that carries its session and CSRF token,
// exactly as a browser would.
type client struct {
	mux     http.Handler
	session string
	csrf    string
}

func (f *authFixture) login(t *testing.T, username, password string) (*client, *httptest.ResponseRecorder) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	f.mux.ServeHTTP(rec, req)

	c := &client{mux: f.mux}
	for _, ck := range rec.Result().Cookies() {
		switch ck.Name {
		case sessionCookieName:
			c.session = ck.Value
		case csrfCookieName:
			c.csrf = ck.Value
		}
	}
	return c, rec
}

func (c *client) do(method, path string, body any) *httptest.ResponseRecorder {
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if c.session != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: c.session})
	}
	if c.csrf != "" {
		r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: c.csrf})
		r.Header.Set(csrfHeaderName, c.csrf)
	}
	rec := httptest.NewRecorder()
	c.mux.ServeHTTP(rec, r)
	return rec
}

// ---------------- authentication ----------------

func TestAuth_SuccessfulLogin(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)

	c, rec := f.login(t, "alice", "correct-horse-battery")
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status %d, body %s", rec.Code, rec.Body.String())
	}
	if c.session == "" {
		t.Fatal("no session cookie issued")
	}
	if c.csrf == "" {
		t.Fatal("no CSRF cookie issued")
	}

	var info SessionInfo
	json.Unmarshal(rec.Body.Bytes(), &info)
	if !info.Authenticated || info.Username != "alice" || info.Role != model.RoleAnalyst {
		t.Errorf("session info = %+v", info)
	}
	if info.CanDelete {
		t.Error("an analyst was told they can delete")
	}
	// The response must never contain password material.
	if strings.Contains(rec.Body.String(), "correct-horse-battery") ||
		strings.Contains(rec.Body.String(), "pbkdf2") {
		t.Error("login response leaked password material")
	}
	// The session token must not appear in the body -- only in the cookie.
	if strings.Contains(rec.Body.String(), c.session) {
		t.Error("session token appeared in the response body")
	}
}

func TestAuth_SessionCookieFlags(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)
	_, rec := f.login(t, "alice", "correct-horse-battery")

	var session, csrf *http.Cookie
	for _, ck := range rec.Result().Cookies() {
		switch ck.Name {
		case sessionCookieName:
			session = ck
		case csrfCookieName:
			csrf = ck
		}
	}
	if session == nil {
		t.Fatal("no session cookie")
	}
	if !session.HttpOnly {
		t.Error("session cookie is not HttpOnly; script could read the session")
	}
	if session.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie SameSite = %v, want Lax", session.SameSite)
	}
	if session.Path != "/" {
		t.Errorf("session cookie path = %q", session.Path)
	}
	// The CSRF cookie MUST be readable by script -- the dashboard has to
	// echo it back in a header for the double-submit check.
	if csrf == nil {
		t.Fatal("no CSRF cookie")
	}
	if csrf.HttpOnly {
		t.Error("CSRF cookie is HttpOnly; the dashboard cannot read it to echo it back")
	}
}

func TestAuth_InvalidPasswordAndUnknownUserAreIndistinguishable(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)

	_, wrongPass := f.login(t, "alice", "wrong-password-here")
	_, unknown := f.login(t, "nosuchuser", "wrong-password-here")

	if wrongPass.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: status %d, want 401", wrongPass.Code)
	}
	if wrongPass.Code != unknown.Code {
		t.Errorf("wrong password (%d) is distinguishable from unknown user (%d): a username oracle",
			wrongPass.Code, unknown.Code)
	}
	if wrongPass.Body.String() != unknown.Body.String() {
		t.Errorf("bodies differ:\n wrong pass: %s\n unknown:    %s", wrongPass.Body.String(), unknown.Body.String())
	}
	if len(wrongPass.Result().Cookies()) != 0 {
		t.Error("a failed login issued cookies")
	}
}

func TestAuth_UnauthenticatedRequestsAreRejected(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	anon := &client{mux: f.mux}

	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/cases"},
		{"POST", "/api/cases"},
		{"GET", "/api/cases/any/timeline"},
		{"GET", "/api/cases/any/export"},
		{"GET", "/api/cases/any/audit"},
		{"DELETE", "/api/cases/any"},
		{"GET", "/api/admin/users"},
	} {
		rec := anon.do(tc.method, tc.path, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: status %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
}

func TestAuth_PublicRoutesStayReachable(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	anon := &client{mux: f.mux}
	for _, path := range []string{"/api/healthz", "/api/auth/session"} {
		if rec := anon.do("GET", path, nil); rec.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200 (public)", path, rec.Code)
		}
	}
}

func TestAuth_InvalidSessionTokenIsRejected(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)
	c, _ := f.login(t, "alice", "correct-horse-battery")

	forged := &client{mux: f.mux, session: "not-a-real-token", csrf: c.csrf}
	if rec := forged.do("GET", "/api/cases", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("forged token: status %d, want 401", rec.Code)
	}
	// A token that is a valid-looking base64 string but never issued.
	forged2 := &client{mux: f.mux, session: strings.Repeat("A", 43), csrf: c.csrf}
	if rec := forged2.do("GET", "/api/cases", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("unissued token: status %d, want 401", rec.Code)
	}
}

func TestAuth_ExpiredSessionIsRejected(t *testing.T) {
	// A one-nanosecond lifetime is expired by the time the next request
	// is built, without the test having to sleep.
	f := newAuthFixture(t, time.Nanosecond)
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)
	c, rec := f.login(t, "alice", "correct-horse-battery")
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d", rec.Code)
	}
	time.Sleep(2 * time.Millisecond)

	got := c.do("GET", "/api/cases", nil)
	if got.Code != http.StatusUnauthorized {
		t.Errorf("expired session: status %d, want 401", got.Code)
	}
	// The dead cookie must be cleared so the browser stops sending it.
	var cleared bool
	for _, ck := range got.Result().Cookies() {
		if ck.Name == sessionCookieName && ck.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("an expired session did not clear the session cookie")
	}
}

func TestAuth_LogoutInvalidatesTheSessionServerSide(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)
	c, _ := f.login(t, "alice", "correct-horse-battery")

	if rec := c.do("GET", "/api/cases", nil); rec.Code != http.StatusOK {
		t.Fatalf("pre-logout request: %d", rec.Code)
	}
	if rec := c.do("POST", "/api/auth/logout", nil); rec.Code != http.StatusOK {
		t.Fatalf("logout: %d", rec.Code)
	}
	// The same token must now be useless even though the client still
	// presents it -- this is why sessions are server-side.
	if rec := c.do("GET", "/api/cases", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("session still valid after logout: status %d, want 401", rec.Code)
	}
}

func TestAuth_DisabledAccountCannotLogInAndLosesSessions(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "admin1", "admin-password-here", model.RoleAdmin)
	u := f.mustCreateUser(t, "bob", "bob-password-here-1", model.RoleAnalyst)
	bob, _ := f.login(t, "bob", "bob-password-here-1")
	if rec := bob.do("GET", "/api/cases", nil); rec.Code != http.StatusOK {
		t.Fatal("bob could not use his session before being disabled")
	}

	admin, _ := f.login(t, "admin1", "admin-password-here")
	if rec := admin.do("PATCH", "/api/admin/users/"+u.ID, map[string]any{"disabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("disable: status %d, body %s", rec.Code, rec.Body.String())
	}

	if rec := bob.do("GET", "/api/cases", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("a disabled user's existing session still works: status %d", rec.Code)
	}
	if _, rec := f.login(t, "bob", "bob-password-here-1"); rec.Code == http.StatusOK {
		t.Error("a disabled account could log in")
	}
}

func TestAuth_LoginThrottleBlocksRepeatedFailures(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)

	var blocked bool
	for i := 0; i < 15; i++ {
		_, rec := f.login(t, "alice", "wrong-password")
		if rec.Code == http.StatusTooManyRequests {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Error("repeated failed logins were never throttled")
	}
	// The correct password is also refused while throttled -- otherwise
	// the throttle would not slow an attacker who eventually guesses.
	if _, rec := f.login(t, "alice", "correct-horse-battery"); rec.Code == http.StatusOK {
		t.Error("throttle did not apply to a correct password during the block window")
	}
}

// ---------------- CSRF ----------------

func TestAuth_StateChangingRequestRequiresCSRFToken(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)
	c, _ := f.login(t, "alice", "correct-horse-battery")

	// A request carrying the session cookie but NO CSRF header is
	// exactly what a cross-site form submission looks like.
	noCSRF := &client{mux: f.mux, session: c.session}
	if rec := noCSRF.do("POST", "/api/cases", map[string]string{"name": "csrf case"}); rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF token: status %d, want 403", rec.Code)
	}
	// A mismatched token is equally rejected.
	bad := &client{mux: f.mux, session: c.session, csrf: "mismatched-token"}
	badReq := httptest.NewRequest("POST", "/api/cases", strings.NewReader(`{"name":"x"}`))
	badReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: c.session})
	badReq.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "cookie-value"})
	badReq.Header.Set(csrfHeaderName, "header-value")
	rec := httptest.NewRecorder()
	bad.mux.ServeHTTP(rec, badReq)
	if rec.Code != http.StatusForbidden {
		t.Errorf("mismatched CSRF token: status %d, want 403", rec.Code)
	}

	// Reads are unaffected.
	readOnly := &client{mux: f.mux, session: c.session}
	if rec := readOnly.do("GET", "/api/cases", nil); rec.Code != http.StatusOK {
		t.Errorf("GET without CSRF token: status %d, want 200", rec.Code)
	}
}

// ---------------- authorization ----------------

func TestAuthz_AnalystCanDoAnalystWork(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)
	c, _ := f.login(t, "alice", "correct-horse-battery")

	rec := c.do("POST", "/api/cases", map[string]string{"name": "Analyst case"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create case: status %d, body %s", rec.Code, rec.Body.String())
	}
	var created model.Case
	json.Unmarshal(rec.Body.Bytes(), &created)

	for _, tc := range []struct {
		name, method, path string
		body               any
		want               int
	}{
		{"list cases", "GET", "/api/cases", nil, http.StatusOK},
		{"get case", "GET", "/api/cases/" + created.ID, nil, http.StatusOK},
		{"timeline", "GET", "/api/cases/" + created.ID + "/timeline", nil, http.StatusOK},
		{"findings", "GET", "/api/cases/" + created.ID + "/findings", nil, http.StatusOK},
		{"provenance", "GET", "/api/cases/" + created.ID + "/provenance", nil, http.StatusOK},
		{"export", "GET", "/api/cases/" + created.ID + "/export", nil, http.StatusOK},
		{"audit", "GET", "/api/cases/" + created.ID + "/audit", nil, http.StatusOK},
		{"add note", "POST", "/api/cases/" + created.ID + "/notes",
			map[string]string{"target_type": model.TargetCase, "target_id": created.ID, "note": "n"}, http.StatusCreated},
		{"update metadata", "PATCH", "/api/cases/" + created.ID,
			map[string]string{"case_status": "investigating"}, http.StatusOK},
	} {
		if rec := c.do(tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d (body %s)", tc.name, rec.Code, tc.want, rec.Body.String())
		}
	}
}

// The privilege boundary: an analyst must not be able to DESTROY
// evidence or administer accounts.
func TestAuthz_AnalystCannotPerformAdminOperations(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "admin1", "admin-password-here", model.RoleAdmin)
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)
	alice, _ := f.login(t, "alice", "correct-horse-battery")

	rec := alice.do("POST", "/api/cases", map[string]string{"name": "To delete"})
	var c model.Case
	json.Unmarshal(rec.Body.Bytes(), &c)

	for _, tc := range []struct{ name, method, path string }{
		{"delete case", "DELETE", "/api/cases/" + c.ID},
		{"bulk delete cases", "DELETE", "/api/cases"},
		{"delete evidence", "DELETE", "/api/cases/" + c.ID + "/evidence"},
		{"delete source file", "DELETE", "/api/cases/" + c.ID + "/evidence/some-id"},
		{"list users", "GET", "/api/admin/users"},
		{"create user", "POST", "/api/admin/users"},
		{"delete user", "DELETE", "/api/admin/users/some-id"},
	} {
		got := alice.do(tc.method, tc.path, map[string]any{"ids": []string{c.ID}})
		if got.Code != http.StatusForbidden {
			t.Errorf("%s as analyst: status %d, want 403", tc.name, got.Code)
		}
	}

	// The case must still exist -- refusal, not partial execution.
	admin, _ := f.login(t, "admin1", "admin-password-here")
	if rec := admin.do("GET", "/api/cases/"+c.ID, nil); rec.Code != http.StatusOK {
		t.Error("the case an analyst was refused permission to delete is gone")
	}
}

func TestAuthz_AdminCanPerformAdminOperations(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "admin1", "admin-password-here", model.RoleAdmin)
	admin, _ := f.login(t, "admin1", "admin-password-here")

	rec := admin.do("POST", "/api/cases", map[string]string{"name": "Admin case"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin create case: %d", rec.Code)
	}
	var c model.Case
	json.Unmarshal(rec.Body.Bytes(), &c)

	// Admin holds analyst privileges too.
	if rec := admin.do("GET", "/api/cases/"+c.ID+"/timeline", nil); rec.Code != http.StatusOK {
		t.Errorf("admin denied an analyst-level read: %d", rec.Code)
	}
	if rec := admin.do("GET", "/api/admin/users", nil); rec.Code != http.StatusOK {
		t.Errorf("admin denied user administration: %d", rec.Code)
	}
	if rec := admin.do("DELETE", "/api/cases/"+c.ID, nil); rec.Code != http.StatusOK {
		t.Errorf("admin denied case deletion: status %d, body %s", rec.Code, rec.Body.String())
	}
	if rec := admin.do("GET", "/api/cases/"+c.ID, nil); rec.Code == http.StatusOK {
		t.Error("the case still exists after an admin deleted it")
	}
}

// ---------------- account administration ----------------

func TestAdmin_CannotRemoveTheLastAdmin(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	only := f.mustCreateUser(t, "admin1", "admin-password-here", model.RoleAdmin)
	second := f.mustCreateUser(t, "admin2", "admin2-password-x1", model.RoleAdmin)
	admin, _ := f.login(t, "admin1", "admin-password-here")

	// With two admins, demoting one is fine.
	if rec := admin.do("PATCH", "/api/admin/users/"+second.ID,
		map[string]any{"role": model.RoleAnalyst}); rec.Code != http.StatusOK {
		t.Fatalf("demote second admin: status %d, body %s", rec.Code, rec.Body.String())
	}

	// Now admin1 is the last one and cannot be removed by any route.
	if rec := admin.do("PATCH", "/api/admin/users/"+only.ID,
		map[string]any{"role": model.RoleAnalyst}); rec.Code != http.StatusConflict {
		t.Errorf("demoting the last admin: status %d, want 409", rec.Code)
	}
	if rec := admin.do("PATCH", "/api/admin/users/"+only.ID,
		map[string]any{"disabled": true}); rec.Code == http.StatusOK {
		t.Error("the last admin was disabled, locking everyone out")
	}
	if rec := admin.do("DELETE", "/api/admin/users/"+only.ID, nil); rec.Code == http.StatusOK {
		t.Error("the last admin was deleted, locking everyone out")
	}
}

func TestAdmin_PasswordPolicyAndDuplicateUsernames(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "admin1", "admin-password-here", model.RoleAdmin)
	admin, _ := f.login(t, "admin1", "admin-password-here")

	if rec := admin.do("POST", "/api/admin/users",
		map[string]string{"username": "shorty", "password": "short", "role": model.RoleAnalyst}); rec.Code != http.StatusBadRequest {
		t.Errorf("short password: status %d, want 400", rec.Code)
	}
	if rec := admin.do("POST", "/api/admin/users",
		map[string]string{"username": "ADMIN1", "password": "another-password-1", "role": model.RoleAnalyst}); rec.Code != http.StatusConflict {
		t.Errorf("duplicate username (different case): status %d, want 409", rec.Code)
	}
	if rec := admin.do("POST", "/api/admin/users",
		map[string]string{"username": "bogus", "password": "a-fine-password-1", "role": "superuser"}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown role: status %d, want 400", rec.Code)
	}
}

// Password material must never appear in any account listing.
func TestAdmin_UserListingNeverExposesPasswordMaterial(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "admin1", "admin-password-here", model.RoleAdmin)
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)
	admin, _ := f.login(t, "admin1", "admin-password-here")

	rec := admin.do("GET", "/api/admin/users", nil)
	body := rec.Body.String()
	for _, forbidden := range []string{"password", "pbkdf2", "correct-horse-battery", "admin-password-here", "hash"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("user listing contains %q: %s", forbidden, body)
		}
	}
}

// ---------------- audit ----------------

func TestAudit_RecordsAuthenticatedActorNotGenericLocalUser(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)
	c, _ := f.login(t, "alice", "correct-horse-battery")

	rec := c.do("POST", "/api/cases", map[string]string{"name": "Actor case"})
	var created model.Case
	json.Unmarshal(rec.Body.Bytes(), &created)

	var entries []model.AuditEvent
	got := c.do("GET", "/api/cases/"+created.ID+"/audit", nil)
	json.Unmarshal(got.Body.Bytes(), &entries)
	if len(entries) == 0 {
		t.Fatal("no audit entries for a newly created case")
	}
	for _, e := range entries {
		if e.Actor != "alice" {
			t.Errorf("audit entry %q recorded actor %q, want the authenticated username", e.Action, e.Actor)
		}
	}
}

func TestAudit_LoginEventsAreRecordedWithoutSecrets(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)
	f.login(t, "alice", "wrong-password-attempt")
	c, _ := f.login(t, "alice", "correct-horse-battery")
	c.do("POST", "/api/auth/logout", nil)

	all, err := f.svc.store.ListSecurityLog(0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range all {
		seen[e.Action] = true
		blob := e.Summary + " " + e.Actor + " " + e.TargetID
		for _, secret := range []string{"correct-horse-battery", "wrong-password-attempt", "pbkdf2", c.session, c.csrf} {
			if secret != "" && strings.Contains(blob, secret) {
				t.Errorf("audit entry %q leaked a secret: %q", e.Action, blob)
			}
		}
	}
	for _, want := range []string{model.AuditLoginFailed, model.AuditLoginSucceeded, model.AuditLogout} {
		if !seen[want] {
			t.Errorf("no %q audit entry was recorded", want)
		}
	}
}

func TestAudit_DeniedAccessIsRecorded(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)
	alice, _ := f.login(t, "alice", "correct-horse-battery")
	alice.do("GET", "/api/admin/users", nil)

	all, _ := f.svc.store.ListSecurityLog(0)
	var found bool
	for _, e := range all {
		if e.Action == "access_denied" && e.Actor == "alice" {
			found = true
		}
	}
	if !found {
		t.Error("a denied admin request left no audit record")
	}
}

// ---------------- password hashing ----------------

func TestAuth_PasswordsAreNeverStoredInPlaintext(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)

	u, err := f.svc.store.FindUserByUsername("alice")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(u.PasswordHash, "correct-horse-battery") {
		t.Fatal("the stored hash contains the plaintext password")
	}
	if !strings.HasPrefix(u.PasswordHash, "pbkdf2-sha256$") {
		t.Errorf("unexpected hash format: %q", u.PasswordHash)
	}
	// Two users with the SAME password must have different hashes, or the
	// salt is not doing its job.
	f.mustCreateUser(t, "bob", "correct-horse-battery", model.RoleAnalyst)
	b, _ := f.svc.store.FindUserByUsername("bob")
	if b.PasswordHash == u.PasswordHash {
		t.Error("identical passwords produced identical hashes; the salt is not per-user")
	}
}

// Sessions must be stored hashed, so a stolen database yields no usable
// cookies.
func TestAuth_SessionTokensAreStoredHashed(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "alice", "correct-horse-battery", model.RoleAnalyst)
	c, _ := f.login(t, "alice", "correct-horse-battery")

	_, _, err := f.svc.store.SessionUser(c.session, time.Now().UTC())
	if err == nil {
		t.Error("the raw session token matched a stored row; tokens must be stored hashed")
	}
	if !isSessionNotFound(err) {
		t.Errorf("unexpected error: %v", err)
	}
}

func isSessionNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), store.ErrSessionNotFound.Error())
}
