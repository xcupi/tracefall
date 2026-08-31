package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// gatedFixture is an authenticated deployment whose only account is a
// bootstrap-style admin behind a mandatory password change -- the state
// a freshly installed Tracefall is in.
func gatedFixture(t *testing.T, password string) (*authFixture, PublicUser) {
	t.Helper()
	f := newAuthFixture(t, time.Hour)
	u, err := f.svc.CreateBootstrapUser(
		Principal{Username: "bootstrap", Role: model.RoleAdmin},
		"tracefall", password, true)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	return f, u
}

// (10) The generated credential actually signs in, and (11) the account
// is reported as gated.
func TestBootstrapGate_LoginWorksAndReportsTheGate(t *testing.T) {
	f, _ := gatedFixture(t, "generated-bootstrap-pw")

	c, rec := f.login(t, "tracefall", "generated-bootstrap-pw")
	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap login: status %d, body %s", rec.Code, rec.Body.String())
	}
	var info SessionInfo
	json.Unmarshal(rec.Body.Bytes(), &info)
	if !info.MustChangePassword {
		t.Error("login did not report must_change_password for the bootstrap account")
	}
	if info.Username != "tracefall" || info.Role != model.RoleAdmin {
		t.Errorf("session info = %+v", info)
	}

	// The session endpoint reports it too, so a reload lands back on the
	// change screen rather than the dashboard.
	sess := c.do("GET", "/api/auth/session", nil)
	var s2 SessionInfo
	json.Unmarshal(sess.Body.Bytes(), &s2)
	if !s2.MustChangePassword {
		t.Error("session endpoint did not report the gate")
	}
}

// (12) The gate cannot be bypassed by calling the API directly. This is
// the property that matters: an attacker holding a printed bootstrap
// password would not use the UI.
func TestBootstrapGate_CannotBeBypassedThroughTheAPI(t *testing.T) {
	f, _ := gatedFixture(t, "generated-bootstrap-pw")
	c, _ := f.login(t, "tracefall", "generated-bootstrap-pw")

	// A broad sweep across reads, writes, admin operations and exports.
	for _, tc := range []struct {
		name, method, path string
		body               any
	}{
		{"list cases", "GET", "/api/cases", nil},
		{"create case", "POST", "/api/cases", map[string]string{"name": "should not exist"}},
		{"timeline", "GET", "/api/cases/any/timeline", nil},
		{"export", "GET", "/api/cases/any/export", nil},
		{"audit", "GET", "/api/cases/any/audit", nil},
		{"capabilities", "GET", "/api/capabilities", nil},
		{"list users", "GET", "/api/admin/users", nil},
		{"create user", "POST", "/api/admin/users",
			map[string]string{"username": "x", "password": "a-fine-password-1", "role": "analyst"}},
		{"security log", "GET", "/api/admin/security-log", nil},
		{"delete case", "DELETE", "/api/cases/any", nil},
	} {
		rec := c.do(tc.method, tc.path, tc.body)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s while gated: status %d, want 403", tc.name, rec.Code)
		}
		if !strings.Contains(strings.ToLower(rec.Body.String()), "change your password") {
			t.Errorf("%s: refusal does not explain the gate: %s", tc.name, rec.Body.String())
		}
	}

	// Nothing was created despite the attempts.
	if n, _ := f.svc.UserCount(); n != 1 {
		t.Errorf("user count = %d, want 1 -- a gated account created an account", n)
	}
}

// The gated account may still reach exactly what it needs to escape the
// gate, and nothing more.
func TestBootstrapGate_AllowsOnlySessionChangeAndLogout(t *testing.T) {
	f, _ := gatedFixture(t, "generated-bootstrap-pw")
	c, _ := f.login(t, "tracefall", "generated-bootstrap-pw")

	if rec := c.do("GET", "/api/auth/session", nil); rec.Code != http.StatusOK {
		t.Errorf("session endpoint while gated: %d, want 200", rec.Code)
	}
	// Wrong current password: rejected on its merits, NOT by the gate.
	rec := c.do("POST", "/api/auth/change-password",
		map[string]string{"current_password": "wrong", "new_password": "a-brand-new-password"})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("change-password with a wrong current password: %d, want 401", rec.Code)
	}
	if rec := c.do("POST", "/api/auth/logout", nil); rec.Code != http.StatusOK {
		t.Errorf("logout while gated: %d, want 200", rec.Code)
	}
}

// (13)(14)(15)(16)(17) The full change flow.
func TestBootstrapGate_PasswordChangeClearsTheGateAndRotatesCredentials(t *testing.T) {
	f, u := gatedFixture(t, "generated-bootstrap-pw")
	c, _ := f.login(t, "tracefall", "generated-bootstrap-pw")
	oldSession := c.session

	rec := c.do("POST", "/api/auth/change-password", map[string]string{
		"current_password": "generated-bootstrap-pw",
		"new_password":     "chosen-by-the-operator",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("change password: status %d, body %s", rec.Code, rec.Body.String())
	}
	var info SessionInfo
	json.Unmarshal(rec.Body.Bytes(), &info)
	if info.MustChangePassword {
		t.Error("the gate is still reported after a successful change")
	}
	if !info.Authenticated {
		t.Error("no fresh session was issued after the change")
	}

	// (16) The gate is cleared in the database, not just in the response.
	stored, err := f.svc.store.GetUser(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.MustChangePassword {
		t.Error("must_change_password is still set in the database")
	}

	// (17) Every pre-existing session is invalidated, including the one
	// that made the request.
	stale := &client{mux: f.mux, session: oldSession, csrf: c.csrf}
	if rec := stale.do("GET", "/api/cases", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("the session used to change the password still works: status %d, want 401", rec.Code)
	}

	// (14) The old password no longer authenticates.
	if _, rec := f.login(t, "tracefall", "generated-bootstrap-pw"); rec.Code == http.StatusOK {
		t.Error("the old bootstrap password still works after the change")
	}
	// (15) The new one does, and is no longer gated.
	fresh, rec2 := f.login(t, "tracefall", "chosen-by-the-operator")
	if rec2.Code != http.StatusOK {
		t.Fatalf("login with the new password: status %d, body %s", rec2.Code, rec2.Body.String())
	}
	var info2 SessionInfo
	json.Unmarshal(rec2.Body.Bytes(), &info2)
	if info2.MustChangePassword {
		t.Error("the account is still gated after changing its password")
	}
	// And normal operation is restored.
	if rec := fresh.do("GET", "/api/cases", nil); rec.Code != http.StatusOK {
		t.Errorf("normal API access after the change: status %d, want 200", rec.Code)
	}
	if rec := fresh.do("POST", "/api/cases", map[string]string{"name": "works now"}); rec.Code != http.StatusCreated {
		t.Errorf("creating a case after the change: status %d, want 201", rec.Code)
	}
}

// "Changing" the printed password to itself would satisfy the gate while
// leaving the displayed credential in force.
func TestBootstrapGate_RefusesAChangeToTheSamePassword(t *testing.T) {
	f, u := gatedFixture(t, "generated-bootstrap-pw")
	c, _ := f.login(t, "tracefall", "generated-bootstrap-pw")

	rec := c.do("POST", "/api/auth/change-password", map[string]string{
		"current_password": "generated-bootstrap-pw",
		"new_password":     "generated-bootstrap-pw",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("no-op password change: status %d, want 400", rec.Code)
	}
	stored, _ := f.svc.store.GetUser(u.ID)
	if !stored.MustChangePassword {
		t.Error("a refused no-op change cleared the gate")
	}
}

func TestBootstrapGate_RefusesAWeakNewPassword(t *testing.T) {
	f, u := gatedFixture(t, "generated-bootstrap-pw")
	c, _ := f.login(t, "tracefall", "generated-bootstrap-pw")

	rec := c.do("POST", "/api/auth/change-password", map[string]string{
		"current_password": "generated-bootstrap-pw",
		"new_password":     "short",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("weak new password: status %d, want 400", rec.Code)
	}
	stored, _ := f.svc.store.GetUser(u.ID)
	if !stored.MustChangePassword {
		t.Error("a refused weak change cleared the gate")
	}
}

// A session alone must not be enough to take an account over: the
// current password is required even though the caller is signed in.
func TestPasswordChange_RequiresTheCurrentPassword(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.mustCreateUser(t, "alice", "alices-real-password", model.RoleAnalyst)
	c, _ := f.login(t, "alice", "alices-real-password")

	rec := c.do("POST", "/api/auth/change-password", map[string]string{
		"current_password": "not-alices-password",
		"new_password":     "attacker-chosen-value",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", rec.Code)
	}
	// The original password still works.
	if _, rec := f.login(t, "alice", "alices-real-password"); rec.Code != http.StatusOK {
		t.Error("the account's password was changed despite a wrong current password")
	}
}

// (3)(4) The generated password is random and never stored in plaintext.
func TestBootstrap_PasswordIsRandomAndNeverStoredPlaintext(t *testing.T) {
	const pw = "generated-bootstrap-pw"
	f, u := gatedFixture(t, pw)

	stored, err := f.svc.store.GetUser(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored.PasswordHash, pw) {
		t.Fatal("the stored hash contains the plaintext password")
	}
	if !strings.HasPrefix(stored.PasswordHash, "pbkdf2-sha256$600000$") {
		t.Errorf("bootstrap account is not using the existing PBKDF2 parameters: %q", stored.PasswordHash)
	}
	// (9) and no plaintext anywhere in the security log.
	events, _ := f.svc.store.ListSecurityLog(0)
	for _, e := range events {
		if strings.Contains(e.Summary+e.Actor+e.TargetID, pw) {
			t.Errorf("the bootstrap password leaked into a security event: %+v", e)
		}
	}
}

// (2) The username is exactly "tracefall", and (1) exactly one admin
// exists after bootstrap.
func TestBootstrap_CreatesExactlyOneAdminNamedTracefall(t *testing.T) {
	f, _ := gatedFixture(t, "generated-bootstrap-pw")

	users, err := f.svc.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Fatalf("got %d users after bootstrap, want exactly 1", len(users))
	}
	if users[0].Username != "tracefall" {
		t.Errorf("username = %q, want %q", users[0].Username, "tracefall")
	}
	if users[0].Role != model.RoleAdmin {
		t.Errorf("role = %q, want %q", users[0].Role, model.RoleAdmin)
	}
	if !users[0].MustChangePassword {
		t.Error("the bootstrap account is not gated behind a password change")
	}
}

// (18) An ordinary account created by an admin is NOT gated -- the gate
// is for a server-generated, displayed credential, not for every account.
func TestBootstrap_OrdinaryAccountsAreNotGated(t *testing.T) {
	f, _ := gatedFixture(t, "generated-bootstrap-pw")
	c, _ := f.login(t, "tracefall", "generated-bootstrap-pw")
	c.do("POST", "/api/auth/change-password", map[string]string{
		"current_password": "generated-bootstrap-pw",
		"new_password":     "chosen-by-the-operator",
	})
	admin, _ := f.login(t, "tracefall", "chosen-by-the-operator")

	rec := admin.do("POST", "/api/admin/users",
		map[string]string{"username": "analyst9", "password": "analyst-password-99", "role": model.RoleAnalyst})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create analyst: status %d, body %s", rec.Code, rec.Body.String())
	}

	analyst, rec2 := f.login(t, "analyst9", "analyst-password-99")
	if rec2.Code != http.StatusOK {
		t.Fatalf("analyst login: %d", rec2.Code)
	}
	var info SessionInfo
	json.Unmarshal(rec2.Body.Bytes(), &info)
	if info.MustChangePassword {
		t.Error("an admin-created account was gated behind a password change")
	}
	if rec := analyst.do("GET", "/api/cases", nil); rec.Code != http.StatusOK {
		t.Errorf("analyst normal access: status %d, want 200", rec.Code)
	}
}
