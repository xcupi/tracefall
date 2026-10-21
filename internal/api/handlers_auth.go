package api

import (
	"errors"
	"net/http"
	"strconv"

	"tracefall/internal/auth"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

// Authentication and account-administration handlers (Phase 12).
//
// Two rules run through this file:
//
//   - A password or session token never appears in a URL, a log line, an
//     audit summary, or a response body. The session token is written to
//     exactly one place: an HttpOnly cookie.
//   - Login failures are reported identically whatever the cause, so the
//     API cannot be used to discover which usernames exist.

// SessionInfo is what the dashboard needs to render its security state.
type SessionInfo struct {
	// AuthEnabled lets the UI tell "signed in as X" from
	// single-operator mode, rather than guessing from an empty username.
	AuthEnabled   bool   `json:"auth_enabled"`
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username,omitempty"`
	Role          string `json:"role,omitempty"`
	// CanDelete is the one permission the UI acts on directly. It is a
	// CONVENIENCE for rendering, never the enforcement point: the server
	// re-checks the role on every destructive request regardless of what
	// the UI chose to display.
	CanDelete bool `json:"can_delete"`
	// SetupRequired means authentication is on but no account exists yet.
	SetupRequired bool `json:"setup_required,omitempty"`
	// MustChangePassword tells the dashboard to show the forced
	// password-change screen instead of the application. The server
	// enforces the same rule independently (see middleware.go), so this
	// is what the UI renders, never what makes the rule true.
	MustChangePassword bool `json:"must_change_password,omitempty"`
}

// login authenticates and issues a session cookie.
func (h *handlers) login(w http.ResponseWriter, r *http.Request) {
	if !h.auth.Enabled {
		writeError(w, http.StatusBadRequest, "authentication is not enabled on this deployment")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	token, user, err := h.svc.LoginFrom(req.Username, req.Password, h.auth.SessionTTL, h.auth.clientAddr(r))
	if err != nil {
		switch {
		case errors.Is(err, ErrTooManyAttempts):
			writeError(w, http.StatusTooManyRequests, err.Error())
		case errors.Is(err, ErrAccountDisabled):
			writeError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, ErrInvalidCredentials):
			// One message for unknown-user and wrong-password alike.
			writeError(w, http.StatusUnauthorized, ErrInvalidCredentials.Error())
		default:
			h.fail(w, err)
		}
		return
	}

	ttl := h.auth.SessionTTL
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	// HttpOnly: script cannot read it, so an injected script cannot
	// exfiltrate the session even if one ever runs.
	setCookie(w, sessionCookieName, token, ttl, true, h.auth.SecureCookies)

	// The CSRF cookie is deliberately NOT HttpOnly: the dashboard's own
	// script must read it to echo it back in a header. That is safe --
	// its only power is to prove same-origin, and a cross-site attacker
	// cannot read it because of the same-origin policy.
	csrf, err := auth.NewSessionToken()
	if err != nil {
		h.fail(w, err)
		return
	}
	setCookie(w, csrfCookieName, csrf, ttl, false, h.auth.SecureCookies)

	writeJSON(w, http.StatusOK, SessionInfo{
		AuthEnabled: true, Authenticated: true,
		Username: user.Username, Role: user.Role,
		CanDelete:          user.Role == model.RoleAdmin,
		MustChangePassword: user.MustChangePassword,
	})
}

// logout invalidates the session server-side and clears the cookies.
func (h *handlers) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		_ = h.svc.Logout(c.Value, principalFrom(r))
	}
	clearCookie(w, sessionCookieName, h.auth.SecureCookies)
	clearCookie(w, csrfCookieName, h.auth.SecureCookies)
	writeJSON(w, http.StatusOK, SessionInfo{AuthEnabled: h.auth.Enabled})
}

// currentSession reports who the caller is.
//
// Public, because the dashboard has to ask it BEFORE it can know whether
// to show a login form. It reveals only whether this request is
// authenticated and, if so, its own username -- never anything about
// other accounts.
func (h *handlers) currentSession(w http.ResponseWriter, r *http.Request) {
	if !h.auth.Enabled {
		writeJSON(w, http.StatusOK, SessionInfo{
			AuthEnabled: false, Authenticated: false,
			Username: model.ActorLocalUser, Role: model.RoleAdmin, CanDelete: true,
		})
		return
	}
	info := SessionInfo{AuthEnabled: true}
	if n, err := h.svc.store.CountUsers(); err == nil && n == 0 {
		info.SetupRequired = true
	}
	if c, err := r.Cookie(sessionCookieName); err == nil {
		if p, err := h.svc.ResolveSession(c.Value); err == nil {
			info.Authenticated = true
			info.Username = p.Username
			info.Role = p.Role
			info.CanDelete = p.Can(model.RoleAdmin)
			info.MustChangePassword = p.MustChangePassword
		}
	}
	writeJSON(w, http.StatusOK, info)
}

// changeOwnPassword lets the signed-in user replace their own password.
//
// This is the route a gated bootstrap account uses to lift its gate, and
// the ordinary "change my password" route for everyone else -- one flow,
// not two, so there is a single implementation to reason about.
//
// Every existing session for the account is invalidated by the change,
// including the one making this request, so a fresh session is issued
// here. Otherwise a user would be signed out by the act of securing
// their own account, which teaches people not to do it.
func (h *handlers) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	if !h.auth.Enabled {
		writeError(w, http.StatusBadRequest, "authentication is not enabled on this deployment")
		return
	}
	p := principalFrom(r)
	if !p.Authenticated {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	if err := h.svc.ChangeOwnPassword(p, req.CurrentPassword, req.NewPassword); err != nil {
		switch {
		case errors.Is(err, ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "your current password is not correct")
		case errors.Is(err, ErrWeakPassword), errors.Is(err, ErrPasswordUnchanged):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, store.ErrUserNotFound):
			writeError(w, http.StatusNotFound, "user not found")
		default:
			h.fail(w, err)
		}
		return
	}

	// Re-authenticate with the NEW password to issue a fresh session.
	// Logging in again rather than minting a session directly keeps one
	// code path responsible for session creation.
	token, user, err := h.svc.LoginFrom(p.Username, req.NewPassword, h.auth.SessionTTL, h.auth.clientAddr(r))
	if err != nil {
		// The password change succeeded; only the convenience re-login
		// failed. Clear the dead cookies and let the user sign in again
		// rather than leaving them on a session that no longer exists.
		clearCookie(w, sessionCookieName, h.auth.SecureCookies)
		clearCookie(w, csrfCookieName, h.auth.SecureCookies)
		writeJSON(w, http.StatusOK, SessionInfo{AuthEnabled: true, Authenticated: false})
		return
	}

	ttl := h.auth.SessionTTL
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	setCookie(w, sessionCookieName, token, ttl, true, h.auth.SecureCookies)
	csrf, err := auth.NewSessionToken()
	if err != nil {
		h.fail(w, err)
		return
	}
	setCookie(w, csrfCookieName, csrf, ttl, false, h.auth.SecureCookies)

	writeJSON(w, http.StatusOK, SessionInfo{
		AuthEnabled: true, Authenticated: true,
		Username: user.Username, Role: user.Role,
		CanDelete:          user.Role == model.RoleAdmin,
		MustChangePassword: false,
	})
}

// ---------------- account administration (admin only) ----------------

func (h *handlers) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.svc.ListUsers()
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (h *handlers) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	u, err := h.svc.CreateUser(principalFrom(r), req.Username, req.Password, req.Role)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrDuplicateUsername):
			writeError(w, http.StatusConflict, err.Error())
		case errors.Is(err, ErrWeakPassword):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			h.failValidation(w, err)
		}
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (h *handlers) deleteUser(w http.ResponseWriter, r *http.Request) {
	actor := principalFrom(r)
	id := r.PathValue("userID")
	// An admin deleting their own account would log themselves out
	// mid-operation and is almost always a mistake.
	if id == actor.UserID {
		writeError(w, http.StatusBadRequest, "you cannot delete the account you are signed in with")
		return
	}
	if err := h.svc.DeleteUser(actor, id); err != nil {
		switch {
		case errors.Is(err, store.ErrUserNotFound):
			writeError(w, http.StatusNotFound, "user not found")
		case errors.Is(err, ErrLastAdmin):
			writeError(w, http.StatusConflict, err.Error())
		default:
			h.fail(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// updateUser changes a role, enabled state, or password.
func (h *handlers) updateUser(w http.ResponseWriter, r *http.Request) {
	actor := principalFrom(r)
	id := r.PathValue("userID")
	var req struct {
		Role     *string `json:"role,omitempty"`
		Disabled *bool   `json:"disabled,omitempty"`
		Password *string `json:"password,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	handle := func(err error) bool {
		if err == nil {
			return false
		}
		switch {
		case errors.Is(err, store.ErrUserNotFound):
			writeError(w, http.StatusNotFound, "user not found")
		case errors.Is(err, ErrLastAdmin):
			writeError(w, http.StatusConflict, err.Error())
		case errors.Is(err, ErrWeakPassword):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			h.failValidation(w, err)
		}
		return true
	}

	if req.Role != nil {
		if handle(h.svc.SetUserRole(actor, id, *req.Role)) {
			return
		}
	}
	if req.Disabled != nil {
		if id == actor.UserID && *req.Disabled {
			writeError(w, http.StatusBadRequest, "you cannot disable the account you are signed in with")
			return
		}
		if handle(h.svc.SetUserDisabled(actor, id, *req.Disabled)) {
			return
		}
	}
	if req.Password != nil {
		if handle(h.svc.SetUserPassword(actor, id, *req.Password)) {
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// failValidation reports an argument error as 400 rather than letting it
// fall through to h.fail's generic 500, which would log a routine
// mistake as an internal error.
func (h *handlers) failValidation(w http.ResponseWriter, err error) {
	writeError(w, http.StatusBadRequest, err.Error())
}

// securityLog serves the authentication/administration event log.
//
// Admin-only (enforced by the /api/admin/ rule in middleware.go). It is
// deliberately NOT part of a case export: it records who used the
// system, which is operational information about the team, not evidence
// about the incident.
func (h *handlers) securityLog(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	events, err := h.svc.store.ListSecurityLog(limit)
	if h.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, events)
}
