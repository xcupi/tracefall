package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"
)

// Request-scoped security middleware (Phase 12).
//
// Authorization is enforced HERE, in one place that every API request
// passes through, rather than as a check each handler is expected to
// remember. A handler added later inherits the protection by default;
// the failure mode of a forgotten call is "denied", not "open".

type principalKey struct{}

// principalFrom returns the authenticated identity for a request.
//
// Every request that reaches a handler has one -- the middleware injects
// the local principal when authentication is disabled -- so a handler
// never has to distinguish "no user" from "not permitted", and absence
// can never be mistaken for permission.
func principalFrom(r *http.Request) Principal {
	if p, ok := r.Context().Value(principalKey{}).(Principal); ok {
		return p
	}
	// Reached only if a handler is invoked outside the middleware, which
	// would be a wiring bug. Deny rather than assume.
	return Principal{}
}

// AuthConfig controls how requests are authenticated.
type AuthConfig struct {
	// Enabled turns on session authentication. When false, every request
	// runs as the local principal -- the single-operator localhost mode
	// Tracefall shipped with before this phase.
	//
	// cmd/tracefall REFUSES TO START with Enabled=false on a non-loopback
	// address, so this can never silently mean "open to the LAN".
	Enabled bool
	// SessionTTL bounds a login's lifetime.
	SessionTTL time.Duration
	// SecureCookies marks session cookies Secure, for a deployment behind
	// HTTPS. Off by default because Tracefall speaks plain HTTP by
	// design; setting it without TLS would make login silently fail.
	SecureCookies bool
}

const (
	sessionCookieName = "tracefall_session"
	csrfCookieName    = "tracefall_csrf"
	csrfHeaderName    = "X-Tracefall-CSRF"
)

// withSecurity wraps the API mux with authentication, authorization and
// security headers.
func (h *handlers) withSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, true)

		if !h.auth.Enabled {
			// Single-operator mode: inject the local principal so handlers
			// and audit entries behave exactly as they did before Phase 12.
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, LocalPrincipal())))
			return
		}

		if isPublicRoute(r.URL.Path) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, Principal{})))
			return
		}

		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		p, err := h.svc.ResolveSession(cookie.Value)
		if err != nil {
			// Clear the dead cookie so the browser stops presenting it.
			clearCookie(w, sessionCookieName, h.auth.SecureCookies)
			writeError(w, http.StatusUnauthorized, "your session has expired; sign in again")
			return
		}

		// CSRF: cookies are an ambient credential, so a state-changing
		// request must prove it came from Tracefall's own page rather
		// than from a form on a site the analyst happened to visit.
		if !safeMethod(r.Method) && !h.csrfOK(r) {
			h.svc.auditSecurity("", "access_denied", "", "", p.Username,
				"Request rejected: missing or invalid CSRF token")
			writeError(w, http.StatusForbidden, "invalid or missing CSRF token")
			return
		}

		// A gated account may authenticate and may change its password.
		// Nothing else. Enforced HERE rather than in the UI, so the
		// requirement cannot be escaped by calling the API directly --
		// which is exactly what an attacker holding a printed bootstrap
		// credential would do.
		if p.MustChangePassword && !isPasswordChangeRoute(r.URL.Path) {
			writeError(w, http.StatusForbidden, ErrPasswordChangeRequired.Error())
			return
		}

		if role, ok := requiredRole(r.Method, r.URL.Path); ok && !p.Can(role) {
			// Denied access is itself security-relevant: an analyst
			// repeatedly probing admin endpoints is worth seeing.
			h.svc.auditSecurity(caseIDFromPath(r.URL.Path), "access_denied", "", "", p.Username,
				"Denied "+r.Method+" "+redactPath(r.URL.Path)+": requires role "+role)
			writeError(w, http.StatusForbidden, ErrForbidden.Error())
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

// safeMethod reports whether a method is read-only and therefore needs
// no CSRF token.
func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// csrfOK implements the double-submit cookie check: the request must
// carry a CSRF token in a header that matches the value in its own
// cookie. A cross-site attacker can cause the cookie to be SENT but
// cannot read it to set the header, because the same-origin policy stops
// them reading the response that would reveal it.
func (h *handlers) csrfOK(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	sent := r.Header.Get(csrfHeaderName)
	if sent == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(sent)) == 1
}

// isPasswordChangeRoute lists what a gated account may still reach.
//
// An explicit allow-list, deliberately tiny: the change-password
// endpoint itself, the session endpoint the dashboard needs to discover
// that it is gated, and logout so the user is never trapped.
func isPasswordChangeRoute(path string) bool {
	switch path {
	case "/api/auth/change-password", "/api/auth/session", "/api/auth/logout":
		return true
	}
	return false
}

// isPublicRoute reports whether a path may be reached unauthenticated.
//
// An explicit allow-list, not a prefix rule: adding a route must not be
// able to make it public by accident.
func isPublicRoute(path string) bool {
	switch path {
	case "/api/healthz", "/api/auth/login", "/api/auth/session":
		return true
	}
	return false
}

// adminRoutes are the operations that DESTROY forensic material or
// administer accounts.
//
// Matched by method plus a path pattern rather than by handler, so the
// rule is readable next to the endpoint list it mirrors and cannot drift
// as handlers are renamed.
func requiredRole(method, path string) (string, bool) {
	if strings.HasPrefix(path, "/api/admin/") {
		return "admin", true
	}
	if method == http.MethodDelete {
		// Every delete is admin-only: deletion is the privilege boundary,
		// because it is the only action that destroys evidence.
		return "admin", true
	}
	// Everything else authenticated is analyst-level, and admin holds
	// analyst privileges too (see Principal.Can).
	if strings.HasPrefix(path, "/api/") {
		return "analyst", true
	}
	return "", false
}

// caseIDFromPath extracts a case id from an API path for audit
// attribution. Best-effort: an audit entry with no case id is still a
// useful record.
func caseIDFromPath(path string) string {
	const prefix = "/api/cases/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(path, prefix)
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i]
	}
	return rest
}

// redactPath keeps an audit summary readable without embedding
// identifiers that make it a tracking record of its own.
func redactPath(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if len(p) >= 32 && strings.Count(p, "-") >= 4 {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

// setSecurityHeaders applies headers to every response.
//
// Chosen to be meaningful for THIS application rather than copied from a
// generic checklist:
//
//   - nosniff, because an evidence file's bytes must never be
//     content-sniffed into something executable.
//   - frame-ancestors 'none' plus X-Frame-Options, so the dashboard
//     cannot be framed for clickjacking a delete button.
//   - Referrer-Policy no-referrer, because a case id in a URL should not
//     travel to any external site.
//   - no-store on API responses, because they carry evidence content and
//     must not sit in a shared browser cache.
func setSecurityHeaders(w http.ResponseWriter, isAPI bool) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	if isAPI {
		h.Set("Cache-Control", "no-store")
	}
}

// SecurityHeaders wraps the non-API handlers (dashboard shell and static
// assets) with the same baseline plus a Content-Security-Policy.
//
// The CSP is written against what the dashboard actually does: one
// same-origin script bundle, one same-origin stylesheet, XHR to its own
// origin, and no external resource of any kind. 'unsafe-inline' is
// included for style-src ONLY because the existing dashboard sets a
// handful of inline style attributes; script-src has no such escape, so
// an injected <script> is blocked outright.
func SecurityHeaders(next http.Handler, secure bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, false)
		w.Header().Set("Content-Security-Policy", strings.Join([]string{
			"default-src 'self'",
			"script-src 'self'",
			"style-src 'self' 'unsafe-inline'",
			"img-src 'self' data:",
			"connect-src 'self'",
			"font-src 'self'",
			"object-src 'none'",
			"base-uri 'none'",
			"form-action 'self'",
			"frame-ancestors 'none'",
		}, "; "))
		next.ServeHTTP(w, r)
	})
}

// setCookie writes a session or CSRF cookie with the right flags.
func setCookie(w http.ResponseWriter, name, value string, ttl time.Duration, httpOnly, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:  name,
		Value: value,
		Path:  "/",
		// SameSite=Lax stops the cookie riding along with a cross-site
		// POST, which is the CSRF vector, while still allowing an analyst
		// to follow a link into Tracefall and stay signed in.
		SameSite: http.SameSiteLaxMode,
		HttpOnly: httpOnly,
		Secure:   secure,
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
	})
}

func clearCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/",
		SameSite: http.SameSiteLaxMode, HttpOnly: true, Secure: secure,
		Expires: time.Unix(0, 0), MaxAge: -1,
	})
}
