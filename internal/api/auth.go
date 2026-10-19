package api

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"tracefall/internal/auth"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

// Authentication service (Phase 12).
//
// # Shape of the design
//
// Local accounts, server-side sessions, cookie transport. No external
// identity provider, no self-contained tokens.
//
//   - LOCAL accounts because a DFIR deployment is usually one small team
//     on an isolated network, where an OIDC dependency is a liability
//     rather than a feature.
//   - SERVER-SIDE sessions because logout has to actually revoke access.
//     A signed self-contained token stays valid until it expires no
//     matter what the server decides, and for a tool holding evidence,
//     "revoke that session now" is worth more than statelessness.
//   - COOKIES because the dashboard is a browser application; a token in
//     localStorage is readable by any script that gets injected, whereas
//     HttpOnly is not. Cookies are an ambient credential, so CSRF
//     defence is mandatory and is implemented alongside (see csrf.go).

var (
	// ErrInvalidCredentials is returned for an unknown username AND for a
	// wrong password, deliberately identically, so the API cannot be used
	// to enumerate valid usernames.
	ErrInvalidCredentials = errors.New("invalid username or password")
	// ErrAccountDisabled means the account exists but has been disabled.
	ErrAccountDisabled = errors.New("this account is disabled")
	// ErrNotAuthenticated means no valid session accompanied the request.
	ErrNotAuthenticated = errors.New("authentication required")
	// ErrForbidden means the caller is authenticated but lacks the role.
	ErrForbidden = errors.New("your role does not permit this operation")
	// ErrTooManyAttempts means login is temporarily throttled.
	ErrTooManyAttempts = errors.New("too many failed login attempts; try again shortly")
	// ErrLastAdmin guards against removing the last way in.
	ErrLastAdmin = errors.New("this is the last enabled admin account; promote another admin first")
	// ErrWeakPassword means the password does not meet the minimum.
	ErrWeakPassword = fmt.Errorf("password must be at least %d characters", minPasswordLength)
	// ErrPasswordUnchanged means the new password equals the current one.
	ErrPasswordUnchanged = errors.New("the new password must be different from the current one")
	// ErrPasswordChangeRequired means the account must set a new password
	// before it may do anything else.
	ErrPasswordChangeRequired = errors.New("you must change your password before continuing")
)

// minPasswordLength is a floor, not a policy.
//
// Tracefall deliberately does not impose composition rules (mixed case,
// symbols, rotation): they are known to push people toward predictable
// passwords, and NIST SP 800-63B recommends length plus a blocklist
// instead. A floor of 12 with a slow KDF is the honest minimum for a
// tool that cannot enforce anything about the environment it runs in.
const minPasswordLength = 12

// Session lifetime.
const (
	// DefaultSessionTTL bounds how long one login stays usable. Long
	// enough for a working day of analysis, short enough that an
	// unattended browser is not indefinitely authenticated.
	DefaultSessionTTL = 12 * time.Hour
)

// loginSlots bounds concurrent password verifications.
var loginSlots = make(chan struct{}, max(2, runtime.NumCPU()))

// loginThrottle rate-limits failed logins per username.
//
// In memory, not in the database. Throttling state is operational, not
// forensic: it must not survive a restart (a restart is a legitimate
// reset), must not be exported with a case, and must not add a write to
// the single SQLite connection on every failed guess -- which would turn
// the throttle itself into a denial-of-service vector.
type loginThrottle struct {
	mu       sync.Mutex
	failures map[string]*throttleEntry
	max      int
	window   time.Duration
}

type throttleEntry struct {
	count int
	first time.Time
}

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{
		failures: map[string]*throttleEntry{},
		// 10 attempts in 15 minutes: generous for a mistyped password,
		// useless for an online guessing attack against a 12-character
		// minimum. Offline attack is bounded by PBKDF2, not by this.
		max:    10,
		window: 15 * time.Minute,
	}
}

// allowed reports whether another attempt may be made for key.
func (t *loginThrottle) allowed(key string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.failures[key]
	if !ok || now.Sub(e.first) > t.window {
		return true
	}
	return e.count < t.max
}

// maxThrottleEntries bounds the table. Expired entries are swept first; if the
// table is still full of live ones, a new username is not recorded, so memory
// stays fixed under a flood of random usernames.
const maxThrottleEntries = 10000

func (t *loginThrottle) sweepLocked(now time.Time) {
	for k, e := range t.failures {
		if now.Sub(e.first) > t.window {
			delete(t.failures, k)
		}
	}
}

func (t *loginThrottle) recordFailure(key string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.failures) >= maxThrottleEntries {
		t.sweepLocked(now)
		if _, known := t.failures[key]; !known && len(t.failures) >= maxThrottleEntries {
			return
		}
	}
	e, ok := t.failures[key]
	if !ok || now.Sub(e.first) > t.window {
		t.failures[key] = &throttleEntry{count: 1, first: now}
		return
	}
	e.count++
}

func (t *loginThrottle) reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failures, key)
}

// Principal is the authenticated identity behind a request.
//
// Every request has one. When authentication is disabled (single-user
// localhost), the middleware injects the local principal below rather
// than leaving it nil, so no handler has to special-case "no user" and
// no code path can accidentally treat absence as permission.
type Principal struct {
	UserID   string
	Username string
	Role     string
	// Authenticated distinguishes a real logged-in user from the
	// injected local principal, so audit entries can be honest about
	// which one acted.
	Authenticated bool
	// MustChangePassword gates this principal behind a mandatory
	// password change. Carried on the principal so the middleware can
	// enforce it without a second database read per request.
	MustChangePassword bool
}

// LocalPrincipal is the identity used when authentication is disabled.
//
// Its username matches model.ActorLocalUser, so audit entries written in
// this mode read exactly as they did before Phase 12 -- the audit trail
// of an existing single-user deployment does not suddenly change
// vocabulary because a feature it does not use was added.
func LocalPrincipal() Principal {
	return Principal{
		UserID:        "",
		Username:      model.ActorLocalUser,
		Role:          model.RoleAdmin, // a single local operator is unrestricted, as before
		Authenticated: false,
	}
}

// Can reports whether this principal holds the given role's privileges.
func (p Principal) Can(role string) bool {
	if role == model.RoleAnalyst {
		// Admin is a superset of analyst: an admin who could not analyse
		// evidence would be a useless account.
		return p.Role == model.RoleAnalyst || p.Role == model.RoleAdmin
	}
	return p.Role == role
}

// Login verifies credentials and creates a session.
//
// It returns the PLAINTEXT token for the cookie; only the hash is
// stored. The token is never logged, never audited, and never placed in
// a URL.
func (s *Service) Login(username, password string, ttl time.Duration) (string, model.User, error) {
	username = strings.TrimSpace(username)
	key := strings.ToLower(username)
	now := time.Now().UTC()

	if !s.throttle.allowed(key, now) {
		s.auditSecurity("", model.AuditLoginFailed, model.TargetUser, "", username,
			"Login blocked: too many failed attempts")
		return "", model.User{}, ErrTooManyAttempts
	}
	// Password verification is deliberately expensive (600k PBKDF2 rounds), so
	// the number running at once is bounded. Without this, parallel logins
	// under any usernames, known or not, pin every CPU. Past the limit the
	// request is refused, not queued.
	select {
	case loginSlots <- struct{}{}:
		defer func() { <-loginSlots }()
	default:
		return "", model.User{}, ErrTooManyAttempts
	}

	u, err := s.store.FindUserByUsername(username)
	if err != nil {
		// An unknown username still costs a password verification, so the
		// response time does not reveal whether the account exists.
		_, _ = auth.VerifyPassword(dummyHash, password)
		s.throttle.recordFailure(key, now)
		s.auditSecurity("", model.AuditLoginFailed, model.TargetUser, "", username,
			"Login failed: invalid credentials")
		return "", model.User{}, ErrInvalidCredentials
	}

	ok, verr := auth.VerifyPassword(u.PasswordHash, password)
	if verr != nil || !ok {
		s.throttle.recordFailure(key, now)
		s.auditSecurity("", model.AuditLoginFailed, model.TargetUser, u.ID, username,
			"Login failed: invalid credentials")
		return "", model.User{}, ErrInvalidCredentials
	}
	if u.Disabled {
		s.auditSecurity("", model.AuditLoginFailed, model.TargetUser, u.ID, username,
			"Login failed: account disabled")
		return "", model.User{}, ErrAccountDisabled
	}

	token, err := auth.NewSessionToken()
	if err != nil {
		return "", model.User{}, err
	}
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	sess := model.Session{
		ID:        auth.HashSessionToken(token),
		UserID:    u.ID,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	if err := s.store.CreateSession(sess); err != nil {
		return "", model.User{}, fmt.Errorf("creating session: %w", err)
	}
	_ = s.store.TouchUserLogin(u.ID, now)
	s.throttle.reset(key)
	s.auditSecurity("", model.AuditLoginSucceeded, model.TargetUser, u.ID, u.Username, "Login succeeded")
	return token, u, nil
}

// dummyHash is a real PBKDF2 hash of a value nobody knows, used to spend
// the same CPU on an unknown username as on a known one. Without it,
// login timing distinguishes "no such user" from "wrong password" and
// hands an attacker a username oracle.
var dummyHash = mustHash("tracefall-timing-equalizer")

func mustHash(s string) string {
	h, err := auth.HashPassword(s)
	if err != nil {
		// Only reachable if crypto/rand fails, in which case the process
		// cannot do anything security-relevant anyway.
		panic("auth: cannot initialize password hashing: " + err.Error())
	}
	return h
}

// ResolveSession returns the principal for a session token.
func (s *Service) ResolveSession(token string) (Principal, error) {
	if token == "" {
		return Principal{}, ErrNotAuthenticated
	}
	u, _, err := s.store.SessionUser(auth.HashSessionToken(token), time.Now().UTC())
	if err != nil {
		return Principal{}, ErrNotAuthenticated
	}
	return Principal{
		UserID: u.ID, Username: u.Username, Role: u.Role, Authenticated: true,
		MustChangePassword: u.MustChangePassword,
	}, nil
}

// Logout invalidates one session.
func (s *Service) Logout(token string, p Principal) error {
	if token == "" {
		return nil
	}
	if err := s.store.DeleteSession(auth.HashSessionToken(token)); err != nil {
		return err
	}
	s.auditSecurity("", model.AuditLogout, model.TargetUser, p.UserID, p.Username, "Logged out")
	return nil
}

// ---------------- user administration ----------------

// PublicUser is the API-facing view of an account.
//
// A separate type, not model.User with a json:"-" on the hash: the type
// a handler can reach for simply has no password field, so no future
// change to serialization can expose one.
type PublicUser struct {
	ID        string     `json:"id"`
	Username  string     `json:"username"`
	Role      string     `json:"role"`
	Disabled  bool       `json:"disabled"`
	CreatedAt time.Time  `json:"created_at"`
	LastLogin *time.Time `json:"last_login,omitempty"`
	// MustChangePassword is visible to an admin so a gated account is
	// not mistaken for a broken one.
	MustChangePassword bool `json:"must_change_password,omitempty"`
}

func publicUser(u model.User) PublicUser {
	return PublicUser{
		ID: u.ID, Username: u.Username, Role: u.Role, Disabled: u.Disabled,
		CreatedAt: u.CreatedAt, LastLogin: u.LastLogin,
		MustChangePassword: u.MustChangePassword,
	}
}

// CreateUser adds an account.
func (s *Service) CreateUser(actor Principal, username, password, role string) (PublicUser, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return PublicUser{}, errors.New("username is required")
	}
	if len(password) < minPasswordLength {
		return PublicUser{}, ErrWeakPassword
	}
	if !model.ValidRole(role) {
		return PublicUser{}, fmt.Errorf("unknown role %q", role)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return PublicUser{}, err
	}
	u := model.User{
		ID: uuid.NewString(), Username: username, PasswordHash: hash,
		Role: role, CreatedAt: time.Now().UTC(),
	}
	if err := s.store.CreateUser(u); err != nil {
		if errors.Is(err, store.ErrDuplicateUsername) {
			return PublicUser{}, err
		}
		return PublicUser{}, fmt.Errorf("creating user: %w", err)
	}
	s.auditSecurity("", model.AuditUserCreated, model.TargetUser, u.ID, actor.Username,
		fmt.Sprintf("Created user %q with role %q", username, role))
	return publicUser(u), nil
}

// UserCount reports how many accounts exist, so a caller can tell an
// uninitialized deployment from one with accounts.
func (s *Service) UserCount() (int, error) { return s.store.CountUsers() }

// CreateBootstrapUser creates the first-run administrator.
//
// Separate from CreateUser only because it can set MustChangePassword,
// which no ordinary account-creation path should be able to do: an
// admin creating an analyst chooses a password and hands it over out of
// band, and gating that would be friction without benefit. The gate
// exists for one specific case -- a password Tracefall itself generated
// and printed -- so only the code that does that can set it.
func (s *Service) CreateBootstrapUser(actor Principal, username, password string, mustChange bool) (PublicUser, error) {
	u, err := s.CreateUser(actor, username, password, model.RoleAdmin)
	if err != nil {
		return PublicUser{}, err
	}
	if !mustChange {
		return u, nil
	}
	if err := s.store.SetMustChangePassword(u.ID, true); err != nil {
		return PublicUser{}, err
	}
	u.MustChangePassword = true
	return u, nil
}

// ListUsers returns every account, without password material.
func (s *Service) ListUsers() ([]PublicUser, error) {
	users, err := s.store.ListUsers()
	if err != nil {
		return nil, err
	}
	out := make([]PublicUser, 0, len(users))
	for _, u := range users {
		out = append(out, publicUser(u))
	}
	return out, nil
}

// DeleteUser removes an account, refusing to remove the last admin.
func (s *Service) DeleteUser(actor Principal, id string) error {
	u, err := s.store.GetUser(id)
	if err != nil {
		return err
	}
	if err := s.guardLastAdmin(u, u.Disabled, u.Role); err != nil {
		return err
	}
	if err := s.store.DeleteUser(id); err != nil {
		return err
	}
	s.auditSecurity("", model.AuditUserDeleted, model.TargetUser, id, actor.Username,
		fmt.Sprintf("Deleted user %q", u.Username))
	return nil
}

// SetUserRole changes a role, refusing to demote the last admin.
func (s *Service) SetUserRole(actor Principal, id, role string) error {
	if !model.ValidRole(role) {
		return fmt.Errorf("unknown role %q", role)
	}
	u, err := s.store.GetUser(id)
	if err != nil {
		return err
	}
	if err := s.guardLastAdmin(u, u.Disabled, role); err != nil {
		return err
	}
	if err := s.store.UpdateUserRole(id, role); err != nil {
		return err
	}
	s.auditSecurity("", model.AuditUserUpdated, model.TargetUser, id, actor.Username,
		fmt.Sprintf("Changed role of %q to %q", u.Username, role))
	return nil
}

// SetUserDisabled enables or disables an account.
func (s *Service) SetUserDisabled(actor Principal, id string, disabled bool) error {
	u, err := s.store.GetUser(id)
	if err != nil {
		return err
	}
	if err := s.guardLastAdmin(u, disabled, u.Role); err != nil {
		return err
	}
	if err := s.store.SetUserDisabled(id, disabled); err != nil {
		return err
	}
	verb := "Enabled"
	if disabled {
		verb = "Disabled"
	}
	s.auditSecurity("", model.AuditUserUpdated, model.TargetUser, id, actor.Username,
		fmt.Sprintf("%s user %q", verb, u.Username))
	return nil
}

// SetUserPassword replaces a password and drops that user's sessions.
func (s *Service) SetUserPassword(actor Principal, id, password string) error {
	if len(password) < minPasswordLength {
		return ErrWeakPassword
	}
	u, err := s.store.GetUser(id)
	if err != nil {
		return err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	if err := s.store.UpdateUserPassword(id, hash); err != nil {
		return err
	}
	// The password itself is never part of the audit record.
	s.auditSecurity("", model.AuditPasswordChanged, model.TargetUser, id, actor.Username,
		fmt.Sprintf("Password changed for %q; existing sessions invalidated", u.Username))
	return nil
}

// ChangeOwnPassword lets a signed-in user replace their own password.
//
// The CURRENT password is required even though the caller already holds
// a valid session: a session that has been left open on an unlocked
// machine should not be enough to take the account over permanently.
// Requiring the current password means an attacker with the session
// still cannot lock the owner out.
//
// It reuses store.UpdateUserPassword, so the new hash, the clearing of
// must_change_password and the invalidation of every existing session
// all happen in one transaction -- including the session making this
// very request, which is why the caller is issued a fresh one.
func (s *Service) ChangeOwnPassword(p Principal, currentPassword, newPassword string) error {
	if !p.Authenticated || p.UserID == "" {
		return ErrNotAuthenticated
	}
	u, err := s.store.GetUser(p.UserID)
	if err != nil {
		return err
	}

	ok, verr := auth.VerifyPassword(u.PasswordHash, currentPassword)
	if verr != nil || !ok {
		s.auditSecurity("", model.AuditLoginFailed, model.TargetUser, u.ID, u.Username,
			"Password change rejected: current password did not match")
		return ErrInvalidCredentials
	}
	if len(newPassword) < minPasswordLength {
		return ErrWeakPassword
	}
	// Refusing a no-op change matters most for the bootstrap account:
	// "changing" the printed password to itself would satisfy the gate
	// while leaving the displayed credential in force.
	if same, _ := auth.VerifyPassword(u.PasswordHash, newPassword); same {
		return ErrPasswordUnchanged
	}

	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.store.UpdateUserPassword(u.ID, hash); err != nil {
		return err
	}
	s.auditSecurity("", model.AuditPasswordChanged, model.TargetUser, u.ID, u.Username,
		"Password changed by the account owner; existing sessions invalidated")
	return nil
}

// guardLastAdmin refuses a change that would leave no enabled admin.
//
// Locking every administrator out of a forensic tool holding evidence is
// not a recoverable mistake through the UI, so it is refused rather than
// warned about.
func (s *Service) guardLastAdmin(u model.User, willBeDisabled bool, newRole string) error {
	stillAdmin := newRole == model.RoleAdmin && !willBeDisabled
	if u.Role != model.RoleAdmin || u.Disabled || stillAdmin {
		return nil
	}
	admins, err := s.store.CountAdmins()
	if err != nil {
		return err
	}
	if admins <= 1 {
		return ErrLastAdmin
	}
	return nil
}

// auditSecurity records a security-relevant action in the security log.
//
// It writes to security_log, NOT audit_log. audit_log.case_id is
// NOT NULL REFERENCES cases(id), so a login or a failed authentication
// -- which belongs to no case -- cannot be stored there: the foreign key
// rejects the row. The first version of this code wrote there anyway and
// every security event was silently discarded, because audit writes are
// deliberately best-effort. The two logs also answer different
// questions; see the security_log comment in schema.go.
//
// Actor is the acting username -- never a password, never a session
// token, never a request body.
func (s *Service) auditSecurity(caseID, action, targetType, targetID, actor, summary string) {
	_ = s.store.CreateSecurityEvent(model.AuditEvent{
		ID:         uuid.NewString(),
		CaseID:     caseID,
		Timestamp:  time.Now().UTC(),
		Action:     action,
		Actor:      actorOrUnknown(actor),
		TargetType: targetType,
		TargetID:   targetID,
		Summary:    summary,
	})
}

// actorOrUnknown keeps the actor field honest when the acting identity
// genuinely is not known (a failed login for an unknown username).
func actorOrUnknown(actor string) string {
	if strings.TrimSpace(actor) == "" {
		return "unauthenticated"
	}
	return actor
}
