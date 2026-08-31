package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"tracefall/internal/model"
)

// User accounts and sessions (Phase 12).
//
// Two rules shape this file:
//
//   - A password hash is written and read, never logged, never returned
//     by a listing helper that a handler might serialize by accident.
//   - A session is looked up by the HASH of its token, so the plaintext
//     token exists only in the cookie and in the request being served.

var (
	// ErrUserNotFound is returned for both an unknown user and a
	// username/password mismatch at the service layer, so the two are
	// indistinguishable to a caller probing for valid usernames.
	ErrUserNotFound = errors.New("user not found")
	// ErrDuplicateUsername means the username is already taken
	// (case-insensitively).
	ErrDuplicateUsername = errors.New("a user with this username already exists")
	// ErrSessionNotFound means the session does not exist or has expired.
	ErrSessionNotFound = errors.New("session not found")
)

const userCols = `id, username, password_hash, role, created_at, disabled, last_login, must_change_password`

func scanUser(row interface{ Scan(...any) error }) (model.User, error) {
	var u model.User
	var created, lastLogin string
	var disabled, mustChange int
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &created, &disabled, &lastLogin, &mustChange); err != nil {
		return model.User{}, err
	}
	u.CreatedAt = parseTime(created)
	u.Disabled = disabled == 1
	u.MustChangePassword = mustChange == 1
	if lastLogin != "" {
		t := parseTime(lastLogin)
		u.LastLogin = &t
	}
	return u, nil
}

// CreateUser inserts a new account.
func (s *Store) CreateUser(u model.User) error {
	_, err := s.db.Exec(`INSERT INTO users (`+userCols+`, username_lower)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, u.Role, fmtTime(u.CreatedAt), boolToInt(u.Disabled),
		fmtOptionalTime(u.LastLogin), boolToInt(u.MustChangePassword), strings.ToLower(u.Username))
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrDuplicateUsername
	}
	return err
}

// FindUserByUsername looks a user up case-insensitively.
func (s *Store) FindUserByUsername(username string) (model.User, error) {
	row := s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE username_lower = ?`, strings.ToLower(strings.TrimSpace(username)))
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrUserNotFound
	}
	return u, err
}

// GetUser looks a user up by ID.
func (s *Store) GetUser(id string) (model.User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrUserNotFound
	}
	return u, err
}

// ListUsers returns every account, oldest first.
func (s *Store) ListUsers() ([]model.User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.User, 0)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountUsers reports how many accounts exist. Used to decide whether a
// deployment has been initialized at all.
func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CountAdmins reports how many enabled admins exist, so the last one
// cannot be deleted or demoted into an unadministrable deployment.
func (s *Store) CountAdmins() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = ? AND disabled = 0`, model.RoleAdmin).Scan(&n)
	return n, err
}

// UpdateUserRole changes a user's role.
func (s *Store) UpdateUserRole(id, role string) error {
	_, err := s.db.Exec(`UPDATE users SET role = ? WHERE id = ?`, role, id)
	return err
}

// UpdateUserPassword replaces a user's password hash and invalidates
// every session they hold.
//
// Invalidation is part of the same operation on purpose: a password
// change that left old sessions alive would not actually lock anyone
// out, which is the main reason to change a password under suspicion.
func (s *Store) UpdateUserPassword(id, passwordHash string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// must_change_password is cleared in the same statement that replaces
	// the hash: the gate exists because the OLD password was displayed,
	// so setting a new one is precisely what lifts it. Clearing it
	// separately would leave a window where the two disagree.
	if _, err := tx.Exec(`UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?`,
		passwordHash, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// SetUserDisabled enables or disables an account, dropping its sessions
// when disabling.
func (s *Store) SetUserDisabled(id string, disabled bool) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE users SET disabled = ? WHERE id = ?`, boolToInt(disabled), id); err != nil {
		return err
	}
	if disabled {
		if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteUser removes an account and its sessions.
func (s *Store) DeleteUser(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM users WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// TouchUserLogin records a successful login time.
func (s *Store) TouchUserLogin(id string, at time.Time) error {
	_, err := s.db.Exec(`UPDATE users SET last_login = ? WHERE id = ?`, fmtTime(at), id)
	return err
}

// ---------------- sessions ----------------

// CreateSession stores a session keyed by its token hash.
func (s *Store) CreateSession(sess model.Session) error {
	_, err := s.db.Exec(`INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		sess.ID, sess.UserID, fmtTime(sess.CreatedAt), fmtTime(sess.ExpiresAt))
	return err
}

// SessionUser resolves a session token hash to its user in ONE query.
//
// One join rather than session-then-user because this runs on every
// authenticated request; two round trips per request to the single
// SQLite connection would be a real cost on a busy import.
//
// Expiry is enforced in the WHERE clause, so an expired row can never be
// returned by accident regardless of what the caller remembers to check.
func (s *Store) SessionUser(tokenHash string, now time.Time) (model.User, model.Session, error) {
	row := s.db.QueryRow(`
		SELECT `+prefixed("u", userCols)+`, s.id, s.user_id, s.created_at, s.expires_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.id = ? AND s.expires_at > ? AND u.disabled = 0`,
		tokenHash, fmtTime(now))

	var u model.User
	var sess model.Session
	var created, lastLogin, sCreated, sExpires string
	var disabled, mustChange int
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &created, &disabled, &lastLogin, &mustChange,
		&sess.ID, &sess.UserID, &sCreated, &sExpires)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, model.Session{}, ErrSessionNotFound
	}
	if err != nil {
		return model.User{}, model.Session{}, err
	}
	u.CreatedAt = parseTime(created)
	u.Disabled = disabled == 1
	u.MustChangePassword = mustChange == 1
	if lastLogin != "" {
		t := parseTime(lastLogin)
		u.LastLogin = &t
	}
	sess.CreatedAt, sess.ExpiresAt = parseTime(sCreated), parseTime(sExpires)
	return u, sess, nil
}

// DeleteSession removes one session (logout).
func (s *Store) DeleteSession(tokenHash string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, tokenHash)
	return err
}

// DeleteExpiredSessions removes sessions that are past their expiry.
func (s *Store) DeleteExpiredSessions(now time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, fmtTime(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// prefixed qualifies a column list with a table alias, so a joined query
// can reuse the same canonical column list rather than restating it and
// risking the two drifting apart.
func prefixed(alias, cols string) string {
	parts := strings.Split(cols, ", ")
	for i, c := range parts {
		parts[i] = alias + "." + c
	}
	return strings.Join(parts, ", ")
}

// ---------------- security log ----------------

// CreateSecurityEvent appends one authentication or account-administration
// event.
//
// Append-only: there is no update or delete counterpart, by design. The
// only way a security event leaves the database is with the database.
func (s *Store) CreateSecurityEvent(e model.AuditEvent) error {
	_, err := s.db.Exec(`INSERT INTO security_log
		(id, timestamp, action, actor, case_id, target_type, target_id, summary)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, fmtTime(e.Timestamp), e.Action, e.Actor, e.CaseID, e.TargetType, e.TargetID, e.Summary)
	return err
}

// ListSecurityLog returns security events, most recent first.
//
// limit bounds the result because this table grows with every request
// that is denied and every login attempt -- an unbounded read would be a
// denial-of-service against the single SQLite connection.
func (s *Store) ListSecurityLog(limit int) ([]model.AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id, case_id, timestamp, action, actor, target_type, target_id, summary
		FROM security_log ORDER BY timestamp DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.AuditEvent, 0)
	for rows.Next() {
		var e model.AuditEvent
		var ts string
		if err := rows.Scan(&e.ID, &e.CaseID, &ts, &e.Action, &e.Actor, &e.TargetType, &e.TargetID, &e.Summary); err != nil {
			return nil, err
		}
		e.Timestamp = parseTime(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// SetMustChangePassword gates or ungates an account behind a mandatory
// password change.
//
// Setting it is used only by the first-run bootstrap; it is cleared as
// part of UpdateUserPassword's transaction, never on its own, so the
// gate and the hash it guards can never disagree.
func (s *Store) SetMustChangePassword(id string, must bool) error {
	_, err := s.db.Exec(`UPDATE users SET must_change_password = ? WHERE id = ?`, boolToInt(must), id)
	return err
}
