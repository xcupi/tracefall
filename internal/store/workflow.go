package store

import (
	"database/sql"
	"errors"
	"time"

	"tracefall/internal/model"
)

// Per-case bulk deletion of notes/tags/analyst_status/audit_log happens
// inline inside Store.DeleteCase's own transaction (matching that
// method's existing style of a flat list of DELETE statements), not via
// helpers here.

// ErrNoteNotFound means the note does not exist, or does not belong to
// the case the caller is acting within. The two are deliberately
// indistinguishable so the API cannot be used to probe for note ids in
// cases the caller cannot see.
var ErrNoteNotFound = errors.New("note not found")

// ---------- Notes ----------

const noteCols = `id, case_id, target_type, target_id, note, created_at, updated_at`

func scanNote(row interface{ Scan(...any) error }) (model.Note, error) {
	var n model.Note
	var created, updated string
	err := row.Scan(&n.ID, &n.CaseID, &n.TargetType, &n.TargetID, &n.Text, &created, &updated)
	if err != nil {
		return model.Note{}, err
	}
	n.CreatedAt, n.UpdatedAt = parseTime(created), parseTime(updated)
	return n, nil
}

func (s *Store) CreateNote(n model.Note) error {
	_, err := s.db.Exec(`INSERT INTO notes (`+noteCols+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		n.ID, n.CaseID, n.TargetType, n.TargetID, n.Text, fmtTime(n.CreatedAt), fmtTime(n.UpdatedAt))
	return err
}

// UpdateNote edits a note that belongs to caseID.
//
// The case is part of the WHERE clause, not merely checked beforehand,
// so the ownership rule cannot be bypassed by a caller that forgets the
// check or by a race between checking and writing. A note id from
// another case matches no row and reports ErrNoteNotFound -- which is
// also what an unknown id reports, so the API cannot be used to discover
// which note ids exist in cases the caller cannot see.
func (s *Store) UpdateNote(caseID, id, text string) error {
	res, err := s.db.Exec(`UPDATE notes SET note = ?, updated_at = ? WHERE id = ? AND case_id = ?`,
		text, fmtTime(time.Now()), id, caseID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoteNotFound
	}
	return nil
}

// DeleteNote removes a note by ID -- an analyst deleting their own
// annotation, distinct from the automatic evidence-deletion behavior
// (which never touches notes -- see model.Note's doc comment).
// DeleteNote removes a note that belongs to caseID. Scoped for the same
// reason as UpdateNote.
func (s *Store) DeleteNote(caseID, id string) error {
	res, err := s.db.Exec(`DELETE FROM notes WHERE id = ? AND case_id = ?`, id, caseID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoteNotFound
	}
	return nil
}

// ListNotes returns a case's notes, optionally filtered to one target
// (pass targetType="" to get every note in the case, e.g. for a full
// case export).
func (s *Store) ListNotes(caseID, targetType, targetID string) ([]model.Note, error) {
	query := `SELECT ` + noteCols + ` FROM notes WHERE case_id = ?`
	args := []any{caseID}
	if targetType != "" {
		query += ` AND target_type = ? AND target_id = ?`
		args = append(args, targetType, targetID)
	}
	query += ` ORDER BY created_at ASC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Note
	for rows.Next() {
		n, err := scanNote(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ---------- Tags ----------

const tagCols = `id, case_id, target_type, target_id, tag, created_at`

func scanTag(row interface{ Scan(...any) error }) (model.Tag, error) {
	var t model.Tag
	var created string
	err := row.Scan(&t.ID, &t.CaseID, &t.TargetType, &t.TargetID, &t.Tag, &created)
	if err != nil {
		return model.Tag{}, err
	}
	t.CreatedAt = parseTime(created)
	return t, nil
}

// CreateTag adds a tag, no-op (not an error) if the exact (target,tag)
// pair already exists -- idx_tags_unique backstops this at the database
// level for concurrent requests, translated here to a plain nil error
// since "the tag is present" is exactly what the caller wanted, whether
// this call or an earlier one is what made it so.
func (s *Store) CreateTag(t model.Tag) error {
	_, err := s.db.Exec(`INSERT INTO tags (`+tagCols+`) VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, t.CaseID, t.TargetType, t.TargetID, t.Tag, fmtTime(t.CreatedAt))
	if isUniqueConstraintViolation(err) {
		return nil
	}
	return err
}

// DeleteTag removes one (target, tag) pairing.
func (s *Store) DeleteTag(caseID, targetType, targetID, tag string) error {
	_, err := s.db.Exec(`DELETE FROM tags WHERE case_id = ? AND target_type = ? AND target_id = ? AND tag = ?`,
		caseID, targetType, targetID, tag)
	return err
}

func (s *Store) ListTags(caseID, targetType, targetID string) ([]model.Tag, error) {
	query := `SELECT ` + tagCols + ` FROM tags WHERE case_id = ?`
	args := []any{caseID}
	if targetType != "" {
		query += ` AND target_type = ? AND target_id = ?`
		args = append(args, targetType, targetID)
	}
	query += ` ORDER BY created_at ASC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Tag
	for rows.Next() {
		t, err := scanTag(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ---------- Analyst status (Finding/Investigation review workflow) ----------

// SetAnalystStatus upserts one target's current review status --
// deliberately one row per target (not append-only like notes), since a
// target has exactly one CURRENT status at a time; the history of how it
// got there belongs in notes or the audit log, not here.
func (s *Store) SetAnalystStatus(a model.AnalystStatus) error {
	_, err := s.db.Exec(`INSERT INTO analyst_status (case_id, target_type, target_id, status, note, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (target_type, target_id) DO UPDATE SET status = excluded.status, note = excluded.note, updated_at = excluded.updated_at`,
		a.CaseID, a.TargetType, a.TargetID, a.Status, a.Note, fmtTime(a.UpdatedAt))
	return err
}

func (s *Store) GetAnalystStatus(targetType, targetID string) (model.AnalystStatus, bool, error) {
	row := s.db.QueryRow(`SELECT case_id, target_type, target_id, status, note, updated_at
		FROM analyst_status WHERE target_type = ? AND target_id = ?`, targetType, targetID)
	var a model.AnalystStatus
	var updated string
	err := row.Scan(&a.CaseID, &a.TargetType, &a.TargetID, &a.Status, &a.Note, &updated)
	if err == sql.ErrNoRows {
		return model.AnalystStatus{}, false, nil
	}
	if err != nil {
		return model.AnalystStatus{}, false, err
	}
	a.UpdatedAt = parseTime(updated)
	return a, true, nil
}

// ListAnalystStatusForCase returns every target's status in a case --
// used to enrich the Findings/Investigations list responses (one query,
// not N) and for case export.
func (s *Store) ListAnalystStatusForCase(caseID string) ([]model.AnalystStatus, error) {
	rows, err := s.db.Query(`SELECT case_id, target_type, target_id, status, note, updated_at
		FROM analyst_status WHERE case_id = ?`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.AnalystStatus
	for rows.Next() {
		var a model.AnalystStatus
		var updated string
		if err := rows.Scan(&a.CaseID, &a.TargetType, &a.TargetID, &a.Status, &a.Note, &updated); err != nil {
			return nil, err
		}
		a.UpdatedAt = parseTime(updated)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------- Audit log ----------

func (s *Store) CreateAuditEvent(e model.AuditEvent) error {
	_, err := s.db.Exec(`INSERT INTO audit_log (id, case_id, timestamp, action, actor, target_type, target_id, summary)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.CaseID, fmtTime(e.Timestamp), e.Action, e.Actor, e.TargetType, e.TargetID, e.Summary)
	return err
}

func (s *Store) ListAuditLog(caseID string) ([]model.AuditEvent, error) {
	rows, err := s.db.Query(`SELECT id, case_id, timestamp, action, actor, target_type, target_id, summary
		FROM audit_log WHERE case_id = ? ORDER BY timestamp ASC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.AuditEvent
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
