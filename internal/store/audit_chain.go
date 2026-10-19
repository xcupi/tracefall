package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"tracefall/internal/model"
)

// The audit log of a case is a hash chain. Every row stores the entry_hash of
// the row before it in the same case (prev_hash) and a hash over its own
// content plus that link. Editing a row, deleting one from the middle, or
// reordering rows breaks the chain at the first affected row, and
// VerifyAuditChain reports where.
//
// What the chain does NOT prove, stated plainly: removing the LAST rows of a
// case leaves a shorter but still consistent chain, so truncation at the tail
// is not detectable from the chain alone. Someone who can rewrite the whole
// database can also recompute every hash. The chain proves that the recorded
// history is intact relative to its own head; comparing that head with a value
// written outside the database (an exported seal, a printed report) is what
// closes the tail. Deleting a case removes its rows, so the service writes a
// tombstone with the final head to security_log, which the case deletion does
// not touch.

// auditRowQuerier is satisfied by *sql.DB and *sql.Tx, so the chain head is
// read inside the same transaction as the insert that extends it.
type auditRowQuerier interface {
	QueryRow(query string, args ...any) *sql.Row
}

// auditChainHead returns the entry_hash of the newest row of a case, or ""
// when the case has no rows. A legacy row (written before the chain existed)
// has an empty entry_hash, so the first chained row gets an empty prev_hash:
// that is the chain's genesis, and VerifyAuditChain accepts exactly that.
func auditChainHead(q auditRowQuerier, caseID string) (string, error) {
	var head string
	err := q.QueryRow(`SELECT entry_hash FROM audit_log WHERE case_id = ? ORDER BY rowid DESC LIMIT 1`, caseID).Scan(&head)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return head, err
}

// auditEntryHash covers every field a reader sees, the timestamp exactly as
// stored, and the previous link. The fields are JSON-encoded as an array, so
// no field's content can be mistaken for a boundary (a summary containing a
// separator cannot shift into the next field).
func auditEntryHash(prev string, e model.AuditEvent, storedTimestamp string) string {
	fields := []string{prev, e.ID, e.CaseID, storedTimestamp, e.Action, e.Actor, e.TargetType, e.TargetID, e.Summary}
	b, _ := json.Marshal(fields)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// AuditChainStatus is the result of verifying one case's audit chain.
type AuditChainStatus struct {
	CaseID string `json:"case_id"`
	// Rows is how many rows were examined, up to the first failure.
	Rows int `json:"rows"`
	// Chained is how many rows carry a hash and verify.
	Chained int `json:"chained"`
	// Unchained is how many rows predate the chain. They are reported, not
	// verified: nothing proves what they contained when they were written.
	Unchained int `json:"unchained"`
	// Valid is true when no row breaks the chain. A case with only unchained
	// rows is Valid with Chained 0: there is nothing to verify, and the
	// report says so.
	Valid bool `json:"valid"`
	// Head is the entry_hash of the last chained row, "" if there is none.
	Head string `json:"head"`
	// BrokenAt is the ID of the first row that fails verification.
	BrokenAt string `json:"broken_at,omitempty"`
	// Reason says what failed at BrokenAt, in analyst terms.
	Reason string `json:"reason,omitempty"`
}

// VerifyAuditChain walks one case's audit rows in insertion order and checks
// every link. It reads the stored timestamp text, not a re-formatted time, so
// the hash is recomputed over exactly the bytes that were hashed.
func (s *Store) VerifyAuditChain(caseID string) (AuditChainStatus, error) {
	st := AuditChainStatus{CaseID: caseID, Valid: true}
	rows, err := s.db.Query(`SELECT id, case_id, timestamp, action, actor, target_type, target_id, summary, prev_hash, entry_hash
		FROM audit_log WHERE case_id = ? ORDER BY rowid ASC`, caseID)
	if err != nil {
		return st, err
	}
	defer rows.Close()

	last := ""
	started := false
	fail := func(id, reason string) (AuditChainStatus, error) {
		st.Valid = false
		st.BrokenAt = id
		st.Reason = reason
		st.Head = last
		return st, nil
	}
	for rows.Next() {
		var e model.AuditEvent
		var ts, prev, entry string
		if err := rows.Scan(&e.ID, &e.CaseID, &ts, &e.Action, &e.Actor, &e.TargetType, &e.TargetID, &e.Summary, &prev, &entry); err != nil {
			return st, err
		}
		st.Rows++
		if entry == "" {
			if started {
				return fail(e.ID, "row has no hash after the chain began: it was inserted or stripped outside Tracefall")
			}
			st.Unchained++
			continue
		}
		started = true
		if prev != last {
			return fail(e.ID, "previous link does not match the row before it: a row was removed, reordered or changed")
		}
		if auditEntryHash(prev, e, ts) != entry {
			return fail(e.ID, "row content does not match its hash: the row was edited after it was written")
		}
		last = entry
		st.Chained++
	}
	if err := rows.Err(); err != nil {
		return st, err
	}
	st.Head = last
	return st, nil
}
