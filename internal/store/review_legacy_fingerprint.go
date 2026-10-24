package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"tracefall/internal/model"
)

type reviewFingerprintCache struct {
	changes, version int64
	hash             string
	events           int
}

// LegacyReviewFingerprint streams the historical single-packet fingerprint
// contract; it does not change selection or payloads on the legacy endpoint.
// Work is O(case size) time but only one bounded record page is retained.
func (s *Store) LegacyReviewFingerprint(ctx context.Context, caseID string) (string, int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, err
	}
	defer tx.Rollback()
	var changes, version int64
	// One Store owns one SQLite connection. total_changes detects every local
	// write (including rolled-back work); data_version detects other connections.
	// Any write conservatively invalidates all cases. The cache is metadata only,
	// hard-capped, and never holds a record or a case-sized identity list.
	if err := tx.QueryRowContext(ctx, `SELECT total_changes(),data_version FROM pragma_data_version`).Scan(&changes, &version); err != nil {
		return "", 0, err
	}
	s.reviewFingerprintMu.Lock()
	cached, ok := s.reviewFingerprints[caseID]
	s.reviewFingerprintMu.Unlock()
	if ok && cached.changes == changes && cached.version == version {
		if err := tx.Commit(); err != nil {
			return "", 0, err
		}
		return cached.hash, cached.events, nil
	}
	h := sha256.New()
	id, _ := json.Marshal(caseID)
	fmt.Fprintf(h, "{\"CaseID\":%s", id)
	kinds := []string{"event", "finding", "correlation", "source"}
	fields := []string{"Events", "Findings", "Correlations", "Sources"}
	index := -1
	wrote := false
	n := 0
	finish := func() {
		if wrote {
			fmt.Fprint(h, "]")
		} else {
			fmt.Fprint(h, "null")
		}
	}
	err = walkReviewTx(ctx, tx, caseID, func(r BatchRecord) error {
		target := 0
		for kinds[target] != r.Kind {
			target++
		}
		for index < target {
			if index >= 0 {
				finish()
			}
			index++
			fmt.Fprintf(h, ",\"%s\":", fields[index])
			wrote = false
		}
		if !wrote {
			fmt.Fprint(h, "[")
		} else {
			fmt.Fprint(h, ",")
		}
		wrote = true
		raw := r.JSON
		if r.Kind == "finding" {
			var f model.Finding
			if err := json.Unmarshal([]byte(raw), &f); err != nil {
				return err
			}
			// Match narrative.canonicalReview, including [] -> nil JSON parity.
			f.SupportingEvents = append([]string(nil), f.SupportingEvents...)
			sort.Strings(f.SupportingEvents)
			b, err := json.Marshal(f)
			if err != nil {
				return err
			}
			raw = string(b)
		}
		fmt.Fprint(h, raw)
		if r.Kind == "event" {
			n++
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	for index < 3 {
		if index >= 0 {
			finish()
		}
		index++
		fmt.Fprintf(h, ",\"%s\":", fields[index])
		wrote = false
	}
	finish()
	fmt.Fprint(h, ",\"Names\":{\"Hosts\":null,\"Users\":null,\"Domains\":null}")
	vtWrote := false
	err = walkReviewVTTx(ctx, tx, caseID, func(r BatchRecord) error {
		if !vtWrote {
			fmt.Fprint(h, ",\"Enrichments\":[")
			vtWrote = true
		} else {
			fmt.Fprint(h, ",")
		}
		fmt.Fprint(h, r.JSON)
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	if vtWrote {
		fmt.Fprint(h, "]")
	}
	fmt.Fprint(h, "}\n")
	if err = tx.Commit(); err != nil {
		return "", 0, err
	}
	hash := hex.EncodeToString(h.Sum(nil))
	s.reviewFingerprintMu.Lock()
	if s.reviewFingerprints == nil || len(s.reviewFingerprints) >= 32 {
		s.reviewFingerprints = map[string]reviewFingerprintCache{}
	}
	s.reviewFingerprints[caseID] = reviewFingerprintCache{changes: changes, version: version, hash: hash, events: n}
	s.reviewFingerprintMu.Unlock()
	return hash, n, nil
}
