package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"

	"tracefall/internal/model"
)

// SaveNarrative stores a draft. Every request makes a row, including one that
// failed: what was sent is recorded either way.
func (s *Store) SaveNarrative(n model.Narrative) error {
	ids, err := json.Marshal(n.FindingIDs)
	if err != nil {
		return err
	}
	if n.SentencesJSON == "" {
		n.SentencesJSON = "[]"
	}
	local := 0
	if n.Local {
		local = 1
	}
	_, err = s.db.Exec(`INSERT INTO narratives (id, case_id, status, error, created_at, destination, local, model, payload_system, payload_user,
		payload_sha256, raw_answer, sentences_json, rejected, reasons_json, finding_ids, prompt_tokens, completion_tokens, requested_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		n.ID, n.CaseID, n.Status, n.Error, fmtTime(n.CreatedAt), n.Destination, local, n.Model, n.PayloadSystem, n.PayloadUser,
		n.PayloadSHA256, n.RawAnswer, n.SentencesJSON, n.Rejected, n.ReasonsJSON, string(ids), n.PromptTokens, n.CompletionTokens, n.RequestedBy)
	return err
}

// LatestNarrative returns the most recent draft of a case, if any.
func (s *Store) LatestNarrative(caseID string) (model.Narrative, bool, error) {
	var n model.Narrative
	var ts, ids string
	var local int
	err := s.db.QueryRow(`SELECT id, case_id, status, error, created_at, destination, local, model, payload_system, payload_user,
		payload_sha256, raw_answer, sentences_json, rejected, reasons_json, finding_ids, prompt_tokens, completion_tokens, requested_by
		FROM narratives WHERE case_id = ? ORDER BY created_at DESC, id DESC LIMIT 1`, caseID).Scan(
		&n.ID, &n.CaseID, &n.Status, &n.Error, &ts, &n.Destination, &local, &n.Model, &n.PayloadSystem, &n.PayloadUser,
		&n.PayloadSHA256, &n.RawAnswer, &n.SentencesJSON, &n.Rejected, &n.ReasonsJSON, &ids, &n.PromptTokens, &n.CompletionTokens, &n.RequestedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Narrative{}, false, nil
	}
	if err != nil {
		return model.Narrative{}, false, err
	}
	n.CreatedAt = parseTime(ts)
	n.Local = local == 1
	_ = json.Unmarshal([]byte(ids), &n.FindingIDs)
	return n, true, nil
}

// CaseNames are the names a case's events carry: hosts, users and domains.
// They are what the pseudonymizer is taught so that a name is replaced wherever
// it appears, including where no pattern would find it.
type CaseNames struct {
	Hosts, Users, Domains []string
}

// nameFields are the Extra fields known to hold a user, a domain or a host.
var nameFields = []struct {
	key  string
	kind string
}{
	{"TargetUserName", "user"}, {"SubjectUserName", "user"}, {"target_user", "user"}, {"user", "user"},
	{"TargetDomainName", "domain"}, {"SubjectDomainName", "domain"}, {"domain", "domain"},
	{"ComputerName", "host"}, {"workstation", "host"},
}

// maxCaseNames bounds each list; a case with more distinct names than this is
// reported to the caller, which must not send anything.
const maxCaseNames = 200000

// ErrTooManyNames: the case has more distinct names than the dictionary holds.
var ErrTooManyNames = errors.New("store: the case has more distinct names than can be listed")

// CaseNames collects the distinct names of a case in one pass over its events.
func (s *Store) CaseNames(caseID string) (CaseNames, error) {
	var out CaseNames
	seen := map[string]bool{}
	add := func(dst *[]string, v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		k := strings.ToLower(v)
		if seen[k] {
			return
		}
		seen[k] = true
		*dst = append(*dst, v)
	}
	notAddr := func(v string) bool { _, err := netip.ParseAddr(strings.TrimSpace(v)); return err != nil }

	cols := []string{"host", "user", "network_source", "network_dest"}
	for _, f := range nameFields {
		cols = append(cols, "json_extract(extra_json, '$."+f.key+"')")
	}
	rows, err := s.db.Query(`SELECT DISTINCT `+strings.Join(cols, ", ")+` FROM events WHERE case_id = ? LIMIT ?`, caseID, maxCaseNames+1)
	if err != nil {
		return CaseNames{}, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
		if n > maxCaseNames {
			return CaseNames{}, ErrTooManyNames
		}
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return CaseNames{}, err
		}
		add(&out.Hosts, vals[0].String)
		add(&out.Users, vals[1].String)
		for _, i := range []int{2, 3} {
			if v := vals[i].String; v != "" && notAddr(v) {
				add(&out.Hosts, v)
			}
		}
		for i, f := range nameFields {
			v := vals[4+i].String
			switch f.kind {
			case "user":
				add(&out.Users, v)
			case "domain":
				add(&out.Domains, v)
			case "host":
				add(&out.Hosts, v)
			}
		}
	}
	return out, rows.Err()
}
