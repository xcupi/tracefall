package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/narrative"
)

var ErrReviewSnapshotLimit = errors.New("bounded local planning limit exceeded; no plan created")

const BatchPageSize = 60
const BatchSnapshotMaxRecords = 1000000
const BatchSnapshotMaxBytes = 256 << 20
const BatchDictionaryMaxNames = 16384

// ReviewSnapshot is local metadata. None of its raw member JSON is an outbound payload.
type ReviewSnapshot struct {
	Fingerprint     string                   `json:"fingerprint"`
	Events          int                      `json:"events"`
	Findings        int                      `json:"findings"`
	Correlations    int                      `json:"correlations"`
	Sources         int                      `json:"sources"`
	SourceParseGaps int                      `json:"source_parse_gaps"`
	Bytes           int                      `json:"bytes"`
	Coverage        narrative.ReviewCoverage `json:"coverage"`
	Names           narrative.Names          `json:"-"`
}

type BatchRecord struct {
	Kind, ID string
	Ordinal  int
	JSON     string
}

// walkReviewTx reads deterministic ID pages in a single consistent SQLite
// transaction. Ordering selects chunks only; it never establishes evidence time.
func walkReviewTx(ctx context.Context, tx *sql.Tx, caseID string, fn func(BatchRecord) error) error {
	for _, kind := range []string{"event", "finding", "correlation", "source"} {
		table, cols, filter := "events", eventCols, " AND "+srcVisible("source_file_id")
		argsBase := []any{caseID}
		switch kind {
		case "finding":
			table, cols, filter = "findings", findingCols, currentAnalysisFilter
			argsBase = append(argsBase, caseID, caseID)
		case "correlation":
			table, cols, filter = "correlations", correlationCols, currentAnalysisFilter
			argsBase = append(argsBase, caseID, caseID)
		case "source":
			table, cols, filter = "source_files", sourceFileCols, " AND deleted_at = ''"
		}
		after, ordinal := "", 0
		started := false
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			args := append([]any{}, argsBase...)
			cursor := ""
			if started {
				cursor = " AND id>?"
				args = append(args, after)
			}
			args = append(args, BatchPageSize)
			rows, err := tx.QueryContext(ctx, `SELECT `+cols+` FROM `+table+` WHERE case_id=?`+filter+cursor+` ORDER BY id LIMIT ?`, args...)
			if err != nil {
				return err
			}
			var page []BatchRecord
			for rows.Next() {
				var value any
				var id string
				switch kind {
				case "event":
					v, e := scanEvent(rows)
					err = e
					value = v
					id = v.ID
				case "finding":
					v, e := scanFinding(rows)
					err = e
					value = v
					id = v.ID
				case "source":
					v, e := scanSourceFile(rows)
					err = e
					value = v
					id = v.ID
				case "correlation":
					var c model.Correlation
					var ids, first, last string
					err = rows.Scan(&c.ID, &c.CaseID, &c.Type, &c.Title, &c.Description, &ids, &first, &last, &c.AnalysisRunID)
					if err == nil {
						err = json.Unmarshal([]byte(ids), &c.EventIDs)
					}
					c.FirstSeen, c.LastSeen = parseTime(first), parseTime(last)
					value = c
					id = c.ID
				}
				if err != nil {
					rows.Close()
					return err
				}
				b, e := json.Marshal(value)
				if e != nil {
					rows.Close()
					return e
				}
				// This also bounds the page accumulator. Source records are trusted local
				// parsed DB rows, not attacker-provided allocation headers.
				if len(b) > 1<<20 {
					rows.Close()
					return fmt.Errorf("%w: record exceeds 1 MiB", ErrReviewSnapshotLimit)
				}
				page = append(page, BatchRecord{Kind: kind, ID: id, Ordinal: ordinal, JSON: string(b)})
				ordinal++
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			for _, r := range page {
				if err := fn(r); err != nil {
					return err
				}
				after = r.ID
				started = true
			}
			if len(page) < BatchPageSize {
				break
			}
		}
	}
	return nil
}

// FreezeReviewSnapshot commits all manifest membership atomically. Any resource
// cap aborts the transaction, never labels a sampled manifest complete.
func (s *Store) FreezeReviewSnapshot(ctx context.Context, caseID, runID string) (ReviewSnapshot, error) {
	return s.reviewSnapshot(ctx, caseID, runID)
}
func (s *Store) ReviewSnapshotFingerprint(ctx context.Context, caseID string) (string, error) {
	snap, err := s.reviewSnapshot(ctx, caseID, "")
	return snap.Fingerprint, err
}
func (s *Store) reviewSnapshot(ctx context.Context, caseID, runID string) (out ReviewSnapshot, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM cases WHERE id=?`, caseID).Scan(&exists); err != nil {
		return out, err
	}
	if exists != 1 {
		return out, sql.ErrNoRows
	}
	// Refuse oversized raw rows in SQLite before a Go scanner/JSON decoder
	// receives their values. This cap is independent of outbound truncation.
	for _, spec := range []struct{ table, cols, filter string }{{"events", eventCols, " AND " + srcVisible("source_file_id")}, {"findings", findingCols, ""}, {"correlations", correlationCols, ""}, {"source_files", sourceFileCols, ""}} {
		var terms []string
		for _, col := range strings.Split(spec.cols, ",") {
			terms = append(terms, "coalesce(length(CAST("+strings.TrimSpace(col)+" AS BLOB)),0)")
		}
		var one int
		e := tx.QueryRowContext(ctx, `SELECT 1 FROM `+spec.table+` WHERE case_id=?`+spec.filter+` AND (`+strings.Join(terms, "+")+`)>131072 LIMIT 1`, caseID).Scan(&one)
		if e == nil {
			return out, fmt.Errorf("%w: raw normalized record exceeds 128 KiB", ErrReviewSnapshotLimit)
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return out, e
		}
	}
	h := sha256.New()
	total := 0
	names := map[string]bool{}
	nameBytes := 0
	nameTooLong := false
	add := func(dst *[]string, v string) {
		v = narrative.ReviewIdentity(strings.TrimSpace(v))
		key := strings.ToLower(v)
		if v != "" && !names[key] {
			if len(v) > 1024 {
				nameTooLong = true
				return
			}
			nameBytes += len(v)
			names[key] = true
			*dst = append(*dst, v)
		}
	}
	learnShapes := func(values ...string) {
		n := narrative.DiscoverReviewNames(values...)
		for _, v := range n.Hosts {
			add(&out.Names.Hosts, v)
		}
		for _, v := range n.Users {
			add(&out.Names.Users, v)
		}
		for _, v := range n.Domains {
			add(&out.Names.Domains, v)
		}
	}
	out.Coverage.VTRecorded = true
	err = walkAllReviewTx(ctx, tx, caseID, func(r BatchRecord) error {
		total++
		out.Bytes += len(r.JSON)
		if total > BatchSnapshotMaxRecords || out.Bytes > BatchSnapshotMaxBytes {
			return fmt.Errorf("%w: at most 1000000 records and 256 MiB serialized snapshot", ErrReviewSnapshotLimit)
		}
		fmt.Fprintf(h, "%s\x00%s\n", r.Kind, r.JSON)
		switch r.Kind {
		case "enrichment":
			var e model.Enrichment
			if err := json.Unmarshal([]byte(r.JSON), &e); err != nil {
				return err
			}
			out.Coverage.VTTotal++
			rvt := narrative.FreezeReviewVT(e, nil, "batch_run_snapshot")
			if !narrative.ValidReviewVTIndicator(e) || rvt.Status == "unusable" {
				out.Coverage.VTInvalid++
			}
			links, err := reviewVTLinksTx(ctx, tx, e)
			if err != nil {
				return err
			}
			if narrative.ValidReviewVTIndicator(e) && len(links) == 0 {
				out.Coverage.VTUnlinked++
			}
			out.Coverage.VTOmitted = out.Coverage.VTTotal

		case "event":
			out.Events++
			var e model.Event
			if err := json.Unmarshal([]byte(r.JSON), &e); err != nil {
				return err
			}
			add(&out.Names.Hosts, e.Host)
			add(&out.Names.Users, e.User)
			learnShapes(e.ProcessName, e.ParentProcessName, e.CommandLine, e.FilePath, e.RegistryPath, e.NetworkSource, e.NetworkDest, e.Extra["logon_type"], e.Extra["outcome"], e.Extra["action"])
			for _, v := range []string{e.NetworkSource, e.NetworkDest} {
				if _, err := netip.ParseAddr(strings.TrimSpace(v)); err != nil {
					add(&out.Names.Hosts, v)
				}
			}
			for _, f := range nameFields {
				v := e.Extra[f.key]
				switch f.kind {
				case "user":
					add(&out.Names.Users, v)
				case "host":
					add(&out.Names.Hosts, v)
				case "domain":
					add(&out.Names.Domains, v)
				}
			}
			if e.Timestamp.IsZero() {
				out.Coverage.UndatedTotal++
			}
		case "finding":
			out.Findings++
			var f model.Finding
			if err := json.Unmarshal([]byte(r.JSON), &f); err != nil {
				return err
			}
			learnShapes(f.Title, f.Description, f.RuleID, f.Severity, f.Confidence)
		case "correlation":
			out.Correlations++
			var c model.Correlation
			if err := json.Unmarshal([]byte(r.JSON), &c); err != nil {
				return err
			}
			learnShapes(c.Title, c.Description, c.Type)
		case "source":
			out.Sources++
			var sf model.SourceFile
			if err := json.Unmarshal([]byte(r.JSON), &sf); err != nil {
				return err
			}
			learnShapes(sf.Path)
			switch {
			case sf.ImportStatus == model.SourceFileImported:
				out.Coverage.SourcesImported++
			case sf.ImportStatus == model.SourceFileFailed:
				out.Coverage.SourcesFailed++
			case !sf.Supported:
				out.Coverage.SourcesUnsupported++
			default:
				out.Coverage.SourcesNotImported++
			}
			if !sf.ParseCoverage.Measured() {
				out.Coverage.ParseCoverageNotRecorded++
			} else if c := sf.ParseCoverage; c.RecordsFailed > 0 || c.ChunksFailed > 0 || c.Unmapped > 0 || c.LimitReached {
				out.SourceParseGaps++
			}
		}
		if len(names) > BatchDictionaryMaxNames || nameTooLong || nameBytes > 2<<20 {
			return fmt.Errorf("%w: privacy dictionary has more than 16384 names, 2 MiB total names, or a name exceeds 1024 bytes", ErrReviewSnapshotLimit)
		}
		if runID != "" {
			_, err := tx.ExecContext(ctx, `INSERT INTO review_batch_members (case_id,run_id,kind,member_id,ordinal,record_json) VALUES (?,?,?,?,?,?)`, caseID, runID, r.Kind, r.ID, r.Ordinal, r.JSON)
			return err
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	sort.Strings(out.Names.Hosts)
	sort.Strings(out.Names.Users)
	sort.Strings(out.Names.Domains)
	out.Fingerprint = hex.EncodeToString(h.Sum(nil))
	out.Coverage.EventsTotal = out.Events
	out.Coverage.FindingsTotal = out.Findings
	out.Coverage.CorrelationsTotal = out.Correlations
	out.Coverage.SourcesTotal = out.Sources
	err = tx.Commit()
	return out, err
}

func (s *Store) BatchMembers(caseID, runID, kind string, offset, limit int) ([]BatchRecord, error) {
	if offset < 0 || limit < 1 || limit > BatchPageSize {
		return nil, errors.New("invalid manifest pagination")
	}
	rows, err := s.db.Query(`SELECT kind,member_id,ordinal,record_json FROM review_batch_members WHERE case_id=? AND run_id=? AND kind=? AND ordinal>=? ORDER BY ordinal LIMIT ?`, caseID, runID, kind, offset, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BatchRecord{}
	for rows.Next() {
		var r BatchRecord
		if err := rows.Scan(&r.Kind, &r.ID, &r.Ordinal, &r.JSON); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) BatchMemberExists(caseID, runID, kind, id string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM review_batch_members WHERE case_id=? AND run_id=? AND kind=? AND member_id=?`, caseID, runID, kind, id).Scan(&n)
	return n == 1, err
}
func (s *Store) BatchMemberJSON(caseID, runID, kind, id string) (json.RawMessage, error) {
	var raw string
	err := s.db.QueryRow(`SELECT record_json FROM review_batch_members WHERE case_id=? AND run_id=? AND kind=? AND member_id=?`, caseID, runID, kind, id).Scan(&raw)
	return json.RawMessage(raw), err
}
func (s *Store) BatchEvent(caseID, runID, id string) (model.Event, bool, error) {
	var raw string
	err := s.db.QueryRow(`SELECT record_json FROM review_batch_members WHERE case_id=? AND run_id=? AND kind='event' AND member_id=?`, caseID, runID, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Event{}, false, nil
	}
	if err != nil {
		return model.Event{}, false, err
	}
	var e model.Event
	err = json.Unmarshal([]byte(raw), &e)
	return e, err == nil, err
}

// Run JSON never includes raw member JSON or names. State is separately indexed
// and transitions use expected-state predicates, preventing stale worker revival.
func (s *Store) SaveBatchRun(caseID, id, state string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO review_batch_runs (id,case_id,state,record_json,created_at) VALUES (?,?,?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now'))`, id, caseID, state, string(b))
	return err
}
func (s *Store) UpdateBatchRun(caseID, id, expected, state string, body any) (bool, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return false, err
	}
	r, err := s.db.Exec(`UPDATE review_batch_runs SET state=?,record_json=? WHERE case_id=? AND id=? AND state=?`, state, string(b), caseID, id, expected)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}
func (s *Store) BatchRun(caseID, id string) (json.RawMessage, string, error) {
	var raw, state string
	var err error
	if id == "" {
		err = s.db.QueryRow(`SELECT record_json,state FROM review_batch_runs WHERE case_id=? ORDER BY created_at DESC,id DESC LIMIT 1`, caseID).Scan(&raw, &state)
	} else {
		err = s.db.QueryRow(`SELECT record_json,state FROM review_batch_runs WHERE case_id=? AND id=?`, caseID, id).Scan(&raw, &state)
	}
	return json.RawMessage(raw), state, err
}
func (s *Store) SaveBatchPacket(caseID, runID string, seq int, state string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO review_batch_packets (case_id,run_id,seq,state,record_json) VALUES (?,?,?,?,?)`, caseID, runID, seq, state, string(b))
	return err
}
func (s *Store) UpdateBatchPacket(caseID, runID string, seq int, expected, state string, body any) (bool, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return false, err
	}
	r, err := s.db.Exec(`UPDATE review_batch_packets SET state=?,record_json=? WHERE case_id=? AND run_id=? AND seq=? AND state=? AND EXISTS (SELECT 1 FROM review_batch_runs WHERE id=? AND case_id=? AND (state='running' OR (state='cancelled' AND ?='cancelled')))`, state, string(b), caseID, runID, seq, expected, runID, caseID, state)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}
func (s *Store) BatchPackets(caseID, runID string, after, limit int, readyOnly ...bool) ([]json.RawMessage, error) {
	if after < -1 || limit < 1 || limit > 100 {
		return nil, errors.New("invalid packet pagination")
	}
	filter := ""
	if len(readyOnly) > 0 && readyOnly[0] {
		filter = " AND state='ready'"
	}
	rows, err := s.db.Query(`SELECT record_json,state FROM review_batch_packets WHERE case_id=? AND run_id=? AND seq>?`+filter+` ORDER BY seq LIMIT ?`, caseID, runID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var raw, state string
		if err := rows.Scan(&raw, &state); err != nil {
			return nil, err
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(raw), &obj); err != nil {
			return nil, err
		}
		obj["state"] = state
		b, err := json.Marshal(obj)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
func (s *Store) ClosePendingBatchPackets(caseID, runID, state string) error {
	if state != "cancelled" && state != "unreviewed" {
		return errors.New("invalid unsent terminal state")
	}
	_, err := s.db.Exec(`UPDATE review_batch_packets SET state=? WHERE case_id=? AND run_id=? AND state='ready'`, state, caseID, runID)
	return err
}
func (s *Store) RecoverReviewBatches() error {
	// Never resume or retry uncertain delivery. Payload/result records remain intact.
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE review_batch_packets SET state='interrupted' WHERE state='sending'`); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE review_batch_runs SET state='interrupted' WHERE state='running'`); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) DeleteBatchPlan(caseID, runID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"review_batch_packets", "review_batch_members", "review_batch_runs"} {
		idcol := "run_id"
		if table == "review_batch_runs" {
			idcol = "id"
		}
		if _, err = tx.Exec(`DELETE FROM `+table+` WHERE case_id=? AND `+idcol+`=?`, caseID, runID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
