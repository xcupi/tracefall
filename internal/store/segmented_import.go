package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"tracefall/internal/model"
)

// Segmented source admission.
//
// A very large source cannot be admitted in one transaction: that holds the
// store's only connection for hours, journals the whole source, and restarts
// from byte zero after a crash. Instead a source moves discovered -> importing
// -> imported (or failed). While importing, bounded segments are committed in
// their own transactions together with a checkpoint row, but the rows are NOT
// evidence: every reader hides rows whose source_file_id belongs to an
// importing source (srcVisible). Finalization verifies the committed rows
// against the checkpoints and the caller's totals and then flips ONE status
// row, so visibility is atomic without a mass UPDATE. Abort removes the
// segments in bounded transactions, leaving a retry-safe failed source.
//
// Rules (tested):
//   - one importing source per case, so deduplication never races another
//     segmented import, and the case's ordinary imports must not run while a
//     segmented import is pending (CaseHasImportingSource; enforced by callers
//     in the service layer);
//   - the importing source deduplicates against visible rows plus its OWN
//     pending rows (FindEventByDedupHashForImport); Finalize refuses to publish
//     an event whose dedup hash already exists on any other row;
//   - small sources keep the unchanged single-transaction path.

// importingSQL is the SQL literal of model.SourceFileImporting.
const importingSQL = "'" + model.SourceFileImporting + "'"

// srcVisible is the ONE predicate that hides the pending rows of importing
// sources. col is the (optionally alias-qualified) source_file_id column.
// The subquery is uncorrelated and served by idx_source_files_importing, so it
// is materialised once per statement and adds a per-row set lookup without
// changing which index the query uses.
func srcVisible(col string) string {
	return col + " NOT IN (SELECT id FROM source_files WHERE import_status = " + importingSQL + ")"
}

// srcVisibleOrOwn is srcVisible except that one importing source is visible.
// It contains exactly one ? placeholder: the importing source's own id.
func srcVisibleOrOwn(col string) string {
	return col + " NOT IN (SELECT id FROM source_files WHERE import_status = " + importingSQL + " AND id <> ?)"
}

// SegmentCheckpoint describes one committed segment. Index starts at 0 and must
// be contiguous. ByteOffset/Position let a parser resume at the next record
// (opaque to the store). Records is the number of parsed events the segment
// represents before deduplication.
type SegmentCheckpoint struct {
	Index      int
	ByteOffset int64
	Position   string
	Records    int
}

// SegmentPayload is the evidence a segment adds. Every row must already carry
// the importing source's id; the caller deduplicates (via
// FindEventByDedupHashForImport) before building it.
type SegmentPayload struct {
	Raw          []model.RawEvidence
	Events       []model.Event
	Observations []model.EventObservation
}

// SegmentTotals is cumulative across the committed segments of one source.
type SegmentTotals struct {
	Segments     int
	Records      int
	Raw          int
	Events       int
	Observations int
}

// SegmentedProgress is the durable resume point of an importing source.
type SegmentedProgress struct {
	SegmentTotals
	ByteOffset int64
	Position   string
}

// FinalizeExpectation is what the caller says the source contains. Records
// becomes source_files.event_count, as for a single-transaction import.
type FinalizeExpectation struct {
	SegmentTotals
	Coverage   *model.ParseCoverage
	ImportedAt time.Time
}

// ImportOutcome is the disclosed terminal result: "imported" or "aborted".
type ImportOutcome struct {
	Outcome string
	Reason  string
	SegmentTotals
}

// RecoveredImport reports one orphaned import cleaned by RecoverOrphanedImports.
type RecoveredImport struct {
	SourceFileID string
	Segments     int
}

var (
	ErrSourceNotAdmissible = errors.New("source is not in a state that allows segmented admission")
	ErrSegmentOutOfOrder   = errors.New("segment checkpoint is out of order")
	ErrFinalizeMismatch    = errors.New("segmented import does not match its checkpoint or expected totals")
	// ErrCaseImportInProgress: another source of the case is importing in
	// segments, so this source may not commit events (it could not see the
	// pending rows when deduplicating).
	ErrCaseImportInProgress = errors.New("another source of this case is importing in segments")
)

type segSource struct{ caseID, collectionID, status string }

type rowQuerier interface {
	QueryRow(string, ...any) *sql.Row
}

func loadSegSource(q rowQuerier, id string) (segSource, error) {
	return loadSegSourceWhere(q, id, " AND deleted_at = ''")
}

// loadSegSourceAny also loads a source marked deleted; Abort/Recover must be
// able to clean it so its hidden rows do not linger.
func loadSegSourceAny(q rowQuerier, id string) (segSource, error) {
	return loadSegSourceWhere(q, id, "")
}

// refuseForeignImporting fails when the case has an importing source other
// than sourceFileID: a writer that cannot see the pending rows must not commit
// events beside it. (The importing source's own segments pass.)
func refuseForeignImporting(q rowQuerier, caseID, sourceFileID string) error {
	var n int
	if err := q.QueryRow(`SELECT EXISTS (SELECT 1 FROM source_files WHERE case_id = ? AND import_status = `+importingSQL+` AND id <> ?)`, caseID, sourceFileID).Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return fmt.Errorf("%w: case %s", ErrCaseImportInProgress, caseID)
	}
	return nil
}

func loadSegSourceWhere(q rowQuerier, id, extra string) (segSource, error) {
	var src segSource
	err := q.QueryRow(`SELECT case_id, collection_id, import_status FROM source_files WHERE id = ?`+extra, id).
		Scan(&src.caseID, &src.collectionID, &src.status)
	if errors.Is(err, sql.ErrNoRows) {
		return segSource{}, fmt.Errorf("%w: unknown or deleted source %s", ErrSourceNotAdmissible, id)
	}
	return src, err
}

func segmentTotals(q rowQuerier, id string) (SegmentTotals, error) {
	var t SegmentTotals
	err := q.QueryRow(`SELECT COUNT(*), COALESCE(SUM(records),0), COALESCE(SUM(raw_n),0), COALESCE(SUM(events_n),0), COALESCE(SUM(obs_n),0)
 FROM source_import_segments WHERE source_file_id = ?`, id).Scan(&t.Segments, &t.Records, &t.Raw, &t.Events, &t.Observations)
	return t, err
}

func maxRowid(q rowQuerier, table string) (int64, error) {
	// table is a package constant, never input.
	var n int64
	err := q.QueryRow(`SELECT COALESCE(MAX(rowid), 0) FROM ` + table).Scan(&n)
	return n, err
}

// CaseHasImportingSource reports whether a segmented import is pending in the
// case. Ordinary imports of the same case must wait: they could not see the
// pending rows when deduplicating.
func (s *Store) CaseHasImportingSource(caseID string) (bool, error) {
	var n int
	err := s.sourceExecutor().QueryRow(`SELECT EXISTS (SELECT 1 FROM source_files WHERE case_id = ? AND import_status = `+importingSQL+` AND deleted_at = '')`, caseID).Scan(&n)
	return n != 0, err
}

// CaseImportingSourceIDs lists the importing sources of a case.
func (s *Store) CaseImportingSourceIDs(caseID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT id FROM source_files WHERE case_id = ? AND import_status = `+importingSQL+` ORDER BY id`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// BeginSegmentedImport moves a discovered source to importing.
func (s *Store) BeginSegmentedImport(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	src, err := loadSegSource(tx, id)
	if err != nil {
		return err
	}
	if src.status != model.SourceFileDiscovered {
		return fmt.Errorf("%w: source %s is %q, want %q", ErrSourceNotAdmissible, id, src.status, model.SourceFileDiscovered)
	}
	var others int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM source_files WHERE case_id = ? AND import_status = `+importingSQL+` AND deleted_at = '' AND id <> ?`, src.caseID, id).Scan(&others); err != nil {
		return err
	}
	if others > 0 {
		return fmt.Errorf("%w: another source of case %s is already importing", ErrSourceNotAdmissible, src.caseID)
	}
	if _, err = tx.Exec(`DELETE FROM source_import_outcomes WHERE source_file_id = ?`, id); err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE source_files SET import_status = `+importingSQL+` WHERE id = ? AND import_status = ?`, id, model.SourceFileDiscovered)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: source %s changed state concurrently", ErrSourceNotAdmissible, id)
	}
	return tx.Commit()
}

// CommitSegment writes one bounded segment and its checkpoint in a single
// transaction and returns the cumulative totals. A rejected or cancelled
// segment leaves nothing behind.
func (s *Store) CommitSegment(ctx context.Context, id string, cp SegmentCheckpoint, p SegmentPayload) (SegmentTotals, error) {
	var totals SegmentTotals
	err := s.WithSourceTransaction(ctx, func(st *Store) error {
		tx := st.sourceTx
		src, err := loadSegSource(tx, id)
		if err != nil {
			return err
		}
		if src.status != model.SourceFileImporting {
			return fmt.Errorf("%w: source %s is %q, not importing", ErrSourceNotAdmissible, id, src.status)
		}
		var last int
		if err = tx.QueryRow(`SELECT COALESCE(MAX(seg_index), -1) FROM source_import_segments WHERE source_file_id = ?`, id).Scan(&last); err != nil {
			return err
		}
		if cp.Index != last+1 {
			return fmt.Errorf("%w: got segment %d after %d", ErrSegmentOutOfOrder, cp.Index, last)
		}
		if cp.Records < 0 || cp.ByteOffset < 0 {
			return fmt.Errorf("segment %d: negative counters", cp.Index)
		}
		for _, r := range p.Raw {
			if r.SourceFileID != id || r.CaseID != src.caseID {
				return fmt.Errorf("segment %d: raw evidence %s is not attributed to source %s of case %s", cp.Index, r.ID, id, src.caseID)
			}
		}
		for _, e := range p.Events {
			if e.SourceFileID != id || e.CaseID != src.caseID {
				return fmt.Errorf("segment %d: event %s is not attributed to source %s of case %s", cp.Index, e.ID, id, src.caseID)
			}
		}
		for _, o := range p.Observations {
			if o.SourceFileID != id || o.CaseID != src.caseID {
				return fmt.Errorf("segment %d: observation %s is not attributed to source %s of case %s", cp.Index, o.ID, id, src.caseID)
			}
		}
		rawLo, err := maxRowid(tx, "raw_evidence")
		if err != nil {
			return err
		}
		evLo, err := maxRowid(tx, "events")
		if err != nil {
			return err
		}
		obsLo, err := maxRowid(tx, "event_observations")
		if err != nil {
			return err
		}
		if err = st.SaveRawEvidence(p.Raw); err != nil {
			return fmt.Errorf("saving raw evidence: %w", err)
		}
		if err = st.SaveEvents(p.Events); err != nil {
			return fmt.Errorf("saving events: %w", err)
		}
		if err = st.SaveEventObservations(p.Observations); err != nil {
			return fmt.Errorf("saving observations: %w", err)
		}
		rawHi, err := maxRowid(tx, "raw_evidence")
		if err != nil {
			return err
		}
		evHi, err := maxRowid(tx, "events")
		if err != nil {
			return err
		}
		obsHi, err := maxRowid(tx, "event_observations")
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`INSERT INTO source_import_segments
 (source_file_id, seg_index, case_id, collection_id, byte_offset, position, records, raw_n, events_n, obs_n, raw_lo, raw_hi, ev_lo, ev_hi, obs_lo, obs_hi, committed_at)
 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, cp.Index, src.caseID, src.collectionID, cp.ByteOffset, cp.Position, cp.Records,
			len(p.Raw), len(p.Events), len(p.Observations), rawLo, rawHi, evLo, evHi, obsLo, obsHi, fmtTime(time.Now())); err != nil {
			return err
		}
		totals, err = segmentTotals(tx, id)
		return err
	})
	if err != nil {
		return SegmentTotals{}, err
	}
	return totals, nil
}

// SegmentedImportProgress returns the durable resume point of an importing
// source; ok is false when no segment has been committed.
func (s *Store) SegmentedImportProgress(id string) (SegmentedProgress, bool, error) {
	t, err := segmentTotals(s.db, id)
	if err != nil || t.Segments == 0 {
		return SegmentedProgress{}, false, err
	}
	p := SegmentedProgress{SegmentTotals: t}
	err = s.db.QueryRow(`SELECT byte_offset, position FROM source_import_segments WHERE source_file_id = ? ORDER BY seg_index DESC LIMIT 1`, id).Scan(&p.ByteOffset, &p.Position)
	return p, err == nil, err
}

type segmentRow struct {
	idx                                    int
	raw, events, obs                       int
	rawLo, rawHi, evLo, evHi, obsLo, obsHi int64
}

func (s *Store) listSegments(id string) ([]segmentRow, error) {
	rows, err := s.db.Query(`SELECT seg_index, raw_n, events_n, obs_n, raw_lo, raw_hi, ev_lo, ev_hi, obs_lo, obs_hi
 FROM source_import_segments WHERE source_file_id = ? ORDER BY seg_index`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []segmentRow
	for rows.Next() {
		var r segmentRow
		if err := rows.Scan(&r.idx, &r.raw, &r.events, &r.obs, &r.rawLo, &r.rawHi, &r.evLo, &r.evHi, &r.obsLo, &r.obsHi); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// FinalizeSegmentedImport verifies an importing source and publishes it with a
// single status flip. Verification reads each segment's rowid interval outside
// any long transaction. On any mismatch the source stays importing (it is never
// published) and the caller should abort it.
func (s *Store) FinalizeSegmentedImport(ctx context.Context, id string, exp FinalizeExpectation) error {
	src, err := loadSegSource(s.db, id)
	if err != nil {
		return err
	}
	if src.status != model.SourceFileImporting {
		return fmt.Errorf("%w: source %s is %q, not importing", ErrSourceNotAdmissible, id, src.status)
	}
	have, err := segmentTotals(s.db, id)
	if err != nil {
		return err
	}
	if have != exp.SegmentTotals {
		return fmt.Errorf("%w: checkpoints hold %+v, caller expects %+v", ErrFinalizeMismatch, have, exp.SegmentTotals)
	}
	segs, err := s.listSegments(id)
	if err != nil {
		return err
	}
	for _, g := range segs {
		if err = ctx.Err(); err != nil {
			return err
		}
		for _, c := range []struct {
			table string
			lo    int64
			hi    int64
			want  int
		}{{"raw_evidence", g.rawLo, g.rawHi, g.raw}, {"events", g.evLo, g.evHi, g.events}, {"event_observations", g.obsLo, g.obsHi, g.obs}} {
			var got int
			if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+c.table+` WHERE rowid > ? AND rowid <= ? AND source_file_id = ?`, c.lo, c.hi, id).Scan(&got); err != nil {
				return err
			}
			if got != c.want {
				return fmt.Errorf("%w: segment %d holds %d %s rows, checkpoint says %d", ErrFinalizeMismatch, g.idx, got, c.table, c.want)
			}
		}
		var dup int
		if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events e WHERE e.rowid > ? AND e.rowid <= ? AND e.source_file_id = ? AND e.dedup_hash <> ''
 AND EXISTS (SELECT 1 FROM events o WHERE o.case_id = e.case_id AND o.dedup_hash = e.dedup_hash AND o.id <> e.id)`, g.evLo, g.evHi, id).Scan(&dup); err != nil {
			return err
		}
		if dup > 0 {
			return fmt.Errorf("%w: segment %d has %d event(s) whose dedup hash already exists on another event", ErrFinalizeMismatch, g.idx, dup)
		}
	}
	var diagnostic string
	if exp.Coverage != nil {
		b, e := json.Marshal(exp.Coverage)
		if e != nil {
			return e
		}
		diagnostic = string(b)
	}
	return s.WithSourceTransaction(ctx, func(st *Store) error {
		tx := st.sourceTx
		cur, err := segmentTotals(tx, id)
		if err != nil {
			return err
		}
		if cur != have {
			return fmt.Errorf("%w: segments changed during verification", ErrFinalizeMismatch)
		}
		res, err := tx.Exec(`UPDATE source_files SET import_status = ?, event_count = ?, imported_at = ?, parse_coverage_json = ?
 WHERE id = ? AND import_status = `+importingSQL, model.SourceFileImported, exp.Records, fmtTime(exp.ImportedAt), diagnostic, id)
		if isUniqueConstraintViolation(err) {
			return ErrDuplicateSourceFile
		}
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("%w: source %s left the importing state", ErrSourceNotAdmissible, id)
		}
		if err = st.UpdateCaseStatus(src.caseID, model.CaseStatusIngested); err != nil {
			return err
		}
		if _, err = tx.Exec(`DELETE FROM source_import_segments WHERE source_file_id = ?`, id); err != nil {
			return err
		}
		return upsertOutcome(tx, id, src, "imported", "", have)
	})
}

func upsertOutcome(tx execer, id string, src segSource, outcome, reason string, t SegmentTotals) error {
	_, err := tx.Exec(`INSERT INTO source_import_outcomes (source_file_id, case_id, collection_id, outcome, reason, segments, records, raw_n, events_n, obs_n, at)
 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
 ON CONFLICT(source_file_id) DO UPDATE SET outcome = excluded.outcome, reason = excluded.reason, segments = excluded.segments,
 records = excluded.records, raw_n = excluded.raw_n, events_n = excluded.events_n, obs_n = excluded.obs_n, at = excluded.at`,
		id, src.caseID, src.collectionID, outcome, reason, t.Segments, t.Records, t.Raw, t.Events, t.Observations, fmtTime(time.Now()))
	return err
}

// AbortSegmentedImport removes every pending segment in bounded transactions
// (one per segment, newest first) and marks the source failed with a disclosed
// reason. It is idempotent: an interrupted abort leaves a shorter, still
// consistent importing source that can be aborted again.
func (s *Store) AbortSegmentedImport(ctx context.Context, id, reason string) error {
	src, err := loadSegSourceAny(s.db, id)
	if err != nil {
		return err
	}
	if src.status != model.SourceFileImporting {
		return fmt.Errorf("%w: source %s is %q, not importing", ErrSourceNotAdmissible, id, src.status)
	}
	total, err := segmentTotals(s.db, id)
	if err != nil {
		return err
	}
	segs, err := s.listSegments(id)
	if err != nil {
		return err
	}
	for i := len(segs) - 1; i >= 0; i-- {
		g := segs[i]
		if err = s.WithSourceTransaction(ctx, func(st *Store) error {
			tx := st.sourceTx
			for _, d := range []struct {
				table  string
				lo, hi int64
			}{{"event_observations", g.obsLo, g.obsHi}, {"events", g.evLo, g.evHi}, {"raw_evidence", g.rawLo, g.rawHi}} {
				if _, e := tx.Exec(`DELETE FROM `+d.table+` WHERE rowid > ? AND rowid <= ? AND source_file_id = ?`, d.lo, d.hi, id); e != nil {
					return e
				}
			}
			_, e := tx.Exec(`DELETE FROM source_import_segments WHERE source_file_id = ? AND seg_index = ?`, id, g.idx)
			return e
		}); err != nil {
			return err
		}
	}
	return s.WithSourceTransaction(ctx, func(st *Store) error {
		tx := st.sourceTx
		res, err := tx.Exec(`UPDATE source_files SET import_status = ?, event_count = 0, imported_at = '', parse_coverage_json = ''
 WHERE id = ? AND import_status = `+importingSQL, model.SourceFileFailed, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("%w: source %s left the importing state", ErrSourceNotAdmissible, id)
		}
		return upsertOutcome(tx, id, src, "aborted", reason, total)
	})
}

// RecoverOrphanedImports aborts every importing source for which live reports
// no running job (for example after a crash). Policy: pending data is removed
// and the source becomes failed with a disclosed reason, so it can be retried
// from the beginning; resuming from a checkpoint is a separate, later feature.
func (s *Store) RecoverOrphanedImports(ctx context.Context, live func(string) bool) ([]RecoveredImport, error) {
	ids, err := s.ImportingSourceIDs()
	if err != nil {
		return nil, err
	}
	return s.RecoverImportingSources(ctx, ids, live, nil)
}

// ImportingSourceIDs lists the sources that are importing right now. Taken once
// at startup it is exactly the set of orphans: nothing in a new process can be
// importing yet.
func (s *Store) ImportingSourceIDs() ([]string, error) {
	rows, err := s.db.Query(`SELECT id FROM source_files WHERE import_status = ` + importingSQL + ` ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// RecoverImportingSources aborts the given importing sources one by one. before
// (optional) is called ahead of each. One stuck orphan does not block the rest.
func (s *Store) RecoverImportingSources(ctx context.Context, ids []string, live func(string) bool, before func(string)) ([]RecoveredImport, error) {
	var out []RecoveredImport
	var errs []error
	for _, id := range ids {
		if live != nil && live(id) {
			continue
		}
		if before != nil {
			before(id)
		}
		t, err := segmentTotals(s.db, id)
		if err == nil {
			err = s.AbortSegmentedImport(ctx, id, "interrupted before finalization (process stopped or job lost); pending segments removed; retry from the beginning")
		}
		if err != nil {
			// One stuck orphan must not block cleanup of the others.
			errs = append(errs, fmt.Errorf("source %s: %w", id, err))
			continue
		}
		out = append(out, RecoveredImport{SourceFileID: id, Segments: t.Segments})
	}
	return out, errors.Join(errs...)
}

// SegmentedImportOutcome returns the disclosed terminal result of the most
// recent segmented import of a source.
func (s *Store) SegmentedImportOutcome(id string) (ImportOutcome, bool, error) {
	var o ImportOutcome
	err := s.db.QueryRow(`SELECT outcome, reason, segments, records, raw_n, events_n, obs_n FROM source_import_outcomes WHERE source_file_id = ?`, id).
		Scan(&o.Outcome, &o.Reason, &o.Segments, &o.Records, &o.Raw, &o.Events, &o.Observations)
	if errors.Is(err, sql.ErrNoRows) {
		return ImportOutcome{}, false, nil
	}
	return o, err == nil, err
}

// FindEventByDedupHashForImport is FindEventByDedupHash for the importing
// source sourceFileID: it also sees that source's own pending rows, but never
// another importing source's.
func (s *Store) FindEventByDedupHashForImport(caseID, hash, sourceFileID string) (model.Event, bool, error) {
	if hash == "" {
		return model.Event{}, false, nil
	}
	row := s.sourceExecutor().QueryRow(`SELECT `+eventCols+` FROM events WHERE case_id = ? AND dedup_hash = ? AND `+srcVisibleOrOwn("source_file_id")+` LIMIT 1`, caseID, hash, sourceFileID)
	e, err := scanEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Event{}, false, nil
	}
	if err != nil {
		return model.Event{}, false, err
	}
	return e, true, nil
}
