package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/narrative"
)

// VT is deliberately a separate walker: the legacy canonical JSON walker has
// four positional primary kinds and cannot accept an unknown fifth kind.
func walkReviewVTTx(ctx context.Context, tx *sql.Tx, caseID string, fn func(BatchRecord) error) error {
	after := ""
	ordinal, totalBytes := 0, 0
	var terms []string
	for _, col := range []string{"id", "case_id", "provider", "indicator_type", "indicator", "status", "result_json", "error", "fetched_at", "source_event_ids"} {
		terms = append(terms, "coalesce(length(CAST("+col+" AS BLOB)),0)")
	}
	var oversized int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM enrichments WHERE case_id=? AND provider='virustotal' AND (`+strings.Join(terms, "+")+`)>131072 LIMIT 1`, caseID).Scan(&oversized)
	if err == nil {
		return fmt.Errorf("%w: stored VT row exceeds 128 KiB", ErrReviewSnapshotLimit)
	}
	if err != sql.ErrNoRows {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		cursor := ""
		args := []any{caseID}
		if ordinal > 0 {
			cursor = " AND id>?"
			args = append(args, after)
		}
		args = append(args, BatchPageSize)
		rows, err := tx.QueryContext(ctx, `SELECT id,case_id,provider,indicator_type,indicator,status,result_json,error,fetched_at,source_event_ids FROM enrichments WHERE case_id=? AND provider='virustotal'`+cursor+` ORDER BY id LIMIT ?`, args...)
		if err != nil {
			return err
		}
		var page []BatchRecord
		for rows.Next() {
			var e model.Enrichment
			var at, ids string
			if err = rows.Scan(&e.ID, &e.CaseID, &e.Provider, &e.IndicatorType, &e.Indicator, &e.Status, &e.ResultJSON, &e.Error, &at, &ids); err != nil {
				rows.Close()
				return err
			}
			e.FetchedAt = parseTime(at)
			// Invalid references are not trusted links. Preserve raw JSON through
			// ResultJSON fingerprinting below only where it is valid storage data.
			_ = json.Unmarshal([]byte(ids), &e.SourceEventIDs)
			e.SourceEventIDs = append([]string(nil), e.SourceEventIDs...)
			sort.Strings(e.SourceEventIDs)
			b, err := json.Marshal(e)
			if err != nil {
				rows.Close()
				return err
			}
			totalBytes += len(b)
			if len(b) > 1<<20 || ordinal >= BatchSnapshotMaxRecords || totalBytes > BatchSnapshotMaxBytes {
				rows.Close()
				return fmt.Errorf("%w: stored VT snapshot cap", ErrReviewSnapshotLimit)
			}
			page = append(page, BatchRecord{Kind: "enrichment", ID: e.ID, Ordinal: ordinal, JSON: string(b)})
			ordinal++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, r := range page {
			if err = fn(r); err != nil {
				return err
			}
			after = r.ID
		}
		if len(page) < BatchPageSize {
			return nil
		}
	}
}
func walkAllReviewTx(ctx context.Context, tx *sql.Tx, caseID string, fn func(BatchRecord) error) error {
	if err := walkReviewTx(ctx, tx, caseID, fn); err != nil {
		return err
	}
	return walkReviewVTTx(ctx, tx, caseID, fn)
}

func (s *Store) ReviewVTContext(ctx context.Context, caseID, runID string, events []model.Event) (out []model.Enrichment, cv narrative.ReviewCoverage, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, cv, err
	}
	defer tx.Rollback()
	accept := func(r BatchRecord) error {
		var e model.Enrichment
		if err := json.Unmarshal([]byte(r.JSON), &e); err != nil {
			return err
		}
		cv.VTTotal++
		rv := narrative.FreezeReviewVT(e, nil, "")
		if !narrative.ValidReviewVTIndicator(e) || rv.Status == "unusable" {
			cv.VTInvalid++
		}
		linked := false
		if narrative.ValidReviewVTIndicator(e) {
			for _, id := range e.SourceEventIDs {
				var ev model.Event
				if runID == "" {
					v, err := scanEvent(tx.QueryRowContext(ctx, `SELECT `+eventCols+` FROM events WHERE case_id=? AND id=? AND `+srcVisible("source_file_id"), caseID, id))
					if err == sql.ErrNoRows {
						continue
					}
					if err != nil {
						return err
					}
					ev = v
				} else {
					var raw string
					err := tx.QueryRowContext(ctx, `SELECT record_json FROM review_batch_members WHERE case_id=? AND run_id=? AND kind='event' AND member_id=?`, caseID, runID, id).Scan(&raw)
					if err == sql.ErrNoRows {
						continue
					}
					if err != nil {
						return err
					}
					if err = json.Unmarshal([]byte(raw), &ev); err != nil {
						return err
					}
				}
				if len(narrative.ReviewVTLinks(e, []model.Event{ev})) > 0 {
					linked = true
					break
				}
			}
			if !linked {
				cv.VTUnlinked++
			}
		}
		if len(out) < narrative.ReviewMaxVT && len(narrative.ReviewVTLinks(e, events)) > 0 {
			out = append(out, e)
		}
		return nil
	}
	if runID == "" {
		err = walkReviewVTTx(ctx, tx, caseID, accept)
	} else {
		for offset := 0; ; offset += BatchPageSize {
			rows, e := tx.QueryContext(ctx, `SELECT member_id,ordinal,record_json FROM review_batch_members WHERE case_id=? AND run_id=? AND kind='enrichment' AND ordinal>=? ORDER BY ordinal LIMIT ?`, caseID, runID, offset, BatchPageSize)
			if e != nil {
				return nil, cv, e
			}
			var page []BatchRecord
			for rows.Next() {
				r := BatchRecord{Kind: "enrichment"}
				if e = rows.Scan(&r.ID, &r.Ordinal, &r.JSON); e != nil {
					rows.Close()
					return nil, cv, e
				}
				page = append(page, r)
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return nil, cv, e
			}
			for _, r := range page {
				if err = accept(r); err != nil {
					return nil, cv, err
				}
			}
			if len(page) < BatchPageSize {
				break
			}
		}
	}
	cv.VTOmitted = cv.VTTotal
	if err != nil {
		return nil, cv, err
	}
	err = tx.Commit()
	cv.VTRecorded = err == nil
	return out, cv, err
}

func reviewVTLinksTx(ctx context.Context, tx *sql.Tx, e model.Enrichment) ([]string, error) {
	if !narrative.ValidReviewVTIndicator(e) {
		return nil, nil
	}
	var events []model.Event
	for _, id := range e.SourceEventIDs {
		ev, err := scanEvent(tx.QueryRowContext(ctx, `SELECT `+eventCols+` FROM events WHERE case_id=? AND id=? AND `+srcVisible("source_file_id"), e.CaseID, id))
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(narrative.ReviewVTLinks(e, []model.Event{ev})) > 0 {
			events = append(events, ev)
			break
		}
	}
	return narrative.ReviewVTLinks(e, events), nil
}
