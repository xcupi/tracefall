package api

import (
	"context"
	"fmt"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/store"
)

func (s *Service) persistSource(ctx context.Context, pf pendingImport, caseID, collectionID string, cancelled func() bool) (int, bool, error) {
	newCount := 0
	applied := false
	err := s.store.WithSourceTransaction(ctx, func(st *store.Store) error {
		if err := pf.eachBatch(func(events []model.Event, raw []model.RawEvidence) error {
			if cancelled() {
				return context.Canceled
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := st.SaveRawEvidence(raw); err != nil {
				return fmt.Errorf("saving raw evidence: %w", err)
			}
			newEvents, observations, err := deduplicateIn(st, caseID, collectionID, events, raw)
			if err != nil {
				return err
			}
			if err = st.SaveEvents(newEvents); err != nil {
				return err
			}
			if err = st.SaveEventObservations(observations); err != nil {
				return err
			}
			newCount += len(newEvents)
			return nil
		}); err != nil {
			return err
		}
		if cancelled() {
			return context.Canceled
		}
		var err error
		applied, err = st.MarkSourceFileImported(pf.sourceFile.ID, pf.eventCount(), time.Now().UTC(), pf.sourceFile.ParseCoverage)
		if err != nil {
			return err
		}
		if !applied {
			return errSourceAlreadyImported
		}
		// Stale analysis in the SAME transaction as source admission, even
		// for a zero-event source. Rollup repair must not be the only signal:
		// startup migrations can already have refreshed imported-file counts.
		return st.UpdateCaseStatus(caseID, model.CaseStatusIngested)
	})
	if err != nil {
		return 0, false, err
	}
	return newCount, applied, nil
}
