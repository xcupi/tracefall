package ingest

import (
	"errors"
	"testing"

	"tracefall/internal/model"
)

func TestStreamRejectsImpossibleTerminalRecordTotals(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	for _, tc := range []struct {
		name           string
		read, unmapped int
	}{
		{"overcount", 1, 999},
		{"unaccounted", 1, 0},
		{"negative read", -1, 0},
		{"negative unmapped", 0, -1},
		{"integer boundary overcount", maxInt - 1, maxInt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cov := &model.ParseCoverage{RecordsRead: tc.read, Unmapped: tc.unmapped}
			_, got, err := runReviewFrames(t, []streamFrame{{Done: true, Coverage: cov}})
			var failure *ProcessFailure
			if !errors.As(err, &failure) || got == nil {
				t.Fatalf("impossible terminal record totals accepted: coverage=%+v err=%v", got, err)
			}
		})
	}
}

func TestStreamAllowsFullyUnmappedTerminalRecordTotals(t *testing.T) {
	for _, n := range []int{0, 1, int(^uint(0) >> 1)} {
		_, cov, err := runReviewFrames(t, []streamFrame{{Done: true, Coverage: &model.ParseCoverage{RecordsRead: n, Unmapped: n}}})
		if err != nil || cov == nil {
			t.Fatalf("valid unmapped totals rejected: n=%d err=%v", n, err)
		}
	}
}
