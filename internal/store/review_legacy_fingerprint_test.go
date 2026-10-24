package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/narrative"
	"tracefall/internal/store"
)

func TestReviewBatchesLegacyFingerprintReferenceNormalization(t *testing.T) {
	for _, tc := range []struct {
		name string
		refs []string
	}{
		{"nil", nil}, {"empty", []string{}}, {"sorted", []string{"event01", "event02"}}, {"shuffled", []string{"event02", "event01"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := store.Open(filepath.Join(t.TempDir(), "synthetic.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := s.CreateCase(model.Case{ID: "case01", Name: "Synthetic", Status: "created"}); err != nil {
				t.Fatal(err)
			}
			f := model.Finding{ID: "finding01", CaseID: "case01", Title: "Recorded observation", SupportingEvents: tc.refs}
			if err := s.SaveFindings([]model.Finding{f}); err != nil {
				t.Fatal(err)
			}
			// Read the same persisted shape as both production fingerprint callers.
			findings, err := s.ListFindings("case01")
			if err != nil {
				t.Fatal(err)
			}
			want := narrative.ReviewFingerprint(narrative.ReviewInput{CaseID: "case01", Findings: findings})
			for i := 0; i < 2; i++ {
				got, n, err := s.LegacyReviewFingerprint(context.Background(), "case01")
				if err != nil || got != want || n != 0 {
					t.Fatalf("canonical parity (scan/cache %d): got=%s/%d want=%s err=%v", i, got, n, want, err)
				}
			}
		})
	}
}
