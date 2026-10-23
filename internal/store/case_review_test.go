package store

import (
	"testing"
	"time"
	"tracefall/internal/model"
)

func TestCaseReviews_LatestFractionalTimeAndExactRecord(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	if _, ok, err := s.LatestCaseReview("case-1"); err != nil || ok {
		t.Fatal("unexpected initial review", err)
	}
	old := CaseReview{Narrative: narr("z-older", time.Date(2025, 1, 1, 0, 0, 0, 900000000, time.UTC)), Fingerprint: "older"}
	latest := CaseReview{Narrative: narr("a-newer", time.Date(2025, 1, 1, 0, 0, 0, 990000000, time.UTC)), Fingerprint: "newer"}
	for _, r := range []CaseReview{old, latest} {
		if err := s.SaveCaseReview(r); err != nil {
			t.Fatal(err)
		}
	}
	got, ok, err := s.LatestCaseReview("case-1")
	if err != nil || !ok || got.Narrative.ID != latest.Narrative.ID {
		t.Fatalf("fractional timestamp selected older review: %+v %v", got, err)
	}
	latest.Narrative.Status = model.NarrativeError
	latest.Narrative.Error = "synthetic error"
	latest.Narrative.PayloadUser = "exact persisted packet"
	if err := s.SaveCaseReview(latest); err != nil {
		t.Fatal(err)
	}
	got, ok, err = s.LatestCaseReview("case-1")
	if err != nil || !ok || got.Narrative.PayloadUser != latest.Narrative.PayloadUser || got.Narrative.Error != latest.Narrative.Error || got.Fingerprint != "newer" {
		t.Fatalf("record mismatch %+v %v", got, err)
	}
}
