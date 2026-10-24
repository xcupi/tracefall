package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"tracefall/internal/model"
	"tracefall/internal/narrative"
	"tracefall/internal/store"
)

func TestReviewVTOversizedRawRowRefuses(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "large.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.CreateCase(model.Case{ID: "case01", Name: "Synthetic"}); err != nil {
		t.Fatal(err)
	}
	e := model.Enrichment{ID: strings.Repeat("x", 140000), CaseID: "case01", Provider: "virustotal", IndicatorType: "sha256", Indicator: strings.Repeat("a", 64), Status: "error"}
	if err = s.UpsertEnrichment(e); err != nil {
		t.Fatal(err)
	}
	_, err = s.FreezeReviewSnapshot(context.Background(), "case01", "run01")
	if !errors.Is(err, store.ErrReviewSnapshotLimit) {
		t.Fatalf("unbounded VT ID accepted: %v", err)
	}
}
func TestReviewVTFrozenRecordsSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CreateCase(model.Case{ID: "case01", Name: "Synthetic"}); err != nil {
		t.Fatal(err)
	}
	e := model.Enrichment{ID: "vt01", CaseID: "case01", Provider: "virustotal", IndicatorType: "sha256", Indicator: strings.Repeat("a", 64), Status: "not_found", ResultJSON: "{}"}
	if err = s.UpsertEnrichment(e); err != nil {
		t.Fatal(err)
	}
	if _, err = s.FreezeReviewSnapshot(context.Background(), "case01", "run01"); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveBatchRun("case01", "run01", "running", map[string]any{"id": "run01", "state": "running"}); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveBatchPacket("case01", "run01", 0, "sending", map[string]any{"seq": 0, "state": "sending", "payload": map[string]any{"user": "exact attempted VT context"}}); err != nil {
		t.Fatal(err)
	}
	dto := narrative.FreezeReviewVT(e, []string{}, "single_review_attempt_snapshot")
	if err = s.SaveCaseReview(store.CaseReview{Narrative: model.Narrative{ID: "review01", CaseID: "case01"}, FrozenVT: []narrative.ReviewVT{dto}}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, state, err := s.BatchRun("case01", "run01")
	if err != nil || state != "interrupted" {
		t.Fatal("restart did not interrupt", state, err)
	}
	e.Status = "error"
	if err = s.UpsertEnrichment(e); err != nil {
		t.Fatal(err)
	}
	got, err := s.CaseReviewVT("case01", "review01", "vt01")
	if err != nil || got.Status != "not_found" || got.FetchedAt != "" {
		t.Fatalf("single snapshot changed %+v %v", got, err)
	}
	raw, err := s.BatchMemberJSON("case01", "run01", "enrichment", "vt01")
	if err != nil || !strings.Contains(string(raw), `"status":"not_found"`) {
		t.Fatalf("run snapshot changed %s %v", raw, err)
	}
}
func TestReviewVTStreamIncludesEmptyStoredIdentity(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "empty-id.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.CreateCase(model.Case{ID: "case01", Name: "Synthetic"}); err != nil {
		t.Fatal(err)
	}
	e := model.Enrichment{ID: "", CaseID: "case01", Provider: "virustotal", IndicatorType: "sha256", Indicator: strings.Repeat("a", 64), Status: "not_found", ResultJSON: "{}"}
	if err = s.UpsertEnrichment(e); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.LegacyReviewFingerprint(context.Background(), "case01")
	want := narrative.ReviewFingerprint(narrative.ReviewInput{CaseID: "case01", Enrichments: []model.Enrichment{e}})
	if err != nil || got != want {
		t.Fatalf("stored identity silently omitted got=%s want=%s err=%v", got, want, err)
	}
}
func TestReviewVTStreamedFingerprintAndFreeze(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "vt.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.CreateCase(model.Case{ID: "case01", Name: "Synthetic"}); err != nil {
		t.Fatal(err)
	}
	in := narrative.ReviewInput{CaseID: "case01"}
	old, _, err := s.LegacyReviewFingerprint(context.Background(), "case01")
	if err != nil || old != narrative.ReviewFingerprint(in) {
		t.Fatalf("zero VT parity: %s %v", old, err)
	}
	e := model.Enrichment{ID: "vt01", CaseID: "case01", Provider: "virustotal", IndicatorType: "sha256", Indicator: strings.Repeat("a", 64), Status: "not_found", ResultJSON: "{}", SourceEventIDs: []string{}}
	if err = s.UpsertEnrichment(e); err != nil {
		t.Fatal(err)
	}
	in.Enrichments = []model.Enrichment{e}
	got, _, err := s.LegacyReviewFingerprint(context.Background(), "case01")
	if err != nil || got == old || got != narrative.ReviewFingerprint(in) {
		t.Fatalf("VT canonical parity got=%s want=%s err=%v", got, narrative.ReviewFingerprint(in), err)
	}
	snap, err := s.FreezeReviewSnapshot(context.Background(), "case01", "run01")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Coverage.VTTotal != 1 || snap.Coverage.VTUnlinked != 1 {
		t.Fatalf("VT catalog=%+v", snap)
	}
	members, err := s.BatchMembers("case01", "run01", "enrichment", 0, 60)
	if err != nil || len(members) != 1 {
		t.Fatalf("VT frozen members=%v %v", members, err)
	}
	e.Status = "error"
	e.ID = "replacement"
	if err = s.UpsertEnrichment(e); err != nil {
		t.Fatal(err)
	}
	now, err := s.ReviewSnapshotFingerprint(context.Background(), "case01")
	if err != nil || now == snap.Fingerprint {
		t.Fatalf("VT change not stale: %v", err)
	}
	members2, err := s.BatchMembers("case01", "run01", "enrichment", 0, 60)
	if err != nil || members2[0].JSON != members[0].JSON {
		t.Fatal("frozen row changed", err)
	}
}
