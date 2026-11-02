package ingest

import (
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

func ntfsFrame(c *model.ParseCoverage) []streamFrame {
	return []streamFrame{
		{Batch: &parsers.ParseResult{Events: []model.Event{{SourceReference: "r:1", Timestamp: time.Unix(1700000000, 0).UTC()}}, Raw: []model.RawEvidence{{SourceReference: "r:1", Raw: "x"}}}},
		{Done: true, Coverage: c},
	}
}

func TestStreamRejectsNtfsClassesThatDoNotAddUpToUnmapped(t *testing.T) {
	bad := &model.ParseCoverage{RecordsRead: 3, Mapped: 1, Unmapped: 2, Ntfs: &model.NtfsCoverage{Source: model.NtfsSourceMFT, UnmappedNonBase: 1}}
	if _, _, err := runReviewFrames(t, ntfsFrame(bad)); err == nil {
		t.Fatal("unmapped reason classes that do not sum to unmapped were accepted")
	}
	neg := &model.ParseCoverage{RecordsRead: 3, Mapped: 1, Unmapped: 2, Ntfs: &model.NtfsCoverage{Source: model.NtfsSourceMFT, UnmappedNonBase: 3, UnmappedNoName: -1}}
	if _, _, err := runReviewFrames(t, ntfsFrame(neg)); err == nil {
		t.Fatal("negative reason class accepted")
	}
	good := &model.ParseCoverage{RecordsRead: 3, Mapped: 1, Unmapped: 2, Ntfs: &model.NtfsCoverage{Source: model.NtfsSourceMFT, UnmappedNonBase: 1, UnmappedNoName: 1}}
	if calls, cov, err := runReviewFrames(t, ntfsFrame(good)); err != nil || calls != 1 || cov.Ntfs == nil {
		t.Fatalf("consistent NTFS coverage rejected: %v", err)
	}
}

func TestStreamRejectsFailedNtfsCoverageWithoutAnError(t *testing.T) {
	c := &model.ParseCoverage{RecordsRead: 1, Mapped: 1, Ntfs: &model.NtfsCoverage{Source: model.NtfsSourceUSN, Failed: true, FailureClass: model.NtfsFailureCorrupt}}
	if _, _, err := runReviewFrames(t, ntfsFrame(c)); err == nil {
		t.Fatal("a worker that reports a failed source without an error was accepted")
	}
}
