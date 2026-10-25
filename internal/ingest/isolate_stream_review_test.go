package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/mssql"
)

func runReviewFrames(t *testing.T, frames []streamFrame) (int, *model.ParseCoverage, error) {
	t.Helper()
	script := "#!/bin/sh\nprintf '%s\\n'"
	for _, f := range frames {
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		script += " '" + string(b) + "'"
	}
	script += "\n"
	path := filepath.Join(t.TempDir(), "worker")
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	calls := 0
	cov, err := (Subprocess{Exe: path}).RunStream(context.Background(), mssql.New(), "", "unused", parsers.ParseContext{}, func(b parsers.ParseResult) error {
		want, _ := json.Marshal(frames[calls].Batch)
		got, _ := json.Marshal(b)
		if string(want) != string(got) {
			t.Error("stream changed original raw evidence, source references or unknown timestamps")
		}
		calls++
		return nil
	})
	return calls, cov, err
}
func TestSQLStreamRejectsMismatchedReferences(t *testing.T) {
	for _, ref := range []string{"", "line:2"} {
		calls, _, err := runReviewFrames(t, []streamFrame{{Batch: &parsers.ParseResult{Events: []model.Event{{SourceReference: "line:1"}}, Raw: []model.RawEvidence{{SourceReference: ref, Raw: "original"}}}}, {Done: true, Coverage: &model.ParseCoverage{RecordsRead: 1, Mapped: 1}}})
		if err == nil || calls != 0 {
			t.Fatalf("reference mismatch accepted: calls=%d err=%v", calls, err)
		}
	}
}

func TestSQLStreamRejectsUnreceivedMappedCoverage(t *testing.T) {
	_, _, err := runReviewFrames(t, []streamFrame{{Done: true, Coverage: &model.ParseCoverage{RecordsRead: 1, Mapped: 1}}})
	if err == nil {
		t.Fatal("terminal mapped record without received batch accepted")
	}
}

func TestSQLStreamRejectsSilentIncompleteCoverage(t *testing.T) {
	for _, cov := range []*model.ParseCoverage{{LimitReached: true}, {RecordsFailed: 1}, {ChunksFailed: 1}} {
		_, got, err := runReviewFrames(t, []streamFrame{{Done: true, Coverage: cov}})
		if err == nil || got == nil {
			t.Fatalf("incomplete coverage accepted: cov=%+v err=%v", got, err)
		}
	}
}

func TestSQLStreamAllowsUnmappedAndUnknownTime(t *testing.T) {
	// Read/mapped need not be equal: unmapped records remain explicit coverage.
	calls, cov, err := runReviewFrames(t, []streamFrame{{Batch: &parsers.ParseResult{Events: []model.Event{{SourceReference: "line:2"}}, Raw: []model.RawEvidence{{SourceReference: "line:2", Raw: "original local reading"}}}}, {Done: true, Coverage: &model.ParseCoverage{RecordsRead: 3, Mapped: 1, Unmapped: 2, Undated: 1}}})
	if err != nil || calls != 1 || cov.Undated != 1 || cov.RecordsRead != 3 {
		t.Fatalf("legitimate coverage rejected: calls=%d coverage=%+v err=%v", calls, cov, err)
	}
}

func TestSQLStreamRejectsIncorrectUndatedCoverage(t *testing.T) {
	_, _, err := runReviewFrames(t, []streamFrame{{Batch: &parsers.ParseResult{Events: []model.Event{{SourceReference: "line:1"}}, Raw: []model.RawEvidence{{SourceReference: "line:1", Raw: "source record"}}}}, {Done: true, Coverage: &model.ParseCoverage{RecordsRead: 1, Mapped: 1}}})
	if err == nil {
		t.Fatal("unknown event time reported as dated coverage")
	}
}

func TestSQLStreamRejectsUnpairedEvidence(t *testing.T) {
	calls, _, err := runReviewFrames(t, []streamFrame{{Batch: &parsers.ParseResult{Events: []model.Event{{SourceReference: "line:1"}}}}, {Done: true, Coverage: &model.ParseCoverage{RecordsRead: 1, Mapped: 1}}})
	var failure *ProcessFailure
	if !errors.As(err, &failure) || calls != 0 {
		t.Fatalf("unpaired evidence accepted: calls=%d err=%v", calls, err)
	}
}
