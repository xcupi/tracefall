package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/report"
)

func TestReportCoverageNotesDoNotHideUnmappedOrLosses(t *testing.T) {
	tests := []struct {
		name     string
		coverage *model.ParseCoverage
		want     []string
		unwanted []string
	}{
		{"notes and unmapped", &model.ParseCoverage{RecordsRead: 120, Unmapped: 120, Notes: []string{"14 zero-filled preallocated chunks"}}, []string{"14 zero-filled preallocated chunks", "1 source file(s) contain 120 record(s)", "Unmapped is not the same as benign."}, nil},
		{"notes and failures and unmapped", &model.ParseCoverage{RecordsRead: 12, Unmapped: 9, RecordsFailed: 2, Notes: []string{"bounded caveat"}}, []string{"bounded caveat", "records_failed=2", "1 source file(s) contain 9 record(s)", "Unmapped is not the same as benign."}, nil},
		{"notes and failed chunk", &model.ParseCoverage{ChunksFailed: 1, Notes: []string{"bounded caveat"}}, []string{"bounded caveat", "chunks_failed=1"}, []string{"Unmapped is not the same as benign."}},
		{"notes only", &model.ParseCoverage{Notes: []string{"coverage was not measured"}}, []string{"coverage was not measured"}, []string{"source file(s) contain", "records_failed=0"}},
		{"unmapped only", &model.ParseCoverage{RecordsRead: 7, Unmapped: 7}, []string{"1 source file(s) contain 7 record(s)", "Unmapped is not the same as benign."}, nil},
		{"measured zero", &model.ParseCoverage{}, nil, []string{"source file(s) contain", "parser coverage is incomplete"}},
		{"historical absent", nil, nil, []string{"source file(s) contain", "parser coverage is incomplete"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before, _ := json.Marshal(tt.coverage)
			got := strings.Join(reportLimitations(report.Data{}, reportInputs{sourceFiles: []model.SourceFile{{Path: "channel.evtx", ParseCoverage: tt.coverage}}}), "\n")
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q in %q", want, got)
				}
			}
			for _, bad := range tt.unwanted {
				if strings.Contains(got, bad) {
					t.Errorf("unexpected %q in %q", bad, got)
				}
			}
			after, _ := json.Marshal(tt.coverage)
			if string(before) != string(after) {
				t.Fatal("report mutated source coverage")
			}
		})
	}
}

func TestReportUnmappedSafetySurvivesDiagnosticCapAndCountsSourcesOnce(t *testing.T) {
	var sources []model.SourceFile
	for i := 0; i < 23; i++ {
		sources = append(sources, model.SourceFile{Path: fmt.Sprintf("channel-%02d.evtx", i), ParseCoverage: &model.ParseCoverage{RecordsRead: 3, Unmapped: 2, RecordsFailed: 1, Notes: []string{"bounded caveat"}}})
	}
	got := strings.Join(reportLimitations(report.Data{}, reportInputs{sourceFiles: sources}), "\n")
	for _, want := range []string{"23 source file(s) contain 46 record(s)", "Unmapped is not the same as benign.", "3 more source file(s) have incomplete parser coverage", "records_failed=1"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if n := strings.Count(got, "Unmapped is not the same as benign."); n != 1 {
		t.Errorf("safety summary repeated %d times", n)
	}
}
