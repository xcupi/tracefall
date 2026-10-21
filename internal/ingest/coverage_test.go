package ingest

import (
	"bytes"
	"encoding/json"
	"testing"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

type coverageOnlyParser struct{}

func (coverageOnlyParser) Name() string         { return "coverage-test@1" }
func (coverageOnlyParser) ArtifactType() string { return model.ArtifactWindowsEventLog }
func (coverageOnlyParser) Detect(string) bool   { return true }
func (coverageOnlyParser) Parse(string) (parsers.ParseResult, error) {
	return parsers.ParseResult{Coverage: &model.ParseCoverage{RecordsRead: 1, Unmapped: 1}}, nil
}
func TestCoverage_SurvivesWorkerSerializationAndIngestWithNoEvents(t *testing.T) {
	original, _ := coverageOnlyParser{}.Parse("")
	var b bytes.Buffer
	if err := writeResult(&b, original); err != nil {
		t.Fatal(err)
	}
	var r workerResponse
	if err := json.Unmarshal(b.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Result.Coverage == nil || r.Result.Coverage.Unmapped != 1 {
		t.Error("worker dropped source-level coverage")
	}
	out, err := ParseFile("case", "collection", "source", t.TempDir(), "file.evtx", coverageOnlyParser{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Coverage == nil || out.Coverage.Unmapped != 1 {
		t.Error("ingest dropped zero-event coverage")
	}
}
