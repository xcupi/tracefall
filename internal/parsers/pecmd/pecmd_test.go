package pecmd

import (
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/model"
)

func TestDetect(t *testing.T) {
	p := New()
	if !p.Detect("PECmd/20260115_PECmd_Output.csv") {
		t.Error("expected PECmd output file to be detected")
	}
	if p.Detect("EvtxECmd/20260115_EvtxECmd_Output.csv") {
		t.Error("expected EvtxECmd output file not to be detected")
	}
}

func TestParse(t *testing.T) {
	csv := `SourceFilename,ExecutableName,RunCount,LastRun,Size
C:\Windows\Prefetch\UPDATE.EXE-7C21F0AA.pf,UPDATE.EXE,1,2026-01-15T09:15:11.0000000Z,18944
`
	dir := t.TempDir()
	path := filepath.Join(dir, "20260115_PECmd_Output.csv")
	if err := os.WriteFile(path, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	e := res.Events[0]
	if e.EventType != model.EventPrefetchExecution {
		t.Errorf("event type = %q, want %q", e.EventType, model.EventPrefetchExecution)
	}
	if e.ProcessName != "update.exe" {
		t.Errorf("process_name = %q, want update.exe", e.ProcessName)
	}
	if e.ArtifactType != model.ArtifactPrefetch {
		t.Errorf("artifact_type = %q, want %q", e.ArtifactType, model.ArtifactPrefetch)
	}
	if e.Extra["run_count"] != "1" {
		t.Errorf("run_count = %q, want 1", e.Extra["run_count"])
	}
}

func TestParseSkipsRowsMissingTimestamp(t *testing.T) {
	csv := `SourceFilename,ExecutableName,RunCount,LastRun,Size
C:\Windows\Prefetch\NOPE.EXE-00000000.pf,NOPE.EXE,1,,18944
`
	dir := t.TempDir()
	path := filepath.Join(dir, "20260115_PECmd_Output.csv")
	if err := os.WriteFile(path, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 0 {
		t.Fatalf("got %d events for a row with no LastRun timestamp, want 0", len(res.Events))
	}
}
