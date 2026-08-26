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

// TestParse_Phase4VolumeAndFilesLoaded covers the additional fields
// Phase 4A added: volume info, a bounded FilesLoaded summary (never the
// full unbounded list), and the earliest of the PreviousRun0..6 columns
// as "earliest_recorded_run".
func TestParse_Phase4VolumeAndFilesLoaded(t *testing.T) {
	csv := `SourceFilename,ExecutableName,RunCount,LastRun,Size,Volume0Name,Volume0Serial,FilesLoaded,PreviousRun0,PreviousRun1
C:\Windows\Prefetch\UPDATE.EXE-7C21F0AA.pf,UPDATE.EXE,3,2026-01-15T09:15:11.0000000Z,18944,OSDisk,1A2B3C4D,C:\Windows\System32\kernel32.dll;C:\Users\jdoe\AppData\Local\Temp\update.exe,2026-01-14T08:00:00.0000000Z,2026-01-10T08:00:00.0000000Z
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
	if e.Extra["volume_name"] != "OSDisk" {
		t.Errorf("volume_name = %q, want OSDisk", e.Extra["volume_name"])
	}
	if e.Extra["volume_serial"] != "1A2B3C4D" {
		t.Errorf("volume_serial = %q, want 1A2B3C4D", e.Extra["volume_serial"])
	}
	if e.Extra["files_loaded_count"] != "2" {
		t.Errorf("files_loaded_count = %q, want 2", e.Extra["files_loaded_count"])
	}
	if e.Extra["files_loaded_sample"] == "" {
		t.Error("expected non-empty files_loaded_sample")
	}
	// The oldest of PreviousRun0/1 is 2026-01-10.
	if e.Extra["earliest_recorded_run"] == "" {
		t.Error("expected earliest_recorded_run to be populated")
	}
}

// A very long FilesLoaded list must be truncated, not stored unbounded.
func TestParse_Phase4FilesLoadedTruncated(t *testing.T) {
	var files string
	for i := 0; i < 200; i++ {
		files += `C:\Windows\System32\somelongishdllname` + string(rune('a'+i%26)) + `.dll;`
	}
	csv := "SourceFilename,ExecutableName,RunCount,LastRun,Size,FilesLoaded\n" +
		`C:\Windows\Prefetch\UPDATE.EXE-7C21F0AA.pf,UPDATE.EXE,1,2026-01-15T09:15:11.0000000Z,18944,` + files + "\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "20260115_PECmd_Output.csv")
	if err := os.WriteFile(path, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	sample := res.Events[0].Extra["files_loaded_sample"]
	if len(sample) > 520 {
		t.Errorf("files_loaded_sample length = %d, want bounded to roughly 500 chars", len(sample))
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
