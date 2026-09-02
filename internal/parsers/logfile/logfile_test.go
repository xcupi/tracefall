package logfile_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/ntfs/mftgen"
	"tracefall/internal/parsers/logfile"
)

func write(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "$LogFile")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func sampleLog() []byte {
	restart := mftgen.LogRestart{
		MajorVersion: 1, MinorVersion: 1, CurrentLSN: 0x5000, ChkdskLSN: 0x10,
		FileSize: 4 * mftgen.LogPageSize, SequenceBits: 0x2B,
		Clients: []mftgen.LogClientEntry{{Name: "NTFS", OldestLSN: 0x1000, ClientRestartLSN: 0x4F00}},
	}
	return mftgen.BuildLogFile(
		mftgen.BuildRestartPage(restart),
		mftgen.BuildRestartPage(restart),
		mftgen.BuildRecordPage(0x4030, 1, 1, []mftgen.LogRec{
			{ThisLSN: 0x4000, TransactionID: 0x11, RedoOperation: 0x19},
			{ThisLSN: 0x4010, ClientPreviousLSN: 0x4000, TransactionID: 0x11,
				RedoOperation: 0x02, UndoOperation: 0x03, TargetAttribute: 0x30},
			{ThisLSN: 0x4020, ClientPreviousLSN: 0x4010, TransactionID: 0x11, RedoOperation: 0x1A},
		}),
	)
}

// THE defining behaviour: the parser produces NO timeline events.
//
// $LogFile records carry no timestamp, and a log record describes a
// byte-level mutation rather than a file operation. Emitting events
// would mean inventing both a time and a meaning.
func TestLogParser_ProducesNoTimelineEvents(t *testing.T) {
	res, err := logfile.New().Parse(write(t, sampleLog()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		t.Fatalf("the $LogFile parser emitted %d timeline events; it must emit none", len(res.Events))
	}
	// But it must not be silent: the validated metadata is recorded.
	if len(res.Raw) == 0 {
		t.Fatal("no metadata was recorded at all")
	}
}

// The summary records validated structure.
func TestLogParser_RecordsValidatedMetadata(t *testing.T) {
	res, err := logfile.New().Parse(write(t, sampleLog()))
	if err != nil {
		t.Fatal(err)
	}
	var summary map[string]any
	var found bool
	for _, r := range res.Raw {
		if r.SourceReference == "logfile:summary" {
			found = true
			if err := json.Unmarshal([]byte(r.Raw), &summary); err != nil {
				t.Fatalf("summary is not valid JSON: %v", err)
			}
		}
	}
	if !found {
		t.Fatal("no summary record")
	}
	for _, key := range []string{
		"parser", "source_file", "file_size", "log_page_size", "pages_scanned",
		"valid_pages", "log_records_parsed", "distinct_transactions", "lsn_range",
		"restart_areas", "redo_operations", "why_no_timeline_events",
	} {
		if _, ok := summary[key]; !ok {
			t.Errorf("summary is missing %q", key)
		}
	}
	if summary["log_records_parsed"].(float64) != 3 {
		t.Errorf("records parsed = %v, want 3", summary["log_records_parsed"])
	}
	if summary["distinct_transactions"].(float64) != 1 {
		t.Errorf("distinct transactions = %v, want 1", summary["distinct_transactions"])
	}
	// The reason for zero events must be stated, not left to inference.
	why, _ := summary["why_no_timeline_events"].(string)
	if !strings.Contains(why, "no timestamp") {
		t.Errorf("the summary does not explain why no events are produced: %q", why)
	}
	// Restart areas with their clients.
	areas, _ := summary["restart_areas"].([]any)
	if len(areas) != 2 {
		t.Fatalf("got %d restart areas, want 2", len(areas))
	}
	a := areas[0].(map[string]any)
	if a["current_lsn"].(float64) != 0x5000 {
		t.Errorf("current LSN = %v", a["current_lsn"])
	}
	clients, _ := a["clients"].([]any)
	if len(clients) != 1 || clients[0].(map[string]any)["name"] != "NTFS" {
		t.Errorf("client records lost: %v", clients)
	}
}

// Per-record metadata carries LSNs, transactions and operations, and
// says explicitly that it is not a timeline entry.
func TestLogParser_PerRecordMetadata(t *testing.T) {
	res, err := logfile.New().Parse(write(t, sampleLog()))
	if err != nil {
		t.Fatal(err)
	}
	var records int
	for _, r := range res.Raw {
		if !strings.HasPrefix(r.SourceReference, "logfile:lsn:") {
			continue
		}
		records++
		var rec map[string]any
		if err := json.Unmarshal([]byte(r.Raw), &rec); err != nil {
			t.Fatalf("record is not valid JSON: %v", err)
		}
		for _, key := range []string{
			"lsn", "transaction_id", "redo_operation", "undo_operation",
			"target_attribute", "record_offset",
		} {
			if _, ok := rec[key]; !ok {
				t.Errorf("record is missing %q", key)
			}
		}
		if rec["timestamp"] != nil {
			t.Errorf("a $LogFile record carries a timestamp it does not have: %v", rec["timestamp"])
		}
		note, _ := rec["note"].(string)
		if !strings.Contains(note, "no timestamp") {
			t.Errorf("record does not state that it is not a timeline entry: %q", note)
		}
	}
	if records != 3 {
		t.Errorf("got %d per-record entries, want 3", records)
	}
}

// Operations render by name, including unknown opcodes.
func TestLogParser_OperationNames(t *testing.T) {
	logf := mftgen.BuildLogFile(
		mftgen.BuildRestartPage(mftgen.LogRestart{CurrentLSN: 1}),
		mftgen.BuildRecordPage(1, 1, 1, []mftgen.LogRec{
			{ThisLSN: 1, RedoOperation: 0x0E, UndoOperation: 0x0F},
			{ThisLSN: 2, RedoOperation: 0x7F},
		}),
	)
	res, err := logfile.New().Parse(write(t, logf))
	if err != nil {
		t.Fatal(err)
	}
	blob := strings.Join(rawStrings(res.Raw), "\n")
	for _, want := range []string{"AddIndexEntryAllocation", "DeleteIndexEntryAllocation", "Unknown(0x7F)"} {
		if !strings.Contains(blob, want) {
			t.Errorf("operation %q was not rendered", want)
		}
	}
}

// Corrupt and truncated logs fail cleanly or degrade, never crash.
func TestLogParser_MalformedNeverCrashes(t *testing.T) {
	base := sampleLog()
	for _, how := range []string{"signature", "fixup", "next-record-offset", "client-data-length", "page-size"} {
		t.Run(how, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", how, r)
				}
			}()
			_, _ = logfile.New().Parse(write(t, mftgen.CorruptLogPage(base, 2, how)))
		})
	}
	for cut := 0; cut < len(base); cut += 997 {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked at truncation %d: %v", cut, r)
				}
			}()
			_, _ = logfile.New().Parse(write(t, base[:cut]))
		}()
	}
}

// Deterministic repeated parsing, byte for byte.
func TestLogParser_IsDeterministic(t *testing.T) {
	path := write(t, sampleLog())
	p := logfile.New()
	first, err := p.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 15; i++ {
		again, err := p.Parse(path)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if len(again.Raw) != len(first.Raw) {
			t.Fatalf("run %d: %d raw records, want %d", i, len(again.Raw), len(first.Raw))
		}
		for j := range first.Raw {
			if first.Raw[j].SourceReference != again.Raw[j].SourceReference ||
				first.Raw[j].Raw != again.Raw[j].Raw {
				t.Fatalf("run %d raw record %d differs", i, j)
			}
		}
	}
}

// Detection is narrow.
func TestLogParser_DetectionIsNarrow(t *testing.T) {
	p := logfile.New()
	for _, name := range []string{"C/$LogFile", "root/$logfile", "export/LogFile"} {
		if !p.Detect(name) {
			t.Errorf("%q was not detected as a $LogFile", name)
		}
	}
	for _, name := range []string{
		"C/$MFT", "C/$Extend/$UsnJrnl:$J", "Windows/System32/config/SYSTEM",
		"Windows/Logs/CBS/CBS.log", "application.log",
	} {
		if p.Detect(name) {
			t.Errorf("%q was misdetected as a $LogFile", name)
		}
	}
	if p.DetectContent([]byte("not an NTFS transaction log, merely some bytes here")) {
		t.Error("arbitrary text was content-detected as a $LogFile")
	}
	if !p.DetectContent(sampleLog()[:512]) {
		t.Error("a real $LogFile was not content-detected")
	}
	if p.ArtifactType() != model.ArtifactLogFile {
		t.Errorf("artifact type = %q", p.ArtifactType())
	}
}

func rawStrings(raw []model.RawEvidence) []string {
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		out = append(out, r.Raw)
	}
	return out
}
