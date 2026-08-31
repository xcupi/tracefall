package evtx_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/evtx"
	"tracefall/internal/evtx/evtxgen"
)

func writeLog(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Security.evtx")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

var baseTime = time.Date(2026, 1, 15, 9, 15, 30, 0, time.UTC)

// logon4624 is a synthetic Security 4624 (successful logon) with the
// EventData fields Windows really emits for it.
func logon4624() evtxgen.Event {
	return evtxgen.Event{
		RecordID:  1001,
		Timestamp: baseTime,
		Provider:  "Microsoft-Windows-Security-Auditing",
		Channel:   "Security",
		Computer:  "WKSTN-042",
		EventID:   4624,
		Level:     0,
		Task:      12544,
		ProcessID: 668,
		ThreadID:  1024,
		UserID:    "S-1-5-18",
		Data: map[string]string{
			"TargetUserName":   "jdoe",
			"TargetDomainName": "CORP",
			"TargetUserSid":    "S-1-5-21-1111-2222-3333-1001",
			"LogonType":        "3",
			"IpAddress":        "10.4.2.15",
			"WorkstationName":  "WKSTN-042",
			"SubjectUserName":  "SYSTEM",
		},
	}
}

func readAll(t *testing.T, path string, lim evtx.Limits) ([]evtx.Record, evtx.Stats) {
	t.Helper()
	f, err := evtx.Open(path, lim)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	var recs []evtx.Record
	stats, err := f.Walk(func(r evtx.Record) error {
		recs = append(recs, r)
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return recs, stats
}

func TestSniff(t *testing.T) {
	if !evtx.Sniff([]byte("ElfFile\x00extra")) {
		t.Error("Sniff rejected a valid EVTX signature")
	}
	if evtx.Sniff([]byte("regf....")) {
		t.Error("Sniff accepted a registry hive as an event log")
	}
	if evtx.Sniff([]byte("Elf")) {
		t.Error("Sniff accepted a too-short header")
	}
}

// The core round-trip: every System field and every EventData pair must
// survive template instantiation and substitution exactly.
func TestWalk_ParsesSystemAndEventData(t *testing.T) {
	want := logon4624()
	recs, stats := readAll(t, writeLog(t, evtxgen.Build([]evtxgen.Event{want})), evtx.Limits{})

	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1 (stats %+v)", len(recs), stats)
	}
	if stats.Partial() {
		t.Errorf("stats report a partial parse of an intact file: %+v", stats)
	}
	got := recs[0]

	if got.System.Provider != want.Provider {
		t.Errorf("Provider = %q, want %q", got.System.Provider, want.Provider)
	}
	if got.System.Channel != want.Channel {
		t.Errorf("Channel = %q, want %q", got.System.Channel, want.Channel)
	}
	if got.System.Computer != want.Computer {
		t.Errorf("Computer = %q, want %q", got.System.Computer, want.Computer)
	}
	if got.System.EventID != want.EventID {
		t.Errorf("EventID = %d, want %d", got.System.EventID, want.EventID)
	}
	if got.System.EventRecordID != want.RecordID {
		t.Errorf("EventRecordID = %d, want %d", got.System.EventRecordID, want.RecordID)
	}
	if !got.System.TimeCreated.Equal(baseTime) {
		t.Errorf("TimeCreated = %v, want %v", got.System.TimeCreated, baseTime)
	}
	if got.System.ProcessID != want.ProcessID || got.System.ThreadID != want.ThreadID {
		t.Errorf("Execution = pid %d tid %d, want %d/%d",
			got.System.ProcessID, got.System.ThreadID, want.ProcessID, want.ThreadID)
	}
	if got.System.Task != want.Task {
		t.Errorf("Task = %d, want %d", got.System.Task, want.Task)
	}
	// The SID is written in binary and must render in the canonical text
	// form, which is what every other Windows tool prints.
	if got.System.UserID != "S-1-5-18" {
		t.Errorf("Security UserID = %q, want S-1-5-18", got.System.UserID)
	}

	for k, v := range want.Data {
		if got.Data[k] != v {
			t.Errorf("EventData[%q] = %q, want %q (all: %+v)", k, got.Data[k], v, got.Data)
		}
	}
}

// Templates exist to be shared. Many records of the same event type must
// all resolve correctly, not just the first one that carried the inline
// definition.
func TestWalk_ManyRecordsShareATemplate(t *testing.T) {
	var events []evtxgen.Event
	for i := 0; i < 200; i++ {
		e := logon4624()
		e.RecordID = uint64(2000 + i)
		e.Timestamp = baseTime.Add(time.Duration(i) * time.Second)
		e.Data["TargetUserName"] = fmt.Sprintf("user%03d", i)
		events = append(events, e)
	}
	recs, stats := readAll(t, writeLog(t, evtxgen.Build(events)), evtx.Limits{})

	if len(recs) != 200 {
		t.Fatalf("records = %d, want 200 (stats %+v)", len(recs), stats)
	}
	for i, r := range recs {
		if want := uint64(2000 + i); r.System.EventRecordID != want {
			t.Fatalf("record %d has EventRecordID %d, want %d", i, r.System.EventRecordID, want)
		}
		if want := fmt.Sprintf("user%03d", i); r.Data["TargetUserName"] != want {
			t.Fatalf("record %d TargetUserName = %q, want %q", i, r.Data["TargetUserName"], want)
		}
		if want := baseTime.Add(time.Duration(i) * time.Second); !r.System.TimeCreated.Equal(want) {
			t.Fatalf("record %d time = %v, want %v", i, r.System.TimeCreated, want)
		}
	}
}

// A chunk holds 64 KiB; enough records must spill into a second chunk,
// and all of them must be read.
func TestWalk_MultiChunk(t *testing.T) {
	var events []evtxgen.Event
	for i := 0; i < 600; i++ {
		e := logon4624()
		e.RecordID = uint64(i + 1)
		e.Data["TargetUserName"] = fmt.Sprintf("multichunk-user-%04d", i)
		events = append(events, e)
	}
	log := evtxgen.Build(events)

	f, err := evtx.Open(writeLog(t, log), evtx.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.ChunkCount() < 2 {
		t.Fatalf("fixture produced %d chunk(s); this test needs a multi-chunk file", f.ChunkCount())
	}

	seen := map[uint64]bool{}
	stats, err := f.Walk(func(r evtx.Record) error {
		seen[r.System.EventRecordID] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 600 {
		t.Errorf("read %d distinct records across %d chunks, want 600 (stats %+v)", len(seen), f.ChunkCount(), stats)
	}
	if stats.ChunksRead < 2 {
		t.Errorf("ChunksRead = %d, want at least 2", stats.ChunksRead)
	}
}

func TestWalk_VariedValueTypes(t *testing.T) {
	e := logon4624()
	e.Keywords = "0x8020000000000000"
	e.Level = 4
	e.Opcode = 0
	recs, _ := readAll(t, writeLog(t, evtxgen.Build([]evtxgen.Event{e})), evtx.Limits{})
	if len(recs) != 1 {
		t.Fatal("expected one record")
	}
	if recs[0].System.Level != 4 {
		t.Errorf("Level = %d, want 4", recs[0].System.Level)
	}
	if recs[0].System.Keywords != "0x8020000000000000" {
		t.Errorf("Keywords = %q", recs[0].System.Keywords)
	}
}

// ---------- malformed input ----------

func TestOpen_RejectsMalformedFiles(t *testing.T) {
	valid := evtxgen.Build([]evtxgen.Event{logon4624()})

	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"bad signature", evtxgen.CorruptSignature(valid), evtx.ErrNotEVTX},
		{"empty file", nil, evtx.ErrCorrupt},
		{"shorter than the header", make([]byte, 512), evtx.ErrCorrupt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := evtx.Open(writeLog(t, tc.data), evtx.Limits{})
			if err == nil {
				t.Fatal("expected an error")
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want one wrapping %v", err, tc.want)
			}
		})
	}
}

func TestOpen_RejectsOversizedFile(t *testing.T) {
	valid := evtxgen.Build([]evtxgen.Event{logon4624()})
	_, err := evtx.Open(writeLog(t, valid), evtx.Limits{MaxFileBytes: 1024})
	if !errors.Is(err, evtx.ErrLimitExceeded) {
		t.Errorf("error = %v, want ErrLimitExceeded", err)
	}
}

// A truncated log is the single most common real-world defect, because
// logs are copied while Windows is writing to them. Records in the
// intact chunks must survive.
func TestWalk_TruncatedFileRecoversIntactChunks(t *testing.T) {
	var events []evtxgen.Event
	for i := 0; i < 600; i++ {
		e := logon4624()
		e.RecordID = uint64(i + 1)
		events = append(events, e)
	}
	full := evtxgen.Build(events)
	if len(full) < 4096+2*65536 {
		t.Fatalf("fixture is only %d bytes; this test needs at least two chunks", len(full))
	}
	// Cut in the middle of the second chunk.
	truncated := evtxgen.Truncate(full, 4096+65536+30000)

	recs, stats := readAll(t, writeLog(t, truncated), evtx.Limits{})
	if len(recs) == 0 {
		t.Fatal("a truncated log yielded no records at all; the intact first chunk should still be readable")
	}
	for _, r := range recs {
		if r.System.Computer != "WKSTN-042" {
			t.Errorf("recovered record has wrong Computer %q", r.System.Computer)
		}
	}
	t.Logf("recovered %d records from a truncated log (stats %+v)", len(recs), stats)
}

// A chunk whose CRC does not match is known-damaged. It must be skipped
// AND counted -- silently trusting it, or silently dropping it, would
// both be wrong.
func TestWalk_BadChunkIsSkippedAndReported(t *testing.T) {
	var events []evtxgen.Event
	for i := 0; i < 600; i++ {
		e := logon4624()
		e.RecordID = uint64(i + 1)
		events = append(events, e)
	}
	log := evtxgen.Build(events)
	damaged := evtxgen.CorruptChunkCRC(log, 0)

	recs, stats := readAll(t, writeLog(t, damaged), evtx.Limits{})
	if stats.ChunksFailed != 1 {
		t.Errorf("ChunksFailed = %d, want 1", stats.ChunksFailed)
	}
	if !stats.Partial() {
		t.Error("Partial() is false despite a skipped chunk -- a caller would report this as a complete parse")
	}
	if len(recs) == 0 {
		t.Error("no records recovered from the undamaged chunks")
	}
}

func TestWalk_BadChunkSignatureIsSkipped(t *testing.T) {
	log := evtxgen.Build([]evtxgen.Event{logon4624()})
	recs, stats := readAll(t, writeLog(t, evtxgen.CorruptChunkSignature(log, 0)), evtx.Limits{})
	if len(recs) != 0 {
		t.Errorf("records = %d, want 0 from a log whose only chunk is unreadable", len(recs))
	}
	if stats.ChunksFailed != 1 {
		t.Errorf("ChunksFailed = %d, want 1", stats.ChunksFailed)
	}
}

func TestWalk_ImplausibleRecordSizeIsRejected(t *testing.T) {
	log := evtxgen.Build([]evtxgen.Event{logon4624(), logon4624()})
	recs, stats := readAll(t, writeLog(t, evtxgen.CorruptRecordSize(log, 0)), evtx.Limits{})
	if len(recs) != 0 {
		t.Errorf("records = %d; a record claiming a 4 GiB size must not be parsed", len(recs))
	}
	if stats.RecordsFailed == 0 {
		t.Error("RecordsFailed = 0; the bad record should have been counted")
	}
}

// A record whose framing is valid but whose BinXML is not must fail
// alone: the other records in the same chunk are independent evidence.
func TestWalk_MalformedBinXMLLosesOnlyThatRecord(t *testing.T) {
	events := []evtxgen.Event{logon4624(), logon4624(), logon4624()}
	for i := range events {
		events[i].RecordID = uint64(i + 1)
	}
	log := evtxgen.Build(events)

	recs, stats := readAll(t, writeLog(t, evtxgen.CorruptBinXML(log, 0)), evtx.Limits{})
	if stats.RecordsFailed != 1 {
		t.Errorf("RecordsFailed = %d, want exactly 1", stats.RecordsFailed)
	}
	if len(recs) != 2 {
		t.Errorf("recovered %d records, want the 2 undamaged ones", len(recs))
	}
	if !stats.Partial() {
		t.Error("Partial() must be true when a record failed")
	}
}

func TestWalk_RespectsRecordLimit(t *testing.T) {
	var events []evtxgen.Event
	for i := 0; i < 50; i++ {
		e := logon4624()
		e.RecordID = uint64(i + 1)
		events = append(events, e)
	}
	recs, stats := readAll(t, writeLog(t, evtxgen.Build(events)), evtx.Limits{MaxRecords: 10})
	if len(recs) != 10 {
		t.Errorf("records = %d, want 10", len(recs))
	}
	if !stats.LimitReached {
		t.Error("LimitReached not set despite MaxRecords stopping the walk")
	}
}

// Every byte of an event log is attacker-controlled. Rather than
// enumerate corruptions, flip bytes throughout and require that parsing
// always terminates with either a result or an error -- never a panic,
// never a hang.
func TestFuzzedLogsNeverPanic(t *testing.T) {
	valid := evtxgen.Build([]evtxgen.Event{logon4624(), logon4624()})

	for offset := 0; offset < len(valid); offset += 101 {
		for _, b := range []byte{0x00, 0xff, 0x41} {
			corrupt := append([]byte(nil), valid...)
			corrupt[offset] = b

			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panic with byte %d set to %#x: %v", offset, b, r)
					}
				}()
				f, err := evtx.Open(writeLog(t, corrupt), evtx.Limits{})
				if err != nil {
					return
				}
				defer f.Close()
				_, _ = f.Walk(func(evtx.Record) error { return nil })
			}()
		}
	}
}

// Parsing must not depend on wall-clock time or map iteration order.
func TestParseIsDeterministic(t *testing.T) {
	log := evtxgen.Build([]evtxgen.Event{logon4624()})
	path := writeLog(t, log)

	first, _ := readAll(t, path, evtx.Limits{})
	for i := 0; i < 5; i++ {
		again, _ := readAll(t, path, evtx.Limits{})
		if len(again) != len(first) {
			t.Fatalf("run %d read %d records, first run read %d", i, len(again), len(first))
		}
		for j := range first {
			if fmt.Sprint(first[j]) != fmt.Sprint(again[j]) {
				t.Fatalf("run %d record %d differs:\n%v\n%v", i, j, first[j], again[j])
			}
		}
	}
}
