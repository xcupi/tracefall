package ntfs_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"tracefall/internal/ntfs"
	"tracefall/internal/ntfs/mftgen"
)

func writeLog(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "$LogFile")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A realistic log: two restart pages, then record pages holding a
// transaction that is prepared, acted on and committed.
func sampleLogFile() []byte {
	restart := mftgen.LogRestart{
		MajorVersion: 1, MinorVersion: 1,
		CurrentLSN: 0x5000, ChkdskLSN: 0x10, FileSize: 4 * mftgen.LogPageSize,
		SequenceBits: 0x2B,
		Clients: []mftgen.LogClientEntry{
			{Name: "NTFS", OldestLSN: 0x1000, ClientRestartLSN: 0x4F00, SequenceNumber: 1},
		},
	}
	recs := []mftgen.LogRec{
		{ThisLSN: 0x4000, TransactionID: 0x11, RedoOperation: 0x19, UndoOperation: 0x00, RecordType: 1},
		{ThisLSN: 0x4010, ClientPreviousLSN: 0x4000, TransactionID: 0x11,
			RedoOperation: 0x02, UndoOperation: 0x03, RedoLength: 16, UndoLength: 8,
			TargetAttribute: 0x30, TargetVCN: 4, TargetLCN: 900, RecordType: 1},
		{ThisLSN: 0x4020, ClientPreviousLSN: 0x4010, TransactionID: 0x11,
			RedoOperation: 0x0E, UndoOperation: 0x0F, RecordType: 1},
		{ThisLSN: 0x4030, ClientPreviousLSN: 0x4020, TransactionID: 0x11,
			RedoOperation: 0x1A, UndoOperation: 0x00, RecordType: 1},
		{ThisLSN: 0x4040, TransactionID: 0x12, RedoOperation: 0x07, UndoOperation: 0x07,
			ClientDataLength: 32, RecordType: 1},
	}
	return mftgen.BuildLogFile(
		mftgen.BuildRestartPage(restart),
		mftgen.BuildRestartPage(restart),
		mftgen.BuildRecordPage(0x4030, 1, 1, recs[:4]),
		mftgen.BuildRecordPage(0x4040, 1, 1, recs[4:]),
	)
}

// 1. The restart area parses, with its LSNs and client records.
func TestLog_ValidRestartArea(t *testing.T) {
	sum, err := ntfs.ScanLogFile(writeLog(t, sampleLogFile()), ntfs.LogScanOptions{}, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(sum.RestartAreas) != 2 {
		t.Fatalf("got %d restart areas, want 2", len(sum.RestartAreas))
	}
	a := sum.RestartAreas[0]
	if a.Signature != "RSTR" {
		t.Errorf("signature = %q", a.Signature)
	}
	if a.CurrentLSN != 0x5000 {
		t.Errorf("current LSN = %#x, want 0x5000", a.CurrentLSN)
	}
	if a.ChkdskLSN != 0x10 {
		t.Errorf("chkdsk LSN = %#x, want 0x10", a.ChkdskLSN)
	}
	if a.MajorVersion != 1 || a.MinorVersion != 1 {
		t.Errorf("version = %d.%d, want 1.1", a.MajorVersion, a.MinorVersion)
	}
	if a.LogPageSize != mftgen.LogPageSize {
		t.Errorf("log page size = %d", a.LogPageSize)
	}
	if len(a.Clients) != 1 {
		t.Fatalf("got %d clients, want 1", len(a.Clients))
	}
	c := a.Clients[0]
	if c.Name != "NTFS" {
		t.Errorf("client name = %q, want NTFS", c.Name)
	}
	if c.OldestLSN != 0x1000 || c.ClientRestartLSN != 0x4F00 {
		t.Errorf("client LSNs = %#x/%#x", c.OldestLSN, c.ClientRestartLSN)
	}
}

// 2 + 3 + 4 + 5. Log records parse with LSNs, transaction IDs and
// redo/undo operations.
func TestLog_ValidRecordsAndTransactionMetadata(t *testing.T) {
	var got []ntfs.LogRecord
	sum, err := ntfs.ScanLogFile(writeLog(t, sampleLogFile()), ntfs.LogScanOptions{},
		func(_ ntfs.LogPage, r ntfs.LogRecord) error { got = append(got, r); return nil })
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d log records, want 5", len(got))
	}
	if sum.RecordsParsed != 5 {
		t.Errorf("summary counted %d records, want 5", sum.RecordsParsed)
	}

	// LSN chain.
	if got[0].ThisLSN != 0x4000 {
		t.Errorf("first LSN = %#x, want 0x4000", got[0].ThisLSN)
	}
	if got[1].ClientPreviousLSN != 0x4000 {
		t.Errorf("previous LSN = %#x, want 0x4000", got[1].ClientPreviousLSN)
	}
	if sum.MinLSN != 0x4000 || sum.MaxLSN != 0x4040 {
		t.Errorf("LSN range = %#x..%#x, want 0x4000..0x4040", sum.MinLSN, sum.MaxLSN)
	}

	// Transactions.
	if sum.TransactionIDs[0x11] != 4 {
		t.Errorf("transaction 0x11 has %d records, want 4", sum.TransactionIDs[0x11])
	}
	if sum.TransactionIDs[0x12] != 1 {
		t.Errorf("transaction 0x12 has %d records, want 1", sum.TransactionIDs[0x12])
	}

	// Redo/undo operations render by name.
	if got[0].RedoName() != "PrepareTransaction" {
		t.Errorf("redo = %q, want PrepareTransaction", got[0].RedoName())
	}
	if got[1].RedoName() != "InitializeFileRecordSegment" {
		t.Errorf("redo = %q", got[1].RedoName())
	}
	if got[1].UndoName() != "DeallocateFileRecordSegment" {
		t.Errorf("undo = %q", got[1].UndoName())
	}
	if got[3].RedoName() != "CommitTransaction" {
		t.Errorf("redo = %q, want CommitTransaction", got[3].RedoName())
	}
	if sum.RedoCounts["CommitTransaction"] != 1 {
		t.Errorf("commit count = %d, want 1", sum.RedoCounts["CommitTransaction"])
	}

	// Target metadata is preserved.
	if got[1].TargetAttribute != 0x30 || got[1].TargetVCN != 4 || got[1].TargetLCN != 900 {
		t.Errorf("target metadata lost: attr=%#x vcn=%d lcn=%d",
			got[1].TargetAttribute, got[1].TargetVCN, got[1].TargetLCN)
	}
	if got[1].RedoLength != 16 || got[1].UndoLength != 8 {
		t.Errorf("redo/undo lengths lost: %d/%d", got[1].RedoLength, got[1].UndoLength)
	}
}

// An unknown opcode is NAMED, not silently blank.
func TestLog_UnknownOperationIsNamed(t *testing.T) {
	page := mftgen.BuildRecordPage(0x100, 1, 1, []mftgen.LogRec{
		{ThisLSN: 0x100, TransactionID: 1, RedoOperation: 0x7F, UndoOperation: 0x7E},
	})
	logfile := mftgen.BuildLogFile(mftgen.BuildRestartPage(mftgen.LogRestart{CurrentLSN: 1}), page)
	var got []ntfs.LogRecord
	if _, err := ntfs.ScanLogFile(writeLog(t, logfile), ntfs.LogScanOptions{},
		func(_ ntfs.LogPage, r ntfs.LogRecord) error { got = append(got, r); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("no records")
	}
	if got[0].RedoName() != "Unknown(0x7F)" {
		t.Errorf("unknown redo opcode rendered as %q", got[0].RedoName())
	}
}

// A chkdsk-rewritten restart page is identified as such.
func TestLog_ChkdskRestartPage(t *testing.T) {
	logfile := mftgen.BuildLogFile(
		mftgen.BuildRestartPage(mftgen.LogRestart{Chkdsk: true, CurrentLSN: 0x77, ChkdskLSN: 0x77}),
		mftgen.BuildRecordPage(0x77, 1, 1, []mftgen.LogRec{{ThisLSN: 0x77, RedoOperation: 0x18}}),
	)
	sum, err := ntfs.ScanLogFile(writeLog(t, logfile), ntfs.LogScanOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.RestartAreas) == 0 || sum.RestartAreas[0].Signature != "CHKD" {
		t.Error("a chkdsk-rewritten restart page was not identified")
	}
}

// 6 + 7. Corrupt and truncated logs must not crash.
func TestLog_MalformedNeverCrashes(t *testing.T) {
	base := sampleLogFile()
	for _, how := range []string{"signature", "fixup", "next-record-offset", "client-data-length", "page-size"} {
		t.Run(how, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", how, r)
				}
			}()
			_, _ = ntfs.ScanLogFile(writeLog(t, mftgen.CorruptLogPage(base, 2, how)),
				ntfs.LogScanOptions{}, func(ntfs.LogPage, ntfs.LogRecord) error { return nil })
		})
	}
	for cut := 0; cut < len(base); cut += 511 {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked at truncation %d: %v", cut, r)
				}
			}()
			_, _ = ntfs.ScanLogFile(writeLog(t, base[:cut]), ntfs.LogScanOptions{}, nil)
		}()
	}
	for i := 0; i < len(base) && i < 5000; i += 17 {
		mutated := append([]byte(nil), base...)
		mutated[i] ^= 0xFF
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on byte flip at %d: %v", i, r)
				}
			}()
			_, _ = ntfs.ScanLogFile(writeLog(t, mutated), ntfs.LogScanOptions{}, nil)
		}()
	}
}

// A damaged page costs its own records, not the whole log.
func TestLog_DamagedPageDoesNotSilenceTheLog(t *testing.T) {
	damaged := mftgen.CorruptLogPage(sampleLogFile(), 2, "signature")
	sum, err := ntfs.ScanLogFile(writeLog(t, damaged), ntfs.LogScanOptions{}, nil)
	if err != nil {
		t.Fatalf("one damaged page aborted the scan: %v", err)
	}
	if len(sum.RestartAreas) == 0 {
		t.Error("the restart areas were lost to a damaged record page")
	}
	if sum.RecordsParsed == 0 {
		t.Error("the undamaged record page produced nothing")
	}
}

// 8. Deterministic repeated parsing.
func TestLog_IsDeterministic(t *testing.T) {
	path := writeLog(t, sampleLogFile())
	read := func() ([]ntfs.LogRecord, ntfs.LogFileSummary) {
		var recs []ntfs.LogRecord
		s, err := ntfs.ScanLogFile(path, ntfs.LogScanOptions{},
			func(_ ntfs.LogPage, r ntfs.LogRecord) error { recs = append(recs, r); return nil })
		if err != nil {
			t.Fatal(err)
		}
		return recs, s
	}
	firstRecs, firstSum := read()
	for i := 0; i < 15; i++ {
		recs, sum := read()
		if !reflect.DeepEqual(firstRecs, recs) {
			t.Fatalf("run %d produced different records", i)
		}
		if !reflect.DeepEqual(firstSum, sum) {
			t.Fatalf("run %d produced a different summary", i)
		}
	}
}

// The parser must produce NO timeline events: a LOG_RECORD_HEADER has no
// timestamp field, so there is nothing to place on a timeline.
func TestLog_RecordsCarryNoTimestamp(t *testing.T) {
	var recs []ntfs.LogRecord
	if _, err := ntfs.ScanLogFile(writeLog(t, sampleLogFile()), ntfs.LogScanOptions{},
		func(_ ntfs.LogPage, r ntfs.LogRecord) error { recs = append(recs, r); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("no records")
	}
	// The struct deliberately has no time field. Assert it by reflection
	// so adding one silently cannot happen.
	typ := reflect.TypeOf(recs[0])
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type.String() == "time.Time" {
			t.Errorf("LogRecord gained a %s field; $LogFile records carry no timestamp and one must not be invented",
				typ.Field(i).Name)
		}
	}
}

// Cancellation and limits are honoured.
func TestLog_CancellationAndRetentionLimit(t *testing.T) {
	var pages [][]byte
	pages = append(pages, mftgen.BuildRestartPage(mftgen.LogRestart{CurrentLSN: 1}))
	for i := 0; i < 200; i++ {
		pages = append(pages, mftgen.BuildRecordPage(uint64(i), 1, 1, []mftgen.LogRec{
			{ThisLSN: uint64(0x1000 + i), TransactionID: uint32(i), RedoOperation: 0x07},
		}))
	}
	path := writeLog(t, mftgen.BuildLogFile(pages...))

	var progress int
	sum, err := ntfs.ScanLogFile(path, ntfs.LogScanOptions{Progress: func(int) { progress++ }}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sum.RecordsParsed != 200 {
		t.Errorf("parsed %d records, want 200", sum.RecordsParsed)
	}

	var retained int
	if _, err := ntfs.ScanLogFile(path, ntfs.LogScanOptions{MaxRecordsRetained: 25},
		func(ntfs.LogPage, ntfs.LogRecord) error { retained++; return nil }); err != nil {
		t.Fatal(err)
	}
	if retained != 25 {
		t.Errorf("retained %d records, want the 25 limit", retained)
	}

	var seen int
	if _, err := ntfs.ScanLogFile(path, ntfs.LogScanOptions{Cancelled: func() bool { return seen > 10 }},
		func(ntfs.LogPage, ntfs.LogRecord) error { seen++; return nil }); err == nil {
		t.Error("cancellation did not stop the scan")
	}
}

// Sniffing must not claim unrelated files.
func TestLog_SniffIsNarrow(t *testing.T) {
	if !ntfs.SniffLogFile(sampleLogFile()) {
		t.Error("a real $LogFile was not recognized")
	}
	for name, data := range map[string][]byte{
		"empty":       {},
		"text":        []byte("plain text, definitely not an NTFS transaction log at all"),
		"zeros":       make([]byte, 4096),
		"mft":         sampleTable(),
		"usn journal": sampleJournal(),
		"RSTR only":   append([]byte("RSTR"), make([]byte, 200)...),
	} {
		if ntfs.SniffLogFile(data) {
			t.Errorf("%q was misidentified as a $LogFile", name)
		}
	}
}
