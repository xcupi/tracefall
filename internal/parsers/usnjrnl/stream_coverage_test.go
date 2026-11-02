package usnjrnl_test

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/ntfs/mftgen"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/usnjrnl"
)

func run(t *testing.T, data []byte) (*model.ParseCoverage, int, error) {
	t.Helper()
	events := 0
	cov, err := usnjrnl.New().ParseStream(context.Background(), write(t, data), parsers.ParseContext{}, func(b parsers.ParseResult) error {
		events += len(b.Events)
		return nil
	})
	return cov, events, err
}

func entry(i int, name string) mftgen.UsnEntry {
	return mftgen.UsnEntry{FileRecord: 64, FileSequence: 2, ParentRecord: 5, ParentSeq: 1, Usn: uint64(i + 1), Timestamp: base, Reason: mftgen.ReasonFileCreate, FileName: name}
}

func TestStreamCoverage_NonRecordBytesAndUnmappedClassesAreCounted(t *testing.T) {
	data := mftgen.BuildUsnJournal(4096, []mftgen.UsnEntry{entry(0, "a.txt"), entry(1, "b.txt"), entry(2, "c.txt")})
	zeroTime := entry(3, "d.txt")
	data = append(data, mftgen.BuildUsnRecord(zeroTime)...)
	data = mftgen.CorruptUsn(data, len(data)-len(mftgen.BuildUsnRecord(zeroTime)), "zero-time")
	first := len(data)
	data = append(data, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE) // 16 non-record bytes
	cov, events, err := run(t, data)
	if err != nil {
		t.Fatal(err)
	}
	n := cov.Ntfs
	if n == nil || n.Source != model.NtfsSourceUSN {
		t.Fatalf("no NTFS coverage: %+v", cov)
	}
	if cov.RecordsRead != 4 || cov.Mapped != 3 || cov.Unmapped != 1 || events != 3 || n.UnmappedUndated != 1 {
		t.Fatalf("counts read=%d mapped=%d unmapped=%d events=%d ntfs=%+v", cov.RecordsRead, cov.Mapped, cov.Unmapped, events, n)
	}
	if n.NonRecordBytes != 16 || n.FirstNonRecordOffset == nil || *n.FirstNonRecordOffset != int64(first) {
		t.Fatalf("non-record bytes: %+v", n)
	}
	if n.Failed || !cov.Incomplete() {
		t.Fatalf("readable but incomplete: failed=%v incomplete=%v", n.Failed, cov.Incomplete())
	}
}

// The layout of the diagnosed real failure, built from neutral data: the file
// holds 1 KiB FILE records at a 2-byte shift (an $MFT carved into a $J slot)
// followed by arbitrary non-journal bytes.
func TestStreamCoverage_MFTShapedBytesInsteadOfAJournalIsAFailedSource(t *testing.T) {
	table := mftgen.Build([]mftgen.File{
		{RecordNumber: 0, SequenceNumber: 1, InUse: true, SI: mftgen.Times{Created: base}, Names: []mftgen.Name{{Name: "a.txt", Namespace: 1, ParentRef: 5, ParentSeq: 1}}},
		{RecordNumber: 1, SequenceNumber: 1, InUse: true, SI: mftgen.Times{Created: base}, Names: []mftgen.Name{{Name: "b.txt", Namespace: 1, ParentRef: 5, ParentSeq: 1}}},
	})
	data := append([]byte{2, 0}, table...)
	cov, events, err := run(t, data)
	if err == nil || events != 0 {
		t.Fatalf("a non-journal was accepted: %v", err)
	}
	n := cov.Ntfs
	if n == nil || !n.Failed || n.Source != model.NtfsSourceUSN || n.FailureClass != model.NtfsFailureNotAJournal {
		t.Fatalf("failure class: %+v", n)
	}
	if n.NonRecordBytes <= 0 || n.FirstNonRecordOffset == nil || *n.FirstNonRecordOffset != 0 || n.FailureOffset == nil || *n.FailureOffset != 0 {
		t.Fatalf("offsets/bytes not recorded: %+v", n)
	}
	if cov.EmittedEvents == nil || *cov.EmittedEvents != 0 {
		t.Fatal("a failed source must state zero events")
	}
	if s := cov.NtfsSummary(); s == "" {
		t.Fatal("no sentence")
	}
}

func TestStreamCoverage_DamagedRecordIsCorruptWithOffset(t *testing.T) {
	data := mftgen.BuildUsnJournal(0, []mftgen.UsnEntry{entry(0, "a.txt"), entry(1, "b.txt")})
	rec := len(mftgen.BuildUsnRecord(entry(0, "a.txt")))
	binary.LittleEndian.PutUint16(data[rec+0x38:], 7) // odd name length in the second record
	cov, _, err := run(t, data)
	if err == nil {
		t.Fatal("accepted a damaged record")
	}
	n := cov.Ntfs
	if n == nil || !n.Failed || n.FailureClass != model.NtfsFailureCorrupt || n.FailureOffset == nil || *n.FailureOffset != int64(rec) {
		t.Fatalf("damage not located: %+v", n)
	}
	if cov.RecordsRead != 1 {
		t.Fatalf("the record before the damage was read: %+v", cov)
	}
}

func TestStreamCoverage_UnsupportedVersionClass(t *testing.T) {
	b := nativeUSN()
	binary.LittleEndian.PutUint16(b[4:], 4)
	cov, _, err := run(t, b)
	if err == nil || cov.Ntfs == nil || cov.Ntfs.FailureClass != model.NtfsFailureUnsupported {
		t.Fatalf("%v %+v", err, cov.Ntfs)
	}
}

// More than the legacy 300,000-event ceiling goes through the streaming path.
func TestStreamCoverage_RecordsExceedLegacyCeiling(t *testing.T) {
	const n = 300_050
	var out []byte
	rec := mftgen.BuildUsnRecord(entry(0, "same.txt"))
	out = make([]byte, 0, n*len(rec))
	for i := 0; i < n; i++ {
		out = append(out, rec...)
	}
	cov, events, err := run(t, out)
	if err != nil {
		t.Fatal(err)
	}
	if events != n || events <= usnjrnl.DefaultMaxEvents || cov.LimitReached || cov.RecordsRead != n || cov.Ntfs == nil || cov.Ntfs.Failed {
		t.Fatalf("events=%d ceiling=%d cov=%+v", events, usnjrnl.DefaultMaxEvents, cov)
	}
	_ = time.Now
}
