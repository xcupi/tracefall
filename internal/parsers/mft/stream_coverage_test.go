package mft_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/ntfs/mftgen"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/mft"
)

func nameOf(n string) []mftgen.Name {
	return []mftgen.Name{{Name: n, Namespace: 1, ParentRef: 5, ParentSeq: 1}}
}

func stream(t *testing.T, data []byte) (*model.ParseCoverage, int, error) {
	t.Helper()
	events := 0
	cov, err := mft.New().ParseStream(context.Background(), write(t, data), parsers.ParseContext{}, func(b parsers.ParseResult) error {
		events += len(b.Events)
		return nil
	})
	return cov, events, err
}

// Every record of this table is accounted for by exactly one class.
func TestStreamCoverage_EveryRecordIsAccountedForByOneClass(t *testing.T) {
	full := si()
	data := mftgen.Build([]mftgen.File{
		{RecordNumber: 0, SequenceNumber: 1, InUse: true, SI: full, Names: nameOf("a.txt")},
		{RecordNumber: 1, SequenceNumber: 1, InUse: true, IsDirectory: true, SI: full, Names: nameOf("d")},
		{RecordNumber: 2, SequenceNumber: 3, InUse: false, SI: full, Names: nameOf("free1.txt")},
		{RecordNumber: 3, SequenceNumber: 3, InUse: false, SI: full, Names: nameOf("free2.txt")},
		{RecordNumber: 4, SequenceNumber: 1, InUse: true, BaseRecordRef: 1, SI: full},
		{RecordNumber: 5, SequenceNumber: 1, InUse: true, SI: full},
		{RecordNumber: 6, SequenceNumber: 1, InUse: true, OmitStandardInformation: true, Names: nameOf("nosi.txt")},
		{RecordNumber: 7, SequenceNumber: 1, InUse: true, SI: mftgen.Times{}, Names: nameOf("notime.txt")},
		{RecordNumber: 8, SequenceNumber: 1, InUse: true, SI: full, Names: nameOf("big.txt"), WithAttributeList: true},
		// 9 and 10 stay empty slots
		{RecordNumber: 11, SequenceNumber: 1, InUse: true, SI: full, Names: nameOf("z.txt")},
	})
	cov, events, err := stream(t, data)
	if err != nil {
		t.Fatal(err)
	}
	n := cov.Ntfs
	if n == nil {
		t.Fatal("no NTFS coverage recorded")
	}
	if n.Source != model.NtfsSourceMFT || cov.RecordsRead != 10 || cov.Mapped != 6 || cov.Unmapped != 4 || events != 24 {
		t.Fatalf("counts: read=%d mapped=%d unmapped=%d events=%d ntfs=%+v", cov.RecordsRead, cov.Mapped, cov.Unmapped, events, n)
	}
	if n.ZeroSlots != 2 || n.FreeMapped != 2 || n.UnmappedNonBase != 1 || n.UnmappedNoName != 1 || n.UnmappedNoTime != 2 || n.AttributeListRecords != 1 {
		t.Fatalf("classes: %+v", n)
	}
	if got := n.UnmappedNonBase + n.UnmappedNoName + n.UnmappedNoTime; got != cov.Unmapped {
		t.Fatalf("classes sum to %d, unmapped %d", got, cov.Unmapped)
	}
	if n.Failed {
		t.Fatal("a readable table is not failed")
	}
}

func TestStreamCoverage_NotAnMFTIsAFailedSourceWithItsClass(t *testing.T) {
	cov, events, err := stream(t, append([]byte{0xAB}, make([]byte, 4096)...))
	if err == nil || events != 0 {
		t.Fatalf("accepted a non-MFT: %v", err)
	}
	if cov.Ntfs == nil || !cov.Ntfs.Failed || cov.Ntfs.FailureClass != model.NtfsFailureNotAnMFT || cov.Ntfs.Source != model.NtfsSourceMFT {
		t.Fatalf("failure not recorded: %+v", cov.Ntfs)
	}
	if cov.EmittedEvents == nil || *cov.EmittedEvents != 0 {
		t.Fatal("a failed source must state zero events")
	}
}

func TestStreamCoverage_CorruptSlotRecordsClassAndOffset(t *testing.T) {
	data := mftgen.Build([]mftgen.File{
		{RecordNumber: 0, SequenceNumber: 1, InUse: true, SI: si(), Names: nameOf("a.txt")},
		{RecordNumber: 1, SequenceNumber: 1, InUse: true, SI: si(), Names: nameOf("b.txt")},
		{RecordNumber: 2, SequenceNumber: 1, InUse: true, SI: si(), Names: nameOf("c.txt")},
	})
	data[2*1024] = 'X' // a non-FILE signature with nonzero bytes in slot 2
	data[2*1024+9] = 7
	cov, _, err := stream(t, data)
	if err == nil {
		t.Fatal("accepted damage")
	}
	n := cov.Ntfs
	if n == nil || !n.Failed || n.FailureClass != model.NtfsFailureCorrupt || n.FailureOffset == nil || *n.FailureOffset != 2*1024 {
		t.Fatalf("corrupt slot not located: %+v", n)
	}
	if cov.RecordsRead < 1 {
		t.Fatalf("records before the damage were read: %+v", cov)
	}
}

func TestStreamCoverage_StopIsClassifiedAsLimitNotCorruption(t *testing.T) {
	data := mftgen.Build([]mftgen.File{{RecordNumber: 0, SequenceNumber: 1, InUse: true, SI: si(), Names: nameOf("a.txt")}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cov, err := mft.New().ParseStream(ctx, write(t, data), parsers.ParseContext{}, func(parsers.ParseResult) error { return nil })
	if !errors.Is(err, context.Canceled) || !cov.LimitReached {
		t.Fatalf("%v %+v", err, cov)
	}
	if cov.Ntfs == nil || cov.Ntfs.FailureClass != model.NtfsFailureLimit {
		t.Fatalf("a stop is a limit, not damage: %+v", cov.Ntfs)
	}
}

// A volume-sized table is not capped at the legacy event ceiling: the
// streaming path emits every event.
func TestStreamCoverage_EmittedEventsExceedLegacyCeiling(t *testing.T) {
	const records = 50_001 // 4 events each = 200,004 > DefaultMaxEvents
	var files []mftgen.File
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for i := 0; i < records; i++ {
		files = append(files, mftgen.File{RecordNumber: uint64(i), SequenceNumber: 1, InUse: true, SI: mftgen.Times{Created: when, Modified: when.Add(time.Second), Changed: when.Add(2 * time.Second), Accessed: when.Add(3 * time.Second)}, Names: nameOf("f")})
	}
	cov, events, err := stream(t, mftgen.Build(files))
	if err != nil {
		t.Fatal(err)
	}
	if events != records*4 || events <= mft.DefaultMaxEvents || cov.LimitReached || cov.EmittedEvents == nil || *cov.EmittedEvents != events {
		t.Fatalf("events=%d (ceiling %d) cov=%+v", events, mft.DefaultMaxEvents, cov)
	}
}
