package ntfs_test

import (
	"errors"
	"testing"
	"tracefall/internal/ntfs"
	"tracefall/internal/ntfs/mftgen"
)

func TestUSNCancellationDuringNonRecordSuffix(t *testing.T) {
	b := mftgen.BuildUsnJournal(0, []mftgen.UsnEntry{{FileRecord: 64, Usn: 1, Timestamp: usnBase, Reason: 0x100, FileName: "file.txt"}})
	b = append(b, []byte("NONREC!!")...)
	b = append(b, make([]byte, 1<<20)...)
	cancelled := false
	err := ntfs.ScanUsnJournal(writeJ(t, b), ntfs.UsnScanOptions{Strict: true, Cancelled: func() bool { return cancelled }, NonRecordRegion: func(int64, int) { cancelled = true }}, func(ntfs.UsnRecord) error { return nil })
	if !errors.Is(err, ntfs.ErrCancelled) {
		t.Fatalf("cancellation ignored while no records were decoded: %v", err)
	}
}
