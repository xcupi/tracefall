package mftgen_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/ntfs/mftgen"
)

// Generates a synthetic NTFS metadata set -- $MFT, $UsnJrnl:$J and
// $LogFile -- for browser verification. Entirely invented.
//
//	NTFS_OUT=/path go test ./internal/ntfs/mftgen -run TestGenerateNTFSSet -write-samples
func TestGenerateNTFSSet(t *testing.T) {
	if !*write {
		t.Skip("pass -write-samples to regenerate")
	}
	root := os.Getenv("NTFS_OUT")
	if root == "" {
		root = filepath.Join(os.TempDir(), "tracefall-ntfs")
	}
	mk := func(rel string, data []byte) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)
	tm := func(off time.Duration) mftgen.Times {
		return mftgen.Times{Created: base.Add(off), Modified: base.Add(off + time.Hour),
			Changed: base.Add(off + time.Hour + time.Minute), Accessed: base.Add(off + 2*time.Hour)}
	}

	// $MFT
	files := mftgen.SystemRecords(tm(0))
	files = append(files,
		mftgen.File{RecordNumber: 40, SequenceNumber: 1, InUse: true, IsDirectory: true, SI: tm(0),
			Names: []mftgen.Name{{Name: "Windows", Namespace: mftgen.NamespaceWin32, ParentRef: 5, ParentSeq: 5}}},
		mftgen.File{RecordNumber: 41, SequenceNumber: 1, InUse: true, IsDirectory: true, SI: tm(0),
			Names: []mftgen.Name{{Name: "Temp", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1}}})
	for i := 0; i < 120; i++ {
		files = append(files, mftgen.File{
			RecordNumber: uint64(100 + i), SequenceNumber: 1, InUse: i%13 != 0, SI: tm(time.Duration(i) * time.Minute),
			Names:        []mftgen.Name{{Name: fmt.Sprintf("artifact-%03d.dat", i), Namespace: mftgen.NamespaceWin32, ParentRef: 41, ParentSeq: 1}},
			ResidentData: []byte("x")})
	}
	mk("C/$MFT", mftgen.Build(files))

	// $UsnJrnl:$J -- a plausible history for those files.
	var entries []mftgen.UsnEntry
	usn := uint64(0x1000)
	for i := 0; i < 120; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		name := fmt.Sprintf("artifact-%03d.dat", i)
		entries = append(entries,
			mftgen.UsnEntry{FileRecord: uint64(100 + i), FileSequence: 1, ParentRecord: 41, ParentSeq: 1,
				Usn: usn, Timestamp: at, Reason: mftgen.ReasonFileCreate, FileAttributes: 0x20, FileName: name},
			mftgen.UsnEntry{FileRecord: uint64(100 + i), FileSequence: 1, ParentRecord: 41, ParentSeq: 1,
				Usn: usn + 0x10, Timestamp: at.Add(30 * time.Second),
				Reason: mftgen.ReasonDataExtend | mftgen.ReasonClose, FileAttributes: 0x20, FileName: name})
		usn += 0x100
		if i%13 == 0 {
			entries = append(entries, mftgen.UsnEntry{
				FileRecord: uint64(100 + i), FileSequence: 1, ParentRecord: 41, ParentSeq: 1,
				Usn: usn, Timestamp: at.Add(time.Minute), Reason: mftgen.ReasonFileDelete,
				FileAttributes: 0x20, FileName: name})
			usn += 0x100
		}
	}
	// A rename pair and a unicode name.
	entries = append(entries,
		mftgen.UsnEntry{FileRecord: 500, FileSequence: 1, ParentRecord: 40, ParentSeq: 1, Usn: usn,
			Timestamp: base.Add(90 * time.Minute), Reason: mftgen.ReasonRenameOldName, FileName: "draft.docx"},
		mftgen.UsnEntry{FileRecord: 500, FileSequence: 1, ParentRecord: 40, ParentSeq: 1, Usn: usn + 0x10,
			Timestamp: base.Add(90 * time.Minute), Reason: mftgen.ReasonRenameNewName, FileName: "отчёт-2026.docx"},
		mftgen.UsnEntry{FileRecord: 501, FileSequence: 1, ParentRecord: 41, ParentSeq: 1, Usn: usn + 0x20,
			Timestamp: base.Add(95 * time.Minute), Reason: mftgen.ReasonSecurityChange, FileName: "acl-changed.bin"})
	mk("C/$Extend/$UsnJrnl_$J", mftgen.BuildUsnJournal(8192, entries))

	// $LogFile
	restart := mftgen.LogRestart{MajorVersion: 1, MinorVersion: 1, CurrentLSN: 0x9000,
		ChkdskLSN: 0x20, FileSize: 6 * mftgen.LogPageSize,
		Clients: []mftgen.LogClientEntry{{Name: "NTFS", OldestLSN: 0x1000, ClientRestartLSN: 0x8F00}}}
	pages := [][]byte{mftgen.BuildRestartPage(restart), mftgen.BuildRestartPage(restart)}
	lsn := uint64(0x4000)
	for p := 0; p < 6; p++ {
		var recs []mftgen.LogRec
		for r := 0; r < 8; r++ {
			recs = append(recs, mftgen.LogRec{
				ThisLSN: lsn, ClientPreviousLSN: lsn - 0x10, TransactionID: uint32(0x10 + p),
				RedoOperation:   uint16([]int{0x02, 0x07, 0x0E, 0x1A, 0x19, 0x08}[r%6]),
				UndoOperation:   uint16([]int{0x03, 0x07, 0x0F, 0x00, 0x00, 0x08}[r%6]),
				TargetAttribute: 0x30, TargetVCN: uint64(r), TargetLCN: uint64(1000 + r)})
			lsn += 0x10
		}
		pages = append(pages, mftgen.BuildRecordPage(lsn, uint16(p+1), 6, recs))
	}
	mk("C/$LogFile", mftgen.BuildLogFile(pages...))
	t.Logf("wrote NTFS metadata set to %s", root)
}
