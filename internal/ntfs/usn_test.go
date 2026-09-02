package ntfs_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"tracefall/internal/ntfs"
	"tracefall/internal/ntfs/mftgen"
)

var usnBase = time.Date(2026, 5, 10, 14, 0, 0, 0, time.UTC)

func writeJ(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "$UsnJrnl_$J")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func scanUsn(t *testing.T, path string) []ntfs.UsnRecord {
	t.Helper()
	var out []ntfs.UsnRecord
	if err := ntfs.ScanUsnJournal(path, ntfs.UsnScanOptions{}, func(r ntfs.UsnRecord) error {
		out = append(out, r)
		return nil
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}

// A realistic journal: create, modify, rename pair, delete.
func sampleJournal() []byte {
	return mftgen.BuildUsnJournal(4096, []mftgen.UsnEntry{
		{FileRecord: 64, FileSequence: 2, ParentRecord: 40, ParentSeq: 1, Usn: 0x1000,
			Timestamp: usnBase, Reason: mftgen.ReasonFileCreate, FileAttributes: 0x20, FileName: "notes.txt"},
		{FileRecord: 64, FileSequence: 2, ParentRecord: 40, ParentSeq: 1, Usn: 0x1100,
			Timestamp: usnBase.Add(time.Minute), Reason: mftgen.ReasonDataExtend | mftgen.ReasonDataOverwrite,
			FileAttributes: 0x20, FileName: "notes.txt"},
		{FileRecord: 64, FileSequence: 2, ParentRecord: 40, ParentSeq: 1, Usn: 0x1200,
			Timestamp: usnBase.Add(2 * time.Minute), Reason: mftgen.ReasonRenameOldName,
			FileAttributes: 0x20, FileName: "notes.txt"},
		{FileRecord: 64, FileSequence: 2, ParentRecord: 40, ParentSeq: 1, Usn: 0x1300,
			Timestamp: usnBase.Add(2 * time.Minute), Reason: mftgen.ReasonRenameNewName | mftgen.ReasonClose,
			FileAttributes: 0x20, FileName: "notes-final.txt"},
		{FileRecord: 64, FileSequence: 2, ParentRecord: 40, ParentSeq: 1, Usn: 0x1400,
			Timestamp: usnBase.Add(5 * time.Minute), Reason: mftgen.ReasonFileDelete | mftgen.ReasonClose,
			FileAttributes: 0x20, FileName: "notes-final.txt"},
	})
}

// 1 + 2 + 13 + 14. A valid V2 record decodes every documented field.
func TestUsn_ValidV2RecordAndFields(t *testing.T) {
	recs := scanUsn(t, writeJ(t, sampleJournal()))
	if len(recs) != 5 {
		t.Fatalf("got %d records, want 5", len(recs))
	}
	first := recs[0]
	if first.MajorVersion != 2 {
		t.Errorf("major version = %d, want 2", first.MajorVersion)
	}
	if first.FileName != "notes.txt" {
		t.Errorf("filename = %q", first.FileName)
	}
	if first.FileReference != 64 || first.FileSequence != 2 {
		t.Errorf("file reference = %d-%d, want 64-2", first.FileReference, first.FileSequence)
	}
	if first.ParentReference != 40 || first.ParentSequence != 1 {
		t.Errorf("parent reference = %d-%d, want 40-1", first.ParentReference, first.ParentSequence)
	}
	if first.Usn != 0x1000 {
		t.Errorf("USN = %#x, want 0x1000", first.Usn)
	}
	if !first.Timestamp.Equal(usnBase) {
		t.Errorf("timestamp = %s, want %s", first.Timestamp, usnBase)
	}
	if first.Timestamp.Location() != time.UTC {
		t.Error("timestamp is not UTC")
	}
	if first.Reason != mftgen.ReasonFileCreate {
		t.Errorf("reason = %#x", first.Reason)
	}
	// Provenance: the offset locates the record in the stream, past the
	// sparse run.
	if first.Offset < 4096 {
		t.Errorf("offset = %d, want it past the 4096-byte sparse run", first.Offset)
	}
	if first.Length == 0 {
		t.Error("record length not recorded")
	}
	if len(first.Warnings) != 0 {
		t.Errorf("a clean record carries warnings: %v", first.Warnings)
	}
}

// 3, 4, 5, 6. Each operation kind is represented, and the rename pair
// keeps both names.
func TestUsn_OperationKinds(t *testing.T) {
	recs := scanUsn(t, writeJ(t, sampleJournal()))
	byReason := map[string]ntfs.UsnRecord{}
	for _, r := range recs {
		for _, n := range r.ReasonNames() {
			if _, seen := byReason[n]; !seen {
				byReason[n] = r
			}
		}
	}
	for _, want := range []string{"FILE_CREATE", "FILE_DELETE", "DATA_EXTEND", "RENAME_OLD_NAME", "RENAME_NEW_NAME", "CLOSE"} {
		if _, ok := byReason[want]; !ok {
			t.Errorf("no record carrying %s", want)
		}
	}
	if byReason["RENAME_OLD_NAME"].FileName != "notes.txt" {
		t.Errorf("old name = %q, want notes.txt", byReason["RENAME_OLD_NAME"].FileName)
	}
	if byReason["RENAME_NEW_NAME"].FileName != "notes-final.txt" {
		t.Errorf("new name = %q, want notes-final.txt", byReason["RENAME_NEW_NAME"].FileName)
	}
	// The rename pair describes ONE file: same reference, two names.
	if byReason["RENAME_OLD_NAME"].FileReference != byReason["RENAME_NEW_NAME"].FileReference {
		t.Error("the rename pair does not share a file reference")
	}
}

// 9 + 10. Multiple flags are all reported; an undocumented bit is named
// rather than dropped.
func TestUsn_ReasonFlagRendering(t *testing.T) {
	multi := ntfs.UsnReasonNames(mftgen.ReasonDataExtend | mftgen.ReasonDataOverwrite | mftgen.ReasonClose)
	for _, want := range []string{"DATA_EXTEND", "DATA_OVERWRITE", "CLOSE"} {
		if !containsStr(multi, want) {
			t.Errorf("%v does not contain %s", multi, want)
		}
	}
	unknown := ntfs.UsnReasonNames(mftgen.ReasonFileCreate | 0x04000000)
	if !containsStr(unknown, "FILE_CREATE") {
		t.Error("a known flag was lost alongside an unknown one")
	}
	var sawUnknown bool
	for _, n := range unknown {
		if strings.HasPrefix(n, "UNKNOWN_0x") {
			sawUnknown = true
		}
	}
	if !sawUnknown {
		t.Errorf("an undocumented reason bit was silently dropped: %v", unknown)
	}
	// Rendering is deterministic.
	if !reflect.DeepEqual(ntfs.UsnReasonNames(0x00000103), ntfs.UsnReasonNames(0x00000103)) {
		t.Error("reason rendering is not deterministic")
	}
}

// 7. Unicode filenames survive.
func TestUsn_UnicodeFilenames(t *testing.T) {
	names := []string{"отчёт.docx", "報告書.xlsx", "café-notes.md", "emoji-\U0001F512.key"}
	var entries []mftgen.UsnEntry
	for i, n := range names {
		entries = append(entries, mftgen.UsnEntry{
			FileRecord: uint64(100 + i), FileSequence: 1, ParentRecord: 5, ParentSeq: 5,
			Usn: uint64(0x2000 + i*0x100), Timestamp: usnBase.Add(time.Duration(i) * time.Minute),
			Reason: mftgen.ReasonFileCreate, FileName: n,
		})
	}
	got := map[string]bool{}
	for _, r := range scanUsn(t, writeJ(t, mftgen.BuildUsnJournal(0, entries))) {
		got[r.FileName] = true
	}
	for _, n := range names {
		if !got[n] {
			t.Errorf("unicode filename %q did not survive", n)
		}
	}
}

// 8. Parent references are preserved for later resolution.
func TestUsn_ParentChildReference(t *testing.T) {
	recs := scanUsn(t, writeJ(t, sampleJournal()))
	for _, r := range recs {
		if r.ParentReference != 40 {
			t.Errorf("parent reference = %d, want 40", r.ParentReference)
		}
		if r.RawParentReference == "" {
			t.Error("the undecoded parent reference was not preserved")
		}
	}
}

// V3 records decode with their wider references.
func TestUsn_V3Records(t *testing.T) {
	stream := mftgen.BuildUsnJournal(0, []mftgen.UsnEntry{{
		Version: 3, FileRecord: 77, FileSequence: 3, ParentRecord: 5, ParentSeq: 5,
		Usn: 0x9000, Timestamp: usnBase, Reason: mftgen.ReasonFileCreate, FileName: "v3file.dat",
	}})
	recs := scanUsn(t, writeJ(t, stream))
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if r.MajorVersion != 3 {
		t.Errorf("major version = %d, want 3", r.MajorVersion)
	}
	if r.FileName != "v3file.dat" {
		t.Errorf("filename = %q", r.FileName)
	}
	if r.FileReference != 77 {
		t.Errorf("file reference = %d, want 77", r.FileReference)
	}
	if !strings.HasPrefix(r.RawFileReference, "0x") || len(r.RawFileReference) != 34 {
		t.Errorf("the 128-bit reference was not preserved in full: %q", r.RawFileReference)
	}
}

// An undecodable version is reported, not guessed at.
func TestUsn_UnsupportedVersionIsReportedNotGuessed(t *testing.T) {
	stream := mftgen.BuildUsnJournal(0, []mftgen.UsnEntry{
		{FileRecord: 1, Usn: 1, Timestamp: usnBase, Reason: mftgen.ReasonFileCreate, FileName: "ok.txt"},
	})
	stream = mftgen.CorruptUsn(stream, 0, "bad-version")
	var warned bool
	_ = ntfs.ScanUsnJournal(writeJ(t, stream), ntfs.UsnScanOptions{}, func(r ntfs.UsnRecord) error {
		if r.MajorVersion == 99 {
			if r.FileName != "" {
				t.Error("an undecoded version still produced a filename")
			}
			for _, w := range r.Warnings {
				if strings.Contains(w, "not decoded") {
					warned = true
				}
			}
		}
		return nil
	})
	if !warned {
		t.Error("an unsupported record version produced no warning")
	}
}

// 11 + 12. Corrupt and truncated records must not crash the scan.
func TestUsn_MalformedRecordsNeverCrash(t *testing.T) {
	base := sampleJournal()
	first := 4096
	for _, how := range []string{"zero-length", "huge-length", "unaligned-length", "name-offset", "name-length", "zero-time"} {
		t.Run(how, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", how, r)
				}
			}()
			_ = ntfs.ScanUsnJournal(writeJ(t, mftgen.CorruptUsn(base, first, how)),
				ntfs.UsnScanOptions{}, func(ntfs.UsnRecord) error { return nil })
		})
	}
	// Every truncation point.
	for cut := 0; cut < len(base); cut += 13 {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked at truncation %d: %v", cut, r)
				}
			}()
			_ = ntfs.ScanUsnJournal(writeJ(t, base[:cut]), ntfs.UsnScanOptions{},
				func(ntfs.UsnRecord) error { return nil })
		}()
	}
	// Byte flips.
	for i := first; i < len(base) && i < first+600; i += 3 {
		mutated := append([]byte(nil), base...)
		mutated[i] ^= 0xFF
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on byte flip at %d: %v", i, r)
				}
			}()
			_ = ntfs.ScanUsnJournal(writeJ(t, mutated), ntfs.UsnScanOptions{},
				func(ntfs.UsnRecord) error { return nil })
		}()
	}
}

// A corrupt region costs its own records, not the rest of the journal.
func TestUsn_ResynchronizesAfterCorruption(t *testing.T) {
	good := sampleJournal()
	clean := len(scanUsn(t, writeJ(t, good)))
	damaged := mftgen.CorruptUsn(good, 4096, "unaligned-length")
	var recovered int
	_ = ntfs.ScanUsnJournal(writeJ(t, damaged), ntfs.UsnScanOptions{}, func(ntfs.UsnRecord) error {
		recovered++
		return nil
	})
	if recovered == 0 {
		t.Error("a single damaged record silenced the whole journal")
	}
	if recovered > clean {
		t.Errorf("recovered %d records from a damaged journal that cleanly holds %d", recovered, clean)
	}
}

// 15. Deterministic repeated parsing.
func TestUsn_IsDeterministic(t *testing.T) {
	path := writeJ(t, sampleJournal())
	first := scanUsn(t, path)
	for i := 0; i < 20; i++ {
		again := scanUsn(t, path)
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d produced different records", i)
		}
	}
}

// A large journal streams, reports progress, and honours cancellation.
func TestUsn_LargeJournalStreamsAndCancels(t *testing.T) {
	const n = 20000
	entries := make([]mftgen.UsnEntry, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, mftgen.UsnEntry{
			FileRecord: uint64(1000 + i), FileSequence: 1, ParentRecord: 5, ParentSeq: 5,
			Usn: uint64(i) * 0x100, Timestamp: usnBase.Add(time.Duration(i) * time.Second),
			Reason: mftgen.ReasonDataExtend, FileName: fmt.Sprintf("bulk-%06d.log", i),
		})
	}
	path := writeJ(t, mftgen.BuildUsnJournal(0, entries))

	var seen, progress int
	if err := ntfs.ScanUsnJournal(path, ntfs.UsnScanOptions{
		Progress: func(int, int64) { progress++ },
	}, func(ntfs.UsnRecord) error { seen++; return nil }); err != nil {
		t.Fatal(err)
	}
	if seen != n {
		t.Errorf("saw %d records, want %d", seen, n)
	}
	if progress == 0 {
		t.Error("no progress reported for a large journal")
	}

	var partial int
	cerr := ntfs.ScanUsnJournal(path, ntfs.UsnScanOptions{
		Cancelled: func() bool { return partial > 1000 },
	}, func(ntfs.UsnRecord) error { partial++; return nil })
	if cerr == nil {
		t.Error("cancellation did not stop the scan")
	}
	if partial >= seen {
		t.Errorf("cancelled scan read %d of %d records", partial, seen)
	}
}

// Sniffing must not claim unrelated files.
func TestUsn_SniffIsNarrow(t *testing.T) {
	if !ntfs.SniffUsnJournal(sampleJournal()[4096:]) {
		t.Error("a real journal was not recognized")
	}
	// Leading sparse zeros are normal and must still be recognized.
	if !ntfs.SniffUsnJournal(sampleJournal()) {
		t.Error("a journal with a sparse run was not recognized")
	}
	for name, data := range map[string][]byte{
		"empty":     {},
		"text":      []byte("this is a plain text file and not a change journal at all, really"),
		"all zeros": make([]byte, 4096),
		"mft":       sampleTable(),
	} {
		if ntfs.SniffUsnJournal(data) {
			t.Errorf("%q was misidentified as a USN journal", name)
		}
	}
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
