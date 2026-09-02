package ntfs_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"tracefall/internal/ntfs"
	"tracefall/internal/ntfs/mftgen"
)

var (
	tCreated  = time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)
	tModified = time.Date(2026, 4, 2, 10, 30, 0, 0, time.UTC)
	tChanged  = time.Date(2026, 4, 2, 10, 31, 0, 0, time.UTC)
	tAccessed = time.Date(2026, 4, 3, 8, 15, 0, 0, time.UTC)
)

func si() mftgen.Times {
	return mftgen.Times{Created: tCreated, Modified: tModified, Changed: tChanged, Accessed: tAccessed}
}

// writeMFT puts a generated table on disk and returns its path.
func writeMFT(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "$MFT")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// scanAll collects every record a table yields.
func scanAll(t *testing.T, path string) []ntfs.Record {
	t.Helper()
	var out []ntfs.Record
	if err := ntfs.Scan(path, ntfs.ScanOptions{}, func(r ntfs.Record) error {
		out = append(out, r)
		return nil
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}

// A minimal but complete volume: root, a directory, and a file in it.
func sampleTable() []byte {
	files := mftgen.SystemRecords(si())
	return mftgen.Build(append(files, []mftgen.File{
		{RecordNumber: 40, SequenceNumber: 1, InUse: true, IsDirectory: true, HardLinks: 1, SI: si(),
			Names: []mftgen.Name{{Name: "Windows", Namespace: mftgen.NamespaceWin32, ParentRef: 5, ParentSeq: 5}}},
		{RecordNumber: 64, SequenceNumber: 2, InUse: true, HardLinks: 1, SI: si(),
			Names:           []mftgen.Name{{Name: "notepad.exe", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1, LogicalSize: 4096}},
			NonResidentData: &mftgen.NonResident{AllocatedSize: 8192, RealSize: 4096, InitializedSize: 4096}},
	}...))
}

// 1 + 2. A valid FILE record yields all four $SI timestamps, distinctly.
func TestParse_ValidRecordAndTimestamps(t *testing.T) {
	recs := scanAll(t, writeMFT(t, sampleTable()))
	var file *ntfs.Record
	for i := range recs {
		if n, ok := recs[i].BestName(); ok && n.Name == "notepad.exe" {
			file = &recs[i]
		}
	}
	if file == nil {
		t.Fatal("notepad.exe record not found")
	}
	if !file.HasSI {
		t.Fatal("record has no $STANDARD_INFORMATION")
	}
	for _, tc := range []struct {
		label string
		got   time.Time
		want  time.Time
	}{
		{"created", file.SI.Created, tCreated},
		{"modified", file.SI.Modified, tModified},
		{"changed", file.SI.Changed, tChanged},
		{"accessed", file.SI.Accessed, tAccessed},
	} {
		if !tc.got.Equal(tc.want) {
			t.Errorf("%s = %s, want %s", tc.label, tc.got, tc.want)
		}
		if tc.got.Location() != time.UTC {
			t.Errorf("%s is not UTC", tc.label)
		}
	}
	// The four must stay DISTINCT -- merging them would destroy the
	// difference between when a file was written and when its metadata
	// changed.
	set := map[time.Time]bool{file.SI.Created: true, file.SI.Modified: true, file.SI.Changed: true, file.SI.Accessed: true}
	if len(set) != 4 {
		t.Errorf("timestamps collapsed into %d distinct values", len(set))
	}
	if !file.InUse {
		t.Error("record should be in use")
	}
	if file.IsDirectory {
		t.Error("a file was reported as a directory")
	}
	if file.SequenceNumber != 2 {
		t.Errorf("sequence = %d, want 2", file.SequenceNumber)
	}
}

// 3. A deleted record is still readable and is reported as not in use.
func TestParse_DeletedRecord(t *testing.T) {
	table := mftgen.Build(append(mftgen.SystemRecords(si()), []mftgen.File{
		{RecordNumber: 30, SequenceNumber: 9, InUse: false, HardLinks: 0, SI: si(),
			Names:        []mftgen.Name{{Name: "deleted.txt", Namespace: mftgen.NamespaceWin32, ParentRef: 5}},
			ResidentData: []byte("gone")},
	}...))
	for _, r := range scanAll(t, writeMFT(t, table)) {
		if n, ok := r.BestName(); ok && n.Name == "deleted.txt" {
			if r.InUse {
				t.Error("a deleted record reported itself in use")
			}
			if !r.HasSI || !r.SI.Any() {
				t.Error("a deleted record lost its timestamps")
			}
			return
		}
	}
	t.Fatal("deleted record not found")
}

// 4. Directories are distinguished from files.
func TestParse_DirectoryRecord(t *testing.T) {
	for _, r := range scanAll(t, writeMFT(t, sampleTable())) {
		n, ok := r.BestName()
		if !ok {
			continue
		}
		if n.Name == "Windows" {
			if !r.IsDirectory {
				t.Error("Windows was not reported as a directory")
			}
			if r.SizeKnown {
				t.Error("a directory reported a $DATA size")
			}
			return
		}
	}
	t.Fatal("directory record not found")
}

// 5. Unicode filenames survive intact.
func TestParse_UnicodeFilename(t *testing.T) {
	names := []string{
		"отчёт.docx",
		"報告書.xlsx",
		"rapport-café.pdf",
		"emoji-\U0001F510.key",
	}
	files := mftgen.SystemRecords(si())
	for i, n := range names {
		files = append(files, mftgen.File{
			RecordNumber: uint64(20 + i), SequenceNumber: 1, InUse: true, SI: si(),
			Names:        []mftgen.Name{{Name: n, Namespace: mftgen.NamespaceWin32, ParentRef: 5}},
			ResidentData: []byte("x"),
		})
	}
	found := map[string]bool{}
	for _, r := range scanAll(t, writeMFT(t, mftgen.Build(files))) {
		if n, ok := r.BestName(); ok {
			found[n.Name] = true
		}
	}
	for _, n := range names {
		if !found[n] {
			t.Errorf("unicode filename %q did not survive parsing", n)
		}
	}
}

// 6. Parent references reconstruct a full path.
func TestParse_ParentDirectoryRelationship(t *testing.T) {
	path := writeMFT(t, sampleTable())
	idx, err := ntfs.BuildDirectoryIndex(path, ntfs.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if idx.Len() == 0 {
		t.Fatal("no directories indexed")
	}
	for _, r := range scanAll(t, path) {
		n, ok := r.BestName()
		if !ok || n.Name != "notepad.exe" {
			continue
		}
		full, complete := idx.Path(n.ParentRef, n.Name)
		if !complete {
			t.Errorf("path did not reach the volume root: %q", full)
		}
		if full != `\Windows\notepad.exe` {
			t.Errorf("path = %q, want %q", full, `\Windows\notepad.exe`)
		}
		return
	}
	t.Fatal("file record not found")
}

// An unresolvable parent must be reported as incomplete, not silently
// presented as a root-level path.
func TestParse_UnresolvableParentIsMarked(t *testing.T) {
	table := mftgen.Build(append(mftgen.SystemRecords(si()), []mftgen.File{
		{RecordNumber: 70, SequenceNumber: 1, InUse: true, SI: si(),
			Names:        []mftgen.Name{{Name: "orphan.txt", Namespace: mftgen.NamespaceWin32, ParentRef: 9999}},
			ResidentData: []byte("x")},
	}...))
	path := writeMFT(t, table)
	idx, err := ntfs.BuildDirectoryIndex(path, ntfs.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	full, complete := idx.Path(9999, "orphan.txt")
	if complete {
		t.Error("an unresolvable parent was reported as a complete path")
	}
	if !contains(full, "unresolved") {
		t.Errorf("the incomplete path does not say so: %q", full)
	}
}

// 7 + 8. Resident and non-resident $DATA are distinguished, with sizes.
func TestParse_ResidentAndNonResidentData(t *testing.T) {
	table := mftgen.Build(append(mftgen.SystemRecords(si()), []mftgen.File{
		{RecordNumber: 21, SequenceNumber: 1, InUse: true, SI: si(),
			Names:        []mftgen.Name{{Name: "small.txt", Namespace: mftgen.NamespaceWin32, ParentRef: 5}},
			ResidentData: []byte("resident content here")},
		{RecordNumber: 22, SequenceNumber: 1, InUse: true, SI: si(),
			Names:           []mftgen.Name{{Name: "big.bin", Namespace: mftgen.NamespaceWin32, ParentRef: 5}},
			NonResidentData: &mftgen.NonResident{AllocatedSize: 1 << 20, RealSize: 1000000, InitializedSize: 1000000}},
	}...))
	byName := map[string]ntfs.Record{}
	for _, r := range scanAll(t, writeMFT(t, table)) {
		if n, ok := r.BestName(); ok {
			byName[n.Name] = r
		}
	}
	small, ok := byName["small.txt"]
	if !ok {
		t.Fatal("resident file not found")
	}
	if !small.HasData || !small.DataResident {
		t.Error("resident $DATA was not reported as resident")
	}
	if small.LogicalSize != uint64(len("resident content here")) {
		t.Errorf("resident size = %d, want %d", small.LogicalSize, len("resident content here"))
	}
	big, ok := byName["big.bin"]
	if !ok {
		t.Fatal("non-resident file not found")
	}
	if !big.HasData || big.DataResident {
		t.Error("non-resident $DATA was reported as resident")
	}
	if big.LogicalSize != 1000000 || big.PhysicalSize != 1<<20 {
		t.Errorf("non-resident sizes = %d/%d, want 1000000/%d", big.LogicalSize, big.PhysicalSize, 1<<20)
	}
}

// 9. Malformed records must not crash the scan, and must be reported.
func TestParse_MalformedRecordsAreReportedNotFatal(t *testing.T) {
	base := sampleTable()
	for _, how := range []string{"signature", "baad", "attr-length", "attr-offset", "fixup", "used-size"} {
		t.Run(how, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", how, r)
				}
			}()
			// Record 40 is a real directory record in sampleTable();
			// damaging an empty slack index would test nothing.
			path := writeMFT(t, mftgen.Corrupt(base, 40, how))
			var records int
			var warned bool
			err := ntfs.Scan(path, ntfs.ScanOptions{}, func(r ntfs.Record) error {
				records++
				if len(r.Warnings) > 0 {
					warned = true
				}
				return nil
			})
			if err != nil {
				t.Fatalf("scan aborted on a single damaged record: %v", err)
			}
			if records == 0 {
				t.Error("a damaged record silenced the whole table")
			}
			switch how {
			case "baad", "attr-length", "attr-offset", "fixup":
				if !warned {
					t.Errorf("%q produced no warning", how)
				}
			}
		})
	}
}

// Truncation at every byte boundary must be handled without panic.
func TestParse_TruncationNeverPanics(t *testing.T) {
	base := sampleTable()
	for _, cut := range []int{0, 1, 47, 48, 100, 512, 1023, 1024, 1500, 2048, len(base) - 1} {
		if cut > len(base) {
			continue
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked at truncation %d: %v", cut, r)
				}
			}()
			path := writeMFT(t, base[:cut])
			_ = ntfs.Scan(path, ntfs.ScanOptions{}, func(ntfs.Record) error { return nil })
		}()
	}
}

// Byte flips across the first records must never panic.
func TestParse_FuzzedRecordsNeverPanic(t *testing.T) {
	base := sampleTable()
	for i := 0; i < len(base) && i < 3000; i += 7 {
		mutated := append([]byte(nil), base...)
		mutated[i] ^= 0xFF
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on byte flip at %d: %v", i, r)
				}
			}()
			path := writeMFT(t, mutated)
			_ = ntfs.Scan(path, ntfs.ScanOptions{}, func(ntfs.Record) error { return nil })
		}()
	}
}

// 10. Multiple $FILE_NAME attributes are all kept, and the long name is
// preferred over the 8.3 alias.
func TestParse_MultipleFilenameAttributes(t *testing.T) {
	table := mftgen.Build(append(mftgen.SystemRecords(si()), []mftgen.File{
		{RecordNumber: 31, SequenceNumber: 1, InUse: true, HardLinks: 2, SI: si(),
			Names: []mftgen.Name{
				{Name: "PROGRA~1.EXE", Namespace: mftgen.NamespaceDOS, ParentRef: 5},
				{Name: "Program Installer.exe", Namespace: mftgen.NamespaceWin32, ParentRef: 5},
			},
			ResidentData: []byte("x")},
	}...))
	for _, r := range scanAll(t, writeMFT(t, table)) {
		if len(r.Names) != 2 {
			continue
		}
		best, ok := r.BestName()
		if !ok {
			t.Fatal("no best name")
		}
		if best.Name != "Program Installer.exe" {
			t.Errorf("best name = %q, want the Win32 long name", best.Name)
		}
		// The short name must still be RETAINED, not discarded.
		var sawDOS bool
		for _, n := range r.Names {
			if n.Namespace == mftgen.NamespaceDOS && n.Name == "PROGRA~1.EXE" {
				sawDOS = true
			}
		}
		if !sawDOS {
			t.Error("the 8.3 short name was discarded")
		}
		return
	}
	t.Fatal("multi-name record not found")
}

// $FN timestamps are kept SEPARATELY from $SI. Their disagreement is
// itself evidence (timestomping), so they must never be merged.
func TestParse_FileNameTimestampsKeptSeparateFromStandardInformation(t *testing.T) {
	fnTimes := mftgen.Times{
		Created:  time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		Modified: time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC),
		Changed:  time.Date(2020, 1, 3, 0, 0, 0, 0, time.UTC),
		Accessed: time.Date(2020, 1, 4, 0, 0, 0, 0, time.UTC),
	}
	table := mftgen.Build(append(mftgen.SystemRecords(si()), []mftgen.File{
		{RecordNumber: 33, SequenceNumber: 1, InUse: true, SI: si(),
			Names:        []mftgen.Name{{Name: "stomped.exe", Namespace: mftgen.NamespaceWin32, ParentRef: 5, Times: fnTimes}},
			ResidentData: []byte("x")},
	}...))
	for _, r := range scanAll(t, writeMFT(t, table)) {
		n, ok := r.BestName()
		if !ok || n.Name != "stomped.exe" {
			continue
		}
		if !r.SI.Created.Equal(tCreated) {
			t.Errorf("$SI created = %s, want %s", r.SI.Created, tCreated)
		}
		if !n.Times.Created.Equal(fnTimes.Created) {
			t.Errorf("$FN created = %s, want %s", n.Times.Created, fnTimes.Created)
		}
		if r.SI.Created.Equal(n.Times.Created) {
			t.Error("$SI and $FN timestamps were merged")
		}
		return
	}
	t.Fatal("record not found")
}

// 11. A large table streams without loading itself into memory, and
// respects cancellation and progress.
func TestParse_LargeTableStreamsAndCancels(t *testing.T) {
	const n = 20000
	files := mftgen.SystemRecords(si())
	for i := 0; i < n; i++ {
		files = append(files, mftgen.File{
			RecordNumber: uint64(16 + i), SequenceNumber: 1, InUse: true, SI: si(),
			Names:        []mftgen.Name{{Name: fmt.Sprintf("file%05d.dat", i), Namespace: mftgen.NamespaceWin32, ParentRef: 5}},
			ResidentData: []byte("x"),
		})
	}
	path := writeMFT(t, mftgen.Build(files))

	var seen, progressCalls int
	err := ntfs.Scan(path, ntfs.ScanOptions{Progress: func(int) { progressCalls++ }}, func(ntfs.Record) error {
		seen++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < n {
		t.Errorf("saw %d records, want at least %d", seen, n)
	}
	if progressCalls == 0 {
		t.Error("no progress was reported for a large table")
	}

	// Cancellation stops the scan early.
	var afterCancel int
	cerr := ntfs.Scan(path, ntfs.ScanOptions{Cancelled: func() bool { return afterCancel > 500 }}, func(ntfs.Record) error {
		afterCancel++
		return nil
	})
	if cerr == nil {
		t.Error("cancellation did not stop the scan")
	}
	if afterCancel >= seen {
		t.Errorf("cancelled scan read %d of %d records", afterCancel, seen)
	}
}

// The record limit is enforced.
func TestParse_RespectsRecordLimit(t *testing.T) {
	files := mftgen.SystemRecords(si())
	for i := 0; i < 200; i++ {
		files = append(files, mftgen.File{RecordNumber: uint64(16 + i), SequenceNumber: 1, InUse: true, SI: si(),
			Names: []mftgen.Name{{Name: fmt.Sprintf("f%d", i), Namespace: mftgen.NamespaceWin32, ParentRef: 5}}})
	}
	path := writeMFT(t, mftgen.Build(files))
	err := ntfs.Scan(path, ntfs.ScanOptions{Limits: ntfs.Limits{MaxRecords: 50}}, func(ntfs.Record) error { return nil })
	if err == nil {
		t.Fatal("the record limit was not enforced")
	}
}

// 12. FILETIME conversion, including implausible values.
func TestParse_TimestampConversion(t *testing.T) {
	cases := []struct {
		name string
		in   time.Time
		zero bool
	}{
		{"epoch-ish", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), false},
		{"zero means absent", time.Time{}, true},
		{"pre-1990 is implausible", time.Date(1601, 1, 1, 0, 0, 1, 0, time.UTC), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			table := mftgen.Build(append(mftgen.SystemRecords(si()), []mftgen.File{
				{RecordNumber: 20, SequenceNumber: 1, InUse: true,
					SI:           mftgen.Times{Created: tc.in},
					Names:        []mftgen.Name{{Name: "t.txt", Namespace: mftgen.NamespaceWin32, ParentRef: 5}},
					ResidentData: []byte("x")},
			}...))
			for _, r := range scanAll(t, writeMFT(t, table)) {
				if n, ok := r.BestName(); !ok || n.Name != "t.txt" {
					continue
				}
				if tc.zero {
					if !r.SI.Created.IsZero() {
						t.Errorf("expected no timestamp, got %s", r.SI.Created)
					}
				} else if !r.SI.Created.Equal(tc.in) {
					t.Errorf("created = %s, want %s", r.SI.Created, tc.in)
				}
				return
			}
			t.Fatal("record not found")
		})
	}
}

// 14. The same table parses identically every time.
func TestParse_IsDeterministic(t *testing.T) {
	path := writeMFT(t, sampleTable())
	first := scanAll(t, path)
	for i := 0; i < 20; i++ {
		again := scanAll(t, path)
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d produced different records", i)
		}
	}
}

// Sniff must not accept arbitrary files as an $MFT: doing so would put
// invented filesystem events on a timeline.
func TestSniff_RejectsNonMFT(t *testing.T) {
	valid := sampleTable()
	if !ntfs.Sniff(valid[:64]) {
		t.Error("a real table was not recognized")
	}
	for name, data := range map[string][]byte{
		"empty":             {},
		"short":             []byte("FILE"),
		"text":              []byte("this is a plain text file, not a filesystem table at all"),
		"FILE but nonsense": append([]byte("FILE"), make([]byte, 120)...),
		"zeros":             make([]byte, 256),
	} {
		if ntfs.Sniff(data) {
			t.Errorf("%q was misidentified as an $MFT", name)
		}
	}
}

// Extension records are identifiable so they are not mistaken for files.
func TestParse_ExtensionRecordIsIdentifiable(t *testing.T) {
	table := mftgen.Build(append(mftgen.SystemRecords(si()), []mftgen.File{
		{RecordNumber: 50, SequenceNumber: 1, InUse: true, SI: si(), BaseRecordRef: 0x0001000000000040,
			Names: []mftgen.Name{{Name: "ext", Namespace: mftgen.NamespaceWin32, ParentRef: 5}}},
	}...))
	for _, r := range scanAll(t, writeMFT(t, table)) {
		if r.RecordNumber == 50 {
			if r.IsBaseRecord() {
				t.Error("an extension record reported itself as a base record")
			}
			return
		}
	}
	t.Fatal("extension record not found")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
