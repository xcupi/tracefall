package mft_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/ntfs/mftgen"
	"tracefall/internal/parsers/mft"
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

func write(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "$MFT")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func table(extra ...mftgen.File) []byte {
	files := mftgen.SystemRecords(si())
	files = append(files, mftgen.File{
		RecordNumber: 40, SequenceNumber: 1, InUse: true, IsDirectory: true, HardLinks: 1, SI: si(),
		Names: []mftgen.Name{{Name: "Windows", Namespace: mftgen.NamespaceWin32, ParentRef: 5, ParentSeq: 5}},
	})
	return mftgen.Build(append(files, extra...))
}

func parse(t *testing.T, data []byte) []model.Event {
	t.Helper()
	res, err := mft.New().Parse(write(t, data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return res.Events
}

// One event per RECORDED TIMESTAMP, each typed by what it means.
func TestParser_EmitsFourDistinctTimestampEvents(t *testing.T) {
	events := parse(t, table(mftgen.File{
		RecordNumber: 64, SequenceNumber: 2, InUse: true, HardLinks: 1, SI: si(),
		Names:           []mftgen.Name{{Name: "notepad.exe", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1}},
		NonResidentData: &mftgen.NonResident{AllocatedSize: 8192, RealSize: 4096, InitializedSize: 4096},
	}))

	byType := map[string]model.Event{}
	for _, e := range events {
		if e.Extra["file_name"] == "notepad.exe" {
			byType[e.EventType] = e
		}
	}
	want := map[string]time.Time{
		model.EventFilesystemCreated:  tCreated,
		model.EventFilesystemModified: tModified,
		model.EventFilesystemChanged:  tChanged,
		model.EventFilesystemAccessed: tAccessed,
	}
	if len(byType) != 4 {
		t.Fatalf("got %d event types for one file, want 4: %v", len(byType), keys(byType))
	}
	for typ, at := range want {
		e, ok := byType[typ]
		if !ok {
			t.Errorf("no %s event", typ)
			continue
		}
		if !e.Timestamp.Equal(at) {
			t.Errorf("%s at %s, want %s", typ, e.Timestamp, at)
		}
		if e.Timestamp.Location() != time.UTC {
			t.Errorf("%s is not stored in UTC", typ)
		}
		if e.ArtifactType != model.ArtifactMFT {
			t.Errorf("%s artifact type = %q", typ, e.ArtifactType)
		}
		if e.Parser == "" {
			t.Errorf("%s carries no parser name", typ)
		}
		if e.Extra["timestamp_meaning"] == "" {
			t.Errorf("%s does not say what the timestamp means", typ)
		}
		if !strings.Contains(e.Extra["timestamp_source"], "STANDARD_INFORMATION") {
			t.Errorf("%s does not name its timestamp source", typ)
		}
	}
	// Each source reference must be unique, so the four never collapse.
	refs := map[string]bool{}
	for _, e := range byType {
		if refs[e.SourceReference] {
			t.Errorf("duplicate source reference %q", e.SourceReference)
		}
		refs[e.SourceReference] = true
	}
}

// Provenance: every event must be traceable back to its record.
func TestParser_Provenance(t *testing.T) {
	events := parse(t, table(mftgen.File{
		RecordNumber: 64, SequenceNumber: 3, InUse: true, SI: si(),
		Names:        []mftgen.Name{{Name: "evidence.txt", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1}},
		ResidentData: []byte("hello"),
	}))
	var found bool
	for _, e := range events {
		if e.Extra["file_name"] != "evidence.txt" {
			continue
		}
		found = true
		for _, key := range []string{"mft_record_number", "mft_sequence_number", "mft_file_reference", "mft_source_file", "filesystem"} {
			if e.Extra[key] == "" {
				t.Errorf("event lacks provenance field %q", key)
			}
		}
		if e.Extra["mft_record_number"] != "64" {
			t.Errorf("record number = %q, want 64", e.Extra["mft_record_number"])
		}
		if e.Extra["mft_file_reference"] != "64-3" {
			t.Errorf("file reference = %q, want 64-3", e.Extra["mft_file_reference"])
		}
		if e.FilePath != `\Windows\evidence.txt` {
			t.Errorf("path = %q, want \\Windows\\evidence.txt", e.FilePath)
		}
		if !strings.HasPrefix(e.SourceReference, "mft:64-3:") {
			t.Errorf("source reference %q does not identify the record", e.SourceReference)
		}
	}
	if !found {
		t.Fatal("no events for the test file")
	}
}

// NTFS records no actor. Nothing may be invented.
func TestParser_DoesNotInventUserOrProcess(t *testing.T) {
	events := parse(t, table(mftgen.File{
		RecordNumber: 70, SequenceNumber: 1, InUse: true, SI: si(),
		Names:        []mftgen.Name{{Name: "payload.exe", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1}},
		ResidentData: []byte("x"),
	}))
	if len(events) == 0 {
		t.Fatal("no events")
	}
	for _, e := range events {
		if e.User != "" {
			t.Errorf("a user was invented from filesystem metadata: %q", e.User)
		}
		if e.ProcessName != "" || e.ProcessPath != "" {
			t.Errorf("a process was invented: %q / %q", e.ProcessName, e.ProcessPath)
		}
		if e.ParentProcessName != "" || e.ParentProcessPath != "" {
			t.Errorf("a parent process was invented: %q / %q", e.ParentProcessName, e.ParentProcessPath)
		}
		if e.Host != "" {
			t.Errorf("a host was invented: %q", e.Host)
		}
		if e.CommandLine != "" {
			t.Errorf("a command line was invented: %q", e.CommandLine)
		}
	}
}

// Deleted records are reported as such, without asserting deletion time.
func TestParser_DeletedRecordState(t *testing.T) {
	events := parse(t, table(mftgen.File{
		RecordNumber: 80, SequenceNumber: 7, InUse: false, SI: si(),
		Names:        []mftgen.Name{{Name: "removed.dat", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1}},
		ResidentData: []byte("x"),
	}))
	var seen bool
	for _, e := range events {
		if e.Extra["file_name"] != "removed.dat" {
			continue
		}
		seen = true
		if !strings.Contains(e.Extra["allocation_state"], "not in use") {
			t.Errorf("allocation state = %q, want it to report the record is free", e.Extra["allocation_state"])
		}
		// The MFT does not record WHEN a file was deleted; the parser
		// must not imply that it does.
		blob := strings.ToLower(fmt.Sprint(e.Extra))
		if strings.Contains(blob, "deleted_at") || strings.Contains(blob, "deletion time") {
			t.Error("the parser asserted a deletion time the MFT does not record")
		}
	}
	if !seen {
		t.Fatal("deleted record produced no events")
	}
}

// Directories and sizes are reported factually.
func TestParser_DirectoryAndSizeMetadata(t *testing.T) {
	events := parse(t, table(
		mftgen.File{RecordNumber: 90, SequenceNumber: 1, InUse: true, SI: si(),
			Names:           []mftgen.Name{{Name: "big.bin", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1}},
			NonResidentData: &mftgen.NonResident{AllocatedSize: 1 << 20, RealSize: 999999, InitializedSize: 999999}},
		mftgen.File{RecordNumber: 91, SequenceNumber: 1, InUse: true, SI: si(),
			Names:        []mftgen.Name{{Name: "tiny.txt", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1}},
			ResidentData: []byte("small")},
	))
	got := map[string]model.Event{}
	for _, e := range events {
		got[e.Extra["file_name"]] = e
	}
	if big, ok := got["big.bin"]; ok {
		if big.Extra["file_size_bytes"] != "999999" {
			t.Errorf("size = %q, want 999999", big.Extra["file_size_bytes"])
		}
		if !strings.Contains(big.Extra["data_residency"], "non-resident") {
			t.Errorf("residency = %q", big.Extra["data_residency"])
		}
	} else {
		t.Error("no events for big.bin")
	}
	if tiny, ok := got["tiny.txt"]; ok {
		if !strings.Contains(tiny.Extra["data_residency"], "resident") {
			t.Errorf("residency = %q, want resident", tiny.Extra["data_residency"])
		}
	} else {
		t.Error("no events for tiny.txt")
	}
	if dir, ok := got["Windows"]; ok {
		if dir.Extra["record_type"] != "directory" {
			t.Errorf("record type = %q, want directory", dir.Extra["record_type"])
		}
	} else {
		t.Error("no events for the directory record")
	}
}

// $FN timestamps ride along as context, never as extra events.
func TestParser_FileNameTimesAreContextNotEvents(t *testing.T) {
	fn := mftgen.Times{
		Created:  time.Date(2019, 5, 5, 5, 5, 5, 0, time.UTC),
		Modified: time.Date(2019, 5, 6, 5, 5, 5, 0, time.UTC),
		Changed:  time.Date(2019, 5, 7, 5, 5, 5, 0, time.UTC),
		Accessed: time.Date(2019, 5, 8, 5, 5, 5, 0, time.UTC),
	}
	events := parse(t, table(mftgen.File{
		RecordNumber: 95, SequenceNumber: 1, InUse: true, SI: si(),
		Names:        []mftgen.Name{{Name: "stomped.exe", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1, Times: fn}},
		ResidentData: []byte("x"),
	}))
	var n int
	for _, e := range events {
		if e.Extra["file_name"] != "stomped.exe" {
			continue
		}
		n++
		if e.Extra["fn_created"] == "" {
			t.Error("the $FILE_NAME timestamps were dropped")
		}
		// The event's own time must be the $SI one, not $FN.
		if e.Timestamp.Year() == 2019 {
			t.Errorf("a $FILE_NAME timestamp became an event timestamp: %s", e.Timestamp)
		}
	}
	if n != 4 {
		t.Errorf("got %d events for one file, want exactly 4 -- $FN must not add more", n)
	}
}

// Repeated parses of the same table are identical.
func TestParser_IsDeterministic(t *testing.T) {
	data := table(mftgen.File{
		RecordNumber: 64, SequenceNumber: 1, InUse: true, SI: si(),
		Names:        []mftgen.Name{{Name: "a.txt", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1}},
		ResidentData: []byte("x")})
	path := write(t, data)
	p := mft.New()
	first, err := p.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 15; i++ {
		again, err := p.Parse(path)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if len(again.Events) != len(first.Events) {
			t.Fatalf("run %d: %d events, want %d", i, len(again.Events), len(first.Events))
		}
		for j := range first.Events {
			a, b := first.Events[j], again.Events[j]
			if !a.Timestamp.Equal(b.Timestamp) || a.EventType != b.EventType ||
				a.SourceReference != b.SourceReference || a.FilePath != b.FilePath {
				t.Fatalf("run %d event %d differs", i, j)
			}
		}
	}
}

// A large table parses without exhausting memory and stays bounded.
func TestParser_LargeTable(t *testing.T) {
	files := mftgen.SystemRecords(si())
	files = append(files, mftgen.File{RecordNumber: 40, SequenceNumber: 1, InUse: true, IsDirectory: true, SI: si(),
		Names: []mftgen.Name{{Name: "Windows", Namespace: mftgen.NamespaceWin32, ParentRef: 5, ParentSeq: 5}}})
	const n = 5000
	for i := 0; i < n; i++ {
		files = append(files, mftgen.File{
			RecordNumber: uint64(100 + i), SequenceNumber: 1, InUse: true, SI: si(),
			Names:        []mftgen.Name{{Name: fmt.Sprintf("f%05d.dat", i), Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1}},
			ResidentData: []byte("x"),
		})
	}
	res, err := mft.New().Parse(write(t, mftgen.Build(files)))
	if err != nil {
		t.Fatal(err)
	}
	// 4 events per file, plus the directory and system records.
	if len(res.Events) < n*4 {
		t.Errorf("got %d events for %d files, want at least %d", len(res.Events), n, n*4)
	}
	if len(res.Raw) == 0 {
		t.Error("no raw evidence recorded")
	}
}

// Malformed records are reported, not fatal, and never produce events
// built on unreadable data.
func TestParser_MalformedRecordsDoNotAbortTheImport(t *testing.T) {
	base := table(mftgen.File{
		RecordNumber: 64, SequenceNumber: 1, InUse: true, SI: si(),
		Names:        []mftgen.Name{{Name: "ok.txt", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1}},
		ResidentData: []byte("x")})
	for _, how := range []string{"baad", "attr-length", "attr-offset", "fixup"} {
		t.Run(how, func(t *testing.T) {
			res, err := mft.New().Parse(write(t, mftgen.Corrupt(base, 40, how)))
			if err != nil {
				t.Fatalf("one damaged record aborted the whole import: %v", err)
			}
			// The good record still produced its events.
			var sawOK bool
			for _, e := range res.Events {
				if e.Extra["file_name"] == "ok.txt" {
					sawOK = true
				}
			}
			if !sawOK {
				t.Error("a damaged record suppressed an undamaged one")
			}
			// And the damage is on the record, for investigation.
			var report bool
			for _, r := range res.Raw {
				if r.SourceReference == "mft:parse-report" && strings.Contains(r.Raw, "warning") {
					report = true
				}
			}
			if !report {
				t.Errorf("%q produced no parse report", how)
			}
		})
	}
}

// Detection must not claim arbitrary files.
func TestParser_DetectionIsNarrow(t *testing.T) {
	p := mft.New()
	for _, name := range []string{"C/$MFT", "root/$mft", "image/$MFT.copy0", "export/volume.mft"} {
		if !p.Detect(name) {
			t.Errorf("%q was not detected as an $MFT", name)
		}
	}
	for _, name := range []string{
		"Windows/System32/config/SYSTEM", "Users/j/NTUSER.DAT",
		"Windows/Prefetch/CMD.EXE-1234.pf", "notes.txt", "$LogFile", "$UsnJrnl",
	} {
		if p.Detect(name) {
			t.Errorf("%q was misdetected as an $MFT", name)
		}
	}
	// Content detection must reject non-tables.
	if p.DetectContent([]byte("this is not a filesystem table at all, just text")) {
		t.Error("arbitrary text was content-detected as an $MFT")
	}
	valid := table()
	if !p.DetectContent(valid[:512]) {
		t.Error("a real table was not content-detected")
	}
	if p.ArtifactType() != model.ArtifactMFT {
		t.Errorf("artifact type = %q", p.ArtifactType())
	}
}

func keys(m map[string]model.Event) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Every event must be paired with raw evidence carrying the SAME source
// reference.
//
// The import links an event to its raw record by that string, so an
// event whose reference has no matching raw record has unresolvable
// provenance -- which surfaced in the UI as "Error loading evidence:
// internal server error" on every filesystem event. Found by opening one
// in the browser, not by any unit test, which is why this one exists.
func TestParser_EveryEventHasMatchingRawEvidence(t *testing.T) {
	res, err := mft.New().Parse(write(t, table(
		mftgen.File{RecordNumber: 64, SequenceNumber: 2, InUse: true, SI: si(),
			Names:        []mftgen.Name{{Name: "a.txt", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1}},
			ResidentData: []byte("x")},
		mftgen.File{RecordNumber: 65, SequenceNumber: 1, InUse: false, SI: si(),
			Names:        []mftgen.Name{{Name: "b.txt", Namespace: mftgen.NamespaceWin32, ParentRef: 40, ParentSeq: 1}},
			ResidentData: []byte("y")},
	)))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) == 0 {
		t.Fatal("no events")
	}

	rawByRef := map[string]int{}
	for _, r := range res.Raw {
		rawByRef[r.SourceReference]++
	}
	for _, e := range res.Events {
		n, ok := rawByRef[e.SourceReference]
		if !ok {
			t.Errorf("event %q has no raw evidence with a matching source reference", e.SourceReference)
			continue
		}
		if n != 1 {
			t.Errorf("event %q matches %d raw records, want exactly 1", e.SourceReference, n)
		}
	}
	// No orphan raw records either, apart from the parse report.
	eventRefs := map[string]bool{}
	for _, e := range res.Events {
		eventRefs[e.SourceReference] = true
	}
	for _, r := range res.Raw {
		if r.SourceReference == "mft:parse-report" {
			continue
		}
		if !eventRefs[r.SourceReference] {
			t.Errorf("raw record %q belongs to no event", r.SourceReference)
		}
	}
	// The raw must say WHICH timestamp its event represents, so four
	// records for one file are distinguishable.
	for _, r := range res.Raw {
		if r.SourceReference == "mft:parse-report" {
			continue
		}
		if !strings.Contains(r.Raw, "event_timestamp_field") {
			t.Errorf("raw record %q does not name the timestamp it belongs to", r.SourceReference)
		}
	}
}
