package usnjrnl_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/ntfs/mftgen"
	"tracefall/internal/parsers/usnjrnl"
)

var base = time.Date(2026, 5, 10, 14, 0, 0, 0, time.UTC)

func write(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "$UsnJrnl_$J")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func journal(entries ...mftgen.UsnEntry) []byte {
	return mftgen.BuildUsnJournal(4096, entries)
}

func parse(t *testing.T, data []byte) []model.Event {
	t.Helper()
	res, err := usnjrnl.New().Parse(write(t, data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return res.Events
}

// Each reason maps to exactly one event of the right type.
func TestUsnParser_EventTypeMapping(t *testing.T) {
	cases := []struct {
		name   string
		reason uint32
		want   string
		class  string
	}{
		{"create", mftgen.ReasonFileCreate, model.EventUsnCreate, "FILE_CREATE"},
		{"create and close", mftgen.ReasonFileCreate | mftgen.ReasonClose, model.EventUsnCreate, "FILE_CREATE"},
		{"delete", mftgen.ReasonFileDelete, model.EventUsnDelete, "FILE_DELETE"},
		{"delete wins over data", mftgen.ReasonFileDelete | mftgen.ReasonDataExtend, model.EventUsnDelete, "FILE_DELETE"},
		{"data extend", mftgen.ReasonDataExtend, model.EventUsnModify, "DATA_CHANGE"},
		{"data overwrite", mftgen.ReasonDataOverwrite | mftgen.ReasonClose, model.EventUsnModify, "DATA_CHANGE"},
		{"truncate", mftgen.ReasonDataTruncation, model.EventUsnModify, "DATA_CHANGE"},
		{"rename old", mftgen.ReasonRenameOldName, model.EventUsnRename, "RENAME"},
		{"rename new", mftgen.ReasonRenameNewName, model.EventUsnRename, "RENAME"},
		{"basic info", mftgen.ReasonBasicInfoChange, model.EventUsnMetadataChange, "METADATA_CHANGE"},
		{"security", mftgen.ReasonSecurityChange, model.EventUsnMetadataChange, "METADATA_CHANGE"},
		{"close only", mftgen.ReasonClose, model.EventUsnMetadataChange, "METADATA_CHANGE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := parse(t, journal(mftgen.UsnEntry{
				FileRecord: 64, FileSequence: 1, ParentRecord: 40, ParentSeq: 1,
				Usn: 0x100, Timestamp: base, Reason: tc.reason, FileName: "f.txt",
			}))
			// ONE event per record, never one per flag.
			if len(events) != 1 {
				t.Fatalf("got %d events for one record, want exactly 1", len(events))
			}
			e := events[0]
			if e.EventType != tc.want {
				t.Errorf("event type = %q, want %q", e.EventType, tc.want)
			}
			if e.Extra["usn_classification"] != tc.class {
				t.Errorf("classification = %q, want %q", e.Extra["usn_classification"], tc.class)
			}
			// The raw mask must always be preserved so the translation
			// can be checked.
			if e.Extra["usn_reason_hex"] != fmt.Sprintf("0x%08X", tc.reason) {
				t.Errorf("raw reason = %q, want 0x%08X", e.Extra["usn_reason_hex"], tc.reason)
			}
			if e.Extra["usn_reason_flags"] == "" {
				t.Error("decoded reason flags were not preserved")
			}
		})
	}
}

// Multiple flags are all preserved on the single event.
func TestUsnParser_AllReasonFlagsPreserved(t *testing.T) {
	reason := uint32(mftgen.ReasonDataExtend | mftgen.ReasonDataOverwrite | mftgen.ReasonClose)
	events := parse(t, journal(mftgen.UsnEntry{
		FileRecord: 64, ParentRecord: 40, Usn: 1, Timestamp: base, Reason: reason, FileName: "multi.bin",
	}))
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	flags := events[0].Extra["usn_reason_flags"]
	for _, want := range []string{"DATA_EXTEND", "DATA_OVERWRITE", "CLOSE"} {
		if !strings.Contains(flags, want) {
			t.Errorf("flags %q missing %s", flags, want)
		}
	}
}

// An undocumented reason bit is surfaced, not dropped.
func TestUsnParser_UnknownReasonBitIsSurfaced(t *testing.T) {
	events := parse(t, journal(mftgen.UsnEntry{
		FileRecord: 64, ParentRecord: 40, Usn: 1, Timestamp: base,
		Reason: mftgen.ReasonFileCreate | 0x04000000, FileName: "odd.dat",
	}))
	if len(events) != 1 {
		t.Fatalf("got %d events", len(events))
	}
	if !strings.Contains(events[0].Extra["usn_reason_flags"], "UNKNOWN_0x") {
		t.Errorf("an undocumented bit was dropped: %q", events[0].Extra["usn_reason_flags"])
	}
	// A known bit still decides the type.
	if events[0].EventType != model.EventUsnCreate {
		t.Errorf("event type = %q, want create", events[0].EventType)
	}
}

// The rename pair produces two events, each labelled with its role.
func TestUsnParser_RenamePairKeepsBothNames(t *testing.T) {
	events := parse(t, journal(
		mftgen.UsnEntry{FileRecord: 64, FileSequence: 2, ParentRecord: 40, Usn: 1,
			Timestamp: base, Reason: mftgen.ReasonRenameOldName, FileName: "before.txt"},
		mftgen.UsnEntry{FileRecord: 64, FileSequence: 2, ParentRecord: 40, Usn: 2,
			Timestamp: base.Add(time.Second), Reason: mftgen.ReasonRenameNewName, FileName: "after.txt"},
	))
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	byName := map[string]model.Event{}
	for _, e := range events {
		byName[e.Extra["file_name"]] = e
	}
	oldE, newE := byName["before.txt"], byName["after.txt"]
	if !strings.Contains(oldE.Extra["rename_role"], "old name") {
		t.Errorf("old-name role = %q", oldE.Extra["rename_role"])
	}
	if !strings.Contains(newE.Extra["rename_role"], "new name") {
		t.Errorf("new-name role = %q", newE.Extra["rename_role"])
	}
	// Both describe the SAME file.
	if oldE.Extra["mft_file_reference"] != newE.Extra["mft_file_reference"] {
		t.Error("the rename pair does not share a file reference")
	}
}

// Provenance and source attribution.
func TestUsnParser_ProvenanceAndSourceAttribution(t *testing.T) {
	res, err := usnjrnl.New().Parse(write(t, journal(mftgen.UsnEntry{
		FileRecord: 64, FileSequence: 2, ParentRecord: 40, ParentSeq: 1, Usn: 0xABCD,
		Timestamp: base, Reason: mftgen.ReasonFileCreate, SecurityID: 267, FileAttributes: 0x20,
		FileName: "evidence.txt",
	})))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d events", len(res.Events))
	}
	e := res.Events[0]
	for _, key := range []string{
		"usn", "usn_record_offset", "mft_file_reference", "parent_file_reference",
		"raw_file_reference", "usn_source_file", "event_source", "filesystem",
	} {
		if e.Extra[key] == "" {
			t.Errorf("missing provenance field %q", key)
		}
	}
	if !strings.Contains(e.Extra["event_source"], "USN") {
		t.Errorf("event source = %q, want it to name the journal", e.Extra["event_source"])
	}
	if e.Extra["security_id"] != "267" {
		t.Errorf("security id = %q, want 267", e.Extra["security_id"])
	}
	if e.ArtifactType != model.ArtifactUsnJournal {
		t.Errorf("artifact type = %q", e.ArtifactType)
	}
	if e.Parser == "" {
		t.Error("no parser recorded")
	}
	// Every event must pair with raw evidence under the SAME reference.
	rawRefs := map[string]int{}
	for _, r := range res.Raw {
		rawRefs[r.SourceReference]++
	}
	if rawRefs[e.SourceReference] != 1 {
		t.Errorf("event %q matches %d raw records, want 1", e.SourceReference, rawRefs[e.SourceReference])
	}
}

// No actor is invented from journal metadata.
func TestUsnParser_InventsNoActor(t *testing.T) {
	events := parse(t, journal(mftgen.UsnEntry{
		FileRecord: 64, ParentRecord: 40, Usn: 1, Timestamp: base,
		Reason: mftgen.ReasonFileCreate, FileName: "payload.exe",
	}))
	for _, e := range events {
		if e.User != "" || e.Host != "" || e.ProcessName != "" ||
			e.ProcessPath != "" || e.ParentProcessName != "" || e.CommandLine != "" {
			t.Errorf("an actor was invented: user=%q host=%q process=%q parent=%q cmd=%q",
				e.User, e.Host, e.ProcessName, e.ParentProcessName, e.CommandLine)
		}
	}
}

// Records with no usable timestamp produce no events rather than
// invented ones, and are reported.
func TestUsnParser_NoTimestampMeansNoEvent(t *testing.T) {
	stream := journal(mftgen.UsnEntry{
		FileRecord: 64, ParentRecord: 40, Usn: 1, Timestamp: base,
		Reason: mftgen.ReasonFileCreate, FileName: "timeless.txt",
	})
	stream = mftgen.CorruptUsn(stream, 4096, "zero-time")
	res, err := usnjrnl.New().Parse(write(t, stream))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Events {
		if e.Timestamp.IsZero() {
			t.Error("an event was emitted with no timestamp")
		}
	}
	var reported bool
	for _, r := range res.Raw {
		if r.SourceReference == "usnjrnl:parse-report" &&
			strings.Contains(r.Raw, "records_without_event") {
			reported = true
		}
	}
	if !reported {
		t.Error("a record that produced no event was not reported")
	}
}

// Timestamps are stored canonically in UTC.
func TestUsnParser_TimestampsAreUTC(t *testing.T) {
	events := parse(t, journal(mftgen.UsnEntry{
		FileRecord: 1, ParentRecord: 5, Usn: 1, Timestamp: base,
		Reason: mftgen.ReasonFileCreate, FileName: "utc.txt",
	}))
	if len(events) == 0 {
		t.Fatal("no events")
	}
	if !events[0].Timestamp.Equal(base) {
		t.Errorf("timestamp = %s, want %s", events[0].Timestamp, base)
	}
	if events[0].Timestamp.Location() != time.UTC {
		t.Error("timestamp is not stored in UTC")
	}
}

// Deterministic repeated parsing.
func TestUsnParser_IsDeterministic(t *testing.T) {
	data := journal(
		mftgen.UsnEntry{FileRecord: 64, ParentRecord: 40, Usn: 1, Timestamp: base,
			Reason: mftgen.ReasonFileCreate, FileName: "a.txt"},
		mftgen.UsnEntry{FileRecord: 65, ParentRecord: 40, Usn: 2, Timestamp: base.Add(time.Minute),
			Reason: mftgen.ReasonFileDelete, FileName: "b.txt"},
	)
	path := write(t, data)
	p := usnjrnl.New()
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
				a.SourceReference != b.SourceReference ||
				a.Extra["usn_reason_flags"] != b.Extra["usn_reason_flags"] {
				t.Fatalf("run %d event %d differs", i, j)
			}
		}
	}
}

// Multiple records for the same file are all retained: a journal is a
// history, and collapsing repeats would erase it.
func TestUsnParser_MultipleRecordsForOneFileAreAllKept(t *testing.T) {
	var entries []mftgen.UsnEntry
	for i := 0; i < 12; i++ {
		entries = append(entries, mftgen.UsnEntry{
			FileRecord: 64, FileSequence: 2, ParentRecord: 40, Usn: uint64(i + 1),
			Timestamp: base.Add(time.Duration(i) * time.Minute),
			Reason:    mftgen.ReasonDataExtend, FileName: "busy.log",
		})
	}
	events := parse(t, journal(entries...))
	if len(events) != 12 {
		t.Fatalf("got %d events for 12 records of one file, want 12", len(events))
	}
	refs := map[string]bool{}
	for _, e := range events {
		if refs[e.SourceReference] {
			t.Errorf("duplicate source reference %q", e.SourceReference)
		}
		refs[e.SourceReference] = true
	}
}

// A large journal parses.
func TestUsnParser_LargeJournal(t *testing.T) {
	const n = 8000
	entries := make([]mftgen.UsnEntry, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, mftgen.UsnEntry{
			FileRecord: uint64(1000 + i), ParentRecord: 40, Usn: uint64(i),
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Reason:    mftgen.ReasonDataExtend, FileName: fmt.Sprintf("bulk-%05d.dat", i),
		})
	}
	res, err := usnjrnl.New().Parse(write(t, journal(entries...)))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != n {
		t.Errorf("got %d events, want %d", len(res.Events), n)
	}
}

// Detection is narrow.
func TestUsnParser_DetectionIsNarrow(t *testing.T) {
	p := usnjrnl.New()
	for _, name := range []string{
		"C/$Extend/$UsnJrnl:$J", "root/$UsnJrnl_$J", "export/$J", "$Extend/$UsnJrnl",
	} {
		if !p.Detect(name) {
			t.Errorf("%q was not detected as a USN journal", name)
		}
	}
	for _, name := range []string{
		"C/$MFT", "C/$LogFile", "Windows/System32/config/SYSTEM",
		"Users/j/NTUSER.DAT", "notes.txt", "journal.txt",
	} {
		if p.Detect(name) {
			t.Errorf("%q was misdetected as a USN journal", name)
		}
	}
	if p.DetectContent([]byte("plain text, certainly not a change journal record stream")) {
		t.Error("arbitrary text was content-detected as a journal")
	}
	if p.ArtifactType() != model.ArtifactUsnJournal {
		t.Errorf("artifact type = %q", p.ArtifactType())
	}
}
