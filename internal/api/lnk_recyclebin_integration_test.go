package api

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/recyclebin/rbgen"
	"tracefall/internal/shelllink/lnkgen"
)

// End-to-end shortcut and Recycle Bin ingestion.
//
// The recurring theme: neither artifact is execution evidence, and the
// pipeline must carry that distinction all the way from the binary
// structure to the timeline row.

var (
	lnkCreated  = time.Date(2026, 2, 11, 8, 30, 0, 0, time.UTC)
	lnkAccessed = time.Date(2026, 3, 4, 17, 45, 12, 0, time.UTC)
	lnkWritten  = time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)
	rbDeleted   = time.Date(2026, 5, 21, 14, 32, 8, 0, time.UTC)
)

func sampleLNK() []byte {
	return lnkgen.Build(lnkgen.Link{
		Unicode: true, FileAttributes: 0x20,
		Creation: lnkCreated, Access: lnkAccessed, Write: lnkWritten,
		FileSize: 184320, ShowCommand: 1,
		Name:          "Quarterly report",
		RelativePath:  `..\..\Documents\report.docx`,
		WorkingDir:    `C:\Users\jdoe\Documents`,
		Arguments:     `/embedding`,
		IconLocation:  `C:\Windows\System32\imageres.dll`,
		LocalBasePath: `C:\Users\jdoe\Documents\report.docx`,
		DriveType:     3, VolumeSerial: 0xC0FFEE01, VolumeLabel: "OSDisk",
		IDList: []lnkgen.Item{
			{Kind: "volume", Name: `C:\`},
			{Kind: "dir", Name: "Users", Attrs: 0x10},
			{Kind: "file", Name: "report.docx", Size: 184320, Modified: lnkWritten, Attrs: 0x20},
		},
		TrackerMachineID: "WKSTN-042",
	})
}

func sampleIRecord() []byte {
	return rbgen.Build(rbgen.Record{
		Version: 2, Size: 1048576, Deleted: rbDeleted,
		Path: `C:\Users\jdoe\Documents\confidential-plan.docx`,
	})
}

// lnkCatalog holds both new artifacts plus files that resemble them but
// are not, so classification is exercised in both directions.
func lnkCatalog() map[string][]byte {
	return map[string][]byte{
		"Users/jdoe/AppData/Roaming/Microsoft/Windows/Recent/report.lnk": sampleLNK(),
		// A shortcut under a name that is not .lnk: content detection
		// must still find it.
		"Users/jdoe/Desktop/renamed-shortcut.bin": sampleLNK(),
		// A .lnk that is not a shortcut: must NOT be claimed.
		"Users/jdoe/Desktop/not-really.lnk": []byte("this file is called .lnk but is plain text, at length"),

		`C/$Recycle.Bin/S-1-5-21-1004336348-1177238915-682003330-1001/$IA1B2C3.docx`: sampleIRecord(),
		`C/$Recycle.Bin/S-1-5-21-1004336348-1177238915-682003330-1001/$RA1B2C3.docx`: []byte("deleted file content"),
		// An $I-named file that is not a record: must NOT be claimed.
		`C/$Recycle.Bin/S-1-5-21-1004336348-1177238915-682003330-1001/$IZZZZZZ.txt`: []byte("not a record at all, just text"),
	}
}

//  1. Both artifacts are classified, supported and HIGH; the impostors
//     are not claimed.
func TestLNKRB_ClassificationIsStructural(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "LNK and $I classification")
	disc := discoverBinaryDir(t, mux, c.ID, lnkCatalog())

	want := map[string]struct {
		artifact  string
		label     string
		supported bool
		priority  string
	}{
		"Users/jdoe/AppData/Roaming/Microsoft/Windows/Recent/report.lnk": {
			model.ArtifactLNK, "Windows LNK shortcut", true, "high"},
		"Users/jdoe/Desktop/renamed-shortcut.bin": {
			model.ArtifactLNK, "Windows LNK shortcut", true, "high"},
		`C/$Recycle.Bin/S-1-5-21-1004336348-1177238915-682003330-1001/$IA1B2C3.docx`: {
			model.ArtifactRecycleBin, "Recycle Bin", true, "high"},
	}
	for path, w := range want {
		sf, ok := sourceFileByPath(disc.SourceFiles, path)
		if !ok {
			t.Errorf("%s was not discovered", path)
			continue
		}
		if !sf.Supported {
			t.Errorf("%s is not supported: %s", path, sf.UnsupportedReason)
			continue
		}
		if sf.ArtifactType != w.artifact {
			t.Errorf("%s artifact type = %q, want %q", path, sf.ArtifactType, w.artifact)
		}
		if sf.TypeLabel != w.label {
			t.Errorf("%s label = %q, want %q", path, sf.TypeLabel, w.label)
		}
		if sf.Priority != w.priority {
			t.Errorf("%s priority = %q, want %q", path, sf.Priority, w.priority)
		}
		if sf.Note == "" {
			t.Errorf("%s carries no forensic note", path)
		}
	}

	// A file that merely LOOKS like one of these must not be claimed:
	// it stays unsupported rather than producing false evidence.
	for _, path := range []string{
		"Users/jdoe/Desktop/not-really.lnk",
		`C/$Recycle.Bin/S-1-5-21-1004336348-1177238915-682003330-1001/$IZZZZZZ.txt`,
	} {
		sf, ok := sourceFileByPath(disc.SourceFiles, path)
		if !ok {
			t.Errorf("%s was not discovered", path)
			continue
		}
		if sf.Supported {
			t.Errorf("%s was claimed as %q on its NAME; structural validation should have refused it",
				path, sf.ArtifactType)
		}
	}
	// The $R half is its OWN supported artifact -- recovered content --
	// and must never be confused with the $I metadata record beside it.
	rf, _ := sourceFileByPath(disc.SourceFiles,
		`C/$Recycle.Bin/S-1-5-21-1004336348-1177238915-682003330-1001/$RA1B2C3.docx`)
	if !rf.Supported {
		t.Errorf("the $R content file is not supported: %s", rf.UnsupportedReason)
	}
	if rf.ArtifactType != model.ArtifactRecycleBinContent {
		t.Errorf("the $R file's artifact type = %q, want %q", rf.ArtifactType, model.ArtifactRecycleBinContent)
	}
	if rf.TypeLabel == "Recycle Bin" {
		t.Error("the $R content file is labelled as an $I metadata record")
	}
	if !strings.Contains(rf.Note, "$I record") {
		t.Errorf("the $R row does not point at the $I record that describes it: %q", rf.Note)
	}
}

//  2. A shortcut yields one event per recorded target timestamp, each
//     labelled as target metadata and none as execution.
func TestLNKRB_ShortcutProducesTargetMetadataEvents(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "LNK timeline")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Users/jdoe/AppData/Roaming/Microsoft/Windows/Recent/report.lnk": sampleLNK(),
	})
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("parse failures: %+v", imp.ParseFailures)
	}

	events := typedTimeline(t, mux, c.ID)
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3 (creation, write, access)", len(events))
	}
	byType := map[string]model.Event{}
	for _, e := range events {
		byType[e.EventType] = e
		if e.ArtifactType != model.ArtifactLNK {
			t.Errorf("artifact type = %q", e.ArtifactType)
		}
		if e.Timestamp.Location() != time.UTC {
			t.Errorf("%s is not stored in UTC", e.EventType)
		}
		// Never execution, in the type, the meaning, or the disclaimer.
		if strings.Contains(e.EventType, "exec") || strings.Contains(e.EventType, "run") {
			t.Errorf("event type %q reads as execution", e.EventType)
		}
		if !strings.Contains(e.Extra["evidence_meaning"], "NOT evidence that the target was executed") {
			t.Errorf("the record does not disclaim execution: %q", e.Extra["evidence_meaning"])
		}
		if e.Extra["timestamp_meaning"] == "" {
			t.Errorf("%s does not say what its timestamp means", e.EventType)
		}
		if e.ProcessName != "" || e.User != "" {
			t.Errorf("a shortcut event invented an actor: user=%q process=%q", e.User, e.ProcessName)
		}
		if e.Confidence >= 1.0 {
			t.Errorf("confidence = %v; a shortcut is weaker than a recorded execution", e.Confidence)
		}
	}
	if !byType[model.EventLnkTargetCreated].Timestamp.Equal(lnkCreated) {
		t.Errorf("creation event at %s, want %s", byType[model.EventLnkTargetCreated].Timestamp, lnkCreated)
	}
	if !byType[model.EventLnkTargetModified].Timestamp.Equal(lnkWritten) {
		t.Errorf("write event at %s, want %s", byType[model.EventLnkTargetModified].Timestamp, lnkWritten)
	}
	if !byType[model.EventLnkTargetAccessed].Timestamp.Equal(lnkAccessed) {
		t.Errorf("access event at %s, want %s", byType[model.EventLnkTargetAccessed].Timestamp, lnkAccessed)
	}

	// Every documented field reached the event.
	e := byType[model.EventLnkTargetCreated]
	for field, want := range map[string]string{
		"lnk_path":               "report.lnk",
		"target_path":            `C:\Users\jdoe\Documents\report.docx`,
		"relative_path":          `..\..\Documents\report.docx`,
		"working_directory":      `C:\Users\jdoe\Documents`,
		"command_line_arguments": `/embedding`,
		"icon_location":          `C:\Windows\System32\imageres.dll`,
		"target_file_size":       "184320",
		"drive_type":             "DRIVE_FIXED",
		"volume_serial":          "C0FFEE01",
		"file_attributes":        "0x00000020",
		"source_file":            "report.lnk",
		"tracker_machine_id":     "WKSTN-042",
		"string_encoding":        "unicode",
	} {
		if e.Extra[field] != want {
			t.Errorf("extra[%q] = %q, want %q", field, e.Extra[field], want)
		}
	}
	// Both path representations are retained.
	if e.Extra["id_list_path"] == "" {
		t.Error("the ID list path representation was discarded")
	}
	if e.Extra["link_info_path"] == "" {
		t.Error("the LinkInfo path representation was discarded")
	}
}

// 3. A Recycle Bin record yields exactly one event, labelled a deletion.
func TestLNKRB_RecycleBinProducesADeletionEvent(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Recycle Bin timeline")
	dir := `C/$Recycle.Bin/S-1-5-21-1004336348-1177238915-682003330-1001/`
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		dir + "$IA1B2C3.docx": sampleIRecord(),
		dir + "$RA1B2C3.docx": []byte("deleted content"),
	})
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("parse failures: %+v", imp.ParseFailures)
	}

	events := typedTimeline(t, mux, c.ID)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	e := events[0]
	if e.EventType != model.EventRecycleBinDeletion {
		t.Errorf("event type = %q", e.EventType)
	}
	if !e.Timestamp.Equal(rbDeleted) {
		t.Errorf("timestamp = %s, want %s", e.Timestamp, rbDeleted)
	}
	if e.Extra["timestamp_meaning"] != "Recycle Bin deletion time" {
		t.Errorf("timestamp meaning = %q, want the exact deletion label", e.Extra["timestamp_meaning"])
	}
	// It must never read as a write or an execution.
	meaning := strings.ToLower(e.Extra["evidence_meaning"])
	for _, phrase := range []string{"not the file's last-write", "not evidence that the"} {
		if !strings.Contains(meaning, phrase) {
			t.Errorf("the record does not disclaim %q: %s", phrase, meaning)
		}
	}
	for field, want := range map[string]string{
		"original_path":      `C:\Users\jdoe\Documents\confidential-plan.docx`,
		"original_name":      "confidential-plan.docx",
		"original_size":      "1048576",
		"recycle_bin_record": "$IA1B2C3.docx",
		"record_version":     "2",
		"recycle_bin_sid":    "S-1-5-21-1004336348-1177238915-682003330-1001",
		"paired_r_file":      "$RA1B2C3.docx",
	} {
		if e.Extra[field] != want {
			t.Errorf("extra[%q] = %q, want %q", field, e.Extra[field], want)
		}
	}
	if !strings.Contains(e.Extra["paired_r_file_status"], "present") {
		t.Errorf("the $R pairing was not resolved: %q", e.Extra["paired_r_file_status"])
	}
	if e.FilePath != `C:\Users\jdoe\Documents\confidential-plan.docx` {
		t.Errorf("file path = %q; the event should be searchable by the deleted path", e.FilePath)
	}
}

// 4. The $R pairing is reported honestly when the file was not collected.
func TestLNKRB_UnpairedRecordSaysSo(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Unpaired record")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		`C/$Recycle.Bin/S-1-5-21-1/$IA1B2C3.docx`: sampleIRecord(),
	})
	importAllFrom(t, mux, c.ID, disc)

	events := typedTimeline(t, mux, c.ID)
	if len(events) != 1 {
		t.Fatalf("got %d events", len(events))
	}
	status := events[0].Extra["paired_r_file_status"]
	if !strings.Contains(status, "not present") {
		t.Errorf("an absent $R file was not reported as absent: %q", status)
	}
	if events[0].Extra["paired_r_file"] != "$RA1B2C3.docx" {
		t.Errorf("the derivable pair name was not recorded: %q", events[0].Extra["paired_r_file"])
	}
}

// 5. Malformed files never crash the pipeline and never become evidence.
func TestLNKRB_MalformedFilesAreSafe(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Malformed shortcuts and records")
	good := sampleLNK()
	rec := sampleIRecord()
	files := map[string][]byte{
		"a/truncated.lnk":                         lnkgen.Truncate(good, 60),
		"a/bad-clsid.lnk":                         lnkgen.Corrupt(good, "clsid"),
		"a/bad-size.lnk":                          lnkgen.Corrupt(good, "header-size"),
		"a/huge-idlist.bin":                       lnkgen.Corrupt(good, "huge-idlist"),
		"a/random.lnk":                            []byte(strings.Repeat("\x00\xFF\xAB", 200)),
		`C/$Recycle.Bin/S-1-5-21-1/$Itrunc.docx`:  rbgen.Truncate(rec, 12),
		`C/$Recycle.Bin/S-1-5-21-1/$Ibadver.docx`: rbgen.WithVersion(rec, 7),
		`C/$Recycle.Bin/S-1-5-21-1/$Irandom.docx`: []byte(strings.Repeat("\x01\x02\x03\x04", 100)),
		"a/valid.lnk":                             good,
		`C/$Recycle.Bin/S-1-5-21-1/$Ivalid.docx`:  rec,
	}
	disc := discoverBinaryDir(t, mux, c.ID, files)
	imp := importAllFrom(t, mux, c.ID, disc)

	// Whatever was claimed must have parsed; the malformed ones should
	// not have been claimed in the first place.
	for _, f := range imp.ParseFailures {
		t.Errorf("a file was claimed and then failed to parse: %s (%s)", f.Filename, f.Message)
	}
	// The valid files still produced their evidence.
	//
	// Six LNK events, not three: "huge-idlist" damages a structure AFTER
	// the header, and the header is where the target timestamps live. A
	// shortcut whose tail is unreadable still carries three real
	// observations, and discarding them would lose evidence that
	// survived. What it must NOT do is invent the part that was lost --
	// checked below.
	events := typedTimeline(t, mux, c.ID)
	var lnkEvents, rbEvents int
	var damaged []model.Event
	for _, e := range events {
		switch e.ArtifactType {
		case model.ArtifactLNK:
			lnkEvents++
			if e.Extra["parse_warnings"] != "" {
				damaged = append(damaged, e)
			}
		case model.ArtifactRecycleBin:
			rbEvents++
		}
	}
	if lnkEvents != 6 {
		t.Errorf("got %d LNK events, want 6 (3 from the valid shortcut, 3 from the one whose header survived)", lnkEvents)
	}
	if rbEvents != 1 {
		t.Errorf("got %d Recycle Bin events, want 1 from the one valid record", rbEvents)
	}
	if len(damaged) != 3 {
		t.Fatalf("got %d events carrying a parse warning, want 3 from the damaged shortcut", len(damaged))
	}
	for _, e := range damaged {
		// The header survived; the structures after it did not, and
		// nothing from them may be reported.
		if e.Timestamp.IsZero() {
			t.Error("a damaged shortcut produced an event with no timestamp")
		}
		if e.Extra["id_list_path"] != "" {
			t.Errorf("a path was reconstructed from an ID list that does not fit: %q", e.Extra["id_list_path"])
		}
		if e.Extra["target_path"] != "" {
			t.Errorf("a target path was reported from unreadable structures: %q", e.Extra["target_path"])
		}
		if !strings.Contains(e.Extra["parse_warnings"], "was not read") {
			t.Errorf("the damage was not explained: %q", e.Extra["parse_warnings"])
		}
	}
}

//  6. A shortcut with no target timestamps imports as evidence with no
//     timeline events -- never with an invented time.
func TestLNKRB_ShortcutWithoutTimestampsMakesNoEvent(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Timeless shortcut")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"a/no-times.lnk": lnkgen.Build(lnkgen.Link{
			Unicode: true, Name: "target", LocalBasePath: `C:\tmp\thing.exe`,
		}),
	})
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("parse failures: %+v", imp.ParseFailures)
	}
	if len(imp.Imported) != 1 {
		t.Fatalf("imported %d files", len(imp.Imported))
	}
	if imp.EventCount != 0 {
		t.Errorf("a shortcut with no target timestamps produced %d events", imp.EventCount)
	}
	if len(typedTimeline(t, mux, c.ID)) != 0 {
		t.Error("an event with an invented time reached the timeline")
	}
}

// 7. Provenance resolves for both, and each event has its own record.
func TestLNKRB_ProvenanceResolves(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "LNK and $I provenance")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"a/report.lnk": sampleLNK(),
		`C/$Recycle.Bin/S-1-5-21-1/$IA1B2C3.docx`: sampleIRecord(),
	})
	importAllFrom(t, mux, c.ID, disc)

	seen := map[string]bool{}
	for _, e := range typedTimeline(t, mux, c.ID) {
		var prov EventProvenance
		rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/"+e.ID, nil, &prov)
		if rec.Code != 200 {
			t.Fatalf("provenance for %s returned %d", e.SourceReference, rec.Code)
		}
		if prov.RawEvidence.Raw == "" {
			t.Errorf("%s resolved no raw evidence", e.SourceReference)
		}
		if prov.SourceFile.SHA256 == "" {
			t.Errorf("%s carries no source hash", e.SourceReference)
		}
		if seen[e.SourceReference] {
			t.Errorf("duplicate source reference %q", e.SourceReference)
		}
		seen[e.SourceReference] = true
	}
	if len(seen) != 4 {
		t.Errorf("got %d distinct references, want 4 (3 LNK + 1 deletion)", len(seen))
	}
}

// 8. Neither artifact manufactures a finding on its own.
func TestLNKRB_NoFindingsAreManufactured(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "No false findings")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		// Deliberately alarming-looking paths.
		"a/mimikatz.lnk": lnkgen.Build(lnkgen.Link{
			Unicode: true, Creation: lnkCreated, Write: lnkWritten,
			LocalBasePath: `C:\Users\jdoe\Downloads\mimikatz.exe`,
			Arguments:     `sekurlsa::logonpasswords`,
		}),
		`C/$Recycle.Bin/S-1-5-21-1/$Ievil.exe`: rbgen.Build(rbgen.Record{
			Version: 2, Size: 1024, Deleted: rbDeleted, Path: `C:\Windows\Temp\payload.exe`,
		}),
	})
	importAllFrom(t, mux, c.ID, disc)
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil)

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings", nil, &findings)
	for _, f := range findings {
		t.Errorf("a shortcut or deletion record alone produced a finding: %q (%s)", f.Title, f.Severity)
	}
}
