package api

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/jumplist/jlgen"
	"tracefall/internal/model"
	"tracefall/internal/shelllink/lnkgen"
)

// End-to-end Jump List ingestion.
//
// The recurring theme: a Jump List ties an APPLICATION to a target. It
// is not proof of execution, and the two kinds of timestamp it can carry
// mean different things that must survive the whole pipeline distinctly.

var (
	jlCreated  = time.Date(2026, 2, 11, 8, 30, 0, 0, time.UTC)
	jlWritten  = time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)
	jlAccessed = time.Date(2026, 3, 4, 17, 45, 12, 0, time.UTC)
	jlLastUsed = time.Date(2026, 3, 5, 9, 15, 30, 0, time.UTC)
)

const autoDir = "C/Users/jdoe/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/"
const customDir = "C/Users/jdoe/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/"

func jlLink(name, target string) lnkgen.Link {
	return lnkgen.Link{
		Unicode: true, FileAttributes: 0x20,
		Creation: jlCreated, Write: jlWritten, Access: jlAccessed,
		FileSize: 184320, ShowCommand: 1,
		Name: name, LocalBasePath: target, WorkingDir: `C:\Users\jdoe\Documents`,
		DriveType: 3, VolumeSerial: 0xC0FFEE01, VolumeLabel: "OSDisk",
		TrackerMachineID: "WKSTN-042",
	}
}

func jlCatalog() map[string][]byte {
	auto := jlgen.BuildAutomatic(jlgen.Automatic{Items: []jlgen.Item{
		{Link: jlLink("report", `C:\Users\jdoe\Documents\report.docx`), EntryNumber: 1,
			AccessCount: 7, LastAccess: jlLastUsed, Hostname: "wkstn-042"},
		{Link: jlLink("budget", `\\fileserver\finance\budget.xlsx`), EntryNumber: 2,
			AccessCount: 2, LastAccess: jlLastUsed.Add(-time.Hour), Pinned: true},
		{Link: jlLink("photos", `E:\photos\DSC0001.jpg`), EntryNumber: 3,
			AccessCount: 1, LastAccess: jlLastUsed.Add(-24 * time.Hour)},
	}})
	return map[string][]byte{
		autoDir + "5f7b5f1e01b83767.automaticDestinations-ms": auto,
		// An unknown AppID, kept rather than discarded.
		autoDir + "ffffffffffffffff.automaticDestinations-ms": jlgen.BuildAutomatic(jlgen.Automatic{
			Items: []jlgen.Item{{Link: jlLink("x", `C:\a\unknown-app.docx`), EntryNumber: 1,
				AccessCount: 1, LastAccess: jlLastUsed}}}),
		customDir + "b0459de4674aab56.customDestinations-ms": jlgen.BuildCustom([]lnkgen.Link{
			jlLink("task", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`),
		}),
		// An impostor: right extension, unrelated content.
		autoDir + "deadbeefdeadbeef.automaticDestinations-ms": []byte(strings.Repeat("impostor content ", 40)),
	}
}

// 1. Both containers classify as their own supported HIGH artifact.
func TestJumpList_ClassifiedAsTwoSupportedArtifacts(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Jump List classification")
	disc := discoverBinaryDir(t, mux, c.ID, jlCatalog())

	want := map[string]struct{ artifact, label string }{
		autoDir + "5f7b5f1e01b83767.automaticDestinations-ms": {
			model.ArtifactJumpListAutomatic, "Windows Jump List (Automatic Destinations)"},
		customDir + "b0459de4674aab56.customDestinations-ms": {
			model.ArtifactJumpListCustom, "Windows Jump List (Custom Destinations)"},
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
		if sf.Priority != "high" {
			t.Errorf("%s priority = %q, want high", path, sf.Priority)
		}
		if sf.Note == "" {
			t.Errorf("%s carries no forensic note", path)
		}
	}
	// The two must not share a label.
	a, _ := sourceFileByPath(disc.SourceFiles, autoDir+"5f7b5f1e01b83767.automaticDestinations-ms")
	cu, _ := sourceFileByPath(disc.SourceFiles, customDir+"b0459de4674aab56.customDestinations-ms")
	if a.TypeLabel == cu.TypeLabel {
		t.Errorf("both containers are labelled %q", a.TypeLabel)
	}
}

//  2. Import: events reach the timeline, with both timestamp kinds and
//     full provenance, and the impostor fails without taking the rest.
func TestJumpList_ImportsWithBothTimestampKinds(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Jump List timeline")
	disc := discoverBinaryDir(t, mux, c.ID, jlCatalog())
	imp := importAllFrom(t, mux, c.ID, disc)

	// The impostor is the only failure, and it is named.
	for _, f := range imp.ParseFailures {
		if !strings.HasPrefix(f.Filename, "deadbeef") {
			t.Errorf("an unexpected parse failure: %s (%s)", f.Filename, f.Message)
		}
	}
	if len(imp.ParseFailures) != 1 {
		t.Errorf("got %d parse failures, want 1 (the impostor)", len(imp.ParseFailures))
	}

	events := typedTimeline(t, mux, c.ID)
	var access, targetMeta, custom int
	for _, e := range events {
		switch e.EventType {
		case model.EventJumpListEntryAccess:
			access++
		case model.EventJumpListTargetMetadata:
			targetMeta++
		}
		if e.ArtifactType == model.ArtifactJumpListCustom {
			custom++
		}
	}
	// 4 automatic entries x 1 access = 4; (4 automatic + 1 custom) x 3
	// target timestamps = 15.
	if access != 4 {
		t.Errorf("got %d access events, want 4", access)
	}
	if targetMeta != 15 {
		t.Errorf("got %d target-metadata events, want 15", targetMeta)
	}
	if custom != 3 {
		t.Errorf("got %d custom-list events, want 3", custom)
	}

	// The access event carries the Jump List's own time; the target
	// events carry the file's.
	for _, e := range events {
		switch e.EventType {
		case model.EventJumpListEntryAccess:
			if e.Timestamp.Equal(jlCreated) || e.Timestamp.Equal(jlWritten) || e.Timestamp.Equal(jlAccessed) {
				t.Errorf("an access event carries a TARGET timestamp: %s", e.Timestamp)
			}
		case model.EventJumpListTargetMetadata:
			if e.Timestamp.Equal(jlLastUsed) {
				t.Errorf("a target-metadata event carries the Jump List's access time: %s", e.Timestamp)
			}
		}
		if e.Timestamp.Location() != time.UTC {
			t.Error("a timestamp is not stored in UTC")
		}
	}
}

// 3. Application attribution: known resolves, unknown is preserved.
func TestJumpList_ApplicationAttribution(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Jump List application")
	disc := discoverBinaryDir(t, mux, c.ID, jlCatalog())
	importAllFrom(t, mux, c.ID, disc)

	byApp := map[string]bool{}
	for _, e := range typedTimeline(t, mux, c.ID) {
		byApp[e.Extra["application"]] = true
		if e.Extra["app_id"] == "" {
			t.Error("an event carries no AppID field at all")
		}
	}
	var sawKnown, sawUnknown bool
	for app := range byApp {
		if strings.Contains(app, "Unknown application") {
			sawUnknown = true
			if !strings.Contains(app, "ffffffffffffffff") {
				t.Errorf("the unknown label hides its identifier: %q", app)
			}
		} else if app != "" {
			sawKnown = true
		}
	}
	if !sawKnown {
		t.Error("no known AppID resolved to an application name")
	}
	if !sawUnknown {
		t.Error("the unknown AppID was discarded rather than reported")
	}
}

// 4. Provenance resolves back to the exact stream inside the artifact.
func TestJumpList_ProvenanceReachesTheEmbeddedStream(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Jump List provenance")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		autoDir + "5f7b5f1e01b83767.automaticDestinations-ms": jlgen.BuildAutomatic(jlgen.Automatic{
			Items: []jlgen.Item{{Link: jlLink("report", `C:\Users\jdoe\Documents\report.docx`),
				EntryNumber: 1, AccessCount: 7, LastAccess: jlLastUsed}}}),
	})
	importAllFrom(t, mux, c.ID, disc)

	events := typedTimeline(t, mux, c.ID)
	if len(events) == 0 {
		t.Fatal("no events")
	}
	seen := map[string]bool{}
	for _, e := range events {
		var prov EventProvenance
		rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/"+e.ID, nil, &prov)
		if rec.Code != 200 {
			t.Fatalf("provenance for %s returned %d", e.SourceReference, rec.Code)
		}
		if prov.RawEvidence.Raw == "" {
			t.Errorf("%s resolved no raw evidence", e.SourceReference)
		}
		// The record must name the stream and where it sat.
		for _, want := range []string{`"stream":"1"`, `"stream_directory_index"`, `"embedded_link"`, `"destlist"`} {
			if !strings.Contains(prov.RawEvidence.Raw, want) {
				t.Errorf("the record omits %s", want)
			}
		}
		if prov.SourceFile.OriginalFilename == "" || prov.SourceFile.SHA256 == "" {
			t.Error("provenance does not reach the Jump List file and its hash")
		}
		if seen[e.SourceReference] {
			t.Errorf("duplicate source reference %q", e.SourceReference)
		}
		seen[e.SourceReference] = true
	}
}

// 5. A Jump List raises no findings on its own.
func TestJumpList_RaisesNoFindings(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Jump List findings")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		// Deliberately alarming targets.
		autoDir + "5f7b5f1e01b83767.automaticDestinations-ms": jlgen.BuildAutomatic(jlgen.Automatic{
			Items: []jlgen.Item{
				{Link: jlLink("m", `C:\Users\jdoe\Downloads\mimikatz.exe`), EntryNumber: 1,
					AccessCount: 9, LastAccess: jlLastUsed},
				{Link: jlLink("p", `C:\Windows\Temp\payload.ps1`), EntryNumber: 2,
					AccessCount: 3, LastAccess: jlLastUsed},
			}}),
	})
	importAllFrom(t, mux, c.ID, disc)
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil)

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings", nil, &findings)
	for _, f := range findings {
		t.Errorf("a Jump List entry alone produced a finding: %q (%s)", f.Title, f.Severity)
	}
}

// 6. A renamed Custom Destinations list is still found by content.
func TestJumpList_RenamedCustomListIsDetected(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Renamed Jump List")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Users/jdoe/Desktop/renamed-evidence.bin": jlgen.BuildCustom([]lnkgen.Link{
			jlLink("task", `C:\Program Files\App\app.exe`),
		}),
	})
	sf, ok := sourceFileByPath(disc.SourceFiles, "Users/jdoe/Desktop/renamed-evidence.bin")
	if !ok {
		t.Fatal("not discovered")
	}
	if !sf.Supported || sf.ArtifactType != model.ArtifactJumpListCustom {
		t.Errorf("a renamed custom list was classified as %q (supported=%v)", sf.ArtifactType, sf.Supported)
	}
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Errorf("parse failures: %+v", imp.ParseFailures)
	}
	if imp.EventCount == 0 {
		t.Error("the renamed list produced no events")
	}
}

// 7. A malformed embedded shortcut does not lose the valid entries.
func TestJumpList_MalformedEntrySurvivesImport(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Malformed Jump List entry")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		autoDir + "5f7b5f1e01b83767.automaticDestinations-ms": jlgen.BuildAutomatic(jlgen.Automatic{
			Items: []jlgen.Item{
				{Link: jlLink("good", `C:\a\one.docx`), EntryNumber: 1, AccessCount: 1, LastAccess: jlLastUsed},
				{RawLink: []byte("not a shortcut"), EntryNumber: 2, AccessCount: 5,
					LastAccess: jlLastUsed.Add(-time.Hour), DestPath: `C:\a\two.docx`},
				{Link: jlLink("third", `C:\a\three.docx`), EntryNumber: 3, AccessCount: 1, LastAccess: jlLastUsed},
			}}),
	})
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("a damaged entry failed the whole file: %+v", imp.ParseFailures)
	}

	paths := map[string]bool{}
	for _, e := range typedTimeline(t, mux, c.ID) {
		paths[e.Extra["target_path"]] = true
	}
	for _, want := range []string{`C:\a\one.docx`, `C:\a\three.docx`, `C:\a\two.docx`} {
		if !paths[want] {
			t.Errorf("target %q was lost", want)
		}
	}
}
