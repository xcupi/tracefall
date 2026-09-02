package jumplist_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/jumplist/jlgen"
	"tracefall/internal/model"
	parser "tracefall/internal/parsers/jumplist"
	"tracefall/internal/shelllink/lnkgen"
)

var (
	created  = time.Date(2026, 2, 11, 8, 30, 0, 0, time.UTC)
	written  = time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)
	accessed = time.Date(2026, 3, 4, 17, 45, 12, 0, time.UTC)
	lastUsed = time.Date(2026, 3, 5, 9, 15, 30, 0, time.UTC)
)

func link(name, target string) lnkgen.Link {
	return lnkgen.Link{
		Unicode: true, FileAttributes: 0x20,
		Creation: created, Write: written, Access: accessed,
		FileSize: 184320, ShowCommand: 1,
		Name: name, LocalBasePath: target, WorkingDir: `C:\Users\jdoe\Documents`,
		Arguments: "/embedding", DriveType: 3, VolumeSerial: 0xC0FFEE01, VolumeLabel: "OSDisk",
		TrackerMachineID: "WKSTN-042",
	}
}

func write(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func autoFixture() []byte {
	return jlgen.BuildAutomatic(jlgen.Automatic{Items: []jlgen.Item{
		{Link: link("report", `C:\Users\jdoe\Documents\report.docx`), EntryNumber: 1,
			AccessCount: 7, LastAccess: lastUsed, Hostname: "wkstn-042"},
		{Link: link("budget", `\\fileserver\finance\budget.xlsx`), EntryNumber: 2,
			AccessCount: 2, LastAccess: lastUsed.Add(-time.Hour), Pinned: true},
	}})
}

// An automatic list yields one access event plus the target-metadata
// events, each labelled with what its timestamp means.
func TestParser_AutomaticEmitsBothTimestampKinds(t *testing.T) {
	res, err := parser.NewAutomatic().Parse(
		write(t, "5f7b5f1e01b83767.automaticDestinations-ms", autoFixture()))
	if err != nil {
		t.Fatal(err)
	}
	// 2 entries x (1 access + 3 target timestamps) = 8.
	if len(res.Events) != 8 {
		t.Fatalf("got %d events, want 8", len(res.Events))
	}
	if len(res.Raw) != len(res.Events) {
		t.Errorf("%d events but %d raw records", len(res.Events), len(res.Raw))
	}

	var access, targetMeta int
	for _, e := range res.Events {
		if e.ArtifactType != model.ArtifactJumpListAutomatic {
			t.Errorf("artifact type = %q", e.ArtifactType)
		}
		if e.Timestamp.Location() != time.UTC {
			t.Error("a timestamp is not stored in UTC")
		}
		if e.Extra["timestamp_meaning"] == "" {
			t.Errorf("%s does not say what its timestamp means", e.EventType)
		}
		if e.Extra["timestamp_source"] == "" {
			t.Errorf("%s does not say where its timestamp came from", e.EventType)
		}
		switch e.EventType {
		case model.EventJumpListEntryAccess:
			access++
			if !strings.Contains(e.Extra["timestamp_meaning"], "last-recorded access") {
				t.Errorf("access event mislabelled: %q", e.Extra["timestamp_meaning"])
			}
			if !strings.Contains(e.Extra["timestamp_source"], "DestList") {
				t.Errorf("access event is not attributed to the DestList: %q", e.Extra["timestamp_source"])
			}
		case model.EventJumpListTargetMetadata:
			targetMeta++
			if !strings.Contains(e.Extra["timestamp_meaning"], "target file") {
				t.Errorf("target event mislabelled: %q", e.Extra["timestamp_meaning"])
			}
			if !strings.Contains(e.Extra["timestamp_source"], "embedded shortcut") {
				t.Errorf("target event is not attributed to the shortcut: %q", e.Extra["timestamp_source"])
			}
		default:
			t.Errorf("unexpected event type %q", e.EventType)
		}
	}
	if access != 2 || targetMeta != 6 {
		t.Errorf("got %d access and %d target events, want 2 and 6", access, targetMeta)
	}
}

// The six provenance questions each event must answer.
func TestParser_EventsCarryFullProvenance(t *testing.T) {
	res, err := parser.NewAutomatic().Parse(
		write(t, "5f7b5f1e01b83767.automaticDestinations-ms", autoFixture()))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Events {
		for _, field := range []string{
			"jumplist_file",                         // 1. which artifact
			"app_id",                                // 2. which application
			"jumplist_stream",                       // 3. which embedded shortcut
			"target_path",                           // 4. what target
			"timestamp_meaning", "timestamp_source", // 5. what the time means
		} {
			if e.Extra[field] == "" {
				t.Errorf("%s: missing provenance field %q", e.EventType, field)
			}
		}
		// 6. where inside the artifact the shortcut was found.
		if e.Extra["jumplist_stream_directory_index"] == "" {
			t.Errorf("%s: no compound-file stream index recorded", e.EventType)
		}
		if e.SourceReference == "" || !strings.HasPrefix(e.SourceReference, "jumplist:") {
			t.Errorf("source reference = %q", e.SourceReference)
		}
	}
	// References are unique per event, so each pairs with its own record.
	seen := map[string]bool{}
	for _, e := range res.Events {
		if seen[e.SourceReference] {
			t.Errorf("duplicate source reference %q", e.SourceReference)
		}
		seen[e.SourceReference] = true
	}
}

// Nothing in the output may read as execution.
func TestParser_NeverClaimsExecution(t *testing.T) {
	res, err := parser.NewAutomatic().Parse(
		write(t, "5f7b5f1e01b83767.automaticDestinations-ms", autoFixture()))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Events {
		if e.ProcessName != "" || e.ProcessPath != "" || e.CommandLine != "" {
			t.Errorf("a Jump List event populated a process field: name=%q path=%q cmdline=%q",
				e.ProcessName, e.ProcessPath, e.CommandLine)
		}
		if e.User != "" {
			t.Errorf("a Jump List event invented a user: %q", e.User)
		}
		for _, banned := range []string{"execut", "process_create", "_run"} {
			if strings.Contains(e.EventType, banned) {
				t.Errorf("event type %q reads as execution", e.EventType)
			}
		}
		if !strings.Contains(e.Extra["evidence_meaning"], "NOT evidence that the target was executed") {
			t.Errorf("the record does not disclaim execution: %q", e.Extra["evidence_meaning"])
		}
		// Arguments are kept as shortcut metadata, never as a command
		// line that ran.
		if e.Extra["shortcut_arguments"] != "/embedding" {
			t.Errorf("the shortcut's arguments were not preserved: %q", e.Extra["shortcut_arguments"])
		}
		if e.Confidence >= 1.0 {
			t.Errorf("confidence = %v", e.Confidence)
		}
	}
}

// Jump List metadata and target metadata both reach the event.
func TestParser_ExtractsBothMetadataLayers(t *testing.T) {
	res, err := parser.NewAutomatic().Parse(
		write(t, "5f7b5f1e01b83767.automaticDestinations-ms", autoFixture()))
	if err != nil {
		t.Fatal(err)
	}
	var report model.Event
	for _, e := range res.Events {
		if e.Extra["target_path"] == `C:\Users\jdoe\Documents\report.docx` &&
			e.EventType == model.EventJumpListEntryAccess {
			report = e
		}
	}
	if report.ID == "" && report.Extra == nil {
		t.Fatal("the report entry was not found")
	}
	for field, want := range map[string]string{
		// From the Jump List itself.
		"access_count":      "7",
		"mru_position":      "0",
		"pinned":            "false",
		"destlist_hostname": "wkstn-042",
		"destlist_version":  "3",
		"jumplist_kind":     "automatic_destinations",
		"app_id":            "5f7b5f1e01b83767",
		"app_id_resolved":   "true",
		// From the embedded shortcut.
		"target_file_size":   "184320",
		"drive_type":         "DRIVE_FIXED",
		"volume_serial":      "C0FFEE01",
		"working_directory":  `C:\Users\jdoe\Documents`,
		"tracker_machine_id": "WKSTN-042",
		"target_name":        "report.docx",
		"target_path_source": "embedded shortcut",
	} {
		if report.Extra[field] != want {
			t.Errorf("extra[%q] = %q, want %q", field, report.Extra[field], want)
		}
	}
	if report.Extra["application"] == "" || strings.Contains(report.Extra["application"], "Unknown") {
		t.Errorf("a known AppID did not resolve: %q", report.Extra["application"])
	}
}

// Custom Destinations: a separate artifact type, no DestList evidence.
func TestParser_CustomIsItsOwnArtifact(t *testing.T) {
	res, err := parser.NewCustom().Parse(write(t, "abc123def4567890.customDestinations-ms",
		jlgen.BuildCustom([]lnkgen.Link{
			link("task", `C:\Program Files\App\app.exe`),
			link("recent", `D:\work\notes.txt`),
		})))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 6 { // 2 entries x 3 target timestamps
		t.Fatalf("got %d events, want 6", len(res.Events))
	}
	for _, e := range res.Events {
		if e.ArtifactType != model.ArtifactJumpListCustom {
			t.Errorf("artifact type = %q", e.ArtifactType)
		}
		if e.EventType != model.EventJumpListTargetMetadata {
			t.Errorf("a custom list produced %q; it has no DestList to date an access", e.EventType)
		}
		// No DestList means no access count, no MRU order, no pinning.
		for _, absent := range []string{"access_count", "mru_position", "pinned", "jumplist_last_access"} {
			if e.Extra[absent] != "" {
				t.Errorf("a custom list reported %q = %q; it records none", absent, e.Extra[absent])
			}
		}
		// Provenance is the byte offset, since there are no streams.
		if e.Extra["embedded_link_offset"] == "" {
			t.Error("no offset recorded for a custom-list entry")
		}
	}
}

// An unknown AppID is preserved, never invented, and the artifact is
// kept.
func TestParser_UnknownAppIDIsPreserved(t *testing.T) {
	res, err := parser.NewAutomatic().Parse(
		write(t, "ffffffffffffffff.automaticDestinations-ms", autoFixture()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) == 0 {
		t.Fatal("an unknown AppID lost the artifact")
	}
	e := res.Events[0]
	if e.Extra["app_id"] != "ffffffffffffffff" {
		t.Errorf("the raw AppID was not preserved: %q", e.Extra["app_id"])
	}
	if e.Extra["app_id_resolved"] != "false" {
		t.Errorf("an unknown AppID reported itself resolved")
	}
	if !strings.Contains(e.Extra["application"], "Unknown application") {
		t.Errorf("application = %q, want an explicit unknown", e.Extra["application"])
	}
	if !strings.Contains(e.Extra["application"], "ffffffffffffffff") {
		t.Errorf("the unknown label hides the identifier an analyst would search for: %q", e.Extra["application"])
	}
}

// A renamed file has no AppID, which is distinct from an unknown one.
func TestParser_RenamedFileHasNoAppID(t *testing.T) {
	res, err := parser.NewAutomatic().Parse(write(t, "5f7b5f1e01b83767.automaticDestinations-ms", autoFixture()))
	if err != nil {
		t.Fatal(err)
	}
	_ = res
	// The parser reads the AppID from the name; a name without one
	// yields the no-AppID label rather than a fabricated identifier.
	res2, err := parser.NewCustom().Parse(write(t, "renamed.customDestinations-ms",
		jlgen.BuildCustom([]lnkgen.Link{link("a", `C:\a\b.txt`)})))
	if err != nil {
		t.Fatal(err)
	}
	e := res2.Events[0]
	if !strings.Contains(e.Extra["application"], "no AppID") {
		t.Errorf("a name with no AppID was not distinguished: %q", e.Extra["application"])
	}
	if !strings.Contains(e.Extra["app_id"], "no AppID") {
		t.Errorf("app_id = %q; the absence should be stated", e.Extra["app_id"])
	}
}

// A malformed embedded shortcut costs one entry, not the file.
func TestParser_MalformedEntryDoesNotLoseTheRest(t *testing.T) {
	items := []jlgen.Item{
		{Link: link("good", `C:\a\one.docx`), EntryNumber: 1, AccessCount: 1, LastAccess: lastUsed},
		{RawLink: []byte("not a shortcut"), EntryNumber: 2, AccessCount: 5,
			LastAccess: lastUsed.Add(-time.Hour), DestPath: `C:\a\two.docx`},
		{Link: link("third", `C:\a\three.docx`), EntryNumber: 3, AccessCount: 1, LastAccess: lastUsed},
	}
	res, err := parser.NewAutomatic().Parse(
		write(t, "5f7b5f1e01b83767.automaticDestinations-ms",
			jlgen.BuildAutomatic(jlgen.Automatic{Items: items})))
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	var damagedAccess bool
	for _, e := range res.Events {
		paths[e.Extra["target_path"]] = true
		if e.Extra["embedded_link_error"] != "" && e.EventType == model.EventJumpListEntryAccess {
			damagedAccess = true
			// The DestList still dated and named it.
			if e.Extra["target_path"] != `C:\a\two.docx` {
				t.Errorf("the damaged entry lost its DestList path: %q", e.Extra["target_path"])
			}
			if e.Extra["target_path_source"] != "DestList record" {
				t.Errorf("path source = %q", e.Extra["target_path_source"])
			}
		}
	}
	for _, want := range []string{`C:\a\one.docx`, `C:\a\three.docx`} {
		if !paths[want] {
			t.Errorf("the valid entry %q was lost", want)
		}
	}
	if !damagedAccess {
		t.Error("the damaged entry produced no event; its DestList row was still readable")
	}
}

// A file named as one container but holding the other is refused, not
// parsed as what it was named.
func TestParser_ContainerMismatchIsRefused(t *testing.T) {
	custom := jlgen.BuildCustom([]lnkgen.Link{link("a", `C:\a\b.txt`)})
	_, err := parser.NewAutomatic().Parse(write(t, "x.automaticDestinations-ms", custom))
	if err == nil {
		t.Fatal("a Custom Destinations file parsed as an Automatic one")
	}
	if !strings.Contains(err.Error(), "container is") {
		t.Errorf("the error does not explain the mismatch: %v", err)
	}

	_, err = parser.NewCustom().Parse(write(t, "y.customDestinations-ms", autoFixture()))
	if err == nil {
		t.Fatal("an Automatic Destinations file parsed as a Custom one")
	}
}

// An impostor with the right extension is refused.
func TestParser_ImpostorIsRefused(t *testing.T) {
	for _, p := range []struct {
		name string
		fn   func(string) (interface{ len() }, error)
	}{} {
		_ = p
	}
	_, err := parser.NewAutomatic().Parse(
		write(t, "5f7b5f1e01b83767.automaticDestinations-ms", []byte(strings.Repeat("impostor ", 100))))
	if err == nil {
		t.Error("a text file with the automatic extension parsed")
	}
	_, err = parser.NewCustom().Parse(
		write(t, "abc.customDestinations-ms", []byte(strings.Repeat("impostor ", 100))))
	if err == nil {
		t.Error("a text file with the custom extension parsed")
	}
}

// Detection: extensions for both, plus content for the custom container.
func TestParser_Detection(t *testing.T) {
	a, c := parser.NewAutomatic(), parser.NewCustom()

	if !a.Detect("Recent/AutomaticDestinations/5f7b.automaticDestinations-ms") {
		t.Error("the automatic extension was not detected")
	}
	if a.Detect("Recent/CustomDestinations/5f7b.customDestinations-ms") {
		t.Error("the automatic parser claimed a custom list")
	}
	if !c.Detect("Recent/CustomDestinations/5f7b.customDestinations-ms") {
		t.Error("the custom extension was not detected")
	}
	if c.Detect("Recent/AutomaticDestinations/5f7b.automaticDestinations-ms") {
		t.Error("the custom parser claimed an automatic list")
	}

	// A RENAMED custom list is still found by content.
	if !c.DetectContent(jlgen.BuildCustom([]lnkgen.Link{link("a", `C:\a\b.txt`)})) {
		t.Error("a renamed Custom Destinations list was not content-detected")
	}
	// A standalone shortcut is NOT a custom list: its link header sits
	// at offset zero.
	if c.DetectContent(lnkgen.Build(link("a", `C:\a\b.txt`))) {
		t.Error("a standalone .lnk was claimed as a Custom Destinations list")
	}
	for name, data := range map[string][]byte{
		"text":  []byte(strings.Repeat("nothing to see ", 60)),
		"zeros": make([]byte, 2048),
		"empty": {},
	} {
		if c.DetectContent(data) {
			t.Errorf("%q was content-detected as a custom list", name)
		}
	}
}

// The raw record separates the two metadata sources.
func TestParser_RawRecordSeparatesSources(t *testing.T) {
	res, err := parser.NewAutomatic().Parse(
		write(t, "5f7b5f1e01b83767.automaticDestinations-ms", autoFixture()))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(res.Raw[0].Raw), &doc); err != nil {
		t.Fatalf("the record is not valid JSON: %v", err)
	}
	for _, key := range []string{"application", "location", "destlist", "embedded_link", "target"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("the record has no %q section", key)
		}
	}
	loc := doc["location"].(map[string]any)
	for _, key := range []string{"stream", "stream_directory_index", "offset", "bytes", "entry_index"} {
		if _, ok := loc[key]; !ok {
			t.Errorf("the location section omits %q", key)
		}
	}
	link := doc["embedded_link"].(map[string]any)
	if link["parsed"] != true {
		t.Error("the embedded link section does not report a successful parse")
	}
	if link["shortcut_arguments"] != "/embedding" {
		t.Errorf("arguments = %v; they belong to the shortcut, not a command line", link["shortcut_arguments"])
	}
}

// Determinism.
func TestParser_IsDeterministic(t *testing.T) {
	path := write(t, "5f7b5f1e01b83767.automaticDestinations-ms", autoFixture())
	p := parser.NewAutomatic()
	first, err := p.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := p.Parse(path)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if len(again.Events) != len(first.Events) {
			t.Fatalf("run %d: %d events vs %d", i, len(again.Events), len(first.Events))
		}
		for j := range first.Events {
			if again.Events[j].SourceReference != first.Events[j].SourceReference ||
				!again.Events[j].Timestamp.Equal(first.Events[j].Timestamp) {
				t.Fatalf("run %d event %d differed", i, j)
			}
			if again.Raw[j].Raw != first.Raw[j].Raw {
				t.Fatalf("run %d raw %d differed", i, j)
			}
		}
	}
}

// An entry with no usable timestamp is kept as a record, never given a
// time it does not have.
func TestParser_EntryWithoutTimestampsMakesNoEvent(t *testing.T) {
	res, err := parser.NewAutomatic().Parse(
		write(t, "5f7b5f1e01b83767.automaticDestinations-ms",
			jlgen.BuildAutomatic(jlgen.Automatic{Items: []jlgen.Item{{
				Link:        lnkgen.Link{Unicode: true, Name: "no times"},
				EntryNumber: 1, DestPath: `C:\a\b.txt`,
			}}})))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		t.Errorf("got %d events from an entry with no timestamps", len(res.Events))
	}
	if len(res.Raw) != 1 {
		t.Fatalf("got %d records, want the entry kept as one", len(res.Raw))
	}
	if !strings.HasSuffix(res.Raw[0].SourceReference, ":metadata") {
		t.Errorf("the timeless entry is not marked as metadata-only: %q", res.Raw[0].SourceReference)
	}
}
