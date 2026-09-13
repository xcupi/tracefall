package registry_test

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"tracefall/internal/amcache"
	"tracefall/internal/model"
	"tracefall/internal/parsers/registry"
	"tracefall/internal/regf/regfgen"
	"tracefall/internal/shellbag/sbgen"
)

// Phase 16: Amcache and the per-user MRU structures.
//
// Fixtures are synthetic hives built by regfgen; nothing here comes from
// real evidence.

var (
	amWrite  = time.Date(2021, 4, 29, 20, 0, 0, 0, time.UTC)
	mruWrite = time.Date(2021, 4, 29, 21, 15, 0, 0, time.UTC)
)

// ---------------- Amcache ----------------

func amcacheHive() []byte {
	inventoryFile := regfgen.NewKey("InventoryApplicationFile",
		regfgen.NewKey("updater.exe|0a1b2c3d").WithLastWrite(amWrite).WithValues(
			regfgen.StringValue("LowerCaseLongPath", `c:\users\jdoe\appdata\local\temp\updater.exe`),
			regfgen.StringValue("Name", "updater.exe"),
			// Stored the way Windows writes it: "0000" then the digest.
			regfgen.StringValue("FileId", "0000da39a3ee5e6b4b0d3255bfef95601890afd80709"),
			regfgen.StringValue("Publisher", "Contoso Ltd"),
			regfgen.StringValue("Version", "1.2.3"),
			regfgen.StringValue("ProductName", "Contoso Updater"),
			regfgen.StringValue("ProgramId", "0006abc123"),
			regfgen.StringValue("LinkDate", "03/14/2021 09:00:00"),
			regfgen.DWordValue("Size", 262144),
		),
		// An entry whose FileId is not a digest at all.
		regfgen.NewKey("odd.exe|ffff").WithLastWrite(amWrite).WithValues(
			regfgen.StringValue("LowerCaseLongPath", `c:\tools\odd.exe`),
			regfgen.StringValue("FileId", "not-a-hash"),
		),
	)
	inventoryApp := regfgen.NewKey("InventoryApplication",
		regfgen.NewKey("0006abc123").WithLastWrite(amWrite).WithValues(
			regfgen.StringValue("Name", "Contoso Updater"),
			regfgen.StringValue("Publisher", "Contoso Ltd"),
			regfgen.StringValue("Version", "1.2.3"),
			regfgen.StringValue("RootDirPath", `c:\program files\contoso`),
			regfgen.StringValue("InstallDate", "01/02/2021 10:30:00"),
		),
	)
	// The Windows 8 layout, with numbered value names.
	fileTree := regfgen.NewKey("File",
		regfgen.NewKey("{11111111-2222-3333-4444-555555555555}",
			regfgen.NewKey("a1b2c3").WithLastWrite(amWrite).WithValues(
				regfgen.StringValue("15", `C:\Windows\System32\legacy.exe`),
				regfgen.StringValue("0", "Legacy Tool"),
				regfgen.StringValue("1", "Legacy Corp"),
				regfgen.StringValue("101", "0000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"),
				// An undocumented numbered field: preserved, not labelled.
				regfgen.StringValue("42", "unknown-meaning-value"),
			)))
	return regfgen.Build("Amcache.hve", regfgen.NewKey("ROOT",
		regfgen.NewKey("Root", inventoryFile, inventoryApp, fileTree),
	).WithLastWrite(amWrite))
}

func parseNamed(t *testing.T, relPath string, data []byte) []model.Event {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := registry.New().Parse(path)
	if err != nil {
		t.Fatalf("parsing %s: %v", relPath, err)
	}
	if len(res.Events) != len(res.Raw) {
		t.Fatalf("%d events but %d raw records", len(res.Events), len(res.Raw))
	}
	return res.Events
}

func TestAmcache_InventoryEntriesDecodeWithHonestSemantics(t *testing.T) {
	events := parseNamed(t, "Windows/appcompat/Programs/Amcache.hve", amcacheHive())
	am := eventsOfType(events, model.ArtifactAmcache)
	if len(am) != 4 {
		t.Fatalf("got %d Amcache events, want 4", len(am))
	}

	var updater *model.Event
	for i := range am {
		if strings.Contains(am[i].Extra["application_path"], "updater.exe") {
			updater = &am[i]
		}
	}
	if updater == nil {
		t.Fatal("the updater.exe entry is missing")
	}

	if updater.EventType != model.EventAmcacheApplication {
		t.Errorf("event type = %q, want %q", updater.EventType, model.EventAmcacheApplication)
	}
	if got := updater.Extra["sha1"]; got != "da39a3ee5e6b4b0d3255bfef95601890afd80709" {
		t.Errorf("sha1 = %q; the leading 0000 padding must be stripped", got)
	}
	if got := updater.Extra["publisher"]; got != "Contoso Ltd" {
		t.Errorf("publisher = %q", got)
	}
	if got := updater.Extra["file_size_bytes"]; got != "262144" {
		t.Errorf("file size = %q", got)
	}
	if got := updater.Extra["pe_link_date"]; got == "" {
		t.Error("LinkDate was not decoded")
	}
	if !strings.Contains(updater.Extra["pe_link_date_note"], "not any activity on this machine") {
		t.Errorf("the PE link date is not qualified: %q", updater.Extra["pe_link_date_note"])
	}
	if !updater.Timestamp.Equal(amWrite) {
		t.Errorf("timestamp = %s, want the key write time %s", updater.Timestamp, amWrite)
	}

	// The semantic guarantee this artifact turns on.
	if !strings.Contains(updater.Extra["evidence_meaning"], "not a process-creation record") {
		t.Errorf("evidence_meaning does not disclaim process creation: %q", updater.Extra["evidence_meaning"])
	}
	if !strings.Contains(updater.Extra["timestamp_meaning"], "NOT an execution time") {
		t.Errorf("timestamp_meaning does not disclaim execution: %q", updater.Extra["timestamp_meaning"])
	}
	if updater.ProcessName != "" || updater.CommandLine != "" {
		t.Errorf("Amcache set ProcessName=%q CommandLine=%q; it records neither",
			updater.ProcessName, updater.CommandLine)
	}
	if updater.FilePath == "" {
		t.Error("the catalogued path must be in FilePath")
	}
}

// A FileId that is not a digest must be preserved raw and flagged, never
// reported as a hash.
func TestAmcache_UnrecognizedFileIdIsNotReportedAsAHash(t *testing.T) {
	events := parseNamed(t, "Windows/appcompat/Programs/Amcache.hve", amcacheHive())
	for _, e := range eventsOfType(events, model.ArtifactAmcache) {
		if !strings.Contains(e.Extra["application_path"], "odd.exe") {
			continue
		}
		if e.Extra["sha1"] != "" {
			t.Errorf("a non-digest FileId was reported as sha1 = %q", e.Extra["sha1"])
		}
		if e.Extra["amcache_file_id_raw"] == "" {
			t.Error("the raw FileId was discarded rather than preserved")
		}
		if !strings.Contains(e.Extra["warnings"], "not a recognizable SHA-1") {
			t.Errorf("no warning explains the unrecognized FileId: %q", e.Extra["warnings"])
		}
		return
	}
	t.Fatal("the odd.exe entry produced no event")
}

// The Windows 8 numbered layout must decode its settled fields and
// preserve the rest without labelling them.
func TestAmcache_Windows8NumberedFieldsAreDecodedOrPreserved(t *testing.T) {
	events := parseNamed(t, "Windows/appcompat/Programs/Amcache.hve", amcacheHive())
	for _, e := range eventsOfType(events, model.ArtifactAmcache) {
		if e.Extra["amcache_generation"] != string(amcache.GenFile) {
			continue
		}
		if got := e.Extra["application_path"]; got != `C:\Windows\System32\legacy.exe` {
			t.Errorf("path = %q", got)
		}
		if got := e.Extra["product_name"]; got != "Legacy Tool" {
			t.Errorf("product name = %q", got)
		}
		if got := e.Extra["publisher"]; got != "Legacy Corp" {
			t.Errorf("publisher = %q", got)
		}
		if e.Extra["sha1"] == "" {
			t.Error("the numbered SHA-1 field was not decoded")
		}
		// The undocumented field survives under its own number.
		if e.Extra["amcache_value_42"] != "unknown-meaning-value" {
			t.Errorf("an undocumented numbered field was discarded: %v", e.Extra)
		}
		if e.Extra["amcache_volume_guid"] == "" {
			t.Error("the volume GUID was not preserved")
		}
		return
	}
	t.Fatal("no Windows 8 layout entry was produced")
}

// An installed-application entry is a different claim from a file entry.
func TestAmcache_InstalledApplicationIsDistinctFromAFileEntry(t *testing.T) {
	events := parseNamed(t, "Windows/appcompat/Programs/Amcache.hve", amcacheHive())
	found := false
	for _, e := range eventsOfType(events, model.ArtifactAmcache) {
		if e.Extra["amcache_generation"] != string(amcache.GenApplication) {
			continue
		}
		found = true
		if !strings.Contains(e.Extra["evidence_meaning"], "installed application") {
			t.Errorf("an application entry reuses the file-entry wording: %q", e.Extra["evidence_meaning"])
		}
		if e.Extra["install_date"] == "" {
			t.Error("InstallDate was not decoded")
		}
	}
	if !found {
		t.Fatal("no InventoryApplication entry was produced")
	}
}

// A hive with no Amcache tree is a valid artifact with zero records.
func TestAmcache_OrdinaryHiveProducesNoAmcacheEvents(t *testing.T) {
	events := parseUserHive(t, "NTUSER.DAT", ntuserWithUserActivity(t))
	if n := len(eventsOfType(events, model.ArtifactAmcache)); n != 0 {
		t.Errorf("an NTUSER.DAT produced %d Amcache events", n)
	}
}

// ---------------- MRU artifacts ----------------

// mruHive builds an NTUSER.DAT holding all five MRU structures.
func mruHive() []byte {
	recentDocs := regfgen.NewKey("RecentDocs",
		regfgen.NewKey(".docx").WithLastWrite(mruWrite).WithValues(
			regfgen.BinaryValue("0", recentDocValue("quarterly-figures.docx")),
			regfgen.BinaryValue("MRUListEx", sbgen.MRUListEx(0)),
		),
	).WithLastWrite(mruWrite).WithValues(
		regfgen.BinaryValue("0", recentDocValue("plan.pdf")),
		regfgen.BinaryValue("1", recentDocValue("notes-日本語.txt")),
		regfgen.BinaryValue("MRUListEx", sbgen.MRUListEx(1, 0)),
	)

	runMRU := regfgen.NewKey("RunMRU").WithLastWrite(mruWrite).WithValues(
		regfgen.StringValue("a", `powershell -nop -w hidden`+"\\1"),
		regfgen.StringValue("b", `cmd.exe`+"\\1"),
		regfgen.StringValue("MRUList", "ba"),
	)

	typedPaths := regfgen.NewKey("TypedPaths").WithLastWrite(mruWrite).WithValues(
		regfgen.StringValue("url1", `\\fileserver\share`),
		regfgen.StringValue("url2", `C:\Users\jdoe\Documents`),
	)

	openSave := regfgen.NewKey("OpenSavePidlMRU",
		regfgen.NewKey("docx").WithLastWrite(mruWrite).WithValues(
			regfgen.BinaryValue("0", sbgen.List(
				sbgen.Root("{20D04FE0-3AEA-1069-A2D8-08002B30309D}"),
				sbgen.Volume(`C:\`),
				sbgen.File(sbgen.FileEntry{
					ShortName: "REPORT~1.DOC", LongName: "report.docx",
					Attributes: 0x20, Modified: mruWrite, ExtVersion: 9,
				}),
			)),
			regfgen.BinaryValue("MRUListEx", sbgen.MRUListEx(0)),
		),
	)
	comDlg := regfgen.NewKey("ComDlg32", openSave)

	muiCache := regfgen.NewKey("MUICache").WithLastWrite(mruWrite).WithValues(
		regfgen.StringValue(`C:\Windows\System32\notepad.exe.FriendlyAppName`, "Notepad"),
		regfgen.StringValue(`C:\Tools\tool.exe.ApplicationCompany`, "Tools Inc"),
		// A resource reference, which names no executable and is skipped.
		regfgen.StringValue(`@%SystemRoot%\system32\shell32.dll,-1`, "Ignored"),
	)
	shellNoRoam := regfgen.NewKey("ShellNoRoam", muiCache)

	explorer := regfgen.NewKey("Explorer", recentDocs, runMRU, typedPaths, comDlg)

	return regfgen.Build("NTUSER.DAT", regfgen.NewKey("ROOT",
		regfgen.NewKey("Software", regfgen.NewKey("Microsoft",
			regfgen.NewKey("Windows",
				regfgen.NewKey("CurrentVersion", explorer),
				shellNoRoam,
			))),
	).WithLastWrite(mruWrite))
}

// recentDocValue builds a RecentDocs value: a UTF-16 name, NUL, then a
// shell item link -- the layout Windows writes.
func recentDocValue(name string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(name)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	b = append(b, 0, 0)
	b = append(b, sbgen.List(sbgen.File(sbgen.FileEntry{
		ShortName: "SHORT", LongName: name, Attributes: 0x20, ExtVersion: 9,
	}))...)
	return b
}

func TestRecentDocs_EntriesDecodeAndDoNotClaimExecution(t *testing.T) {
	events := parseUserHive(t, "NTUSER.DAT", mruHive())
	docs := eventsOfType(events, model.ArtifactRecentDocs)
	if len(docs) != 3 {
		t.Fatalf("got %d RecentDocs events, want 3 (two general plus one extension-scoped)", len(docs))
	}

	names := map[string]model.Event{}
	scopes := map[string]bool{}
	for _, e := range docs {
		if e.EventType != model.EventRecentDocument {
			t.Errorf("event type = %q", e.EventType)
		}
		names[e.FilePath] = e
		scopes[e.Extra["recentdocs_scope"]] = true
		if e.ProcessName != "" || e.CommandLine != "" {
			t.Errorf("RecentDocs set ProcessName=%q CommandLine=%q", e.ProcessName, e.CommandLine)
		}
		if !strings.Contains(e.Extra["evidence_meaning"], "not a process-creation record") {
			t.Errorf("evidence_meaning does not disclaim execution: %q", e.Extra["evidence_meaning"])
		}
		// The awkward truth about MRU timestamps must be stated.
		if !strings.Contains(e.Extra["timestamp_meaning"], "MOST RECENT") {
			t.Errorf("timestamp_meaning does not explain that the key dates only its newest entry: %q",
				e.Extra["timestamp_meaning"])
		}
	}
	if _, ok := names["plan.pdf"]; !ok {
		t.Errorf("plan.pdf missing; got %v", keys(names))
	}
	if _, ok := names["notes-日本語.txt"]; !ok {
		t.Errorf("the Unicode document name did not survive; got %v", keys(names))
	}
	if len(scopes) != 2 {
		t.Errorf("extension-scoped and general entries are not distinguished: %v", scopes)
	}
	// MRU ordering must be recorded.
	if p := names["notes-日本語.txt"].Extra["mru_position"]; p != "0" {
		t.Errorf("the most-recent entry has mru_position %q, want 0", p)
	}
}

func TestRunMRU_RecordsTypedCommandsWithoutClaimingExecution(t *testing.T) {
	events := parseUserHive(t, "NTUSER.DAT", mruHive())
	cmds := eventsOfType(events, model.ArtifactRunMRU)
	if len(cmds) != 2 {
		t.Fatalf("got %d RunMRU events, want 2", len(cmds))
	}
	for _, e := range cmds {
		if e.EventType != model.EventRunMRUCommand {
			t.Errorf("event type = %q", e.EventType)
		}
		if e.CommandLine == "" {
			t.Error("the typed command is not in CommandLine")
		}
		if strings.HasSuffix(e.CommandLine, `\1`) {
			t.Errorf("the trailing \\1 Windows appends was not stripped: %q", e.CommandLine)
		}
		// ProcessName must stay empty: no process is recorded.
		if e.ProcessName != "" {
			t.Errorf("RunMRU set ProcessName=%q; no process is recorded by this artifact", e.ProcessName)
		}
		if !strings.Contains(e.Extra["evidence_meaning"], "not evidence that the command executed") {
			t.Errorf("evidence_meaning does not disclaim execution: %q", e.Extra["evidence_meaning"])
		}
		if e.Extra["raw_value"] == "" {
			t.Error("the raw stored value was not preserved")
		}
	}
}

func TestTypedPaths_RecordsWhatWasTypedNotWhatWasOpened(t *testing.T) {
	events := parseUserHive(t, "NTUSER.DAT", mruHive())
	paths := eventsOfType(events, model.ArtifactTypedPaths)
	if len(paths) != 2 {
		t.Fatalf("got %d TypedPaths events, want 2", len(paths))
	}
	seen := map[string]string{}
	for _, e := range paths {
		if e.EventType != model.EventTypedPath {
			t.Errorf("event type = %q", e.EventType)
		}
		seen[e.FilePath] = e.Extra["mru_position"]
		meaning := e.Extra["evidence_meaning"]
		for _, want := range []string{"not that the path was opened", "not that anything was executed"} {
			if !strings.Contains(meaning, want) {
				t.Errorf("evidence_meaning is missing %q: %q", want, meaning)
			}
		}
		if e.ProcessName != "" || e.CommandLine != "" {
			t.Errorf("TypedPaths set ProcessName=%q CommandLine=%q", e.ProcessName, e.CommandLine)
		}
	}
	if pos, ok := seen[`\\fileserver\share`]; !ok {
		t.Errorf("the UNC path is missing; got %v", keys(seen))
	} else if pos != "0" {
		t.Errorf("url1 has mru_position %q, want 0 (most recent)", pos)
	}
}

func TestOpenSaveMRU_ReconstructsThePathViaTheSharedShellItemDecoder(t *testing.T) {
	events := parseUserHive(t, "NTUSER.DAT", mruHive())
	sel := eventsOfType(events, model.ArtifactOpenSaveMRU)
	if len(sel) != 1 {
		t.Fatalf("got %d OpenSave events, want 1", len(sel))
	}
	e := sel[0]
	if e.EventType != model.EventOpenSaveMRU {
		t.Errorf("event type = %q", e.EventType)
	}
	if !strings.HasSuffix(e.FilePath, `report.docx`) {
		t.Errorf("reconstructed path = %q, want it to end in report.docx", e.FilePath)
	}
	if got := e.Extra["opensave_extension"]; got != "docx" {
		t.Errorf("extension = %q, want docx", got)
	}
	if got := e.Extra["shell_item_name"]; got != "report.docx" {
		t.Errorf("shell item name = %q", got)
	}
	// The shell item's DOS reading must be labelled, not used as the time.
	if e.Extra["shell_item_modified_local"] == "" {
		t.Error("the shell item's own date was dropped")
	}
	if !e.Timestamp.Equal(mruWrite) {
		t.Errorf("timestamp = %s, want the key write time", e.Timestamp)
	}
	if !strings.Contains(e.Extra["evidence_meaning"], "not that it was executed") {
		t.Errorf("evidence_meaning does not disclaim execution: %q", e.Extra["evidence_meaning"])
	}
}

func TestMUICache_IsPresenceEvidenceNotExecution(t *testing.T) {
	events := parseUserHive(t, "NTUSER.DAT", mruHive())
	mui := eventsOfType(events, model.ArtifactMUICache)
	if len(mui) != 2 {
		t.Fatalf("got %d MUICache events, want 2 (the @resource reference must be skipped)", len(mui))
	}
	fields := map[string]string{}
	for _, e := range mui {
		if e.EventType != model.EventMUICacheEntry {
			t.Errorf("event type = %q", e.EventType)
		}
		fields[e.FilePath] = e.Extra["muicache_field"]
		if !strings.Contains(e.Extra["evidence_meaning"], "not evidence that the program ran") {
			t.Errorf("evidence_meaning does not disclaim execution: %q", e.Extra["evidence_meaning"])
		}
		if e.ProcessName != "" {
			t.Errorf("MUICache set ProcessName=%q", e.ProcessName)
		}
	}
	if f := fields[`C:\Windows\System32\notepad.exe`]; f != "friendly_name" {
		t.Errorf("notepad entry field = %q, want friendly_name", f)
	}
	if f := fields[`C:\Tools\tool.exe`]; f != "application_company" {
		t.Errorf("tool entry field = %q, want application_company", f)
	}
}

// Every MRU artifact must attribute its user and say where that came from.
func TestMRU_UserContextIsAttributedToItsSource(t *testing.T) {
	events := parseUserHive(t, "NTUSER.DAT", mruHive())
	checked := 0
	for _, e := range events {
		switch e.ArtifactType {
		case model.ArtifactRecentDocs, model.ArtifactRunMRU, model.ArtifactTypedPaths,
			model.ArtifactOpenSaveMRU, model.ArtifactMUICache:
		default:
			continue
		}
		checked++
		if e.User != "jdoe" {
			t.Errorf("%s: user = %q, want jdoe", e.ArtifactType, e.User)
		}
		src := e.Extra["user_context_source"]
		if !strings.Contains(src, "not recorded inside the artifact") {
			t.Errorf("%s: user_context_source does not distinguish path-derived context: %q", e.ArtifactType, src)
		}
	}
	if checked == 0 {
		t.Fatal("no MRU events were produced")
	}
}

// A hive with none of these structures is not a failure.
func TestMRU_HiveWithoutTheKeysProducesNothing(t *testing.T) {
	plain := regfgen.Build("NTUSER.DAT", regfgen.NewKey("ROOT",
		regfgen.NewKey("Software", regfgen.NewKey("Nothing")),
	).WithLastWrite(mruWrite))
	events := parseUserHive(t, "NTUSER.DAT", plain)
	for _, at := range []string{
		model.ArtifactRecentDocs, model.ArtifactRunMRU, model.ArtifactTypedPaths,
		model.ArtifactOpenSaveMRU, model.ArtifactMUICache,
	} {
		if n := len(eventsOfType(events, at)); n != 0 {
			t.Errorf("%s produced %d events from a hive with no such key", at, n)
		}
	}
}

// Every event must carry unique provenance back into the hive.
func TestPhase16_EveryEventCarriesUniqueProvenance(t *testing.T) {
	for name, data := range map[string][]byte{
		"NTUSER.DAT":                             mruHive(),
		"Windows/appcompat/Programs/Amcache.hve": amcacheHive(),
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "Users", "jdoe", filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := registry.New().Parse(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		refs := map[string]int{}
		for _, e := range res.Events {
			refs[e.SourceReference]++
			if e.SourceReference == "" {
				t.Errorf("%s: an event has no source reference", name)
			}
			if e.RegistryPath == "" {
				t.Errorf("%s: %s names no registry location", name, e.EventType)
			}
		}
		for ref, n := range refs {
			if n != 1 {
				t.Errorf("%s: source reference %q used by %d events", name, ref, n)
			}
		}
		if len(res.Events) == 0 {
			t.Errorf("%s produced no events", name)
		}
	}
}

// Parsing must be deterministic and must never panic on damaged input.
func TestPhase16_ParsingIsDeterministicAndSurvivesCorruption(t *testing.T) {
	first := parseUserHive(t, "NTUSER.DAT", mruHive())
	for i := 0; i < 4; i++ {
		again := parseUserHive(t, "NTUSER.DAT", mruHive())
		if len(again) != len(first) {
			t.Fatalf("run %d produced %d events, first %d", i, len(again), len(first))
		}
		for j := range first {
			if again[j].SourceReference != first[j].SourceReference {
				t.Fatalf("run %d differs at %d", i, j)
			}
		}
	}

	for name, data := range map[string][]byte{
		"truncated amcache": regfgen.Truncate(amcacheHive(), len(amcacheHive())/3),
		"bad signature":     regfgen.CorruptSignature(mruHive()),
		"bad root offset":   regfgen.CorruptRootOffset(mruHive()),
		"empty":             {},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: panic: %v", name, r)
				}
			}()
			dir := t.TempDir()
			path := filepath.Join(dir, "NTUSER.DAT")
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
			_, _ = registry.New().Parse(path)
		}()
	}
}

// Parsing must not modify the evidence file.
func TestPhase16_EvidenceIsNotModified(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Users", "jdoe", "NTUSER.DAT")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data := mruHive()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.New().Parse(path); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("the hive was modified by parsing it")
	}
	// And no sidecar was written next to it.
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("parsing left extra files beside the evidence: %v", names)
	}
}

// ---------------- Scale ----------------

// A large Amcache must parse in bounded time and memory. Real inventory
// hives hold thousands of entries; the limit exists so a crafted one
// cannot turn a single file into unbounded work, and this checks that
// the ordinary case stays comfortably inside it.
func TestScale_LargeAmcacheAndMRU(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in short mode")
	}
	const n = 20000

	entries := make([]*regfgen.Key, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, regfgen.NewKey(fmt.Sprintf("app%05d.exe|%08x", i, i)).
			WithLastWrite(amWrite).WithValues(
			regfgen.StringValue("LowerCaseLongPath", fmt.Sprintf(`c:\program files\vendor%d\app%05d.exe`, i%50, i)),
			regfgen.StringValue("Name", fmt.Sprintf("app%05d.exe", i)),
			regfgen.StringValue("FileId", fmt.Sprintf("0000%040x", i)),
			regfgen.StringValue("Publisher", fmt.Sprintf("Vendor %d", i%50)),
			regfgen.DWordValue("Size", uint32(1024*(i%512+1))),
		))
	}
	hive := regfgen.Build("Amcache.hve", regfgen.NewKey("ROOT",
		regfgen.NewKey("Root", regfgen.NewKey("InventoryApplicationFile", entries...)),
	).WithLastWrite(amWrite))

	dir := t.TempDir()
	path := filepath.Join(dir, "Amcache.hve")
	if err := os.WriteFile(path, hive, 0o644); err != nil {
		t.Fatal(err)
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	res, err := registry.New().Parse(path)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}

	am := eventsOfType(res.Events, model.ArtifactAmcache)
	t.Logf("%d Amcache entries parsed from a %.1f MiB hive in %v (%.1f MiB allocated)",
		len(am), float64(len(hive))/(1<<20), elapsed.Round(time.Millisecond),
		float64(after.TotalAlloc-before.TotalAlloc)/(1<<20))

	if len(am) != n {
		t.Errorf("got %d entries, want %d", len(am), n)
	}
	if elapsed > 60*time.Second {
		t.Errorf("parsing %d Amcache entries took %v", n, elapsed)
	}
}

// Many MRU entries in one key must not degrade, and the hive reader's
// per-key value cap must apply predictably.
//
// regf.DefaultLimits caps one key at 4096 values. That is far above any
// real RecentDocs key -- Windows itself keeps on the order of 150
// entries per extension -- so the cap bounds a hostile hive without
// truncating legitimate evidence. This asserts the bound holds rather
// than expecting every synthetic value back.
func TestScale_LargeRecentDocs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in short mode")
	}
	const n = 5000
	values := make([]regfgen.Value, 0, n)
	for i := 0; i < n; i++ {
		values = append(values, regfgen.BinaryValue(strconv.Itoa(i),
			recentDocValue(fmt.Sprintf("document-%05d.docx", i))))
	}
	hive := regfgen.Build("NTUSER.DAT", regfgen.NewKey("ROOT",
		regfgen.NewKey("Software", regfgen.NewKey("Microsoft",
			regfgen.NewKey("Windows", regfgen.NewKey("CurrentVersion",
				regfgen.NewKey("Explorer",
					regfgen.NewKey("RecentDocs").WithLastWrite(mruWrite).WithValues(values...)))))),
	).WithLastWrite(mruWrite))

	start := time.Now()
	events := parseUserHive(t, "NTUSER.DAT", hive)
	elapsed := time.Since(start)

	docs := eventsOfType(events, model.ArtifactRecentDocs)
	t.Logf("%d of %d RecentDocs values parsed in %v (capped by regf MaxValuesPerKey)",
		len(docs), n, elapsed.Round(time.Millisecond))

	const perKeyCap = 4096 // regf.DefaultLimits().MaxValuesPerKey
	if len(docs) != perKeyCap {
		t.Errorf("got %d entries from a %d-value key, want the %d-value cap applied exactly",
			len(docs), n, perKeyCap)
	}
	// Whatever survives must be intact -- a cap must truncate the LIST,
	// never corrupt the entries it does return.
	for _, e := range docs {
		if e.FilePath == "" || !strings.HasPrefix(e.FilePath, "document-") {
			t.Errorf("a capped key returned a malformed entry: %q", e.FilePath)
			break
		}
	}
	if elapsed > 60*time.Second {
		t.Errorf("parsing %d RecentDocs entries took %v", n, elapsed)
	}
}
