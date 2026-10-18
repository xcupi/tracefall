package registry_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/registry"
	"tracefall/internal/regf/regfgen"
	"tracefall/internal/shellbag/sbgen"
	"tracefall/internal/userassist"
	"tracefall/internal/userassist/uagen"
)

// Phase 15: UserAssist and ShellBags read out of a per-user hive.
//
// The fixtures are synthetic hives built by regfgen; nothing here comes
// from real evidence.

const (
	uaExecGUID = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"
	uaLnkGUID  = "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"
	thisPCGUID = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
)

var (
	uaRunAt   = time.Date(2021, 4, 29, 18, 17, 38, 0, time.UTC)
	bagWrite  = time.Date(2021, 4, 29, 19, 5, 0, 0, time.UTC)
	hiveWrite = time.Date(2021, 5, 1, 0, 0, 0, 0, time.UTC)
)

// ntuserWithUserActivity builds an NTUSER.DAT holding a UserAssist tree
// and a BagMRU tree.
func ntuserWithUserActivity(t *testing.T) []byte {
	t.Helper()

	countKey := regfgen.NewKey("Count").WithLastWrite(hiveWrite).WithValues(
		regfgen.BinaryValue(uagen.Name(`{6D809377-6AF0-444B-8957-A3773F02200E}\Vendor\tool.exe`),
			uagen.BuildV5(uagen.Entry{SessionID: 1, RunCount: 12, FocusCount: 30,
				FocusTime: 90 * time.Second, LastExecuted: uaRunAt})),
		regfgen.BinaryValue(uagen.Name(`C:\Windows\System32\notepad.exe`),
			uagen.BuildV5(uagen.Entry{SessionID: 1, RunCount: 3, LastExecuted: uaRunAt.Add(-time.Hour)})),
		// A value with no usable timestamp: still evidence, still an event.
		regfgen.BinaryValue(uagen.Name(`C:\Tools\untimed.exe`),
			uagen.BuildV5(uagen.Entry{RunCount: 2})),
		// A value that is not a UserAssist record at all. The Count key
		// legitimately holds these, and they must be skipped rather than
		// reported as broken evidence.
		regfgen.DWordValue("SomeSetting", 1),
	)
	lnkCountKey := regfgen.NewKey("Count").WithLastWrite(hiveWrite).WithValues(
		regfgen.BinaryValue(uagen.Name(`{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}\Report.lnk`),
			uagen.BuildV5(uagen.Entry{RunCount: 5, LastExecuted: uaRunAt.Add(-2 * time.Hour)})),
	)

	userAssist := regfgen.NewKey("UserAssist",
		regfgen.NewKey(uaExecGUID, countKey),
		regfgen.NewKey(uaLnkGUID, lnkCountKey),
	)

	// BagMRU: This PC -> C:\ -> Users -> jdoe
	bag3 := regfgen.NewKey("3").WithLastWrite(bagWrite)
	bag2 := regfgen.NewKey("2", bag3).WithLastWrite(bagWrite).WithValues(
		regfgen.BinaryValue("3", sbgen.List(sbgen.File(sbgen.FileEntry{
			ShortName: "JDOE", LongName: "jdoe", IsDirectory: true, Attributes: 0x10,
			Modified: time.Date(2021, 4, 29, 18, 17, 38, 0, time.UTC), ExtVersion: 9,
		}))),
		regfgen.BinaryValue("MRUListEx", sbgen.MRUListEx(3)),
	)
	bag1 := regfgen.NewKey("1", bag2).WithLastWrite(bagWrite).WithValues(
		regfgen.BinaryValue("2", sbgen.List(sbgen.File(sbgen.FileEntry{
			ShortName: "USERS", LongName: "Users", IsDirectory: true, Attributes: 0x10,
			ExtVersion: 9,
		}))),
		regfgen.BinaryValue("MRUListEx", sbgen.MRUListEx(2)),
	)
	bag0 := regfgen.NewKey("0", bag1).WithLastWrite(bagWrite).WithValues(
		regfgen.BinaryValue("1", sbgen.List(sbgen.Volume(`C:\`))),
		regfgen.BinaryValue("MRUListEx", sbgen.MRUListEx(1)),
	)
	bagMRU := regfgen.NewKey("BagMRU", bag0).WithLastWrite(bagWrite).WithValues(
		regfgen.BinaryValue("0", sbgen.List(sbgen.Root(thisPCGUID))),
		regfgen.BinaryValue("MRUListEx", sbgen.MRUListEx(0)),
	)

	root := regfgen.NewKey("ROOT",
		regfgen.NewKey("Software",
			regfgen.NewKey("Microsoft",
				regfgen.NewKey("Windows",
					regfgen.NewKey("CurrentVersion",
						regfgen.NewKey("Explorer", userAssist),
					),
					regfgen.NewKey("Shell", bagMRU),
				),
			),
		),
	).WithLastWrite(hiveWrite)

	return regfgen.Build("NTUSER.DAT", root)
}

// parseHive writes the bytes to a path that carries a username and parses
// them.
func parseUserHive(t *testing.T, name string, data []byte) []model.Event {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Users", "jdoe", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := registry.New().ParseWithContext(path, parsers.ParseContext{EvidencePath: filepath.ToSlash(filepath.Join("Users", "jdoe", name))})
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	if len(res.Events) != len(res.Raw) {
		t.Fatalf("%d events but %d raw records; every event must carry its own provenance",
			len(res.Events), len(res.Raw))
	}
	return res.Events
}

func eventsOfType(events []model.Event, artifactType string) []model.Event {
	var out []model.Event
	for _, e := range events {
		if e.ArtifactType == artifactType {
			out = append(out, e)
		}
	}
	return out
}

// ---------------- UserAssist ----------------

func TestUserAssist_EntriesBecomeEventsWithHonestSemantics(t *testing.T) {
	events := parseUserHive(t, "NTUSER.DAT", ntuserWithUserActivity(t))
	ua := eventsOfType(events, model.ArtifactUserAssist)
	if len(ua) != 4 {
		t.Fatalf("got %d UserAssist events, want 4 (the non-UserAssist value must be skipped, not counted)", len(ua))
	}

	byName := map[string]model.Event{}
	for _, e := range ua {
		if e.EventType != model.EventUserAssistActivity {
			t.Errorf("event type = %q, want %q", e.EventType, model.EventUserAssistActivity)
		}
		byName[e.Extra["decoded_name"]] = e
	}

	tool, ok := byName[`{6D809377-6AF0-444B-8957-A3773F02200E}\Vendor\tool.exe`]
	if !ok {
		t.Fatalf("the tool.exe entry is missing; decoded names present: %v", keys(byName))
	}
	if !tool.Timestamp.Equal(uaRunAt) {
		t.Errorf("timestamp = %s, want %s", tool.Timestamp, uaRunAt)
	}
	if got := tool.Extra["run_count"]; got != "12" {
		t.Errorf("run_count = %q, want 12", got)
	}
	if got := tool.Extra["resolved_path"]; got != `C:\Program Files (x86)\Vendor\tool.exe` {
		t.Errorf("resolved path = %q", got)
	}
	if tool.FilePath != `C:\Program Files (x86)\Vendor\tool.exe` {
		t.Errorf("FilePath = %q, want the resolved path", tool.FilePath)
	}
	if got := tool.Extra["focus_count"]; got != "30" {
		t.Errorf("focus_count = %q, want 30", got)
	}

	// The semantic guarantee this whole artifact turns on.
	meaning := tool.Extra["evidence_meaning"]
	if !strings.Contains(meaning, "not a process-creation record") {
		t.Errorf("evidence_meaning does not disclaim process creation: %q", meaning)
	}
	tsMeaning := tool.Extra["timestamp_meaning"]
	if !strings.Contains(strings.ToLower(tsMeaning), "not a process start") {
		t.Errorf("timestamp_meaning does not disclaim a process start time: %q", tsMeaning)
	}
	// ProcessName/CommandLine must NOT be populated: neither is supported
	// by the artifact, and using them would assert a process existed.
	if tool.ProcessName != "" || tool.CommandLine != "" {
		t.Errorf("UserAssist set ProcessName=%q CommandLine=%q; the artifact supports neither",
			tool.ProcessName, tool.CommandLine)
	}
}

// An entry with no recorded time is still evidence: the run count stands,
// and the missing timestamp is stated rather than filled in from the
// hive, the key, or the file.
func TestUserAssist_EntryWithoutTimestampKeepsItsCountAndSaysSo(t *testing.T) {
	events := parseUserHive(t, "NTUSER.DAT", ntuserWithUserActivity(t))
	var untimed *model.Event
	for i, e := range eventsOfType(events, model.ArtifactUserAssist) {
		if strings.Contains(e.Extra["decoded_name"], "untimed.exe") {
			ua := eventsOfType(events, model.ArtifactUserAssist)
			untimed = &ua[i]
			break
		}
	}
	if untimed == nil {
		t.Fatal("the untimed entry produced no event; a missing timestamp must not drop the evidence")
	}
	if !untimed.Timestamp.IsZero() {
		t.Errorf("a timestamp was invented: %s", untimed.Timestamp)
	}
	if got := untimed.Extra["run_count"]; got != "2" {
		t.Errorf("run_count = %q, want 2", got)
	}
	if untimed.Extra["timestamp_basis"] == "" {
		t.Error("no timestamp_basis explains why the event has no time")
	}
	// Specifically: neither the key's last-write time nor the hive's.
	if untimed.Timestamp.Equal(hiveWrite) || untimed.Timestamp.Equal(bagWrite) {
		t.Error("a surrogate timestamp was substituted from the hive")
	}
}

func TestUserAssist_UserContextIsAttributedToItsSource(t *testing.T) {
	events := parseUserHive(t, "NTUSER.DAT", ntuserWithUserActivity(t))
	ua := eventsOfType(events, model.ArtifactUserAssist)
	if len(ua) == 0 {
		t.Fatal("no events")
	}
	for _, e := range ua {
		if e.User != "jdoe" {
			t.Errorf("user = %q, want jdoe from the evidence path", e.User)
		}
		if e.Extra["user_context"] != "jdoe" {
			t.Errorf("user_context = %q", e.Extra["user_context"])
		}
		src := e.Extra["user_context_source"]
		if !strings.Contains(src, "path") || !strings.Contains(src, "not recorded inside the artifact") {
			t.Errorf("user_context_source does not distinguish path-derived from artifact-recorded: %q", src)
		}
	}
}

// A hive with no UserAssist tree is a valid artifact with zero records of
// that kind -- not a parse failure.
func TestUserAssist_HiveWithoutTheTreeIsNotAFailure(t *testing.T) {
	plain := regfgen.Build("NTUSER.DAT", regfgen.NewKey("ROOT",
		regfgen.NewKey("Software", regfgen.NewKey("Nothing")),
	).WithLastWrite(hiveWrite))

	events := parseUserHive(t, "NTUSER.DAT", plain)
	if n := len(eventsOfType(events, model.ArtifactUserAssist)); n != 0 {
		t.Errorf("a hive with no UserAssist tree produced %d entries", n)
	}
}

// UserAssist is only read from a USER hive. A SYSTEM hive holding keys
// at the same relative path must not be mined for it.
//
// The hive is built with an embedded name of SYSTEM, not merely placed
// at a SYSTEM path: classifyHive trusts the hive's own embedded name
// over its location, which is the more reliable signal and means a
// user hive copied to an odd path is still recognized as a user hive.
func TestUserAssist_OnlyReadFromAUserHive(t *testing.T) {
	countKey := regfgen.NewKey("Count").WithLastWrite(hiveWrite).WithValues(
		regfgen.BinaryValue(uagen.Name(`C:\Windows\System32\notepad.exe`),
			uagen.BuildV5(uagen.Entry{RunCount: 3, LastExecuted: uaRunAt})),
	)
	systemHive := regfgen.Build("SYSTEM", regfgen.NewKey("ROOT",
		regfgen.NewKey("ControlSet001"),
		regfgen.NewKey("Software", regfgen.NewKey("Microsoft",
			regfgen.NewKey("Windows", regfgen.NewKey("CurrentVersion",
				regfgen.NewKey("Explorer", regfgen.NewKey("UserAssist",
					regfgen.NewKey(uaExecGUID, countKey))))))),
	).WithLastWrite(hiveWrite))

	dir := t.TempDir()
	path := filepath.Join(dir, "Windows", "System32", "config", "SYSTEM")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, systemHive, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := registry.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(eventsOfType(res.Events, model.ArtifactUserAssist)); n != 0 {
		t.Errorf("a SYSTEM hive yielded %d UserAssist events; the tree is only read from a user hive", n)
	}
}

// ---------------- ShellBags ----------------

func TestShellBags_PathIsReconstructedAcrossTreeLevels(t *testing.T) {
	events := parseUserHive(t, "NTUSER.DAT", ntuserWithUserActivity(t))
	bags := eventsOfType(events, model.ArtifactShellBags)
	if len(bags) != 4 {
		t.Fatalf("got %d ShellBags events, want 4 (one per BagMRU level)", len(bags))
	}

	paths := map[string]model.Event{}
	for _, e := range bags {
		if e.EventType != model.EventShellBagNavigation {
			t.Errorf("event type = %q, want %q", e.EventType, model.EventShellBagNavigation)
		}
		paths[e.Extra["reconstructed_path"]] = e
	}

	want := `This PC / My Computer\C:\Users\jdoe`
	deepest, ok := paths[want]
	if !ok {
		t.Fatalf("the deepest path was not reconstructed; got: %v", keys(paths))
	}
	if deepest.FilePath != want {
		t.Errorf("FilePath = %q, want %q", deepest.FilePath, want)
	}
	if got := deepest.Extra["bag_depth"]; got != "4" {
		t.Errorf("bag_depth = %q, want 4", got)
	}
	if got := deepest.Extra["shell_item_name"]; got != "jdoe" {
		t.Errorf("shell item name = %q, want the long name jdoe", got)
	}
	if got := deepest.Extra["shell_item_kind"]; got != "directory" {
		t.Errorf("kind = %q, want directory", got)
	}
}

// The event's timestamp is the registry key's last-write time, and the
// shell item's own DOS fields are reported as local-time readings that
// are explicitly NOT the timestamp.
func TestShellBags_TimestampIsTheKeyWriteTimeNotTheShellItemDates(t *testing.T) {
	events := parseUserHive(t, "NTUSER.DAT", ntuserWithUserActivity(t))
	bags := eventsOfType(events, model.ArtifactShellBags)
	if len(bags) == 0 {
		t.Fatal("no ShellBags events")
	}

	var withDates *model.Event
	for i := range bags {
		if bags[i].Extra["shell_item_modified_local"] != "" {
			withDates = &bags[i]
			break
		}
	}
	if withDates == nil {
		t.Fatal("no event carries a shell item DOS reading; the fixture sets one")
	}

	if !withDates.Timestamp.Equal(bagWrite) {
		t.Errorf("timestamp = %s, want the BagMRU key last-write %s", withDates.Timestamp, bagWrite)
	}
	if got := withDates.Extra["shell_item_modified_local"]; got != "2021-04-29 18:17:38" {
		t.Errorf("shell item local reading = %q", got)
	}
	// The reading must never be presented as an instant.
	if strings.HasSuffix(withDates.Extra["shell_item_modified_local"], "Z") {
		t.Error("a DOS wall-clock reading was rendered as a UTC instant")
	}
	note := withDates.Extra["shell_item_time_note"]
	for _, want := range []string{"local time", "no timezone", "not used as this event's timestamp"} {
		if !strings.Contains(note, want) {
			t.Errorf("shell_item_time_note does not say %q: %q", want, note)
		}
	}
	tsMeaning := withDates.Extra["timestamp_meaning"]
	if !strings.Contains(tsMeaning, "last-write") {
		t.Errorf("timestamp_meaning does not identify the key write time: %q", tsMeaning)
	}
}

// The semantic guarantee: a ShellBag is navigation evidence, never "file
// opened" and never execution.
func TestShellBags_NeverClaimFileOpenOrExecution(t *testing.T) {
	events := parseUserHive(t, "NTUSER.DAT", ntuserWithUserActivity(t))
	for _, e := range eventsOfType(events, model.ArtifactShellBags) {
		meaning := strings.ToLower(e.Extra["evidence_meaning"])
		if !strings.Contains(meaning, "not evidence that a file was opened") {
			t.Errorf("evidence_meaning does not disclaim file opening: %q", e.Extra["evidence_meaning"])
		}
		if !strings.Contains(meaning, "not evidence that anything was executed") {
			t.Errorf("evidence_meaning does not disclaim execution: %q", e.Extra["evidence_meaning"])
		}
		if e.ProcessName != "" || e.CommandLine != "" {
			t.Errorf("ShellBag set ProcessName=%q CommandLine=%q; it supports neither",
				e.ProcessName, e.CommandLine)
		}
		if e.EventType == model.EventProcessCreate {
			t.Error("a ShellBag was emitted as a process-creation event")
		}
	}
}

func TestShellBags_HiveWithoutABagMRUTreeIsNotAFailure(t *testing.T) {
	plain := regfgen.Build("NTUSER.DAT", regfgen.NewKey("ROOT",
		regfgen.NewKey("Software", regfgen.NewKey("Nothing")),
	).WithLastWrite(hiveWrite))
	events := parseUserHive(t, "NTUSER.DAT", plain)
	if n := len(eventsOfType(events, model.ArtifactShellBags)); n != 0 {
		t.Errorf("a hive with no BagMRU produced %d ShellBags events", n)
	}
}

// A malformed shell item must not lose the levels that decoded cleanly.
func TestShellBags_MalformedItemDoesNotDiscardTheRestOfTheTree(t *testing.T) {
	good := sbgen.File(sbgen.FileEntry{ShortName: "OK", LongName: "Good", IsDirectory: true, ExtVersion: 9})
	bagBad := regfgen.NewKey("1").WithLastWrite(bagWrite).WithValues(
		regfgen.BinaryValue("0", sbgen.CorruptSize(good, 0xFFFF)),
	)
	bag0 := regfgen.NewKey("0", bagBad).WithLastWrite(bagWrite).WithValues(
		regfgen.BinaryValue("1", sbgen.List(sbgen.Volume(`C:\`))),
	)
	bagMRU := regfgen.NewKey("BagMRU", bag0).WithLastWrite(bagWrite).WithValues(
		regfgen.BinaryValue("0", sbgen.List(sbgen.Root(thisPCGUID))),
	)
	hive := regfgen.Build("NTUSER.DAT", regfgen.NewKey("ROOT",
		regfgen.NewKey("Software", regfgen.NewKey("Microsoft",
			regfgen.NewKey("Windows", regfgen.NewKey("Shell", bagMRU)))),
	).WithLastWrite(hiveWrite))

	events := parseUserHive(t, "NTUSER.DAT", hive)
	bags := eventsOfType(events, model.ArtifactShellBags)
	if len(bags) < 2 {
		t.Fatalf("got %d events; the levels above the malformed item must survive", len(bags))
	}
	for _, e := range bags {
		if e.Extra["reconstructed_path"] == "" {
			t.Error("an event carries no reconstructed path")
		}
	}
}

// ---------------- Both, and the shared pipeline ----------------

// Every event must carry provenance that points back into the hive.
func TestUserActivity_EveryEventCarriesProvenance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Users", "jdoe", "NTUSER.DAT")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, ntuserWithUserActivity(t), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := registry.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}

	refs := map[string]bool{}
	for _, r := range res.Raw {
		refs[r.SourceReference] = true
		if r.Raw == "" {
			t.Errorf("raw record %q has no content", r.SourceReference)
		}
	}
	for _, e := range res.Events {
		if e.SourceReference == "" {
			t.Errorf("event %s has no source reference", e.EventType)
		}
		if !refs[e.SourceReference] {
			t.Errorf("event source reference %q has no matching raw record", e.SourceReference)
		}
		if e.Parser == "" {
			t.Error("event names no parser")
		}
		if e.RegistryPath == "" {
			t.Errorf("event %q does not name the registry location it came from", e.SourceReference)
		}
	}
}

// Source references must be unique, or deduplication would collapse
// distinct entries into one.
func TestUserActivity_SourceReferencesAreUnique(t *testing.T) {
	events := parseUserHive(t, "NTUSER.DAT", ntuserWithUserActivity(t))
	seen := map[string]int{}
	for _, e := range events {
		seen[e.SourceReference]++
	}
	for ref, n := range seen {
		if n != 1 {
			t.Errorf("source reference %q used by %d events", ref, n)
		}
	}
}

// Parsing the same hive twice must produce identical output.
func TestUserActivity_ParsingIsDeterministic(t *testing.T) {
	data := ntuserWithUserActivity(t)
	first := parseUserHive(t, "NTUSER.DAT", data)
	for i := 0; i < 5; i++ {
		again := parseUserHive(t, "NTUSER.DAT", data)
		if len(again) != len(first) {
			t.Fatalf("run %d produced %d events, first run produced %d", i, len(again), len(first))
		}
		for j := range first {
			if again[j].SourceReference != first[j].SourceReference ||
				!again[j].Timestamp.Equal(first[j].Timestamp) ||
				again[j].FilePath != first[j].FilePath {
				t.Fatalf("run %d differs at event %d", i, j)
			}
		}
	}
}

// Truncated and corrupt hives must fail as hives, not panic.
func TestUserActivity_CorruptHiveIsRejectedWithoutPanicking(t *testing.T) {
	data := ntuserWithUserActivity(t)
	cases := map[string][]byte{
		"truncated":         regfgen.Truncate(data, len(data)/2),
		"bad signature":     regfgen.CorruptSignature(data),
		"bad root offset":   regfgen.CorruptRootOffset(data),
		"empty":             {},
		"tiny":              {1, 2, 3},
		"subkey list cycle": regfgen.CycleSubkeyList(data),
	}
	for name, bytes := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: panic: %v", name, r)
				}
			}()
			dir := t.TempDir()
			path := filepath.Join(dir, "NTUSER.DAT")
			if err := os.WriteFile(path, bytes, 0o644); err != nil {
				t.Fatal(err)
			}
			// Either an error or a clean zero-event result is acceptable;
			// a panic or a hang is not.
			_, _ = registry.New().Parse(path)
		}()
	}
}

// The decoded UserAssist name must be the ROT13 decode of what is stored,
// and both forms must be retained so the transformation is auditable.
func TestUserAssist_BothNameFormsAreRetained(t *testing.T) {
	events := parseUserHive(t, "NTUSER.DAT", ntuserWithUserActivity(t))
	for _, e := range eventsOfType(events, model.ArtifactUserAssist) {
		stored := e.Extra["userassist_value_name"]
		decoded := e.Extra["decoded_name"]
		if stored == "" || decoded == "" {
			t.Errorf("a name form is missing: stored=%q decoded=%q", stored, decoded)
			continue
		}
		if userassist.ROT13(stored) != decoded {
			t.Errorf("decoded name %q is not the ROT13 decode of %q", decoded, stored)
		}
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
