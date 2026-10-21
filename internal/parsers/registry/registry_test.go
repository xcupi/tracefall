package registry_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	parser "tracefall/internal/parsers/registry"
	"tracefall/internal/regf/regfgen"
)

var lastWrite = time.Date(2026, 1, 15, 8, 45, 0, 0, time.UTC)

func writeHive(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func parseHive(t *testing.T, path string) []model.Event {
	t.Helper()
	relPath := filepath.Base(path)
	if filepath.Base(filepath.Dir(filepath.Dir(path))) == "Users" {
		relPath = filepath.ToSlash(filepath.Join("Users", "jdoe", filepath.Base(path)))
	}
	res, err := parser.New().ParseWithContext(path, parsers.ParseContext{EvidencePath: relPath})
	if err != nil {
		t.Fatalf("Parse(%s): %v", path, err)
	}
	if len(res.Raw) != len(res.Events) {
		t.Fatalf("raw records = %d, events = %d; they must pair 1:1", len(res.Raw), len(res.Events))
	}
	return res.Events
}

func eventByRegistryPath(events []model.Event, want string) (model.Event, bool) {
	for _, e := range events {
		if e.RegistryPath == want {
			return e, true
		}
	}
	return model.Event{}, false
}

// systemHive is a synthetic SYSTEM hive carrying a hostname and a
// service whose ImagePath points somewhere suspicious.
func systemHive() []byte {
	computerName := regfgen.NewKey("ComputerName").WithLastWrite(lastWrite).WithValues(
		regfgen.StringValue("ComputerName", "WKSTN-042"),
	)
	computerNameParent := regfgen.NewKey("ComputerName", computerName)

	svc := regfgen.NewKey("AcmeUpdater").WithLastWrite(lastWrite).WithValues(
		regfgen.ExpandStringValue("ImagePath", `C:\Windows\Temp\acme_updater.exe`),
		regfgen.DWordValue("Start", 2),
	)
	services := regfgen.NewKey("Services", svc)
	control := regfgen.NewKey("Control", computerNameParent)
	cs1 := regfgen.NewKey("ControlSet001", control, services)
	root := regfgen.NewKey("CMI-CreateHive{SYSTEM}", cs1, regfgen.NewKey("Select").WithValues(regfgen.DWordValue("Current", 1))).WithLastWrite(lastWrite)
	return regfgen.Build(`\??\C:\Windows\System32\config\SYSTEM`, root)
}

// TestParse_SystemHiveHostname is the Phase 11 requirement: a SYSTEM
// hive's ComputerName becomes a real, evidence-backed host.
func TestParse_SystemHiveHostname(t *testing.T) {
	events := parseHive(t, writeHive(t, "SYSTEM", systemHive()))
	if len(events) == 0 {
		t.Fatal("no events from a SYSTEM hive")
	}

	var hostnameEvent *model.Event
	for i := range events {
		if events[i].EventType == model.EventRegistryKeyLastWrite {
			hostnameEvent = &events[i]
			break
		}
	}
	if hostnameEvent == nil {
		t.Fatal("no hostname observation event emitted from the SYSTEM hive")
	}
	if hostnameEvent.Host != "WKSTN-042" {
		t.Errorf("Host = %q, want WKSTN-042", hostnameEvent.Host)
	}
	if hostnameEvent.Extra["registry_value_data"] != "WKSTN-042" {
		t.Errorf("recorded hostname = %q", hostnameEvent.Extra["registry_value_data"])
	}
	// Phase 12: the hive only knows a last-write time. The event type
	// must say that, not claim the key was "created" by anyone.
	if hostnameEvent.EventType != "registry_key_last_write" {
		t.Errorf("EventType = %q; it must describe an observation, not an action", hostnameEvent.EventType)
	}

	// Every event from this hive inherits the host it genuinely knows.
	for _, e := range events {
		if e.Host != "WKSTN-042" {
			t.Errorf("event %q has Host %q, want WKSTN-042", e.RegistryPath, e.Host)
		}
	}
}

// A service ImagePath is persistence, and must be classified by the same
// shared regpersist table the RECmd and Sysmon paths use.
func TestParse_ServiceImagePath(t *testing.T) {
	events := parseHive(t, writeHive(t, "SYSTEM", systemHive()))

	got, ok := eventByRegistryPath(events, `HKLM\SYSTEM\ControlSet001\Services\AcmeUpdater\ImagePath`)
	if !ok {
		t.Fatalf("no event for the service ImagePath; got %+v", registryPaths(events))
	}
	if got.EventType != model.EventRegistryPersistence {
		t.Errorf("EventType = %q, want %q", got.EventType, model.EventRegistryPersistence)
	}
	if got.Extra["registry_persistence_type"] != "service_image_path" {
		t.Errorf("persistence type = %q, want service_image_path", got.Extra["registry_persistence_type"])
	}
	if got.FilePath != `C:\Windows\Temp\acme_updater.exe` {
		t.Errorf("FilePath = %q", got.FilePath)
	}
	if got.ProcessName != "acme_updater.exe" {
		t.Errorf("ProcessName = %q, want acme_updater.exe", got.ProcessName)
	}
	if !got.Timestamp.Equal(lastWrite) {
		t.Errorf("Timestamp = %v, want the key's last-write %v", got.Timestamp, lastWrite)
	}
}

// softwareHive carries one of each remaining persistence location.
func softwareHive() []byte {
	run := regfgen.NewKey("Run").WithLastWrite(lastWrite).WithValues(
		regfgen.StringValue("AcmeTray", `C:\ProgramData\acme\tray.exe`),
	)
	runOnce := regfgen.NewKey("RunOnce").WithLastWrite(lastWrite).WithValues(
		regfgen.StringValue("Cleanup", `C:\Windows\Temp\cleanup.exe`),
	)
	cvWindows := regfgen.NewKey("CurrentVersion", run, runOnce)
	windows := regfgen.NewKey("Windows", cvWindows)

	winlogon := regfgen.NewKey("Winlogon").WithLastWrite(lastWrite).WithValues(
		regfgen.StringValue("Userinit", `C:\Windows\system32\userinit.exe,C:\Windows\Temp\evil.exe`),
	)
	ifeoTarget := regfgen.NewKey("sethc.exe").WithLastWrite(lastWrite).WithValues(
		regfgen.StringValue("Debugger", `C:\Windows\System32\cmd.exe`),
	)
	ifeo := regfgen.NewKey("Image File Execution Options", ifeoTarget)
	windowsNTWindows := regfgen.NewKey("Windows").WithLastWrite(lastWrite).WithValues(
		regfgen.StringValue("AppInit_DLLs", `C:\Windows\Temp\inject.dll`),
	)
	cvNT := regfgen.NewKey("CurrentVersion", winlogon, ifeo, windowsNTWindows)
	windowsNT := regfgen.NewKey("Windows NT", cvNT)

	microsoft := regfgen.NewKey("Microsoft", windows, windowsNT)
	root := regfgen.NewKey("CMI-CreateHive{SOFTWARE}", microsoft).WithLastWrite(lastWrite)
	return regfgen.Build(`\??\C:\Windows\System32\config\SOFTWARE`, root)
}

func TestParse_SoftwareHivePersistenceLocations(t *testing.T) {
	events := parseHive(t, writeHive(t, "SOFTWARE", softwareHive()))

	cases := []struct {
		path     string
		wantType string
		wantKind string
	}{
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\AcmeTray`, model.EventRegistryRunKey, ""},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\Cleanup`, model.EventRegistryRunKey, ""},
		{`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`, model.EventRegistryPersistence, "winlogon"},
		{`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger`, model.EventRegistryPersistence, "ifeo"},
		{`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`, model.EventRegistryPersistence, "appinit_dlls"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got, ok := eventByRegistryPath(events, tc.path)
			if !ok {
				t.Fatalf("no event for %s; got %v", tc.path, registryPaths(events))
			}
			if got.EventType != tc.wantType {
				t.Errorf("EventType = %q, want %q", got.EventType, tc.wantType)
			}
			if tc.wantKind != "" && got.Extra["registry_persistence_type"] != tc.wantKind {
				t.Errorf("persistence type = %q, want %q", got.Extra["registry_persistence_type"], tc.wantKind)
			}
			if got.ArtifactType != model.ArtifactRegistryHive {
				t.Errorf("ArtifactType = %q, want %q", got.ArtifactType, model.ArtifactRegistryHive)
			}
		})
	}
}

// A SOFTWARE hive knows no hostname. It must NOT invent one -- the
// collection-scoped host enrichment resolves it later, or it stays blank.
func TestParse_NonSystemHiveNeverInventsAHost(t *testing.T) {
	for _, e := range parseHive(t, writeHive(t, "SOFTWARE", softwareHive())) {
		if e.Host != "" {
			t.Errorf("event %q carries Host %q, but a SOFTWARE hive records no hostname", e.RegistryPath, e.Host)
		}
	}
}

// An NTUSER.DAT belongs to one user, and only the evidence path says who.
func TestParse_NTUserHiveAttributesTheOwningUser(t *testing.T) {
	run := regfgen.NewKey("Run").WithLastWrite(lastWrite).WithValues(
		regfgen.StringValue("Updater", `C:\Users\jdoe\AppData\Roaming\updater.exe`),
	)
	cv := regfgen.NewKey("CurrentVersion", run)
	windows := regfgen.NewKey("Windows", cv)
	microsoft := regfgen.NewKey("Microsoft", windows)
	software := regfgen.NewKey("Software", microsoft)
	root := regfgen.NewKey("CMI-CreateHive{NTUSER}", software).WithLastWrite(lastWrite)
	hive := regfgen.Build(`\??\C:\Users\jdoe\NTUSER.DAT`, root)

	dir := t.TempDir()
	userDir := filepath.Join(dir, "Users", "jdoe")
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(userDir, "NTUSER.DAT")
	if err := os.WriteFile(path, hive, 0o644); err != nil {
		t.Fatal(err)
	}

	events := parseHive(t, path)
	got, ok := eventByRegistryPath(events, `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater`)
	if !ok {
		t.Fatalf("no Run key event; got %v", registryPaths(events))
	}
	if got.User != "jdoe" {
		t.Errorf("User = %q, want jdoe (from the evidence path)", got.User)
	}
	if got.Host != "" {
		t.Errorf("Host = %q; an NTUSER.DAT records no hostname", got.Host)
	}
}

// A path with no Users/<name> segment must leave the user unknown rather
// than guessing.
func TestParse_UnknownUserStaysUnknown(t *testing.T) {
	run := regfgen.NewKey("Run").WithLastWrite(lastWrite).WithValues(
		regfgen.StringValue("Thing", `C:\thing.exe`),
	)
	cv := regfgen.NewKey("CurrentVersion", run)
	windows := regfgen.NewKey("Windows", cv)
	microsoft := regfgen.NewKey("Microsoft", windows)
	software := regfgen.NewKey("Software", microsoft)
	root := regfgen.NewKey("root", software).WithLastWrite(lastWrite)

	events := parseHive(t, writeHive(t, "NTUSER.DAT", regfgen.Build("NTUSER.DAT", root)))
	for _, e := range events {
		if e.User != "" {
			t.Errorf("User = %q, but nothing in the evidence identifies the user", e.User)
		}
	}
}

// Only targeted locations become events. A hive full of ordinary keys
// must produce none -- an event per key would be unusable noise.
func TestParse_OrdinaryKeysProduceNoEvents(t *testing.T) {
	var subs []*regfgen.Key
	for i := 0; i < 50; i++ {
		subs = append(subs, regfgen.NewKey("Ordinary"+string(rune('A'+i%26))).WithLastWrite(lastWrite).
			WithValues(regfgen.StringValue("Setting", "value")))
	}
	root := regfgen.NewKey("root", subs...).WithLastWrite(lastWrite)

	events := parseHive(t, writeHive(t, "SOFTWARE", regfgen.Build("SOFTWARE", root)))
	if len(events) != 0 {
		t.Errorf("events = %d, want 0 from a hive with no persistence locations: %v", len(events), registryPaths(events))
	}
}

// An empty persistence value is an empty slot, not evidence.
func TestParse_EmptyValueIsNotEvidence(t *testing.T) {
	run := regfgen.NewKey("Run").WithLastWrite(lastWrite).WithValues(
		regfgen.StringValue("Empty", ""),
	)
	cv := regfgen.NewKey("CurrentVersion", run)
	windows := regfgen.NewKey("Windows", cv)
	microsoft := regfgen.NewKey("Microsoft", windows)
	root := regfgen.NewKey("root", microsoft).WithLastWrite(lastWrite)

	if events := parseHive(t, writeHive(t, "SOFTWARE", regfgen.Build("SOFTWARE", root))); len(events) != 0 {
		t.Errorf("events = %d, want 0 for an empty Run value: %v", len(events), registryPaths(events))
	}
}

func TestDetect(t *testing.T) {
	p := parser.New()
	for _, name := range []string{"SYSTEM", "software", "NTUSER.DAT", "UsrClass.dat", "SAM", "SECURITY"} {
		if !p.Detect("C/Windows/System32/config/" + name) {
			t.Errorf("Detect missed %q", name)
		}
	}
	if p.Detect("EvtxECmd/out.csv") {
		t.Error("Detect claimed a CSV")
	}
	// Content detection is what finds a hive under any other name. It
	// needs a real base block: the signature alone is shared with
	// registry TRANSACTION LOGS, and matching on it catalogued 20 of
	// those as hives in one image and failed every one at import.
	if !p.DetectContent(primaryHiveHeader()) {
		t.Error("DetectContent missed a primary hive header")
	}
	if p.DetectContent([]byte("ElfFile\x00")) {
		t.Error("DetectContent accepted an event log as a hive")
	}
	for _, ft := range []uint32{1, 2, 6} {
		if p.DetectContent(transactionLogHeader(ft)) {
			t.Errorf("DetectContent accepted a transaction log (file type %d) as a hive", ft)
		}
	}
	// The name match must be confirmed by the bytes too, so SAM.LOG1 is
	// not claimed on its name either.
	if p.ConfirmContent(transactionLogHeader(6)) {
		t.Error("ConfirmContent accepted a transaction log")
	}
	if !p.ConfirmContent(primaryHiveHeader()) {
		t.Error("ConfirmContent rejected a primary hive")
	}
}

// primaryHiveHeader is a base block whose file type says primary hive.
func primaryHiveHeader() []byte {
	b := make([]byte, 512)
	copy(b[0:4], "regf")
	return b
}

// transactionLogHeader is the same block with a transaction-log file
// type, which is what SAM.LOG1 and its siblings actually carry.
func transactionLogHeader(fileType uint32) []byte {
	b := primaryHiveHeader()
	binary.LittleEndian.PutUint32(b[28:32], fileType)
	return b
}

// A hive whose name is meaningless must still be found by content, and
// still classified correctly from its embedded name.
func TestParse_RenamedHiveIsStillRecognized(t *testing.T) {
	path := writeHive(t, "blob.bin", systemHive())
	if !parser.New().DetectContent(primaryHiveHeader()) {
		t.Fatal("DetectContent should match a primary hive base block")
	}
	events := parseHive(t, path)
	if len(events) == 0 {
		t.Fatal("no events from a hive that was renamed")
	}
	if events[0].Host != "WKSTN-042" {
		t.Errorf("Host = %q; the hive's embedded name identifies it as SYSTEM regardless of the filename", events[0].Host)
	}
}

func TestParse_MalformedHiveIsAnError(t *testing.T) {
	cases := map[string][]byte{
		"not a hive":      []byte("this is a text file, not a registry hive"),
		"empty":           nil,
		"truncated":       regfgen.Truncate(systemHive(), 3000),
		"bad signature":   regfgen.CorruptSignature(systemHive()),
		"transaction log": regfgen.MakeTransactionLog(systemHive()),
		"bad root offset": regfgen.CorruptRootOffset(systemHive()),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parser.New().Parse(writeHive(t, "SYSTEM", data)); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// A cyclic subkey list must terminate rather than hang the parser.
func TestParse_CyclicHiveTerminates(t *testing.T) {
	path := writeHive(t, "SYSTEM", regfgen.CycleSubkeyList(systemHive()))

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = parser.New().Parse(path)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("parsing a hive with a cyclic subkey list did not terminate")
	}
}

func TestParse_IsDeterministic(t *testing.T) {
	path := writeHive(t, "SOFTWARE", softwareHive())
	first := parseHive(t, path)
	for i := 0; i < 3; i++ {
		again := parseHive(t, path)
		if len(again) != len(first) {
			t.Fatalf("run %d produced %d events, first run %d", i, len(again), len(first))
		}
		firstHashes := map[string]bool{}
		for _, e := range first {
			firstHashes[e.ComputeDedupHash()] = true
		}
		for _, e := range again {
			if !firstHashes[e.ComputeDedupHash()] {
				t.Fatalf("run %d produced an event absent from the first run: %+v", i, e)
			}
		}
	}
}

func registryPaths(events []model.Event) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.RegistryPath)
	}
	return out
}
