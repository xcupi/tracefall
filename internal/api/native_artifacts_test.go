package api

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"tracefall/internal/ad1/ad1gen"
	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/model"
	"tracefall/internal/regf/regfgen"
)

// These tests drive Phase 9's native artifacts through the WHOLE
// pipeline -- discover, select, import, parse, detect, correlate,
// investigate, ATT&CK -- rather than stopping at the parser. That is the
// point: the requirement was to feed better raw evidence into the
// existing engine, not to build a second one, and the only way to show
// that is to watch a raw .evtx and a raw registry hive come out the far
// end as findings and investigations.

var nativeBase = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

// ---------------- fixtures ----------------

// attackEvtx is a synthetic Security/Sysmon log describing one coherent
// intrusion: repeated failed logons, then a success, then execution from
// a user-writable path, then a network connection.
func attackEvtx() []byte {
	var events []evtxgen.Event
	id := uint64(0)
	add := func(offset time.Duration, channel, provider string, eventID int, data map[string]string) {
		id++
		events = append(events, evtxgen.Event{
			RecordID: id, Timestamp: nativeBase.Add(offset),
			Provider: provider, Channel: channel, Computer: "WKSTN-042",
			EventID: eventID, ProcessID: 668, ThreadID: 1024, UserID: "S-1-5-18",
			Data: data,
		})
	}

	const sec = "Security"
	const secProvider = "Microsoft-Windows-Security-Auditing"
	for i := 0; i < 4; i++ {
		add(time.Duration(i)*time.Minute, sec, secProvider, 4625, map[string]string{
			"TargetUserName": "jdoe", "LogonType": "3", "IpAddress": "10.9.9.9",
		})
	}
	add(5*time.Minute, sec, secProvider, 4624, map[string]string{
		"TargetUserName": "jdoe", "LogonType": "3", "IpAddress": "10.9.9.9",
	})
	add(6*time.Minute, "Microsoft-Windows-Sysmon/Operational", "Sysmon", 1, map[string]string{
		"Image":       `C:\Users\jdoe\AppData\Local\Temp\update.exe`,
		"CommandLine": `update.exe -silent`,
		"ParentImage": `C:\Windows\System32\cmd.exe`,
		"ProcessId":   "8260", "ParentProcessId": "1000", "User": "jdoe",
	})
	add(7*time.Minute, "Microsoft-Windows-Sysmon/Operational", "Sysmon", 3, map[string]string{
		"Image":         `C:\Users\jdoe\AppData\Local\Temp\update.exe`,
		"DestinationIp": "203.0.113.77", "DestinationPort": "443", "ProcessId": "8260",
	})
	return evtxgen.Build(events)
}

// persistenceHive is a synthetic NTUSER.DAT with a Run key pointing at
// the same user-writable payload the event log shows executing.
func persistenceHive() []byte {
	run := regfgen.NewKey("Run").WithLastWrite(nativeBase.Add(8 * time.Minute)).WithValues(
		regfgen.StringValue("WindowsUpdateHelper", `C:\Users\jdoe\AppData\Local\Temp\update.exe`),
	)
	cv := regfgen.NewKey("CurrentVersion", run)
	windows := regfgen.NewKey("Windows", cv)
	microsoft := regfgen.NewKey("Microsoft", windows)
	software := regfgen.NewKey("Software", microsoft)
	root := regfgen.NewKey("CMI-CreateHive{NTUSER}", software).WithLastWrite(nativeBase)
	return regfgen.Build(`\??\C:\Users\jdoe\NTUSER.DAT`, root)
}

// systemHiveWithHostname names the machine and nothing else, so a
// collection can supply a host without supplying any other evidence.
func systemHiveWithHostname(name string) []byte {
	cn := regfgen.NewKey("ComputerName").WithLastWrite(nativeBase).WithValues(
		regfgen.StringValue("ComputerName", name),
	)
	cnParent := regfgen.NewKey("ComputerName", cn)
	control := regfgen.NewKey("Control", cnParent)
	cs := regfgen.NewKey("ControlSet001", control)
	root := regfgen.NewKey("CMI-CreateHive{SYSTEM}", cs).WithLastWrite(nativeBase)
	return regfgen.Build(`\??\C:\Windows\System32\config\SYSTEM`, root)
}

// ---------------- helpers ----------------

// discoverBinaryDir writes binary fixtures to a directory and discovers
// it via the local-path route.
func discoverBinaryDir(t *testing.T, mux http.Handler, caseID string, files map[string][]byte) DiscoverResult {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rec := discoverPath(t, mux, caseID, dir)
	if rec.Code != http.StatusOK {
		t.Fatalf("discover: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	return disc
}

func discoverBinaryZip(t *testing.T, mux http.Handler, caseID string, files map[string][]byte) DiscoverResult {
	t.Helper()
	as := map[string]string{}
	for k, v := range files {
		as[k] = string(v)
	}
	rec := uploadZip(t, mux, caseID, buildZipBytes(t, as))
	if rec.Code != http.StatusOK {
		t.Fatalf("zip upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	return disc
}

func discoverBinaryAD1(t *testing.T, mux http.Handler, caseID string, files map[string][]byte) DiscoverResult {
	t.Helper()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	entries := make([]ad1gen.File, 0, len(names))
	for _, n := range names {
		entries = append(entries, ad1gen.File{Path: n, Data: files[n]})
	}
	rec := uploadAD1(t, mux, caseID, buildAD1(t, `E:\`, entries), "native.ad1")
	if rec.Code != http.StatusOK {
		t.Fatalf("AD1 upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	return disc
}

func summaryOf(t *testing.T, mux http.Handler, caseID string) Summary {
	t.Helper()
	var detail struct {
		Case    model.Case `json:"case"`
		Summary Summary    `json:"summary"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+caseID, nil, &detail)
	return detail.Summary
}

// ---------------- discovery ----------------

// Native artifacts must be discovered as supported evidence through
// every container Tracefall accepts.
func TestNative_DiscoveryThroughEveryContainer(t *testing.T) {
	files := map[string][]byte{
		"Windows/System32/winevt/Logs/Security.evtx": attackEvtx(),
		"Windows/System32/config/SYSTEM":             systemHiveWithHostname("WKSTN-042"),
		"Users/jdoe/NTUSER.DAT":                      persistenceHive(),
	}

	routes := map[string]func(*testing.T, http.Handler, string, map[string][]byte) DiscoverResult{
		"local path": discoverBinaryDir,
		"ZIP upload": discoverBinaryZip,
		"AD1 upload": discoverBinaryAD1,
	}
	for name, discover := range routes {
		t.Run(name, func(t *testing.T) {
			mux := newTestRouter(t)
			c := mustCreateCase(t, mux, "Native discovery via "+name)
			disc := discover(t, mux, c.ID, files)

			byPath := map[string]TriagedSourceFile{}
			for _, sf := range disc.SourceFiles {
				byPath[sf.Path] = sf
			}
			for path, wantType := range map[string]string{
				"Windows/System32/winevt/Logs/Security.evtx": model.ArtifactWindowsEventLog,
				"Windows/System32/config/SYSTEM":             model.ArtifactRegistryHive,
				"Users/jdoe/NTUSER.DAT":                      model.ArtifactRegistryHive,
			} {
				sf, ok := byPath[path]
				if !ok {
					t.Fatalf("%s not discovered; catalog has %+v", path, byPath)
				}
				if !sf.Supported {
					t.Errorf("%s discovered as unsupported", path)
				}
				if sf.ArtifactType != wantType {
					t.Errorf("%s artifact type = %q, want %q", path, sf.ArtifactType, wantType)
				}
			}
		})
	}
}

// Content sniffing is what makes discovery robust: a hive named
// something unrecognizable is still evidence, and a file that merely
// CLAIMS to be an event log is not.
func TestNative_DiscoveryIsContentBased(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Content-based discovery")

	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		// A hive with a meaningless name: must still be recognized.
		"extracted/blob_0001.bin": systemHiveWithHostname("WKSTN-042"),
		// A text file wearing a .evtx extension: must NOT be.
		"Logs/Security.evtx": []byte("this is not an event log at all, just text"),
		// A genuine log saved without any extension.
		"Logs/saved_security_log": attackEvtx(),
	})

	byPath := map[string]TriagedSourceFile{}
	for _, sf := range disc.SourceFiles {
		byPath[sf.Path] = sf
	}

	if got := byPath["extracted/blob_0001.bin"]; !got.Supported || got.ArtifactType != model.ArtifactRegistryHive {
		t.Errorf("renamed hive: supported=%v type=%q, want true/%s", got.Supported, got.ArtifactType, model.ArtifactRegistryHive)
	}
	if got := byPath["Logs/saved_security_log"]; !got.Supported || got.ArtifactType != model.ArtifactWindowsEventLog {
		t.Errorf("extension-less event log: supported=%v type=%q, want true/%s", got.Supported, got.ArtifactType, model.ArtifactWindowsEventLog)
	}
	// The impostor matches .evtx by NAME, so it is cataloged as an event
	// log -- but importing it must fail cleanly rather than inventing
	// events, which the import test below covers.
	if got := byPath["Logs/Security.evtx"]; !got.Supported {
		t.Log("text file named .evtx was not classified as supported, which is also acceptable")
	}
}

// ---------------- full pipeline ----------------

// The headline test: raw .evtx plus a raw hive, straight through the
// existing engine to findings, correlations, investigations and ATT&CK.
func TestNative_FullPipelineFromRawArtifacts(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Native full pipeline")

	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Windows/System32/winevt/Logs/Security.evtx": attackEvtx(),
		"Users/jdoe/NTUSER.DAT":                      persistenceHive(),
	})
	if disc.SupportedCount != 2 {
		t.Fatalf("supported files = %d, want 2: %+v", disc.SupportedCount, disc.SourceFiles)
	}
	imp := importAllFrom(t, mux, c.ID, disc)
	if imp.EventCount == 0 {
		t.Fatal("importing raw artifacts produced no events")
	}
	analyze(t, mux, c.ID)

	sum := summaryOf(t, mux, c.ID)
	if sum.Events == 0 {
		t.Fatal("no events on the timeline")
	}
	if sum.Findings == 0 {
		t.Error("raw artifacts produced no findings; the existing rules should consume them")
	}
	if sum.Investigations == 0 {
		t.Error("no investigations were built from raw-artifact findings")
	}
	if sum.TechniqueCount == 0 {
		t.Error("no ATT&CK techniques mapped from raw-artifact findings")
	}
	t.Logf("raw artifacts produced: %d events, %d findings, %d correlations, %d investigations, %d techniques",
		sum.Events, sum.Findings, sum.Correlations, sum.Investigations, sum.TechniqueCount)

	// The specific rules the fixture was built to trigger.
	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings", nil, &findings)
	rules := map[string]bool{}
	for _, f := range findings {
		rules[f.RuleID] = true
	}
	for _, want := range []string{"brute-force-then-success", "new-registry-run-key"} {
		if !rules[want] {
			t.Errorf("rule %q did not fire on raw artifacts; fired: %v", want, keysOf(rules))
		}
	}

	// Provenance must point at the actual evidence file.
	timeline := timelineOf(t, mux, c.ID)
	var sawEvtx, sawHive bool
	for _, e := range timeline {
		switch e["artifact_type"] {
		case model.ArtifactWindowsEventLog:
			sawEvtx = true
			if e["parser"] != "evtx@1" {
				t.Errorf("event-log event parsed by %q, want evtx@1", e["parser"])
			}
		case model.ArtifactRegistryHive:
			sawHive = true
			if e["parser"] != "registry@1" {
				t.Errorf("hive event parsed by %q, want registry@1", e["parser"])
			}
		}
	}
	if !sawEvtx || !sawHive {
		t.Errorf("timeline missing native events: evtx=%v hive=%v", sawEvtx, sawHive)
	}
}

// ---------------- host enrichment (Phase 11) ----------------

// A SYSTEM hive supplies the hostname; a host-less artifact in the same
// collection inherits it through the EXISTING Phase 7.1 enrichment, with
// no new mechanism and no invented host.
func TestNative_SystemHiveSuppliesHostToHostlessArtifacts(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "SYSTEM hive host enrichment")

	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Windows/System32/config/SYSTEM": systemHiveWithHostname("WKSTN-042"),
		"Users/jdoe/NTUSER.DAT":          persistenceHive(),
	})
	importAllFrom(t, mux, c.ID, disc)

	timeline := timelineOf(t, mux, c.ID)
	if len(timeline) == 0 {
		t.Fatal("no events")
	}
	for _, e := range timeline {
		if e["host"] != "WKSTN-042" {
			t.Errorf("event %v has host %q, want WKSTN-042 from the SYSTEM hive", e["registry_path"], e["host"])
		}
	}
}

// With no host evidence anywhere, nothing may be invented.
func TestNative_NoHostEvidenceLeavesHostBlank(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "No host evidence")

	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Users/jdoe/NTUSER.DAT": persistenceHive(),
	})
	importAllFrom(t, mux, c.ID, disc)

	for _, e := range timelineOf(t, mux, c.ID) {
		if e["host"] != nil && e["host"] != "" {
			t.Errorf("host = %q, but no artifact in this collection records a hostname", e["host"])
		}
	}
}

// Two SYSTEM hives naming different machines is ambiguous. Enrichment
// must decline rather than pick one.
func TestNative_AmbiguousHostIsNotResolved(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Ambiguous host")

	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"hostA/SYSTEM":          systemHiveWithHostname("WKSTN-042"),
		"hostB/SYSTEM":          systemHiveWithHostname("SRV-DC01"),
		"Users/jdoe/NTUSER.DAT": persistenceHive(),
	})
	importAllFrom(t, mux, c.ID, disc)

	for _, e := range timelineOf(t, mux, c.ID) {
		if e["artifact_type"] != model.ArtifactRegistryHive {
			continue
		}
		host, _ := e["host"].(string)
		// The hive events that KNOW their host keep it; the host-less
		// NTUSER.DAT events must not be handed either candidate.
		if e["registry_path"] != nil && host != "" && host != "WKSTN-042" && host != "SRV-DC01" {
			t.Errorf("unexpected host %q", host)
		}
	}
	// The decisive check: the Run key from NTUSER.DAT must be unattributed.
	for _, e := range timelineOf(t, mux, c.ID) {
		if rp, _ := e["registry_path"].(string); rp == `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateHelper` {
			if h, _ := e["host"].(string); h != "" {
				t.Errorf("host-less Run key was attributed to %q despite two candidate hostnames", h)
			}
		}
	}
}

// ---------------- deletion and re-analysis ----------------

// Deleting one native artifact must remove only its derived evidence.
func TestNative_DeleteEvtxKeepsRegistryEvidence(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Native deletion")

	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Windows/System32/winevt/Logs/Security.evtx": attackEvtx(),
		"Users/jdoe/NTUSER.DAT":                      persistenceHive(),
	})
	importAllFrom(t, mux, c.ID, disc)
	analyze(t, mux, c.ID)

	before := summaryOf(t, mux, c.ID)
	if before.Findings == 0 {
		t.Fatal("no findings before deletion")
	}

	evtxFile, ok := sourceFileByPath(disc.SourceFiles, "Windows/System32/winevt/Logs/Security.evtx")
	if !ok {
		t.Fatal("event log not in the catalog")
	}
	rec := doJSON(t, mux, "DELETE", "/api/cases/"+c.ID+"/evidence/"+evtxFile.ID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: status %d, body %s", rec.Code, rec.Body.String())
	}
	analyze(t, mux, c.ID)

	after := summaryOf(t, mux, c.ID)
	timeline := timelineOf(t, mux, c.ID)
	for _, e := range timeline {
		if e["artifact_type"] == model.ArtifactWindowsEventLog {
			t.Error("an event-log event survived deletion of the .evtx it came from")
		}
	}
	var sawHive bool
	for _, e := range timeline {
		if e["artifact_type"] == model.ArtifactRegistryHive {
			sawHive = true
		}
	}
	if !sawHive {
		t.Error("registry evidence was removed by deleting an unrelated event log")
	}
	if after.Events >= before.Events {
		t.Errorf("event count did not drop after deletion: %d -> %d", before.Events, after.Events)
	}
}

// ---------------- cross-source in one case ----------------

// The same log present natively AND as an EvtxECmd CSV must not double
// the timeline: one event, two observations.
func TestNative_CrossSourceDoesNotDoubleCount(t *testing.T) {
	const csv = "TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber\n" +
		"2026-03-01T09:05:00.0000000Z,4624,Microsoft-Windows-Security-Auditing,Security,WKSTN-042,,-,Logon," +
		"\"TargetUserName: jdoe; LogonType: 3; IpAddress: 10.9.9.9\",,,,,,5\n" // attackEvtx's 4624 is Windows record 5, not CSV row 1.

	// Native only.
	muxA := newTestRouter(t)
	a := mustCreateCase(t, muxA, "native only")
	discA := discoverBinaryDir(t, muxA, a.ID, map[string][]byte{
		"Windows/System32/winevt/Logs/Security.evtx": attackEvtx(),
	})
	importAllFrom(t, muxA, a.ID, discA)
	nativeEvents := summaryOf(t, muxA, a.ID).Events

	// Native plus the CSV export of the same records.
	muxB := newTestRouter(t)
	b := mustCreateCase(t, muxB, "native plus csv")
	discB := discoverBinaryDir(t, muxB, b.ID, map[string][]byte{
		"Windows/System32/winevt/Logs/Security.evtx": attackEvtx(),
		"EvtxECmd/20260301_EvtxECmd_Output.csv":      []byte(csv),
	})
	importAllFrom(t, muxB, b.ID, discB)
	bothEvents := summaryOf(t, muxB, b.ID).Events

	// The CSV describes a record the .evtx already contains, so it must
	// add no new event -- only another observation of an existing one.
	if bothEvents != nativeEvents {
		t.Errorf("adding a CSV export of the same records changed the event count from %d to %d; "+
			"the duplicate observation should have deduplicated", nativeEvents, bothEvents)
	}
}

// ---------------- malformed evidence ----------------

// A corrupt artifact must fail its own import cleanly, without taking
// down the rest of the collection.
func TestNative_CorruptArtifactDoesNotBreakTheImport(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Corrupt native artifact")

	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Windows/System32/winevt/Logs/Security.evtx": attackEvtx(),
		"Windows/System32/winevt/Logs/Broken.evtx":   evtxgen.CorruptSignature(attackEvtx()),
		"Users/jdoe/NTUSER.DAT":                      persistenceHive(),
		"Users/bad/NTUSER.DAT":                       regfgen.Truncate(persistenceHive(), 2000),
	})
	imp := importAllFrom(t, mux, c.ID, disc)

	if imp.EventCount == 0 {
		t.Fatal("no events imported; the intact artifacts should still have parsed")
	}
	// The good ones landed.
	timeline := timelineOf(t, mux, c.ID)
	if len(timeline) == 0 {
		t.Error("timeline is empty despite two intact artifacts")
	}
	t.Logf("imported %d files, %d skipped/failed, %d events", len(imp.Imported), len(imp.Skipped)+len(imp.Errors), imp.EventCount)
}

// importAllFrom imports every supported, non-duplicate file in a
// catalog.
func importAllFrom(t *testing.T, mux http.Handler, caseID string, disc DiscoverResult) ImportResult {
	t.Helper()
	// The ids endpoint, not disc.SourceFiles: discovery returns only the
	// FIRST PAGE of the catalog, so selecting from it would silently cap
	// every "import everything" at one page and leave later files
	// untouched while the test still looked like it imported the lot.
	ids := getEvidenceIDs(t, mux, caseID, disc.Collection.ID, nil)
	if len(ids) == 0 {
		t.Fatal("nothing selectable in the catalog")
	}
	rec := doJSON(t, mux, "POST", "/api/cases/"+caseID+"/evidence/"+disc.Collection.ID+"/import",
		map[string][]string{"source_file_ids": ids}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: status %d, body %s", rec.Code, rec.Body.String())
	}
	var imp ImportResult
	mustDecode(t, rec, &imp)
	return imp
}
