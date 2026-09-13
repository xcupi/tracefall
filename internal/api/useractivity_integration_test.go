package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/model"
	"tracefall/internal/prefetch/prefetchgen"
	"tracefall/internal/regf/regfgen"
	"tracefall/internal/shellbag/sbgen"
	"tracefall/internal/shelllink/lnkgen"
	"tracefall/internal/userassist/uagen"
)

// Phase 15 integration: UserAssist, ShellBags and the EVTX logoff events
// reaching the analyst through the whole pipeline.
//
// These are about VISIBILITY and SEMANTICS, not decoding -- the decoders
// have their own tests. What matters here is that an event produced from
// a hive is searchable in the Phase 14 forensic timeline, traceable back
// to the evidence, and never overstated.

const (
	p15ExecGUID = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"
	p15ThisPC   = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
	// The one executable the cross-artifact test tracks through four
	// independent artifacts.
	p15Executable = "updater.exe"
	p15FullPath   = `C:\Users\jdoe\AppData\Local\Temp\updater.exe`
)

var (
	p15UserAssistAt = time.Date(2021, 4, 29, 18, 17, 38, 0, time.UTC)
	p15BagWriteAt   = time.Date(2021, 4, 29, 19, 5, 0, 0, time.UTC)
	p15ProcessAt    = time.Date(2021, 4, 29, 18, 20, 0, 0, time.UTC)
	p15LogonAt      = time.Date(2021, 4, 29, 9, 0, 0, 0, time.UTC)
	p15LogoffAt     = time.Date(2021, 4, 29, 17, 30, 0, 0, time.UTC)
	p15HiveWriteAt  = time.Date(2021, 5, 1, 0, 0, 0, 0, time.UTC)
)

// p15NTUser builds an NTUSER.DAT holding a UserAssist entry for
// p15FullPath and a BagMRU tree.
func p15NTUser(t *testing.T) []byte {
	t.Helper()
	count := regfgen.NewKey("Count").WithLastWrite(p15HiveWriteAt).WithValues(
		regfgen.BinaryValue(uagen.Name(p15FullPath),
			uagen.BuildV5(uagen.Entry{SessionID: 1, RunCount: 4, FocusCount: 9,
				FocusTime: 30 * time.Second, LastExecuted: p15UserAssistAt})),
	)
	userAssist := regfgen.NewKey("UserAssist", regfgen.NewKey(p15ExecGUID, count))

	bag1 := regfgen.NewKey("1").WithLastWrite(p15BagWriteAt)
	bag0 := regfgen.NewKey("0", bag1).WithLastWrite(p15BagWriteAt).WithValues(
		regfgen.BinaryValue("1", sbgen.List(sbgen.File(sbgen.FileEntry{
			ShortName: "TEMP", LongName: "Temp", IsDirectory: true, Attributes: 0x10,
			Modified: p15BagWriteAt, ExtVersion: 9,
		}))),
	)
	bagMRU := regfgen.NewKey("BagMRU", bag0).WithLastWrite(p15BagWriteAt).WithValues(
		regfgen.BinaryValue("0", sbgen.List(sbgen.Root(p15ThisPC))),
	)

	return regfgen.Build("NTUSER.DAT", regfgen.NewKey("ROOT",
		regfgen.NewKey("Software", regfgen.NewKey("Microsoft",
			regfgen.NewKey("Windows",
				regfgen.NewKey("CurrentVersion", regfgen.NewKey("Explorer", userAssist)),
				regfgen.NewKey("Shell", bagMRU),
			))),
	).WithLastWrite(p15HiveWriteAt))
}

// p15SecurityLog builds a Security.evtx holding a logon, a process
// creation for p15FullPath, and both logoff kinds.
func p15SecurityLog() []byte {
	const ch, pr = "Security", "Microsoft-Windows-Security-Auditing"
	return evtxgen.Build([]evtxgen.Event{
		{RecordID: 1, Timestamp: p15LogonAt, Provider: pr, Channel: ch, Computer: "WKSTN-042",
			EventID: 4624, ProcessID: 4, ThreadID: 8, UserID: "S-1-5-18",
			Data: map[string]string{
				"TargetUserName": "jdoe", "LogonType": "2", "TargetLogonId": "0x1a2b3c",
				"IpAddress": "-", "WorkstationName": "WKSTN-042",
			}},
		{RecordID: 2, Timestamp: p15ProcessAt, Provider: pr, Channel: ch, Computer: "WKSTN-042",
			EventID: 4688, ProcessID: 4, ThreadID: 8, UserID: "S-1-5-18",
			Data: map[string]string{
				"NewProcessName": p15FullPath, "NewProcessId": "0x1f4",
				"ParentProcessName": `C:\Windows\explorer.exe`, "ProcessId": "0xc8",
				"SubjectUserName": "jdoe", "CommandLine": p15FullPath + " /silent",
			}},
		{RecordID: 3, Timestamp: p15LogoffAt, Provider: pr, Channel: ch, Computer: "WKSTN-042",
			EventID: 4647, ProcessID: 4, ThreadID: 8, UserID: "S-1-5-18",
			Data: map[string]string{
				"TargetUserName": "jdoe", "TargetLogonId": "0x1a2b3c", "TargetDomainName": "CORP",
			}},
		{RecordID: 4, Timestamp: p15LogoffAt.Add(time.Second), Provider: pr, Channel: ch, Computer: "WKSTN-042",
			EventID: 4634, ProcessID: 4, ThreadID: 8, UserID: "S-1-5-18",
			Data: map[string]string{
				"TargetUserName": "jdoe", "TargetLogonId": "0x1a2b3c", "LogonType": "2",
			}},
	})
}

// p15Prefetch is a Prefetch record for the tracked executable. Built
// here rather than reusing samplePrefetch, which names a different
// binary -- the cross-artifact test turns on all four artifacts
// genuinely referencing the SAME one.
func p15Prefetch() []byte {
	return prefetchgen.Build(prefetchgen.File{
		Version:        30,
		ExecutableName: "UPDATER.EXE",
		PrefetchHash:   0x11223344,
		RunCount:       4,
		LastRunTimes:   []time.Time{p15ProcessAt, p15ProcessAt.Add(-2 * time.Hour)},
		Filenames: []string{
			`\VOLUME{01d7}\USERS\JDOE\APPDATA\LOCAL\TEMP\UPDATER.EXE`,
			`\VOLUME{01d7}\WINDOWS\SYSTEM32\NTDLL.DLL`,
		},
		VolumeDevicePath: `\DEVICE\HARDDISKVOLUME2`,
		VolumeSerial:     0xCAFEBABE,
		VolumeCreated:    p15ProcessAt.Add(-5000 * time.Hour),
	})
}

// p15LNK is a shortcut whose target is the tracked executable.
func p15LNK() []byte {
	return lnkgen.Build(lnkgen.Link{
		Unicode: true, FileAttributes: 0x20,
		Creation: p15ProcessAt.Add(-time.Hour),
		Access:   p15ProcessAt,
		Write:    p15ProcessAt.Add(-time.Hour),
		FileSize: 262144, ShowCommand: 1,
		Name:          "Updater",
		RelativePath:  `..\..\AppData\Local\Temp\updater.exe`,
		WorkingDir:    `C:\Users\jdoe\AppData\Local\Temp`,
		LocalBasePath: p15FullPath,
		DriveType:     3, VolumeSerial: 0xCAFEBABE, VolumeLabel: "OSDisk",
		IDList: []lnkgen.Item{
			{Kind: "volume", Name: `C:\`},
			{Kind: "dir", Name: "Users", Attrs: 0x10},
			{Kind: "file", Name: "updater.exe", Size: 262144, Modified: p15ProcessAt, Attrs: 0x20},
		},
		TrackerMachineID: "WKSTN-042",
	})
}

// p15Catalog spans the four artifacts that independently reference the
// same executable, plus the ShellBags tree.
func p15Catalog(t *testing.T) map[string][]byte {
	t.Helper()
	return map[string][]byte{
		"Users/jdoe/NTUSER.DAT":                                           p15NTUser(t),
		"Windows/System32/winevt/Logs/Security.evtx":                      p15SecurityLog(),
		"Windows/Prefetch/UPDATER.EXE-11223344.pf":                        p15Prefetch(),
		"Users/jdoe/AppData/Roaming/Microsoft/Windows/Recent/updater.lnk": p15LNK(),
	}
}

func p15Case(t *testing.T, mux http.Handler, files map[string][]byte) string {
	t.Helper()
	c := mustCreateCase(t, mux, "Phase 15 "+t.Name())
	disc := discoverBinaryDir(t, mux, c.ID, files)
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("fixture failed to parse: %+v", imp.ParseFailures)
	}
	return c.ID
}

// ---------------- Timeline visibility ----------------

// Every new artifact must be reachable through the Phase 14 timeline:
// artifact filter, event filter, free text and provenance.
func TestPhase15_NewArtifactsAreVisibleInTheForensicTimeline(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p15Case(t, mux, p15Catalog(t))

	for _, tc := range []struct {
		artifactType string
		eventType    string
	}{
		{model.ArtifactUserAssist, model.EventUserAssistActivity},
		{model.ArtifactShellBags, model.EventShellBagNavigation},
	} {
		byArtifact := searchEvents(t, mux, caseID, vals("artifact_type", tc.artifactType))
		if byArtifact.Total == 0 {
			t.Errorf("artifact filter %q returned nothing", tc.artifactType)
			continue
		}
		for _, e := range byArtifact.Items {
			if e.ArtifactType != tc.artifactType {
				t.Errorf("filter %q returned artifact %q", tc.artifactType, e.ArtifactType)
			}
			if e.ArtifactLabel == "" || e.ArtifactLabel == tc.artifactType {
				t.Errorf("%s has no human label (got %q)", tc.artifactType, e.ArtifactLabel)
			}
		}
		byEvent := searchEvents(t, mux, caseID, vals("event_type", tc.eventType))
		if byEvent.Total == 0 {
			t.Errorf("event type filter %q returned nothing", tc.eventType)
		}
	}

	// The logoff events, both kinds, on one normalized type.
	logoffs := searchEvents(t, mux, caseID, vals("event_type", model.EventLogoff))
	if logoffs.Total != 2 {
		t.Fatalf("got %d logoff events, want 2 (4634 and 4647)", logoffs.Total)
	}
	kinds := map[string]bool{}
	for _, e := range logoffs.Items {
		kinds[e.Extra["logoff_kind"]] = true
		if e.Extra["logon_id"] == "" {
			t.Error("a logoff event does not carry the logon id that bounds the session")
		}
	}
	if len(kinds) != 2 {
		t.Errorf("both logoff kinds must stay distinguishable, got: %v", kinds)
	}
}

// The facet vocabulary must offer the new artifacts, with real labels.
func TestPhase15_NewArtifactsAppearInTheFilterVocabulary(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p15Case(t, mux, p15Catalog(t))

	var facets EventFacetsResponse
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/facets", nil, &facets)
	if rec.Code != http.StatusOK {
		t.Fatalf("facets: %d %s", rec.Code, rec.Body.String())
	}
	labels := map[string]string{}
	for _, o := range facets.ArtifactTypes {
		labels[o.Value] = o.Label
	}
	for artifactType, wantLabel := range map[string]string{
		model.ArtifactUserAssist: "UserAssist",
		model.ArtifactShellBags:  "ShellBags",
	} {
		got, ok := labels[artifactType]
		if !ok {
			t.Errorf("%q is absent from the artifact filter vocabulary", artifactType)
			continue
		}
		if got != wantLabel {
			t.Errorf("%q label = %q, want %q", artifactType, got, wantLabel)
		}
	}
}

// Free text must reach the values an analyst would actually type.
func TestPhase15_NewArtifactsAreSearchableByTheirContent(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p15Case(t, mux, p15Catalog(t))

	for _, tc := range []struct {
		name, term, wantArtifact string
	}{
		{"the UserAssist target path", "updater.exe", model.ArtifactUserAssist},
		{"a reconstructed ShellBag path", "Temp", model.ArtifactShellBags},
	} {
		res := searchEvents(t, mux, caseID, vals("q", tc.term))
		if res.Total == 0 {
			t.Errorf("%s: free text %q matched nothing", tc.name, tc.term)
			continue
		}
		found := false
		for _, e := range res.Items {
			if e.ArtifactType == tc.wantArtifact {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: %q did not reach a %s event", tc.name, tc.term, tc.wantArtifact)
		}
	}

	// A path-scoped search must reach the reconstructed ShellBag path.
	byPath := searchEvents(t, mux, caseID, vals("path", "Temp"))
	if byPath.Total == 0 {
		t.Error("path-scoped search did not reach the reconstructed ShellBag path")
	}
	// A username search must reach hive-derived events.
	byUser := searchEvents(t, mux, caseID, vals("q", "jdoe"))
	if byUser.Total == 0 {
		t.Error("searching the username matched nothing")
	}
	// An event ID search must reach the EVTX records.
	byID := searchEvents(t, mux, caseID, vals("q", "4688"))
	if byID.Total == 0 {
		t.Error("searching event ID 4688 matched nothing")
	}
}

// Date filtering must work for the new events like any other.
func TestPhase15_NewArtifactsAreFoundByDate(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p15Case(t, mux, p15Catalog(t))

	day := searchEvents(t, mux, caseID, vals("date", "2021-04-29"))
	if day.Total == 0 {
		t.Fatal("the acceptance day returned nothing")
	}
	kinds := map[string]bool{}
	for _, e := range day.Items {
		kinds[e.ArtifactType] = true
	}
	for _, want := range []string{model.ArtifactUserAssist, model.ArtifactShellBags} {
		if !kinds[want] {
			t.Errorf("%s is not reachable by date filter", want)
		}
	}
}

// ---------------- Provenance ----------------

func TestPhase15_NewEventsTraceBackToTheirHive(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p15Case(t, mux, p15Catalog(t))

	for _, artifactType := range []string{model.ArtifactUserAssist, model.ArtifactShellBags} {
		res := searchEvents(t, mux, caseID, vals("artifact_type", artifactType, "page_size", "100"))
		if res.Total == 0 {
			t.Fatalf("no %s events", artifactType)
		}
		for _, e := range res.Items {
			var prov EventProvenance
			rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/"+e.ID, nil, &prov)
			if rec.Code != http.StatusOK {
				t.Fatalf("provenance for %s: %d %s", e.ID, rec.Code, rec.Body.String())
			}
			if prov.RawEvidence.Raw == "" {
				t.Errorf("%s event %s has no raw record", artifactType, e.ID)
			}
			// The chain must reach the hive FILE, which stays classified
			// as a registry hive -- that is what was collected and hashed.
			if !strings.Contains(strings.ToUpper(prov.SourceFile.Path), "NTUSER.DAT") {
				t.Errorf("%s event does not resolve to the hive it came from: %q",
					artifactType, prov.SourceFile.Path)
			}
			if prov.SourceFile.ArtifactType != model.ArtifactRegistryHive {
				t.Errorf("the source FILE is classified %q; it must stay a registry hive",
					prov.SourceFile.ArtifactType)
			}
			if prov.Collection == nil || prov.Collection.CollectionID == "" {
				t.Errorf("%s event does not resolve to a collection", artifactType)
			}
		}
	}
}

// ---------------- Cross-artifact corroboration (spec 21) ----------------

// The same executable appears in four independent artifacts. Tracefall
// must store four DISTINCT events -- merging them would destroy the
// corroboration that makes them valuable.
func TestPhase15_SameExecutableInFourArtifactsStaysFourEvents(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p15Case(t, mux, p15Catalog(t))

	res := searchEvents(t, mux, caseID, vals("q", p15Executable, "page_size", "100"))
	if res.Total == 0 {
		t.Fatal("the executable was not found in any artifact")
	}

	byArtifact := map[string][]TimelineEvent{}
	for _, e := range res.Items {
		byArtifact[e.ArtifactType] = append(byArtifact[e.ArtifactType], e)
	}
	want := []string{
		model.ArtifactUserAssist,      // the shell launched it
		model.ArtifactWindowsEventLog, // a process was created for it
		model.ArtifactPrefetch,        // Windows prefetched it
		model.ArtifactLNK,             // a shortcut references it
	}
	for _, artifactType := range want {
		if len(byArtifact[artifactType]) == 0 {
			t.Errorf("%s contributes no event mentioning %s", artifactType, p15Executable)
		}
	}

	// Every event must be distinct: its own id, and its own source file.
	ids := map[string]bool{}
	sources := map[string]bool{}
	for _, e := range res.Items {
		if ids[e.ID] {
			t.Errorf("event id %s appears twice", e.ID)
		}
		ids[e.ID] = true
		sources[e.SourceFileID] = true
	}
	if len(sources) < len(want) {
		t.Errorf("the matching events come from %d source files; four independent artifacts should give four",
			len(sources))
	}

	// And their forensic weight must NOT be flattened. Only the EVTX
	// record is a process-creation event.
	for _, e := range res.Items {
		switch e.ArtifactType {
		case model.ArtifactWindowsEventLog:
			if e.EventType != model.EventProcessCreate {
				continue // other records in the same log
			}
		case model.ArtifactUserAssist:
			if e.EventType == model.EventProcessCreate {
				t.Error("a UserAssist entry was emitted as a process-creation event")
			}
		case model.ArtifactLNK:
			if e.EventType == model.EventProcessCreate {
				t.Error("an LNK was emitted as a process-creation event")
			}
		}
	}
}

// ---------------- Layer boundaries (spec 21, 22) ----------------

// Scenario A: a raw artifact produces events and NOTHING else.
func TestPhase15_UserActivityAloneProducesNoFindingOrInvestigation(t *testing.T) {
	mux := newTestRouter(t)
	// Only the hive: UserAssist and ShellBags, nothing a rule fires on.
	caseID := p15Case(t, mux, map[string][]byte{
		"Users/jdoe/NTUSER.DAT": p15NTUser(t),
	})

	events := searchEvents(t, mux, caseID, vals("page_size", "100"))
	if events.Total == 0 {
		t.Fatal("the hive produced no events")
	}

	if rec := doJSON(t, mux, "POST", "/api/cases/"+caseID+"/analyze", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("analyze: %d %s", rec.Code, rec.Body.String())
	}

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings)
	if len(findings) != 0 {
		t.Errorf("UserAssist/ShellBags evidence alone produced %d findings; these are evidence, not detections", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected finding: %s", f.Title)
		}
	}
	var investigations []model.Investigation
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/investigations", nil, &investigations)
	if len(investigations) != 0 {
		t.Errorf("produced %d investigations", len(investigations))
	}

	// The events themselves must still be there and carry no finding.
	after := searchEvents(t, mux, caseID, vals("page_size", "100"))
	if after.Total != events.Total {
		t.Errorf("analysis changed the event count from %d to %d", events.Total, after.Total)
	}
	for _, e := range after.Items {
		if len(e.Findings) != 0 {
			t.Errorf("event %s is cited by a finding", e.ID)
		}
	}
}

// PowerShell history alone must likewise produce events but no finding.
func TestPhase15_PowerShellHistoryAloneProducesNoFinding(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p15Case(t, mux, map[string][]byte{
		"Users/jdoe/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt": []byte(
			"Get-Process\nGet-ChildItem C:\\Users\ncd Documents\nwhoami\n"),
	})

	events := searchEvents(t, mux, caseID, vals("page_size", "100"))
	if events.Total != 4 {
		t.Fatalf("got %d events, want 4 commands", events.Total)
	}
	// No fabricated timestamps: PSReadLine records none.
	for _, e := range events.Items {
		if e.TimestampKnown {
			t.Errorf("a PowerShell history command carries a timestamp (%s); the artifact records none", e.Timestamp)
		}
	}

	doJSON(t, mux, "POST", "/api/cases/"+caseID+"/analyze", nil, nil)
	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings)
	if len(findings) != 0 {
		t.Errorf("benign PowerShell history produced %d findings", len(findings))
	}
}

// Scenario C, and the lifecycle rule: deleting the evidence removes the
// events and invalidates anything derived from them.
func TestPhase15_DeletingTheHiveRemovesItsEvents(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "hive deletion")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Users/jdoe/NTUSER.DAT": p15NTUser(t),
	})
	importAllFrom(t, mux, c.ID, disc)

	before := searchEvents(t, mux, c.ID, nil)
	if before.Total == 0 {
		t.Fatal("no events to delete")
	}

	rec := doJSON(t, mux, "DELETE", "/api/cases/"+c.ID+"/collections/"+disc.Collection.ID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("deleting: %d %s", rec.Code, rec.Body.String())
	}

	after := searchEvents(t, mux, c.ID, nil)
	if after.Total != 0 {
		t.Errorf("%d events survived deletion of the hive they came from", after.Total)
	}
	for _, artifactType := range []string{model.ArtifactUserAssist, model.ArtifactShellBags} {
		if n := searchEvents(t, mux, c.ID, vals("artifact_type", artifactType)).Total; n != 0 {
			t.Errorf("%d %s events remain", n, artifactType)
		}
	}
}

// ---------------- Semantics as the analyst sees them ----------------

// The acceptance criterion: for every new artifact, the analyst can read
// what it actually proves off the event itself.
func TestPhase15_EveryNewEventStatesWhatItProves(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p15Case(t, mux, p15Catalog(t))

	res := searchEvents(t, mux, caseID, vals("page_size", "100"))
	if res.Total == 0 {
		t.Fatal("no events")
	}
	checked := map[string]bool{}
	for _, e := range res.Items {
		switch e.ArtifactType {
		case model.ArtifactUserAssist, model.ArtifactShellBags:
		default:
			continue
		}
		checked[e.ArtifactType] = true

		if e.Extra["evidence_meaning"] == "" {
			t.Errorf("%s event %s does not state what the artifact proves", e.ArtifactType, e.ID)
		}
		if e.Extra["timestamp_meaning"] == "" {
			t.Errorf("%s event %s does not state what its timestamp means", e.ArtifactType, e.ID)
		}
		if e.Extra["user_context"] == "" {
			t.Errorf("%s event %s does not state whose activity it is", e.ArtifactType, e.ID)
		}
		if e.Confidence <= 0 || e.Confidence > 1 {
			t.Errorf("%s event %s has confidence %v", e.ArtifactType, e.ID, e.Confidence)
		}
		// No new artifact may claim execution in its own event type.
		if e.EventType == model.EventProcessCreate {
			t.Errorf("%s was emitted as a process-creation event", e.ArtifactType)
		}
	}
	for _, want := range []string{model.ArtifactUserAssist, model.ArtifactShellBags} {
		if !checked[want] {
			t.Errorf("no %s event was present to check", want)
		}
	}
}

// A ShellBag must never be searchable as though it were an execution.
func TestPhase15_ShellBagsAreNotExecutionEvidence(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p15Case(t, mux, p15Catalog(t))

	res := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactShellBags, "page_size", "100"))
	if res.Total == 0 {
		t.Fatal("no ShellBags events")
	}
	for _, e := range res.Items {
		if e.ProcessName != "" {
			t.Errorf("a ShellBag carries ProcessName %q", e.ProcessName)
		}
		if e.CommandLine != "" {
			t.Errorf("a ShellBag carries CommandLine %q", e.CommandLine)
		}
		meaning := e.Extra["evidence_meaning"]
		if !strings.Contains(meaning, "not evidence that anything was executed") {
			t.Errorf("evidence_meaning does not disclaim execution: %q", meaning)
		}
	}
}

// Long values must survive the API intact, for the UI to truncate.
func TestPhase15_LongReconstructedPathsSurviveIntact(t *testing.T) {
	mux := newTestRouter(t)
	longSegment := strings.Repeat("deep-folder-", 20)

	bag1 := regfgen.NewKey("1").WithLastWrite(p15BagWriteAt)
	bag0 := regfgen.NewKey("0", bag1).WithLastWrite(p15BagWriteAt).WithValues(
		regfgen.BinaryValue("1", sbgen.List(sbgen.File(sbgen.FileEntry{
			ShortName: "DEEP~1", LongName: longSegment, IsDirectory: true, ExtVersion: 9,
		}))),
	)
	bagMRU := regfgen.NewKey("BagMRU", bag0).WithLastWrite(p15BagWriteAt).WithValues(
		regfgen.BinaryValue("0", sbgen.List(sbgen.Root(p15ThisPC))),
	)
	hive := regfgen.Build("NTUSER.DAT", regfgen.NewKey("ROOT",
		regfgen.NewKey("Software", regfgen.NewKey("Microsoft",
			regfgen.NewKey("Windows", regfgen.NewKey("Shell", bagMRU)))),
	).WithLastWrite(p15HiveWriteAt))

	caseID := p15Case(t, mux, map[string][]byte{"Users/jdoe/NTUSER.DAT": hive})
	res := searchEvents(t, mux, caseID, vals("q", "deep-folder", "page_size", "100"))
	if res.Total == 0 {
		t.Fatal("the long path was not searchable")
	}
	found := false
	for _, e := range res.Items {
		if strings.Contains(e.Extra["reconstructed_path"], longSegment) {
			found = true
		}
	}
	if !found {
		t.Error("the long reconstructed path came back altered or truncated by the API")
	}
}

// A file that merely resembles a hive must not be claimed as one.
func TestPhase15_NonHiveIsNotParsedAsUserActivity(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "decoy hive")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		// Named like a hive, but plain text.
		"Users/jdoe/NTUSER.DAT": []byte("this file is named NTUSER.DAT but is not a registry hive at all"),
	})
	// UNRECOGNIZED, not "claimed and then broken" (changed in Phase 18).
	//
	// This test previously asserted the opposite: the file was claimed on
	// its name, counted as supported evidence, and reported as a parse
	// failure. That reads to an analyst as "your NTUSER.DAT is corrupt",
	// which is a false statement about the evidence -- no hive was ever
	// there. A name is now a hint that the header has to confirm; see
	// parsers.ContentConfirmer. The decoy still produces no events, which
	// is what this test exists to protect.
	for _, f := range disc.SourceFiles {
		if strings.Contains(f.Path, "NTUSER.DAT") {
			if f.Supported {
				t.Errorf("a text file named NTUSER.DAT was claimed as supported evidence by %q", f.Parser)
			}
			if f.Parser != "" {
				t.Errorf("a text file named NTUSER.DAT was assigned parser %q", f.Parser)
			}
		}
	}

	// Nothing is importable, so there is nothing to fail: the analyst is
	// told the file was not recognized rather than that a hive broke.
	if ids := getEvidenceIDs(t, mux, c.ID, disc.Collection.ID, nil); len(ids) != 0 {
		t.Errorf("%d files were selectable for import from a collection holding only a decoy", len(ids))
	}
	if n := searchEvents(t, mux, c.ID, nil).Total; n != 0 {
		t.Errorf("a decoy produced %d events", n)
	}
}
