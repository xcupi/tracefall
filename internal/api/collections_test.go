package api

import (
	"net/http"
	"testing"

	"tracefall/internal/model"
)

// evtxRow builds one EvtxECmd CSV data row with the given payload
// key:value pairs joined into PayloadData1, matching the format
// internal/parsers/evtxcsv expects (see that package's tests for the
// same convention).
func evtxRow(timeCreated, eventID, channel, computer, user, payload, recordNum string) string {
	provider := "Microsoft-Windows-Security-Auditing"
	if channel == "Microsoft-Windows-Sysmon/Operational" {
		provider = "Sysmon"
	}
	return timeCreated + "," + eventID + "," + provider + "," + channel + "," + computer + "," + user + ",-,," +
		`"` + payload + `"` + ",,,,,," + recordNum + "\n"
}

const evtxHeader = "TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber\n"

// buildExecutionCollectionZip is "Collection #1" in the cross-collection
// scenario below: a logon, then Office spawning PowerShell with an
// encoded command, then PowerShell spawning a payload, then that payload
// beaconing out. No persistence evidence at all -- that arrives later,
// in a separate collection.
func buildExecutionCollectionZip(t *testing.T) []byte {
	t.Helper()
	csv := evtxHeader +
		evtxRow("2026-01-15T09:00:00.0000000Z", "4624", "Security", "WKSTN-042", "jdoe",
			"TargetUserName: jdoe; LogonType: 2", "1") +
		evtxRow("2026-01-15T09:14:22.0000000Z", "4688", "Security", "WKSTN-042", "",
			`NewProcessId: 0x1A2C; NewProcessName: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE; ParentProcessName: C:\Windows\explorer.exe; ProcessId: 0x0D10; CommandLine: WINWORD.EXE; SubjectUserName: jdoe`, "2") +
		evtxRow("2026-01-15T09:14:47.0000000Z", "4688", "Security", "WKSTN-042", "",
			`NewProcessId: 0x1F30; NewProcessName: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe; ParentProcessName: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE; ProcessId: 0x1A2C; CommandLine: powershell.exe -nop -w hidden -enc AAAA; SubjectUserName: jdoe`, "3") +
		evtxRow("2026-01-15T09:15:10.0000000Z", "4688", "Security", "WKSTN-042", "",
			`NewProcessId: 0x2044; NewProcessName: C:\Users\jdoe\AppData\Local\Temp\update.exe; ParentProcessName: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe; ProcessId: 0x1F30; CommandLine: update.exe -silent; SubjectUserName: jdoe`, "4") +
		evtxRow("2026-01-15T09:18:05.0000000Z", "3", "Microsoft-Windows-Sysmon/Operational", "WKSTN-042", "jdoe",
			`Image: C:\Users\jdoe\AppData\Local\Temp\update.exe; ProcessId: 8260; SourceIp: 10.1.10.42; DestinationIp: 203.0.113.77; DestinationPort: 443`, "5")

	return buildZipBytes(t, map[string]string{
		"EvtxECmd/collection1_EvtxECmd_Output.csv": csv,
	})
}

// buildPersistenceCollectionZip is "Collection #2": a follow-up KAPE
// triage that collected the registry hive and scheduled task XML --
// artifact types that weren't part of collection #1 at all -- showing
// the payload from collection #1 (by name; the collections share no
// events) established persistence.
func buildPersistenceCollectionZip(t *testing.T) []byte {
	t.Helper()
	recmdCSV := "HivePath,KeyPath,ValueName,ValueData,LastWriteTimestamp\n" +
		`C:\Users\jdoe\NTUSER.DAT,Software\Microsoft\Windows\CurrentVersion\Run,WindowsUpdateHelper,"C:\Users\jdoe\AppData\Local\Temp\update.exe",2026-01-15T09:16:02.0000000Z` + "\n"

	taskXML := `<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-01-15T09:17:30.0000000</Date>
    <Author>CORP\jdoe</Author>
  </RegistrationInfo>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\jdoe\AppData\Local\Temp\update.exe</Command>
      <Arguments>-silent</Arguments>
    </Exec>
  </Actions>
</Task>`

	return buildZipBytes(t, map[string]string{
		"RECmd/collection2_RECmd_Batch_RunKeys_Output.csv": recmdCSV,
		"Tasks/UpdateTask.xml":                             taskXML,
	})
}

// TestMultiCollection_EndToEnd is the required end-to-end test for this
// phase: create case -> upload collection #1 -> analyze -> upload
// collection #2 -> analyze/recalculate -> verify unified timeline ->
// verify cross-collection correlation -> verify findings -> verify
// provenance.
//
// Collection #1 (an EvtxECmd export) has the entire execution chain --
// logon, Office spawning PowerShell, PowerShell spawning a payload, the
// payload beaconing out -- but no persistence artifact of any kind.
// Collection #2 (a RECmd export plus a Task Scheduler XML, artifact
// types collection #1 never had) has only the registry Run key and
// scheduled task the same payload later established. Neither collection
// alone contains enough evidence for the execution-persistence-temporal
// rule or the full activity chain to fire; only once both are in the
// case do those relationships become visible -- proving correlation
// truly operates over the complete case, not per-collection.
func TestMultiCollection_EndToEnd(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Cross-collection case")

	// -- Upload collection #1 --
	rec := uploadZip(t, mux, c.ID, buildExecutionCollectionZip(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload collection #1: status %d, body %s", rec.Code, rec.Body.String())
	}
	var res1 UploadResultSummary
	mustDecode(t, rec, &res1)
	if res1.EventCount != 5 {
		t.Fatalf("collection #1 parsed %d events, want 5", res1.EventCount)
	}

	// -- Analyze after just collection #1 --
	var analyze1 AnalyzeResultSummary
	rec = doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, &analyze1)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyze #1: status %d, body %s", rec.Code, rec.Body.String())
	}
	for _, f := range analyze1.Findings {
		if f.RuleID == "execution-persistence-temporal" {
			t.Error("execution-persistence-temporal fired before any persistence evidence existed in the case")
		}
	}

	// -- Upload collection #2 --
	rec = uploadZip(t, mux, c.ID, buildPersistenceCollectionZip(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload collection #2: status %d, body %s", rec.Code, rec.Body.String())
	}
	var res2 UploadResultSummary
	mustDecode(t, rec, &res2)
	if res2.EventCount != 2 {
		t.Fatalf("collection #2 parsed %d events, want 2 (registry key + scheduled task)", res2.EventCount)
	}
	if res2.NewEventCount != 2 {
		t.Errorf("collection #2 NewEventCount = %d, want 2 (no overlap with collection #1's artifact types)", res2.NewEventCount)
	}

	// -- Re-analyze / recalculate across the complete case --
	var analyze2 AnalyzeResultSummary
	rec = doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, &analyze2)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyze #2: status %d, body %s", rec.Code, rec.Body.String())
	}

	// -- Verify unified timeline: both collections, chronological --
	var timeline []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
	if len(timeline) != 7 {
		t.Fatalf("unified timeline has %d events, want 7 (5 + 2)", len(timeline))
	}
	seenCollections := map[string]bool{}
	for i, e := range timeline {
		seenCollections[e.CollectionID] = true
		if i > 0 && e.Timestamp.Before(timeline[i-1].Timestamp) {
			t.Fatalf("timeline not chronologically sorted at index %d", i)
		}
	}
	if len(seenCollections) != 2 {
		t.Errorf("timeline events come from %d distinct collections, want 2", len(seenCollections))
	}

	// -- Verify cross-collection correlation: the execution-persistence
	// finding must exist now, backed by events from BOTH collections.
	var findingCollectionIDs []string
	var crossCollectionFinding *model.Finding
	for i, f := range analyze2.Findings {
		if f.RuleID == "execution-persistence-temporal" {
			crossCollectionFinding = &analyze2.Findings[i]
			break
		}
	}
	if crossCollectionFinding == nil {
		t.Fatal("expected an execution-persistence-temporal finding once both collections are present")
	}

	var findingDetail FindingDetail
	rec = doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings/"+crossCollectionFinding.ID, nil, &findingDetail)
	if rec.Code != http.StatusOK {
		t.Fatalf("get finding detail: status %d", rec.Code)
	}
	distinctCollections := map[string]bool{}
	for _, e := range findingDetail.SupportingEventDetails {
		distinctCollections[e.CollectionID] = true
		findingCollectionIDs = append(findingCollectionIDs, e.CollectionID)
	}
	if len(distinctCollections) != 2 {
		t.Errorf("execution-persistence-temporal finding's supporting events span %d collections, want 2 (evidence: %v)", len(distinctCollections), findingCollectionIDs)
	}

	// -- Verify the activity chain also spans both collections. --
	var correlations []model.Correlation
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/correlations", nil, &correlations)
	var chainSpansCollections bool
	for _, corr := range correlations {
		if corr.Type != model.CorrelationActivityChain {
			continue
		}
		chainCollections := map[string]bool{}
		for _, eventID := range corr.EventIDs {
			for _, e := range timeline {
				if e.ID == eventID {
					chainCollections[e.CollectionID] = true
					break
				}
			}
		}
		if len(chainCollections) == 2 {
			chainSpansCollections = true
		}
	}
	if !chainSpansCollections {
		t.Error("expected the activity chain correlation to include events from both collections")
	}

	// -- Verify findings are case-level and not spuriously duplicated --
	// collection #2 has two distinct persistence mechanisms (registry Run
	// key and scheduled task), and the rule fires once per persistence
	// event by design (see docs/detection-engine.md), so exactly 2 are
	// expected here -- not 1 (which would suggest one mechanism went
	// undetected) and not more than 2 (which would suggest findings are
	// being duplicated, e.g. once per collection touched, rather than
	// computed once over the deduplicated case-wide event set).
	epCount := 0
	for _, f := range analyze2.Findings {
		if f.RuleID == "execution-persistence-temporal" {
			epCount++
		}
	}
	if epCount != 2 {
		t.Errorf("got %d execution-persistence-temporal findings, want exactly 2 (one per persistence mechanism, not duplicated)", epCount)
	}

	// -- Verify provenance: the registry-key event (from collection #2)
	// resolves back to collection #2's own source file and raw evidence.
	var registryEvent model.Event
	for _, e := range findingDetail.SupportingEventDetails {
		if e.EventType == model.EventRegistryRunKey {
			registryEvent = e
		}
	}
	if registryEvent.ID == "" {
		t.Fatal("expected a registry_run_key_set event among the finding's supporting evidence")
	}
	var prov EventProvenance
	rec = doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/"+registryEvent.ID, nil, &prov)
	if rec.Code != http.StatusOK {
		t.Fatalf("get event provenance: status %d", rec.Code)
	}
	if prov.SourceFile.CollectionID != res2.Collection.ID {
		t.Errorf("registry event's source file belongs to collection %q, want collection #2 (%q)", prov.SourceFile.CollectionID, res2.Collection.ID)
	}
	if prov.RawEvidence.Raw == "" {
		t.Error("registry event's raw evidence is empty")
	}
}

// TestMultiCollection_SameEventObservedTwice covers deduplication and
// provenance retention directly: two DIFFERENT collections (different
// archive bytes/hash, so neither is rejected as a duplicate collection --
// see TestDuplicateEvidence_* for that behavior) that happen to both
// contain a copy of the same underlying event must not create a
// duplicate Event row for it, and the UI-facing provenance must show
// that event as observed in both collections. This is what "do not
// change the event deduplication model" (event-level, by content hash)
// looks like continuing to work once evidence-COLLECTION-level
// duplicate rejection (archive-hash equality) is layered on top of it --
// the two are deliberately different checks at different granularities.
func TestMultiCollection_SameEventObservedTwice(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Dedup case")

	sharedRow := evtxRow("2026-01-15T09:00:00.0000000Z", "4624", "Security", "WKSTN-042", "jdoe",
		"TargetUserName: jdoe; LogonType: 2", "1")
	// Each collection also has one distinguishing event of its own, so
	// the two archives' bytes (and hence archive_hash) differ.
	csv1 := evtxHeader + sharedRow + evtxRow("2026-01-15T09:05:00.0000000Z", "4624", "Security", "WKSTN-042", "alice",
		"TargetUserName: alice; LogonType: 2", "2")
	csv2 := evtxHeader + sharedRow + evtxRow("2026-01-15T09:10:00.0000000Z", "4624", "Security", "WKSTN-042", "bob",
		"TargetUserName: bob; LogonType: 2", "3")
	zip1 := buildZipBytes(t, map[string]string{"EvtxECmd/a_EvtxECmd_Output.csv": csv1})
	zip2 := buildZipBytes(t, map[string]string{"EvtxECmd/b_EvtxECmd_Output.csv": csv2})

	rec := uploadZip(t, mux, c.ID, zip1)
	if rec.Code != http.StatusOK {
		t.Fatalf("first upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var res1 UploadResultSummary
	mustDecode(t, rec, &res1)
	if res1.NewEventCount != 2 {
		t.Fatalf("first upload NewEventCount = %d, want 2 (jdoe + alice)", res1.NewEventCount)
	}

	rec = uploadZip(t, mux, c.ID, zip2)
	if rec.Code != http.StatusOK {
		t.Fatalf("second upload: status %d, body %s (a genuinely different archive must not be rejected as a duplicate collection)", rec.Code, rec.Body.String())
	}
	var res2 UploadResultSummary
	mustDecode(t, rec, &res2)
	if res2.NewEventCount != 1 {
		t.Errorf("second upload NewEventCount = %d, want 1 (only bob is new)", res2.NewEventCount)
	}
	if res2.DuplicateEventCount != 1 {
		t.Errorf("second upload DuplicateEventCount = %d, want 1 (the shared jdoe logon)", res2.DuplicateEventCount)
	}
	if res1.Collection.ID == res2.Collection.ID {
		t.Fatal("expected two distinct collections")
	}

	// The case must have exactly 3 canonical events (jdoe, alice, bob) --
	// not 4, which is what it would be without event-level dedup.
	var timeline []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
	if len(timeline) != 3 {
		t.Fatalf("case timeline has %d events, want 3 (deduplicated)", len(timeline))
	}

	var sharedEventID string
	for _, e := range timeline {
		if e.User == "jdoe" {
			sharedEventID = e.ID
		}
	}
	if sharedEventID == "" {
		t.Fatal("could not find the shared jdoe logon event in the timeline")
	}

	// Provenance must show the shared event as observed in both collections.
	var prov EventProvenance
	rec = doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/"+sharedEventID, nil, &prov)
	if rec.Code != http.StatusOK {
		t.Fatalf("get event provenance: status %d", rec.Code)
	}
	if len(prov.Observations) != 2 {
		t.Fatalf("got %d observations, want 2 (one per collection)", len(prov.Observations))
	}
	seen := map[string]bool{res1.Collection.ID: false, res2.Collection.ID: false}
	for _, o := range prov.Observations {
		if _, ok := seen[o.CollectionID]; ok {
			seen[o.CollectionID] = true
		}
	}
	for collID, found := range seen {
		if !found {
			t.Errorf("expected an observation for collection %q", collID)
		}
	}
}
