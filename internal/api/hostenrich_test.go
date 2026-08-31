package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"tracefall/internal/ad1/ad1gen"
	"tracefall/internal/model"
)

// ---------------- fixtures ----------------
//
// Three artifact files describing ONE host's activity, split the way a
// real triage splits it: only the Event Log names the host, while the
// Prefetch and registry exports structurally cannot. That asymmetry is
// the entire subject of these tests -- see internal/api/hostenrich.go.

const hostEvtxCSV = `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
2026-03-01T09:14:47.0000000Z,4688,Microsoft-Windows-Security-Auditing,Security,WKSTN-042,,-,Process Create: powershell.exe,SubjectUserName: jdoe; SubjectDomainName: CORP; NewProcessId: 0x1F30; NewProcessName: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe; ParentProcessName: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE; ProcessId: 0x1A2C; CommandLine: powershell.exe -nop -w hidden -enc SQBFAFgA,,,,,,20001
2026-03-01T09:15:10.0000000Z,4688,Microsoft-Windows-Security-Auditing,Security,WKSTN-042,,-,Process Create: update.exe,"SubjectUserName: jdoe; SubjectDomainName: CORP; NewProcessId: 0x2044; NewProcessName: C:\Users\jdoe\AppData\Local\Temp\update.exe; ParentProcessName: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe; ProcessId: 0x1F30; CommandLine: ""C:\Users\jdoe\AppData\Local\Temp\update.exe"" -silent",,,,,,20002
`

// A second host's Event Log, for the multi-host ambiguity case.
const hostEvtxCSVOtherHost = `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
2026-03-01T11:00:00.0000000Z,4688,Microsoft-Windows-Security-Auditing,Security,SRV-DC-01,,-,Process Create: cmd.exe,SubjectUserName: admin; SubjectDomainName: CORP; NewProcessId: 0x3000; NewProcessName: C:\Windows\System32\cmd.exe; ParentProcessName: C:\Windows\explorer.exe; ProcessId: 0x2000; CommandLine: cmd.exe /c whoami,,,,,,30001
`

// Prefetch: no ComputerName column exists in PECmd output at all.
const hostPecmdCSV = `SourceFilename,ExecutableName,RunCount,LastRun,Size
C:\Windows\Prefetch\UPDATE.EXE-7C21F0AA.pf,UPDATE.EXE,3,2026-03-01T09:15:11.0000000Z,18234
`

// Registry: hives don't record the machine name either.
const hostRecmdCSV = `HivePath,KeyPath,ValueName,ValueData,LastWriteTimestamp
C:\Users\jdoe\NTUSER.DAT,Software\Microsoft\Windows\CurrentVersion\Run,WindowsUpdateHelper,C:\Users\jdoe\AppData\Local\Temp\update.exe,2026-03-01T09:16:02.0000000Z
`

const (
	pathEvtx  = "EvtxECmd/20260301_090000_EvtxECmd_Output.csv"
	pathEvtx2 = "EvtxECmd/20260301_110000_other_EvtxECmd_Output.csv"
	pathPecmd = "PECmd/20260301_090000_PECmd_Output.csv"
	pathRecmd = "RECmd/20260301_090000_RECmd_Batch_RunKeys_Output.csv"
)

func hostFixtureFiles() map[string]string {
	return map[string]string{
		pathEvtx:  hostEvtxCSV,
		pathPecmd: hostPecmdCSV,
		pathRecmd: hostRecmdCSV,
	}
}

// ---------------- helpers ----------------

// discoverZip uploads files as a ZIP and returns the discovery catalog
// without importing anything, so a test can choose its own import order.
func discoverZip(t *testing.T, mux http.Handler, caseID string, files map[string]string) DiscoverResult {
	t.Helper()
	rec := uploadZip(t, mux, caseID, buildZipBytes(t, files))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	return disc
}

// discoverLocalDir writes files into a temp directory and discovers it,
// exercising the local-path ingestion route rather than an upload.
func discoverLocalDir(t *testing.T, mux http.Handler, caseID string, files map[string]string) DiscoverResult {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rec := discoverPath(t, mux, caseID, dir)
	if rec.Code != http.StatusOK {
		t.Fatalf("local-path discover: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	return disc
}

// discoverAD1Fixture builds an AD1 image from files and discovers it.
func discoverAD1Fixture(t *testing.T, mux http.Handler, caseID string, files map[string]string) DiscoverResult {
	t.Helper()
	paths := make([]string, 0, len(files))
	for name := range files {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	entries := make([]ad1gen.File, 0, len(paths))
	for _, name := range paths {
		entries = append(entries, ad1gen.File{Path: name, Data: []byte(files[name])})
	}
	rec := uploadAD1(t, mux, caseID, buildAD1(t, `E:\`, entries), "hosts.ad1")
	if rec.Code != http.StatusOK {
		t.Fatalf("AD1 upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	return disc
}

// importInPathOrder imports exactly the named paths, in exactly the order
// given -- which is the order ImportEvidence's loop processes them in,
// and therefore the variable these tests exist to hold constant.
func importInPathOrder(t *testing.T, mux http.Handler, caseID string, disc DiscoverResult, paths ...string) ImportResult {
	t.Helper()
	ids := make([]string, 0, len(paths))
	for _, want := range paths {
		sf, ok := sourceFileByPath(disc.SourceFiles, want)
		if !ok {
			t.Fatalf("path %q not found in discovery catalog; have %+v", want, disc.SourceFiles)
		}
		ids = append(ids, sf.ID)
	}
	rec := doJSON(t, mux, "POST", "/api/cases/"+caseID+"/evidence/"+disc.Collection.ID+"/import",
		map[string][]string{"source_file_ids": ids}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: status %d, body %s", rec.Code, rec.Body.String())
	}
	var imp ImportResult
	mustDecode(t, rec, &imp)
	if len(imp.Imported) != len(paths) {
		t.Fatalf("imported %d files, want %d (skipped=%+v errors=%v)", len(imp.Imported), len(paths), imp.Skipped, imp.Errors)
	}
	return imp
}

func timelineOf(t *testing.T, mux http.Handler, caseID string) []map[string]any {
	t.Helper()
	var timeline []map[string]any
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/timeline", nil, &timeline)
	return timeline
}

// hostByArtifactType maps artifact_type -> the set of distinct hosts its
// events carry, which is what every case below actually asserts on.
func hostByArtifactType(timeline []map[string]any) map[string][]string {
	seen := map[string]map[string]bool{}
	for _, ev := range timeline {
		at, _ := ev["artifact_type"].(string)
		h, _ := ev["host"].(string)
		if seen[at] == nil {
			seen[at] = map[string]bool{}
		}
		seen[at][h] = true
	}
	out := map[string][]string{}
	for at, hosts := range seen {
		for h := range hosts {
			out[at] = append(out[at], h)
		}
		sort.Strings(out[at])
	}
	return out
}

func assertAllHosts(t *testing.T, timeline []map[string]any, artifactType string, want ...string) {
	t.Helper()
	got := hostByArtifactType(timeline)[artifactType]
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("%s events carry hosts %v, want %v", artifactType, got, want)
	}
}

// ---------------- Case A / Case B / Case C: order independence ----------------

// TestHostEnrichment_CaseA_HostLessFilesImportedFirst is the reported
// bug, stated directly: Prefetch and registry files processed BEFORE the
// Event Log file that names the host must still end up carrying that
// host. Before Phase 7.1 they did not -- enrichment consulted only
// already-persisted events, and at the moment those two files were
// processed nothing with a host had been written yet.
func TestHostEnrichment_CaseA_HostLessFilesImportedFirst(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "case A - host-less first")

	disc := discoverZip(t, mux, c.ID, hostFixtureFiles())
	importInPathOrder(t, mux, c.ID, disc, pathPecmd, pathRecmd, pathEvtx)

	timeline := timelineOf(t, mux, c.ID)
	assertAllHosts(t, timeline, model.ArtifactPrefetch, "WKSTN-042")
	assertAllHosts(t, timeline, model.ArtifactRegistryRunKey, "WKSTN-042")
	assertAllHosts(t, timeline, model.ArtifactWindowsEventLog, "WKSTN-042")
}

// TestHostEnrichment_CaseB_HostBearingFileImportedFirst is Case A with
// the opposite processing order, and must reach the identical result.
func TestHostEnrichment_CaseB_HostBearingFileImportedFirst(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "case B - host-bearing first")

	disc := discoverZip(t, mux, c.ID, hostFixtureFiles())
	importInPathOrder(t, mux, c.ID, disc, pathEvtx, pathPecmd, pathRecmd)

	timeline := timelineOf(t, mux, c.ID)
	assertAllHosts(t, timeline, model.ArtifactPrefetch, "WKSTN-042")
	assertAllHosts(t, timeline, model.ArtifactRegistryRunKey, "WKSTN-042")
	assertAllHosts(t, timeline, model.ArtifactWindowsEventLog, "WKSTN-042")
}

// eventFingerprints reduces a timeline to order-independent, ID-free
// content: everything that identifies the real-world event, with the
// random UUIDs deliberately excluded (they differ every run by design,
// so comparing them would prove nothing about determinism).
func eventFingerprints(timeline []map[string]any) []string {
	out := make([]string, 0, len(timeline))
	for _, ev := range timeline {
		out = append(out, fmt.Sprintf("%v|%v|%v|%v|%v|%v|%v|%v|%v",
			ev["timestamp"], ev["event_type"], ev["host"], ev["user"],
			ev["process_name"], ev["parent_process"], ev["artifact_type"],
			ev["registry_path"], ev["dedup_hash"]))
	}
	sort.Strings(out)
	return out
}

// TestHostEnrichment_CaseC_IdenticalEventsRegardlessOfOrder compares the
// two orderings above field by field -- including dedup_hash, which Host
// feeds into (model.Event.ComputeDedupHash). An unresolved host doesn't
// just leave a display field blank; it changes the event's dedup
// identity, so a host resolved inconsistently would silently break
// deduplication of the same event re-observed in a later collection.
func TestHostEnrichment_CaseC_IdenticalEventsRegardlessOfOrder(t *testing.T) {
	orders := [][]string{
		{pathPecmd, pathRecmd, pathEvtx},
		{pathEvtx, pathPecmd, pathRecmd},
		{pathRecmd, pathEvtx, pathPecmd},
	}

	var reference []string
	for i, order := range orders {
		mux := newTestRouter(t)
		c := mustCreateCase(t, mux, fmt.Sprintf("case C order %d", i))
		disc := discoverZip(t, mux, c.ID, hostFixtureFiles())
		importInPathOrder(t, mux, c.ID, disc, order...)

		got := eventFingerprints(timelineOf(t, mux, c.ID))
		if len(got) == 0 {
			t.Fatalf("order %v produced no events", order)
		}
		if i == 0 {
			reference = got
			continue
		}
		if strings.Join(got, "\n") != strings.Join(reference, "\n") {
			t.Errorf("order %v produced different normalized events than order %v:\ngot:\n%s\nwant:\n%s",
				order, orders[0], strings.Join(got, "\n"), strings.Join(reference, "\n"))
		}
	}
}

// ---------------- Case D: multiple legitimate hosts ----------------

// TestHostEnrichment_CaseD_MultipleHostsAreNotMerged covers the rule that
// makes this safe rather than merely consistent: a collection that
// genuinely spans two hosts gives no evidence about which of them a
// host-less Prefetch record belongs to, so that record stays blank. Each
// Event Log file keeps its own real host -- they are never merged into
// one, and neither is imposed on the Prefetch data by majority vote.
func TestHostEnrichment_CaseD_MultipleHostsAreNotMerged(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "case D - two hosts")

	files := hostFixtureFiles()
	files[pathEvtx2] = hostEvtxCSVOtherHost
	delete(files, pathRecmd) // keep the ambiguity about the Prefetch file specifically

	disc := discoverZip(t, mux, c.ID, files)
	importInPathOrder(t, mux, c.ID, disc, pathPecmd, pathEvtx, pathEvtx2)

	timeline := timelineOf(t, mux, c.ID)
	assertAllHosts(t, timeline, model.ArtifactWindowsEventLog, "SRV-DC-01", "WKSTN-042")
	assertAllHosts(t, timeline, model.ArtifactPrefetch, "")
}

// TestHostEnrichment_CaseD_PerFileHostWinsOverAmbiguousCollection checks
// the scope hierarchy's first rung: even in that same two-host
// collection, a file that itself names exactly one host resolves its own
// blank records from it, rather than being dragged down to blank by the
// collection's ambiguity. Asserted at the unit level because no real
// parser emits a partially-host-bearing file today -- it is a property
// of the resolution rule, not of any current artifact format.
func TestHostEnrichment_CaseD_PerFileHostWinsOverAmbiguousCollection(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("case D - per-file scope", "")
	if err != nil {
		t.Fatalf("CreateCase: %v", err)
	}

	batch := []pendingImport{
		{ // one file naming exactly one host, with a blank record of its own
			sourceFile: model.SourceFile{ID: "sf-a"},
			events: []model.Event{
				{Host: "WKSTN-042", EventType: model.EventProcessCreate},
				{Host: "", EventType: model.EventProcessCreate},
			},
		},
		{ // a second file naming a different host -- collection is ambiguous
			sourceFile: model.SourceFile{ID: "sf-b"},
			events:     []model.Event{{Host: "SRV-DC-01", EventType: model.EventProcessCreate}},
		},
		{ // a file naming no host at all: nothing narrower than the
			// ambiguous collection applies, so it must stay blank
			sourceFile: model.SourceFile{ID: "sf-c"},
			events:     []model.Event{{Host: "", EventType: model.EventPrefetchExecution}},
		},
	}
	if err := svc.enrichBatchHosts(c.ID, "collection-1", batch); err != nil {
		t.Fatalf("enrichBatchHosts: %v", err)
	}

	if got := batch[0].events[1].Host; got != "WKSTN-042" {
		t.Errorf("blank record in a single-host file resolved to %q, want WKSTN-042 (its own file's host)", got)
	}
	if got := batch[1].events[0].Host; got != "SRV-DC-01" {
		t.Errorf("real host overwritten: got %q, want SRV-DC-01", got)
	}
	if got := batch[2].events[0].Host; got != "" {
		t.Errorf("host-less file in an ambiguous collection resolved to %q, want \"\" -- a hostname must never be invented", got)
	}
}

// ---------------- Case E / Case F: same behavior across every source ----------------

// TestHostEnrichment_CaseE_AD1 runs Case A's ordering against an AD1
// forensic image instead of a ZIP.
func TestHostEnrichment_CaseE_AD1(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "case E - AD1")

	disc := discoverAD1Fixture(t, mux, c.ID, hostFixtureFiles())
	importInPathOrder(t, mux, c.ID, disc, pathPecmd, pathRecmd, pathEvtx)

	timeline := timelineOf(t, mux, c.ID)
	assertAllHosts(t, timeline, model.ArtifactPrefetch, "WKSTN-042")
	assertAllHosts(t, timeline, model.ArtifactRegistryRunKey, "WKSTN-042")
}

// TestHostEnrichment_CaseF_LocalDirectory runs Case A's ordering against
// a local evidence directory instead of an upload.
func TestHostEnrichment_CaseF_LocalDirectory(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "case F - local directory")

	disc := discoverLocalDir(t, mux, c.ID, hostFixtureFiles())
	importInPathOrder(t, mux, c.ID, disc, pathPecmd, pathRecmd, pathEvtx)

	timeline := timelineOf(t, mux, c.ID)
	assertAllHosts(t, timeline, model.ArtifactPrefetch, "WKSTN-042")
	assertAllHosts(t, timeline, model.ArtifactRegistryRunKey, "WKSTN-042")
}

// TestHostEnrichment_AllSourceTypesAgree pins Cases E and F to Case A's
// result explicitly: the same evidence in a ZIP, an AD1, and a local
// directory must normalize to byte-identical events. Without this, each
// route could drift independently and still pass its own test.
func TestHostEnrichment_AllSourceTypesAgree(t *testing.T) {
	discoverers := map[string]func(*testing.T, http.Handler, string, map[string]string) DiscoverResult{
		"zip":       discoverZip,
		"ad1":       discoverAD1Fixture,
		"localpath": discoverLocalDir,
	}

	results := map[string][]string{}
	for name, discover := range discoverers {
		mux := newTestRouter(t)
		c := mustCreateCase(t, mux, "agree - "+name)
		disc := discover(t, mux, c.ID, hostFixtureFiles())
		importInPathOrder(t, mux, c.ID, disc, pathPecmd, pathRecmd, pathEvtx)
		results[name] = eventFingerprints(timelineOf(t, mux, c.ID))
	}

	reference := results["zip"]
	if len(reference) == 0 {
		t.Fatal("zip route produced no events")
	}
	for name, got := range results {
		if strings.Join(got, "\n") != strings.Join(reference, "\n") {
			t.Errorf("%s route produced different normalized events than the zip route:\ngot:\n%s\nwant:\n%s",
				name, strings.Join(got, "\n"), strings.Join(reference, "\n"))
		}
	}
}

// ---------------- end-to-end determinism ----------------

// analysisFingerprint reduces a fully analyzed case to order-independent,
// ID-free content across every downstream layer, so the end-to-end test
// below can compare two runs meaningfully. IDs are excluded on purpose:
// event IDs are random UUIDs, and finding/correlation/investigation IDs
// are content-derived from those event IDs (see model.StableID), so they
// legitimately differ between runs while the analysis itself is
// identical. What must not differ is everything here.
func analysisFingerprint(t *testing.T, mux http.Handler, caseID string) map[string][]string {
	t.Helper()
	fp := map[string][]string{}

	fp["events"] = eventFingerprints(timelineOf(t, mux, caseID))

	var findings []map[string]any
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings)
	for _, f := range findings {
		fp["findings"] = append(fp["findings"], fmt.Sprintf("%v|%v|%v|%v|%v",
			f["detection_rule"], f["severity"], f["confidence"], f["title"], f["attack_techniques"]))
	}

	var correlations []map[string]any
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/correlations", nil, &correlations)
	for _, c := range correlations {
		fp["correlations"] = append(fp["correlations"], fmt.Sprintf("%v|%v", c["correlation_type"], c["title"]))
	}

	var investigations []map[string]any
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/investigations", nil, &investigations)
	for _, i := range investigations {
		fp["investigations"] = append(fp["investigations"], fmt.Sprintf("%v|%v|%v|%v|%v|%v",
			i["category"], i["severity"], i["confidence"], i["risk_score"], i["title"], i["hosts"]))
	}

	var attack []map[string]any
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/attack", nil, &attack)
	for _, a := range attack {
		fp["attack"] = append(fp["attack"], fmt.Sprintf("%v|%v", a["technique_id"], a["tactic"]))
	}

	for k := range fp {
		sort.Strings(fp[k])
	}
	return fp
}

// TestHostEnrichment_EndToEndOrderIndependence is the requirement stated
// whole: changing the order source files are processed in must not change
// the events, findings, correlations, investigations, or ATT&CK mapping
// the case ends up with.
//
// It's a meaningful check specifically because host resolution feeds all
// of them: internal/correlate groups by host, so a Prefetch record left
// blank in one ordering and resolved in another wouldn't just look
// different -- it would drop out of the process/entity/activity chains
// that produce findings and investigations downstream.
func TestHostEnrichment_EndToEndOrderIndependence(t *testing.T) {
	orders := [][]string{
		{pathPecmd, pathRecmd, pathEvtx},
		{pathEvtx, pathRecmd, pathPecmd},
		{pathRecmd, pathPecmd, pathEvtx},
	}

	var reference map[string][]string
	for i, order := range orders {
		mux := newTestRouter(t)
		c := mustCreateCase(t, mux, fmt.Sprintf("e2e order %d", i))
		disc := discoverZip(t, mux, c.ID, hostFixtureFiles())
		importInPathOrder(t, mux, c.ID, disc, order...)

		rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("analyze: status %d, body %s", rec.Code, rec.Body.String())
		}

		got := analysisFingerprint(t, mux, c.ID)
		if len(got["events"]) == 0 || len(got["findings"]) == 0 {
			t.Fatalf("order %v produced %d events / %d findings; expected a non-trivial analysis to compare",
				order, len(got["events"]), len(got["findings"]))
		}
		if i == 0 {
			reference = got
			continue
		}
		for _, layer := range []string{"events", "findings", "correlations", "investigations", "attack"} {
			if strings.Join(got[layer], "\n") != strings.Join(reference[layer], "\n") {
				t.Errorf("order %v produced different %s than order %v:\ngot:\n%s\nwant:\n%s",
					order, layer, orders[0], strings.Join(got[layer], "\n"), strings.Join(reference[layer], "\n"))
			}
		}
	}
}

// ---------------- unambiguousHost unit coverage ----------------

func TestUnambiguousHost(t *testing.T) {
	ev := func(hosts ...string) []model.Event {
		out := make([]model.Event, 0, len(hosts))
		for _, h := range hosts {
			out = append(out, model.Event{Host: h})
		}
		return out
	}

	for _, tc := range []struct {
		name   string
		scopes [][]model.Event
		want   string
	}{
		{"no events", [][]model.Event{{}}, ""},
		{"all blank", [][]model.Event{ev("", "")}, ""},
		{"single host", [][]model.Event{ev("WKSTN-042")}, "WKSTN-042"},
		{"single host with blanks", [][]model.Event{ev("", "WKSTN-042", "")}, "WKSTN-042"},
		{"two hosts is ambiguous", [][]model.Event{ev("WKSTN-042", "SRV-DC-01")}, ""},
		{"two hosts, ambiguous regardless of order", [][]model.Event{ev("SRV-DC-01", "WKSTN-042")}, ""},
		{"same host across scopes", [][]model.Event{ev("WKSTN-042"), ev("WKSTN-042")}, "WKSTN-042"},
		{"different host in second scope is ambiguous", [][]model.Event{ev("WKSTN-042"), ev("SRV-DC-01")}, ""},
		// Casing/whitespace variants name ONE host (matching how
		// ComputeDedupHash already normalizes), and the spelling chosen
		// is a real observed one, picked deterministically.
		{"casing variants are one host", [][]model.Event{ev("WKSTN-042", "wkstn-042")}, "WKSTN-042"},
		{"whitespace variants are one host", [][]model.Event{ev(" WKSTN-042 ", "WKSTN-042")}, " WKSTN-042 "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := unambiguousHost(tc.scopes...); got != tc.want {
				t.Errorf("unambiguousHost = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEnrichBatchHosts_NeverInventsAHost pins requirement 6 on its own: a
// batch with no host information anywhere, in a case with none either,
// must come back exactly as it went in.
func TestEnrichBatchHosts_NeverInventsAHost(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("no host anywhere", "")
	if err != nil {
		t.Fatalf("CreateCase: %v", err)
	}

	batch := []pendingImport{{
		sourceFile: model.SourceFile{ID: "sf-a"},
		events:     []model.Event{{Host: "", EventType: model.EventPrefetchExecution}, {Host: "", EventType: model.EventRegistryRunKey}},
	}}
	if err := svc.enrichBatchHosts(c.ID, "collection-1", batch); err != nil {
		t.Fatalf("enrichBatchHosts: %v", err)
	}
	for i, e := range batch[0].events {
		if e.Host != "" {
			t.Errorf("event %d received host %q out of nowhere; want it left blank", i, e.Host)
		}
	}
}

// TestEnrichBatchHosts_CaseScopeFallback covers the third rung: a
// follow-up collection made up entirely of host-less artifact types
// inherits the host an earlier collection already established for the
// case. This is the one scope that reaches across collections, and it
// only applies when the case names exactly one host.
func TestEnrichBatchHosts_CaseScopeFallback(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "case-scope fallback")

	// Collection 1: the Event Log alone, establishing the case's host.
	disc1 := discoverZip(t, mux, c.ID, map[string]string{pathEvtx: hostEvtxCSV})
	importInPathOrder(t, mux, c.ID, disc1, pathEvtx)

	// Collection 2: only host-less artifact types, nothing in this
	// collection names a host at all.
	disc2 := discoverZip(t, mux, c.ID, map[string]string{pathPecmd: hostPecmdCSV, pathRecmd: hostRecmdCSV})
	importInPathOrder(t, mux, c.ID, disc2, pathPecmd, pathRecmd)

	timeline := timelineOf(t, mux, c.ID)
	assertAllHosts(t, timeline, model.ArtifactPrefetch, "WKSTN-042")
	assertAllHosts(t, timeline, model.ArtifactRegistryRunKey, "WKSTN-042")
}
