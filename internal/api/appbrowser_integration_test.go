package api

import (
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	_ "modernc.org/sqlite"

	"tracefall/internal/model"
	"tracefall/internal/regf/regfgen"
	"tracefall/internal/shellbag/sbgen"
	"tracefall/internal/userassist/uagen"
)

// Phase 16 integration: Amcache, the per-user MRU structures, Windows
// Timeline and browser downloads reaching the analyst through the whole
// pipeline.

const (
	p16Executable  = "updater.exe"
	p16FullPath    = `C:\Users\jdoe\AppData\Local\Temp\updater.exe`
	p16Document    = "quarterly-figures.docx"
	p16DownloadURL = "https://downloads.example.test/tools/updater.exe"
	p16ExecGUID    = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"
	p16ThisPC      = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
)

var (
	p16AmcacheAt  = time.Date(2021, 4, 29, 17, 0, 0, 0, time.UTC)
	p16UserAssist = time.Date(2021, 4, 29, 18, 17, 38, 0, time.UTC)
	p16ProcessAt  = time.Date(2021, 4, 29, 18, 20, 0, 0, time.UTC)
	p16MRUAt      = time.Date(2021, 4, 29, 19, 0, 0, 0, time.UTC)
	p16DownloadAt = time.Date(2021, 4, 29, 16, 45, 0, 0, time.UTC)
	p16ActivityAt = time.Date(2021, 4, 29, 18, 30, 0, 0, time.UTC)
	p16HiveWrite  = time.Date(2021, 5, 1, 0, 0, 0, 0, time.UTC)
)

// ---------------- Fixtures ----------------

// p16Amcache builds an Amcache.hve cataloguing the tracked executable.
func p16Amcache() []byte {
	return regfgen.Build("Amcache.hve", regfgen.NewKey("ROOT",
		regfgen.NewKey("Root", regfgen.NewKey("InventoryApplicationFile",
			regfgen.NewKey("updater.exe|aabb").WithLastWrite(p16AmcacheAt).WithValues(
				regfgen.StringValue("LowerCaseLongPath", strings.ToLower(p16FullPath)),
				regfgen.StringValue("Name", p16Executable),
				regfgen.StringValue("FileId", "0000da39a3ee5e6b4b0d3255bfef95601890afd80709"),
				regfgen.StringValue("Publisher", "Contoso Ltd"),
				regfgen.DWordValue("Size", 262144),
			))),
	).WithLastWrite(p16AmcacheAt))
}

// p16NTUser builds an NTUSER.DAT with UserAssist, RecentDocs and RunMRU.
func p16NTUser() []byte {
	userAssist := regfgen.NewKey("UserAssist", regfgen.NewKey(p16ExecGUID,
		regfgen.NewKey("Count").WithLastWrite(p16HiveWrite).WithValues(
			regfgen.BinaryValue(uagen.Name(p16FullPath),
				uagen.BuildV5(uagen.Entry{RunCount: 3, LastExecuted: p16UserAssist})),
		)))

	recentDocs := regfgen.NewKey("RecentDocs").WithLastWrite(p16MRUAt).WithValues(
		regfgen.BinaryValue("0", p16RecentDocValue(p16Document)),
		regfgen.BinaryValue("MRUListEx", sbgen.MRUListEx(0)),
	)
	runMRU := regfgen.NewKey("RunMRU").WithLastWrite(p16MRUAt).WithValues(
		regfgen.StringValue("a", p16FullPath+" /silent"+"\\1"),
		regfgen.StringValue("MRUList", "a"),
	)
	explorer := regfgen.NewKey("Explorer", userAssist, recentDocs, runMRU)

	return regfgen.Build("NTUSER.DAT", regfgen.NewKey("ROOT",
		regfgen.NewKey("Software", regfgen.NewKey("Microsoft",
			regfgen.NewKey("Windows", regfgen.NewKey("CurrentVersion", explorer)))),
	).WithLastWrite(p16HiveWrite))
}

func p16RecentDocValue(name string) []byte {
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

// p16ChromeHistory builds a Chromium History holding one visit and one
// download of the tracked executable.
func p16ChromeHistory(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "History")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		`CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)`,
		`CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER)`,
		`CREATE TABLE downloads(id INTEGER PRIMARY KEY, target_path TEXT, start_time INTEGER,
		    end_time INTEGER, total_bytes INTEGER, received_bytes INTEGER, state INTEGER,
		    referrer TEXT, mime_type TEXT, danger_type INTEGER, opened INTEGER)`,
		`CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url TEXT)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	chromeTime := func(at time.Time) int64 { return (at.Unix() + 11644473600) * 1_000_000 }

	db.Exec(`INSERT INTO urls VALUES(1,'https://downloads.example.test/tools/','Tools',1,?)`,
		chromeTime(p16DownloadAt.Add(-time.Minute)))
	db.Exec(`INSERT INTO visits VALUES(1,1,?,805306368)`, chromeTime(p16DownloadAt.Add(-time.Minute)))

	db.Exec(`INSERT INTO downloads VALUES(1,?,?,?,?,?,1,'https://downloads.example.test/tools/',
	         'application/octet-stream',0,0)`,
		p16FullPath, chromeTime(p16DownloadAt), chromeTime(p16DownloadAt.Add(30*time.Second)),
		262144, 262144)
	db.Exec(`INSERT INTO downloads_url_chains VALUES(1,0,'https://downloads.example.test/redirect')`)
	db.Exec(`INSERT INTO downloads_url_chains VALUES(1,1,?)`, p16DownloadURL)
	db.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// p16ActivitiesCache builds a Windows Timeline database.
func p16ActivitiesCache(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ActivitiesCache.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE Activity(
		Id TEXT, AppId TEXT, ActivityType INTEGER, Payload TEXT,
		StartTime INTEGER, EndTime INTEGER, LastModifiedTime INTEGER,
		LastModifiedOnClient INTEGER, PlatformDeviceId TEXT)`); err != nil {
		t.Fatal(err)
	}
	appID, _ := json.Marshal([]map[string]string{
		{"application": p16FullPath, "platform": "windows_win32"},
	})
	payload, _ := json.Marshal(map[string]string{
		"displayText":    p16Document,
		"appDisplayName": "Contoso Updater",
		"contentUri":     `file:///C:/Users/jdoe/Documents/` + p16Document,
	})
	db.Exec(`INSERT INTO Activity VALUES(?,?,?,?,?,?,?,?,?)`,
		"11111111-2222-3333-4444-555555555555", string(appID), 5, string(payload),
		p16ActivityAt.Unix(), p16ActivityAt.Add(5*time.Minute).Unix(),
		p16ActivityAt.Unix(), p16ActivityAt.Unix(), "device-abc")
	// A row whose payload is not readable JSON: must survive, flagged.
	db.Exec(`INSERT INTO Activity VALUES(?,?,?,?,?,?,?,?,?)`,
		"22222222-0000-0000-0000-000000000000", string(appID), 6, "{not json",
		p16ActivityAt.Add(time.Hour).Unix(), 0, 0, 0, "")
	db.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// p16Catalog is the cross-artifact acceptance case.
func p16Catalog(t *testing.T) map[string][]byte {
	t.Helper()
	return map[string][]byte{
		"Windows/appcompat/Programs/Amcache.hve":                                      p16Amcache(),
		"Users/jdoe/NTUSER.DAT":                                                       p16NTUser(),
		"Windows/Prefetch/UPDATER.EXE-11223344.pf":                                    p15Prefetch(),
		"Windows/System32/winevt/Logs/Security.evtx":                                  p15SecurityLog(),
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History":            p16ChromeHistory(t),
		"Users/jdoe/AppData/Local/ConnectedDevicesPlatform/L.jdoe/ActivitiesCache.db": p16ActivitiesCache(t),
	}
}

func p16Case(t *testing.T, mux http.Handler, files map[string][]byte) string {
	t.Helper()
	c := mustCreateCase(t, mux, "Phase 16 "+t.Name())
	disc := discoverBinaryDir(t, mux, c.ID, files)
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("fixture failed to parse: %+v", imp.ParseFailures)
	}
	return c.ID
}

// ---------------- Classification and visibility ----------------

// Amcache was previously classified "supported" while producing nothing.
// It must now produce events AND stay classified as the hive it is.
func TestPhase16_AmcacheProducesEventsAndKeepsItsFileClassification(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p16Case(t, mux, p16Catalog(t))

	am := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactAmcache))
	if am.Total == 0 {
		t.Fatal("Amcache produced no events; it was classified supported while parsing to nothing")
	}
	e := am.Items[0]
	if e.ArtifactLabel != "Amcache" {
		t.Errorf("artifact label = %q, want Amcache", e.ArtifactLabel)
	}
	var prov EventProvenance
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/"+e.ID, nil, &prov)
	if rec.Code != http.StatusOK {
		t.Fatalf("provenance: %d", rec.Code)
	}
	if !strings.Contains(strings.ToLower(prov.SourceFile.Path), "amcache.hve") {
		t.Errorf("provenance does not reach the hive: %q", prov.SourceFile.Path)
	}
	if prov.SourceFile.ArtifactType != model.ArtifactRegistryHive {
		t.Errorf("the source FILE is %q; it must stay a registry hive", prov.SourceFile.ArtifactType)
	}
}

// Every new artifact must be filterable, searchable and labelled.
func TestPhase16_NewArtifactsAreVisibleInTheTimeline(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p16Case(t, mux, p16Catalog(t))

	want := map[string]string{
		model.ArtifactAmcache:         "Amcache",
		model.ArtifactRecentDocs:      "RecentDocs",
		model.ArtifactRunMRU:          "Run dialog (RunMRU)",
		model.ArtifactBrowserDownload: "Browser download",
		model.ArtifactActivitiesCache: "Windows Timeline (ActivitiesCache)",
	}
	var facets EventFacetsResponse
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/facets", nil, &facets)
	labels := map[string]string{}
	for _, o := range facets.ArtifactTypes {
		labels[o.Value] = o.Label
	}

	for artifactType, label := range want {
		res := searchEvents(t, mux, caseID, vals("artifact_type", artifactType))
		if res.Total == 0 {
			t.Errorf("%s produced no events", artifactType)
			continue
		}
		if got := labels[artifactType]; got != label {
			t.Errorf("%s label = %q, want %q", artifactType, got, label)
		}
		for _, e := range res.Items {
			if e.Extra["evidence_meaning"] == "" {
				t.Errorf("%s event does not state what it proves", artifactType)
			}
			if e.Extra["timestamp_meaning"] == "" {
				t.Errorf("%s event does not state what its timestamp means", artifactType)
			}
		}
	}
}

// ---------------- Cross-artifact acceptance (spec 31) ----------------

// The same executable appears in Amcache, Prefetch, EVTX 4688,
// UserAssist, RunMRU and a browser download. Each must remain its own
// event with its own provenance, timestamp and forensic weight.
func TestPhase16_SameExecutableAcrossSixArtifactsStaysSixEvents(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p16Case(t, mux, p16Catalog(t))

	res := searchEvents(t, mux, caseID, vals("q", p16Executable, "page_size", "100"))
	if res.Total == 0 {
		t.Fatal("the executable was not found in any artifact")
	}

	byArtifact := map[string][]TimelineEvent{}
	for _, e := range res.Items {
		byArtifact[e.ArtifactType] = append(byArtifact[e.ArtifactType], e)
	}
	for _, want := range []string{
		model.ArtifactAmcache,
		model.ArtifactPrefetch,
		model.ArtifactWindowsEventLog,
		model.ArtifactUserAssist,
		model.ArtifactRunMRU,
		model.ArtifactBrowserDownload,
	} {
		if len(byArtifact[want]) == 0 {
			t.Errorf("%s contributes no event mentioning %s", want, p16Executable)
		}
	}

	// Distinct events, distinct provenance.
	ids := map[string]bool{}
	sources := map[string]bool{}
	for _, e := range res.Items {
		if ids[e.ID] {
			t.Errorf("event id %s appears twice", e.ID)
		}
		ids[e.ID] = true
		sources[e.SourceFileID] = true
	}
	if len(sources) < 4 {
		t.Errorf("the matching events come from %d source files; the artifacts are independent files", len(sources))
	}

	// Timestamps must NOT be overwritten by each other.
	stamps := map[string]time.Time{}
	for at, evs := range byArtifact {
		stamps[at] = evs[0].Timestamp
	}
	if a, b := stamps[model.ArtifactAmcache], stamps[model.ArtifactUserAssist]; a.Equal(b) && !a.IsZero() {
		t.Error("Amcache and UserAssist share a timestamp; each must keep its own")
	}
	if got, want := stamps[model.ArtifactAmcache], p16AmcacheAt; !got.Equal(want) {
		t.Errorf("Amcache timestamp = %s, want %s", got, want)
	}
	if got, want := stamps[model.ArtifactBrowserDownload], p16DownloadAt; !got.Equal(want) {
		t.Errorf("download timestamp = %s, want the start time %s", got, want)
	}

	// Only the EVTX record may be a process creation.
	for _, e := range res.Items {
		if e.EventType != model.EventProcessCreate {
			continue
		}
		if e.ArtifactType != model.ArtifactWindowsEventLog {
			t.Errorf("%s was emitted as a process-creation event; only EVTX 4688 records that", e.ArtifactType)
		}
	}
	// And the weaker artifacts must each disclaim execution.
	disclaimers := map[string]string{
		model.ArtifactAmcache:         "not a process-creation record",
		model.ArtifactRunMRU:          "not evidence that the command executed",
		model.ArtifactBrowserDownload: "NOT evidence that it was executed",
		model.ArtifactUserAssist:      "not a process-creation record",
	}
	for artifactType, phrase := range disclaimers {
		for _, e := range byArtifact[artifactType] {
			if !strings.Contains(e.Extra["evidence_meaning"], phrase) {
				t.Errorf("%s does not disclaim execution (%q): %q", artifactType, phrase, e.Extra["evidence_meaning"])
			}
		}
	}
}

// ---------------- Browser acceptance (spec 32) ----------------

func TestPhase16_BrowserVisitDownloadAndCacheStayDistinct(t *testing.T) {
	mux := newTestRouter(t)
	files := map[string][]byte{
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History": p16ChromeHistory(t),
	}
	for k, v := range cacheCatalog(t) {
		if strings.HasSuffix(k, "/History") {
			continue // the Phase 16 History above is the one under test
		}
		files[k] = v
	}
	caseID := p16Case(t, mux, files)

	visits := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactBrowserHistory))
	downloads := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactBrowserDownload))
	cache := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactBrowserCache))

	if visits.Total == 0 || downloads.Total == 0 || cache.Total == 0 {
		t.Fatalf("visits=%d downloads=%d cache=%d; all three must be present",
			visits.Total, downloads.Total, cache.Total)
	}
	// Three artifact types, three event types, no overlap.
	types := map[string]string{}
	for _, set := range []EventSearchResponse{visits, downloads, cache} {
		for _, e := range set.Items {
			if prev, ok := types[e.ID]; ok && prev != e.ArtifactType {
				t.Errorf("event %s appears under two artifact types", e.ID)
			}
			types[e.ID] = e.ArtifactType
		}
	}
	if visits.Items[0].EventType == downloads.Items[0].EventType {
		t.Error("a visit and a download share an event type")
	}
	if downloads.Items[0].EventType != model.EventBrowserDownload {
		t.Errorf("download event type = %q", downloads.Items[0].EventType)
	}

	// The download must carry what an analyst pivots on.
	d := downloads.Items[0]
	if d.Extra["url"] != p16DownloadURL {
		t.Errorf("download URL = %q, want the final chain entry %q", d.Extra["url"], p16DownloadURL)
	}
	if d.FilePath != p16FullPath {
		t.Errorf("download target path = %q, want %q", d.FilePath, p16FullPath)
	}
	if d.Extra["download_state"] != "complete" {
		t.Errorf("download state = %q", d.Extra["download_state"])
	}
	if d.Extra["download_end_time"] == "" {
		t.Error("the download end time was not recorded")
	}
	if d.Extra["download_referrer"] == "" {
		t.Error("the referrer was not recorded")
	}

	// No finding may arise merely because browser artifacts exist.
	doJSON(t, mux, "POST", "/api/cases/"+caseID+"/analyze", nil, nil)
	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings)
	if len(findings) != 0 {
		t.Errorf("browser artifacts alone produced %d findings", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected: %s", f.Title)
		}
	}
}

// ---------------- Layer boundaries (spec 22, 24) ----------------

// Scenario: artifact -> event, with zero findings and zero investigations.
func TestPhase16_NewArtifactsAloneProduceNoFindingOrInvestigation(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p16Case(t, mux, map[string][]byte{
		"Windows/appcompat/Programs/Amcache.hve": p16Amcache(),
		"Users/jdoe/NTUSER.DAT":                  p16NTUser(),
		"Users/jdoe/AppData/Local/ConnectedDevicesPlatform/L.jdoe/ActivitiesCache.db": p16ActivitiesCache(t),
	})

	events := searchEvents(t, mux, caseID, vals("page_size", "100"))
	if events.Total == 0 {
		t.Fatal("no events")
	}
	if rec := doJSON(t, mux, "POST", "/api/cases/"+caseID+"/analyze", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("analyze: %d", rec.Code)
	}

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/findings", nil, &findings)
	if len(findings) != 0 {
		t.Errorf("Amcache/MRU/Timeline evidence alone produced %d findings", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected: %s", f.Title)
		}
	}
	var investigations []model.Investigation
	doJSON(t, mux, "GET", "/api/cases/"+caseID+"/investigations", nil, &investigations)
	if len(investigations) != 0 {
		t.Errorf("produced %d investigations", len(investigations))
	}
	for _, e := range events.Items {
		if len(e.Findings) != 0 {
			t.Errorf("event %s (%s) is cited by a finding", e.ID, e.ArtifactType)
		}
	}
}

// Deleting the evidence removes the derived events.
func TestPhase16_DeletingEvidenceRemovesItsEvents(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "phase16 deletion")
	disc := discoverBinaryDir(t, mux, c.ID, p16Catalog(t))
	importAllFrom(t, mux, c.ID, disc)

	if searchEvents(t, mux, c.ID, nil).Total == 0 {
		t.Fatal("no events to delete")
	}
	rec := doJSON(t, mux, "DELETE", "/api/cases/"+c.ID+"/collections/"+disc.Collection.ID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("deleting: %d %s", rec.Code, rec.Body.String())
	}
	if n := searchEvents(t, mux, c.ID, nil).Total; n != 0 {
		t.Errorf("%d events survived deletion", n)
	}
	for _, at := range []string{
		model.ArtifactAmcache, model.ArtifactRecentDocs, model.ArtifactRunMRU,
		model.ArtifactBrowserDownload, model.ArtifactActivitiesCache,
	} {
		if n := searchEvents(t, mux, c.ID, vals("artifact_type", at)).Total; n != 0 {
			t.Errorf("%d %s events remain", n, at)
		}
	}
}

// ---------------- ActivitiesCache ----------------

func TestPhase16_ActivitiesCacheRecordsActivityNotExecution(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p16Case(t, mux, p16Catalog(t))

	res := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactActivitiesCache, "page_size", "50"))
	if res.Total != 2 {
		t.Fatalf("got %d activity events, want 2 (including the malformed-payload row)", res.Total)
	}
	var main *TimelineEvent
	for i := range res.Items {
		if res.Items[i].Extra["display_text"] == p16Document {
			main = &res.Items[i]
		}
	}
	if main == nil {
		t.Fatal("the activity naming the document is missing")
	}
	if main.EventType != model.EventActivityRecorded {
		t.Errorf("event type = %q", main.EventType)
	}
	if !main.Timestamp.Equal(p16ActivityAt) {
		t.Errorf("timestamp = %s, want the start time %s", main.Timestamp, p16ActivityAt)
	}
	if got := main.Extra["activity_type"]; got != "application or file opened" {
		t.Errorf("activity type = %q", got)
	}
	if main.Extra["activity_end_time"] == "" {
		t.Error("the end time was not recorded")
	}
	if !strings.Contains(main.Extra["evidence_meaning"], "NOT a process-creation record") {
		t.Errorf("evidence_meaning does not disclaim process creation: %q", main.Extra["evidence_meaning"])
	}
	if !strings.Contains(main.Extra["device_note"], "need not have happened on this machine") {
		t.Errorf("device context is not qualified: %q", main.Extra["device_note"])
	}
	if main.EventType == model.EventProcessCreate {
		t.Error("an activity was emitted as a process creation")
	}

	// The malformed-payload row must survive with a warning.
	warned := false
	for _, e := range res.Items {
		if strings.Contains(e.Extra["warnings"], "not readable JSON") {
			warned = true
		}
	}
	if !warned {
		t.Error("the row with an unreadable payload was dropped rather than flagged")
	}
}

// A SQLite file that is not a Timeline database must not be claimed.
func TestPhase16_NonTimelineSQLiteIsNotParsedAsActivitiesCache(t *testing.T) {
	mux := newTestRouter(t)
	path := filepath.Join(t.TempDir(), "ActivitiesCache.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE unrelated(id INTEGER PRIMARY KEY, note TEXT)`)
	db.Exec(`INSERT INTO unrelated VALUES(1,'nothing to do with Windows Timeline')`)
	db.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	c := mustCreateCase(t, mux, "decoy timeline")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Users/jdoe/AppData/Local/ConnectedDevicesPlatform/L.jdoe/ActivitiesCache.db": data,
	})
	imp := importAllFrom(t, mux, c.ID, disc)

	// Claimed by name, then honestly reported as not this artifact.
	if len(imp.ParseFailures) != 1 {
		t.Fatalf("got %d parse failures, want 1", len(imp.ParseFailures))
	}
	if n := searchEvents(t, mux, c.ID, nil).Total; n != 0 {
		t.Errorf("a decoy produced %d events", n)
	}
}

// ---------------- Search and semantics ----------------

func TestPhase16_NewArtifactsAreSearchableByTheirContent(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p16Case(t, mux, p16Catalog(t))

	for _, tc := range []struct{ name, field, term, wantArtifact string }{
		{"the Amcache SHA-1 is NOT free-text searchable", "q", "da39a3ee5e6b4b0d3255bfef95601890afd80709", ""},
		{"the download URL", "url", "downloads.example.test", model.ArtifactBrowserDownload},
		{"the RecentDocs document", "q", "quarterly-figures", ""},
		{"the RunMRU command", "command_line", "/silent", model.ArtifactRunMRU},
		{"the catalogued path", "path", "updater.exe", ""},
	} {
		res := searchEvents(t, mux, caseID, vals(tc.field, tc.term))
		if tc.wantArtifact == "" && tc.field == "q" && strings.HasPrefix(tc.term, "da39") {
			// Hashes are deliberately outside the free-text surface.
			if res.Total != 0 {
				t.Errorf("%s: matched %d events; hashes are not free-text searchable", tc.name, res.Total)
			}
			continue
		}
		if res.Total == 0 {
			t.Errorf("%s: %s=%q matched nothing", tc.name, tc.field, tc.term)
			continue
		}
		if tc.wantArtifact == "" {
			continue
		}
		found := false
		for _, e := range res.Items {
			if e.ArtifactType == tc.wantArtifact {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: did not reach a %s event", tc.name, tc.wantArtifact)
		}
	}
}

// A download must never be presented as an execution.
func TestPhase16_DownloadIsNotExecution(t *testing.T) {
	mux := newTestRouter(t)
	caseID := p16Case(t, mux, p16Catalog(t))

	res := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactBrowserDownload))
	if res.Total == 0 {
		t.Fatal("no download events")
	}
	for _, e := range res.Items {
		if e.EventType == model.EventProcessCreate {
			t.Error("a download was emitted as a process creation")
		}
		meaning := e.Extra["evidence_meaning"]
		for _, want := range []string{"NOT evidence that the file was opened", "NOT evidence that it was executed"} {
			if !strings.Contains(meaning, want) {
				t.Errorf("evidence_meaning is missing %q: %q", want, meaning)
			}
		}
		// The browser IS the process that fetched it, which is honest.
		if e.ProcessName == "" {
			t.Error("the retrieving browser is not named")
		}
	}
}

// Long URLs and paths must survive the API intact for the UI to truncate.
func TestPhase16_LongValuesSurviveIntact(t *testing.T) {
	mux := newTestRouter(t)
	long := strings.Repeat("very-long-path-segment-", 30)
	hive := regfgen.Build("NTUSER.DAT", regfgen.NewKey("ROOT",
		regfgen.NewKey("Software", regfgen.NewKey("Microsoft",
			regfgen.NewKey("Windows", regfgen.NewKey("CurrentVersion",
				regfgen.NewKey("Explorer",
					regfgen.NewKey("TypedPaths").WithLastWrite(p16MRUAt).WithValues(
						regfgen.StringValue("url1", `C:\`+long+`\end`),
					)))))),
	).WithLastWrite(p16HiveWrite))

	caseID := p16Case(t, mux, map[string][]byte{"Users/jdoe/NTUSER.DAT": hive})
	res := searchEvents(t, mux, caseID, vals("q", "very-long-path-segment", "page_size", "50"))
	if res.Total == 0 {
		t.Fatal("the long path was not searchable")
	}
	found := false
	for _, e := range res.Items {
		if strings.Contains(e.FilePath, long) {
			found = true
		}
	}
	if !found {
		t.Error("the long path came back altered or truncated by the API")
	}
}
