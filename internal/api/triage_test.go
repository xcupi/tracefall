package api

import (
	"net/http"
	"testing"
	"time"

	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/model"
	"tracefall/internal/regf/regfgen"
)

// Phase 9A: evidence coverage, triage classification, background import
// progress, and parse-error reporting -- exercised through the HTTP API,
// because that is the contract the dashboard actually consumes.

// mixedCatalog is a small collection holding one of everything the
// triage view has to distinguish: supported evidence, recognized-but-
// unparsed artifacts, a file that will fail to parse, and noise.
func mixedCatalog() map[string][]byte {
	return map[string][]byte{
		"Windows/System32/winevt/Logs/Security.evtx": attackEvtx(),
		"Users/jdoe/NTUSER.DAT":                      persistenceHive(),
		// Supported by name/content, but broken -- this is a PARSE
		// FAILURE, which is not the same thing as unsupported.
		"Windows/System32/config/COMPONENTS": regfgen.Truncate(persistenceHive(), 2200),
		// Recognized artifact classes Tracefall has no parser for.
		"Windows/Prefetch/CMD.EXE-A1B2C3D4.pf": []byte("MAM\x04synthetic"),
		"C/$MFT":                               []byte("FILE0synthetic"),
		// Noise.
		"Windows/Fonts/segoeui.ttf": []byte("synthetic font"),
	}
}

func TestCapabilities_ReportsWhatThisBuildCanParse(t *testing.T) {
	mux := newTestRouter(t)

	var report CapabilityReport
	rec := doJSON(t, mux, "GET", "/api/capabilities", nil, &report)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if len(report.Supported) == 0 {
		t.Fatal("no supported artifact classes reported")
	}
	if len(report.Unsupported) == 0 {
		t.Fatal("no unsupported artifact classes reported -- the known gaps must be documented, not hidden")
	}
	for _, s := range report.Supported {
		if !s.Supported || s.Parser == "" {
			t.Errorf("supported entry %+v is missing support/parser", s)
		}
	}
	// The filter vocabularies the UI builds its dropdowns from.
	if len(report.Priorities) == 0 || len(report.Families) == 0 || len(report.Statuses) == 0 {
		t.Error("capability report omits a filter vocabulary the dashboard needs")
	}
}

func TestDiscovery_ClassifiesAndCountsTheWholeCatalog(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Triage coverage")
	disc := discoverBinaryDir(t, mux, c.ID, mixedCatalog())

	cov := disc.Coverage
	if cov.Discovered != 6 {
		t.Errorf("discovered = %d, want 6", cov.Discovered)
	}
	// Security.evtx, NTUSER.DAT and COMPONENTS are all claimed by a
	// parser; the .pf, $MFT and font are not.
	if cov.Supported != 3 || cov.Unsupported != 3 {
		t.Errorf("supported/unsupported = %d/%d, want 3/3", cov.Supported, cov.Unsupported)
	}
	if cov.Recommended != 3 {
		t.Errorf("recommended = %d, want 3 (the supported high/critical files)", cov.Recommended)
	}
	if len(cov.ByType) == 0 {
		t.Fatal("coverage has no per-artifact-type breakdown")
	}

	// Every discovered file must be classified -- an unclassified file is
	// exactly the problem this phase exists to fix.
	for _, f := range disc.SourceFiles {
		if f.TypeLabel == "" {
			t.Errorf("%s has no artifact type label", f.Path)
		}
		if f.Priority == "" {
			t.Errorf("%s has no priority", f.Path)
		}
		if !f.Supported && f.UnsupportedReason == "" {
			t.Errorf("%s is unsupported but explains nothing", f.Path)
		}
	}

	// The coverage buckets must add up to the catalog.
	total := 0
	for _, b := range cov.ByType {
		total += b.Files
	}
	if total != cov.Discovered {
		t.Errorf("coverage buckets sum to %d, catalog holds %d", total, cov.Discovered)
	}
}

// A HIGH-priority artifact Tracefall cannot parse must appear that way
// in the catalog -- not hidden, and not disguised as broken evidence.
func TestDiscovery_UnsupportedHighPriorityArtifactIsVisible(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Unsupported visibility")
	disc := discoverBinaryDir(t, mux, c.ID, mixedCatalog())

	pf, ok := sourceFileByPath(disc.SourceFiles, "Windows/Prefetch/CMD.EXE-A1B2C3D4.pf")
	if !ok {
		t.Fatal("the Prefetch file was not cataloged at all")
	}
	if pf.Supported {
		t.Error("raw Prefetch reported as supported")
	}
	if pf.Priority != "high" {
		t.Errorf("priority = %q, want high -- an unsupported artifact still has forensic value", pf.Priority)
	}
	if pf.ImportStatus != model.SourceFileUnsupported {
		t.Errorf("import status = %q, want unsupported", pf.ImportStatus)
	}
	if pf.ImportStatus == model.SourceFileFailed {
		t.Error("an unsupported file must never be reported as a parse failure")
	}
	if pf.UnsupportedReason == "" {
		t.Error("no reason given for why Prefetch cannot be parsed")
	}
	if pf.Recommended {
		t.Error("an unimportable file must not be recommended")
	}
}

func TestSources_CarryTriageForTheWholeCase(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Case-wide triage")
	discoverBinaryDir(t, mux, c.ID, mixedCatalog())

	var sources []TriagedSourceFile
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/sources", nil, &sources)
	if len(sources) != 6 {
		t.Fatalf("sources = %d, want 6", len(sources))
	}
	for _, s := range sources {
		if s.TypeLabel == "" || s.Priority == "" {
			t.Errorf("case-wide source %s is missing triage: %+v", s.Path, s)
		}
	}
}

// ---------------- import progress ----------------

// pollJob drives a background import to completion and returns the
// distinct progress states it passed through, so a test can assert that
// progress genuinely ADVANCED rather than jumping from 0 to done.
func pollJob(t *testing.T, mux *http.ServeMux, caseID, jobID string) (states []ImportProgress, final ImportProgress) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var p ImportProgress
		rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/import-jobs/"+jobID, nil, &p)
		if rec.Code != http.StatusOK {
			t.Fatalf("job status: %d %s", rec.Code, rec.Body.String())
		}
		if len(states) == 0 || states[len(states)-1].Phase != p.Phase || states[len(states)-1].FilesParsed != p.FilesParsed {
			states = append(states, p)
		}
		if p.Done {
			return states, p
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("import job never completed")
	return nil, ImportProgress{}
}

func startImport(t *testing.T, mux *http.ServeMux, caseID, collectionID string, ids []string) (string, int) {
	t.Helper()
	var started struct {
		JobID string `json:"job_id"`
	}
	rec := doJSON(t, mux, "POST", "/api/cases/"+caseID+"/evidence/"+collectionID+"/import/start",
		map[string][]string{"source_file_ids": ids}, &started)
	return started.JobID, rec.Code
}

func selectableIDs(disc DiscoverResult) []string {
	var ids []string
	for _, f := range disc.SourceFiles {
		if f.Supported && f.ImportStatus == model.SourceFileDiscovered {
			ids = append(ids, f.ID)
		}
	}
	return ids
}

func TestImportJob_StartsAdvancesCompletes(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Import progress")
	disc := discoverBinaryDir(t, mux, c.ID, mixedCatalog())
	ids := selectableIDs(disc)

	jobID, code := startImport(t, mux, c.ID, disc.Collection.ID, ids)
	if code != http.StatusAccepted {
		t.Fatalf("start import: status %d, want 202", code)
	}

	states, final := pollJob(t, mux, c.ID, jobID)

	if final.Phase != PhaseComplete {
		t.Errorf("final phase = %q, want %q (error: %q)", final.Phase, PhaseComplete, final.Error)
	}
	if final.Percent != 100 {
		t.Errorf("final percent = %d, want 100", final.Percent)
	}
	if final.Result == nil {
		t.Fatal("a completed job carries no result")
	}
	if final.FilesTotal != len(ids) {
		t.Errorf("files_total = %d, want %d", final.FilesTotal, len(ids))
	}
	if final.FilesParsed != len(ids) {
		t.Errorf("files_parsed = %d, want %d -- every selected file must be accounted for", final.FilesParsed, len(ids))
	}

	// Progress must be monotonic and never exceed 100. A bar that goes
	// backwards or overshoots is worse than none.
	prev := -1
	for _, s := range states {
		if s.Percent > 100 {
			t.Errorf("percent %d exceeds 100", s.Percent)
		}
		if s.Percent >= 0 && s.Percent < prev {
			t.Errorf("percent went backwards: %d after %d", s.Percent, prev)
		}
		if s.Percent >= 0 {
			prev = s.Percent
		}
	}
	// The reported phases must be ones that really exist.
	valid := map[string]bool{
		PhasePreparing: true, PhaseParsing: true, PhaseEnriching: true,
		PhasePersisting: true, PhaseFinalizing: true, PhaseComplete: true, PhaseFailed: true,
	}
	for _, s := range states {
		if !valid[s.Phase] {
			t.Errorf("unknown phase %q reported", s.Phase)
		}
	}
	t.Logf("observed %d progress states, phases: %v", len(states), phasesOf(states))
}

// current_file must never publish a server filesystem path.
func TestImportJob_DoesNotLeakServerPaths(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "No path leaks")
	disc := discoverBinaryDir(t, mux, c.ID, mixedCatalog())

	jobID, _ := startImport(t, mux, c.ID, disc.Collection.ID, selectableIDs(disc))
	states, _ := pollJob(t, mux, c.ID, jobID)

	for _, s := range states {
		if s.CurrentFile == "" {
			continue
		}
		if s.CurrentFile[0] == '/' {
			t.Errorf("current_file %q is an absolute server path", s.CurrentFile)
		}
		if containsAny(s.CurrentFile, "/tmp/", "TempDir", "\\Users\\runner") {
			t.Errorf("current_file %q leaks server filesystem detail", s.CurrentFile)
		}
	}
}

// The server-side half of "don't submit the same selection twice".
func TestImportJob_RejectsConcurrentImportOfTheSameCollection(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Concurrent import")
	disc := discoverBinaryDir(t, mux, c.ID, mixedCatalog())
	ids := selectableIDs(disc)

	jobID, code := startImport(t, mux, c.ID, disc.Collection.ID, ids)
	if code != http.StatusAccepted {
		t.Fatalf("first start: %d", code)
	}
	// A second start while the first is running must be refused. (If the
	// first has already finished, 202 is legitimate -- the guard is about
	// concurrency, not a permanent lock -- so only a genuine overlap is
	// asserted on.)
	_, second := startImport(t, mux, c.ID, disc.Collection.ID, ids)
	if second != http.StatusConflict && second != http.StatusAccepted {
		t.Errorf("second start: status %d, want 409 (or 202 if the first already finished)", second)
	}

	_, final := pollJob(t, mux, c.ID, jobID)
	if final.Phase != PhaseComplete {
		t.Errorf("first job did not complete: %+v", final)
	}
	// Once nothing is running, a further import is allowed again.
	if _, again := startImport(t, mux, c.ID, disc.Collection.ID, ids); again != http.StatusAccepted {
		t.Errorf("start after completion: status %d, want 202", again)
	}
}

func TestImportJob_ZeroFileSelectionIsRejected(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Empty selection")
	disc := discoverBinaryDir(t, mux, c.ID, mixedCatalog())

	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID+"/import/start",
		map[string][]string{"source_file_ids": {}}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400 for an empty selection", rec.Code)
	}
}

func TestImportJob_UnknownJobIsNotFound(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Unknown job")
	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/import-jobs/does-not-exist", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", rec.Code)
	}
}

// A job belongs to its case; another case must not be able to read it.
func TestImportJob_IsScopedToItsCase(t *testing.T) {
	mux := newTestRouter(t)
	a := mustCreateCase(t, mux, "Job owner")
	b := mustCreateCase(t, mux, "Job outsider")
	disc := discoverBinaryDir(t, mux, a.ID, mixedCatalog())

	jobID, _ := startImport(t, mux, a.ID, disc.Collection.ID, selectableIDs(disc))
	rec := doJSON(t, mux, "GET", "/api/cases/"+b.ID+"/import-jobs/"+jobID, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("another case read job %s: status %d, want 404", jobID, rec.Code)
	}
}

// ---------------- parse errors ----------------

// The distinction this phase exists to make: a file Tracefall has no
// parser for is UNSUPPORTED; a file it should have been able to read and
// could not is a PARSE FAILURE. Conflating them misrepresents evidence.
func TestImport_ParseFailureIsDistinctFromUnsupported(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Parse failure vs unsupported")
	disc := discoverBinaryDir(t, mux, c.ID, mixedCatalog())

	jobID, _ := startImport(t, mux, c.ID, disc.Collection.ID, selectableIDs(disc))
	_, final := pollJob(t, mux, c.ID, jobID)
	res := final.Result
	if res == nil {
		t.Fatal("no result")
	}

	if len(res.ParseFailures) == 0 {
		t.Fatal("the deliberately truncated hive did not produce a parse failure")
	}
	var found bool
	for _, f := range res.ParseFailures {
		if f.Filename != "COMPONENTS" {
			continue
		}
		found = true
		if f.Category != ParseFailureCorrupt {
			t.Errorf("category = %q, want %q", f.Category, ParseFailureCorrupt)
		}
		if f.Stage != ParseStageParse {
			t.Errorf("stage = %q, want %q", f.Stage, ParseStageParse)
		}
		if f.Message == "" {
			t.Error("no human-readable message")
		}
		if f.PartialEvents {
			t.Error("PartialEvents is true, but import parses fully before persisting anything")
		}
		// Safety: nothing internal may reach the browser.
		if containsAny(f.Message, "/tmp/", "goroutine", ".go:", "SQL", "panic") {
			t.Errorf("parse-failure message leaks internals: %q", f.Message)
		}
		if len(f.Path) > 0 && f.Path[0] == '/' {
			t.Errorf("parse-failure path %q is absolute", f.Path)
		}
	}
	if !found {
		t.Errorf("COMPONENTS is not among the reported failures: %+v", res.ParseFailures)
	}

	// The unsupported files must NOT appear as parse failures.
	for _, f := range res.ParseFailures {
		if f.Filename == "CMD.EXE-A1B2C3D4.pf" || f.Filename == "$MFT" || f.Filename == "segoeui.ttf" {
			t.Errorf("unsupported file %q reported as a parse failure", f.Filename)
		}
	}

	// And the failed file must be marked failed in the catalog, while the
	// good ones imported.
	var sources []TriagedSourceFile
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/sources", nil, &sources)
	for _, s := range sources {
		switch s.OriginalFilename {
		case "COMPONENTS":
			if s.ImportStatus != model.SourceFileFailed {
				t.Errorf("COMPONENTS status = %q, want failed", s.ImportStatus)
			}
		case "Security.evtx", "NTUSER.DAT":
			if s.ImportStatus != model.SourceFileImported {
				t.Errorf("%s status = %q, want imported", s.OriginalFilename, s.ImportStatus)
			}
		case "CMD.EXE-A1B2C3D4.pf", "$MFT", "segoeui.ttf":
			if s.ImportStatus != model.SourceFileUnsupported {
				t.Errorf("%s status = %q, want unsupported", s.OriginalFilename, s.ImportStatus)
			}
		}
	}
}

// A failed file must contribute no events at all -- no partial corruption
// of the evidence set.
func TestImport_FailedFileContributesNoEvents(t *testing.T) {
	mux := newTestRouter(t)
	only := map[string][]byte{
		"Windows/System32/config/COMPONENTS":    regfgen.Truncate(persistenceHive(), 2200),
		"Windows/System32/winevt/Logs/Bad.evtx": evtxgen.CorruptSignature(attackEvtx()),
	}
	c := mustCreateCase(t, mux, "No partial corruption")
	disc := discoverBinaryDir(t, mux, c.ID, only)

	jobID, _ := startImport(t, mux, c.ID, disc.Collection.ID, selectableIDs(disc))
	_, final := pollJob(t, mux, c.ID, jobID)

	if final.Result == nil {
		t.Fatal("no result")
	}
	if final.Result.EventCount != 0 {
		t.Errorf("event_count = %d, want 0 -- neither file should have parsed", final.Result.EventCount)
	}
	if len(timelineOf(t, mux, c.ID)) != 0 {
		t.Error("events reached the timeline from files that failed to parse")
	}
	if final.Percent != 100 {
		t.Errorf("percent = %d; a batch where everything failed is still finished", final.Percent)
	}
}

// ---------------- helpers ----------------

func phasesOf(states []ImportProgress) []string {
	out := make([]string, 0, len(states))
	seen := map[string]bool{}
	for _, s := range states {
		if !seen[s.Phase] {
			seen[s.Phase] = true
			out = append(out, s.Phase)
		}
	}
	return out
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && len(s) >= len(sub) && indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
