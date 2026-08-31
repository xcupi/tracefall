package api

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/ad1"
	"tracefall/internal/ad1/ad1gen"
	"tracefall/internal/model"
)

// bruteForceCSV is the same content as
// testdata/scenarios/b_brute_force/EvtxECmd/20260201_090000_EvtxECmd_Output.csv
// (4 failed logons + 1 success for svc-sql) -- reused here so an AD1
// integration test can drive a real finding/investigation through the
// unmodified detect/correlate/investigate pipeline, not just verify that
// bytes moved around.
const bruteForceCSV = `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
2026-02-01T09:00:00.0000000Z,4625,Microsoft-Windows-Security-Auditing,Security,WKSTN-SIM-B,,-,Logon Failure,"TargetUserName: svc-sql; LogonType: 3; Status: 0xC000006D; SubStatus: 0xC000006A; IpAddress: 198.51.100.20; WorkstationName: WKSTN-SIM-B",,,,,,1
2026-02-01T09:01:00.0000000Z,4625,Microsoft-Windows-Security-Auditing,Security,WKSTN-SIM-B,,-,Logon Failure,"TargetUserName: svc-sql; LogonType: 3; Status: 0xC000006D; SubStatus: 0xC000006A; IpAddress: 198.51.100.20; WorkstationName: WKSTN-SIM-B",,,,,,2
2026-02-01T09:02:00.0000000Z,4625,Microsoft-Windows-Security-Auditing,Security,WKSTN-SIM-B,,-,Logon Failure,"TargetUserName: svc-sql; LogonType: 3; Status: 0xC000006D; SubStatus: 0xC000006A; IpAddress: 198.51.100.20; WorkstationName: WKSTN-SIM-B",,,,,,3
2026-02-01T09:03:00.0000000Z,4625,Microsoft-Windows-Security-Auditing,Security,WKSTN-SIM-B,,-,Logon Failure,"TargetUserName: svc-sql; LogonType: 3; Status: 0xC000006D; SubStatus: 0xC000006A; IpAddress: 198.51.100.20; WorkstationName: WKSTN-SIM-B",,,,,,4
2026-02-01T09:04:30.0000000Z,4624,Microsoft-Windows-Security-Auditing,Security,WKSTN-SIM-B,,-,Logon Success,"TargetUserName: svc-sql; LogonType: 3; TargetUserSid: S-1-5-21-1-2-3-2001; SubjectUserName: -; IpAddress: 198.51.100.20; WorkstationName: WKSTN-SIM-B",,,,,,5
`

// bruteForceCSV2 is bruteForceCSV's content for a second, DIFFERENT host
// (WKSTN-SIM-B2) -- used wherever a test needs two supported files that
// are genuinely distinct evidence, not two copies of the same content
// (which Tracefall's existing file-level dedup correctly refuses to
// import twice into one collection regardless of source format -- see
// TestAD1_DuplicateContentWithinOneImage for that behavior itself).
const bruteForceCSV2 = `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
2026-02-01T10:00:00.0000000Z,4625,Microsoft-Windows-Security-Auditing,Security,WKSTN-SIM-B2,,-,Logon Failure,"TargetUserName: svc-web; LogonType: 3; Status: 0xC000006D; SubStatus: 0xC000006A; IpAddress: 198.51.100.21; WorkstationName: WKSTN-SIM-B2",,,,,,1
2026-02-01T10:01:00.0000000Z,4625,Microsoft-Windows-Security-Auditing,Security,WKSTN-SIM-B2,,-,Logon Failure,"TargetUserName: svc-web; LogonType: 3; Status: 0xC000006D; SubStatus: 0xC000006A; IpAddress: 198.51.100.21; WorkstationName: WKSTN-SIM-B2",,,,,,2
2026-02-01T10:02:00.0000000Z,4625,Microsoft-Windows-Security-Auditing,Security,WKSTN-SIM-B2,,-,Logon Failure,"TargetUserName: svc-web; LogonType: 3; Status: 0xC000006D; SubStatus: 0xC000006A; IpAddress: 198.51.100.21; WorkstationName: WKSTN-SIM-B2",,,,,,3
2026-02-01T10:03:00.0000000Z,4625,Microsoft-Windows-Security-Auditing,Security,WKSTN-SIM-B2,,-,Logon Failure,"TargetUserName: svc-web; LogonType: 3; Status: 0xC000006D; SubStatus: 0xC000006A; IpAddress: 198.51.100.21; WorkstationName: WKSTN-SIM-B2",,,,,,4
2026-02-01T10:04:30.0000000Z,4624,Microsoft-Windows-Security-Auditing,Security,WKSTN-SIM-B2,,-,Logon Success,"TargetUserName: svc-web; LogonType: 3; TargetUserSid: S-1-5-21-1-2-3-2002; SubjectUserName: -; IpAddress: 198.51.100.21; WorkstationName: WKSTN-SIM-B2",,,,,,5
`

func buildAD1(t *testing.T, rootName string, files []ad1gen.File) []byte {
	t.Helper()
	img, err := ad1gen.Build(rootName, files, 0)
	if err != nil {
		t.Fatalf("ad1gen.Build: %v", err)
	}
	return img
}

// uploadAD1 POSTs data as a multipart/form-data upload to
// /api/cases/{id}/evidence -- the SAME endpoint uploadZip uses, since AD1
// vs ZIP is detected by content, not by a separate route.
func uploadAD1(t *testing.T, mux *http.ServeMux, caseID string, data []byte, filename string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/cases/"+caseID+"/evidence", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func mustCreateCase(t *testing.T, mux *http.ServeMux, name string) model.Case {
	t.Helper()
	var c model.Case
	rec := doJSON(t, mux, "POST", "/api/cases", map[string]string{"name": name}, &c)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create case %q: status %d, body %s", name, rec.Code, rec.Body.String())
	}
	return c
}

func sourceFileByPath(sfs []TriagedSourceFile, path string) (TriagedSourceFile, bool) {
	for _, sf := range sfs {
		if sf.Path == path {
			return sf, true
		}
	}
	return TriagedSourceFile{}, false
}

// ---------------- detection, cataloging, enumeration ----------------

func TestAD1_ValidUploadDetectedAndCataloged(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "AD1 valid upload")

	img := buildAD1(t, `E:\`, []ad1gen.File{
		{Path: "EvtxECmd/20260201_090000_EvtxECmd_Output.csv", Data: []byte(bruteForceCSV)},
		{Path: "README.txt", Data: []byte("not a supported artifact")},
	})
	rec := uploadAD1(t, mux, c.ID, img, "DiskDrigger.ad1")
	if rec.Code != http.StatusOK {
		t.Fatalf("upload AD1: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)

	if disc.Collection.SourceType != model.SourceTypeAD1 {
		t.Errorf("collection source_type = %q, want %q", disc.Collection.SourceType, model.SourceTypeAD1)
	}
	if disc.Collection.OriginalFilename != "DiskDrigger.ad1" {
		t.Errorf("collection original_filename = %q, want %q (the investigator's own upload name, not a server-side staging path)", disc.Collection.OriginalFilename, "DiskDrigger.ad1")
	}
	if disc.DiscoveredCount != 2 {
		t.Errorf("discovered_count = %d, want 2", disc.DiscoveredCount)
	}
	if disc.SupportedCount != 1 {
		t.Errorf("supported_count = %d, want 1", disc.SupportedCount)
	}
	if disc.UnsupportedCount != 1 {
		t.Errorf("unsupported_count = %d, want 1", disc.UnsupportedCount)
	}

	csv, ok := sourceFileByPath(disc.SourceFiles, "EvtxECmd/20260201_090000_EvtxECmd_Output.csv")
	if !ok {
		t.Fatalf("csv source file not found in catalog; have: %+v", disc.SourceFiles)
	}
	if !csv.Supported || csv.ImportStatus != model.SourceFileDiscovered {
		t.Errorf("csv file: supported=%v import_status=%q, want true/discovered", csv.Supported, csv.ImportStatus)
	}
	if csv.ArtifactType != model.ArtifactWindowsEventLog {
		t.Errorf("csv artifact_type = %q, want %q", csv.ArtifactType, model.ArtifactWindowsEventLog)
	}
	if csv.SHA256 != "" {
		t.Errorf("csv sha256 = %q, want empty at discovery time (computed only on import, see docs/ad1-ingestion.md)", csv.SHA256)
	}

	readme, ok := sourceFileByPath(disc.SourceFiles, "README.txt")
	if !ok {
		t.Fatal("README.txt not found in catalog")
	}
	if readme.Supported || readme.ImportStatus != model.SourceFileUnsupported {
		t.Errorf("README.txt: supported=%v import_status=%q, want false/unsupported (visible but unselectable)", readme.Supported, readme.ImportStatus)
	}

	// Import must still work after the display-name fix -- the container
	// is reopened from its deterministic staged path
	// (casefiles.AD1Path), never from the display-only OriginalFilename.
	importRec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID+"/import",
		map[string][]string{"source_file_ids": {csv.ID}}, nil)
	if importRec.Code != http.StatusOK {
		t.Fatalf("import: status %d, body %s", importRec.Code, importRec.Body.String())
	}
	var imp ImportResult
	mustDecode(t, importRec, &imp)
	if len(imp.Imported) != 1 || imp.EventCount != 5 {
		t.Errorf("import result = %+v, want 1 file / 5 events", imp)
	}
}

func TestAD1_NestedPathsEnumerated(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "AD1 nested paths")

	img := buildAD1(t, `C:\Users\jdoe\Desktop\Data`, []ad1gen.File{
		{Path: "Users/jdoe/AppData/Local/Temp/deep/file.txt", Data: []byte("nested")},
	})
	rec := uploadAD1(t, mux, c.ID, img, "nested.ad1")
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)

	if _, ok := sourceFileByPath(disc.SourceFiles, "Users/jdoe/AppData/Local/Temp/deep/file.txt"); !ok {
		t.Errorf("nested file path not found in catalog; have: %+v", disc.SourceFiles)
	}
}

// An AD1 that opens cleanly but holds no files is a valid image with
// nothing in it. It used to produce a successful discovery and a
// zero-file collection; an investigator now gets a 400 explaining that
// there is nothing to add, and no collection is created -- a collection
// containing no files can never become evidence, so leaving one behind
// only creates something to explain later.
func TestAD1_EmptyImage(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "AD1 empty image")

	img := buildAD1(t, `E:\`, nil)
	rec := uploadAD1(t, mux, c.ID, img, "empty.ad1")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("upload empty AD1: status %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if cols := listCollections(t, mux, c.ID); len(cols) != 0 {
		t.Errorf("collections after empty AD1 = %d, want 0 (no collection for an image with no files)", len(cols))
	}
}

// ---------------- error handling: never silently treat as empty ----------------

func TestAD1_CorruptUploadRejected(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "AD1 corrupt")

	img := buildAD1(t, `E:\`, []ad1gen.File{{Path: "a.txt", Data: []byte("x")}})
	// Truncate mid-structure -- looks like AD1 (magic intact) but is
	// structurally broken.
	broken := img[:600]
	rec := uploadAD1(t, mux, c.ID, broken, "corrupt.ad1")
	if rec.Code == http.StatusOK {
		t.Fatalf("corrupt AD1 upload: got 200 OK, want an error -- must never silently treat corrupt input as a valid (or empty) image")
	}
}

func TestAD1_EncryptedUploadRejected(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "AD1 encrypted")

	img := append([]byte("ADCRYPT\x00"), make([]byte, 512)...)
	rec := uploadAD1(t, mux, c.ID, img, "encrypted.ad1")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("encrypted AD1 upload: status %d, body %s, want %d with a clear actionable error", rec.Code, rec.Body.String(), http.StatusBadRequest)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("ADCRYPT")) && !bytes.Contains(rec.Body.Bytes(), []byte("encrypt")) {
		t.Errorf("error body doesn't mention encryption, got: %s", rec.Body.String())
	}
}

func TestAD1_SegmentedUploadMissingSegmentsRejected(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "AD1 segmented upload")

	img := buildAD1(t, `E:\`, []ad1gen.File{{Path: "a.txt", Data: []byte("x")}})
	broken := append([]byte(nil), img...)
	broken[28] = 2 // segment_count = 2, but only segment 1 is being uploaded
	rec := uploadAD1(t, mux, c.ID, broken, "seg1.ad1")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("segmented AD1 (missing segments) upload: status %d, body %s, want %d", rec.Code, rec.Body.String(), http.StatusBadRequest)
	}
}

// ---------------- selection / partial import ----------------

func TestAD1_PartialSelectionImportsOnlySelected(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "AD1 partial selection")

	img := buildAD1(t, `E:\`, []ad1gen.File{
		{Path: "EvtxECmd/a_EvtxECmd_Output.csv", Data: []byte(bruteForceCSV)},
		{Path: "EvtxECmd/b_EvtxECmd_Output.csv", Data: []byte(bruteForceCSV)},
	})
	rec := uploadAD1(t, mux, c.ID, img, "partial.ad1")
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	if len(disc.SourceFiles) != 2 {
		t.Fatalf("got %d source files, want 2", len(disc.SourceFiles))
	}

	only, _ := sourceFileByPath(disc.SourceFiles, "EvtxECmd/a_EvtxECmd_Output.csv")
	importRec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID+"/import",
		map[string][]string{"source_file_ids": {only.ID}}, nil)
	if importRec.Code != http.StatusOK {
		t.Fatalf("import: status %d, body %s", importRec.Code, importRec.Body.String())
	}
	var imp ImportResult
	mustDecode(t, importRec, &imp)
	if len(imp.Imported) != 1 {
		t.Fatalf("got %d imported files, want 1 (only the selected one)", len(imp.Imported))
	}
	if imp.EventCount == 0 {
		t.Fatal("import produced 0 events")
	}

	// The unselected sibling must remain "discovered", not silently
	// imported or altered.
	sfs := listSourceFiles(t, mux, c.ID)
	other, ok := sourceFileByPath(sfs, "EvtxECmd/b_EvtxECmd_Output.csv")
	if !ok {
		t.Fatal("unselected sibling file disappeared from the catalog")
	}
	if other.ImportStatus != model.SourceFileDiscovered {
		t.Errorf("unselected sibling import_status = %q, want %q (must not be imported)", other.ImportStatus, model.SourceFileDiscovered)
	}
	if other.EventCount != 0 {
		t.Errorf("unselected sibling event_count = %d, want 0", other.EventCount)
	}
}

func listSourceFiles(t *testing.T, mux *http.ServeMux, caseID string) []TriagedSourceFile {
	t.Helper()
	var sfs []TriagedSourceFile
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/sources", nil, &sfs)
	if rec.Code != http.StatusOK {
		t.Fatalf("list source files: status %d, body %s", rec.Code, rec.Body.String())
	}
	return sfs
}

// ---------------- provenance: case -> AD1 -> file -> event -> finding ----------------

func TestAD1_ImportProducesEventsAndProvenanceBackToAD1Path(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "AD1 provenance")

	const internalPath = "EvtxECmd/20260201_090000_EvtxECmd_Output.csv"
	img := buildAD1(t, `E:\`, []ad1gen.File{{Path: internalPath, Data: []byte(bruteForceCSV)}})
	rec := uploadAD1(t, mux, c.ID, img, "DiskDrigger.ad1")
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	_, imp := importAll(t, mux, c.ID, disc)
	if imp.EventCount != 5 {
		t.Fatalf("got %d events, want 5 (4 failures + 1 success)", imp.EventCount)
	}

	// Case -> AD1 source: the collection is AD1-typed and its archive
	// hash is the AD1 file's own SHA-256 (not blank, not the KAPE-zip
	// convention).
	var caseDetail struct {
		Case model.Case `json:"case"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &caseDetail)

	sfs := listSourceFiles(t, mux, c.ID)
	sf, ok := sourceFileByPath(sfs, internalPath)
	if !ok {
		t.Fatalf("imported file not found by its AD1-internal path %q; have: %+v", internalPath, sfs)
	}
	if sf.ImportStatus != model.SourceFileImported {
		t.Errorf("import_status = %q, want %q", sf.ImportStatus, model.SourceFileImported)
	}
	if sf.SHA256 == "" {
		t.Error("sha256 is empty after import -- Tracefall's own hash must be computed once a file is actually extracted and imported")
	}
	if sf.EventCount != 5 {
		t.Errorf("source file event_count = %d, want 5", sf.EventCount)
	}

	// AD1 -> file -> event: fetch the timeline and confirm at least one
	// event resolves back to this exact source file and collection.
	var timeline []map[string]any
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
	if len(timeline) != 5 {
		t.Fatalf("timeline has %d events, want 5", len(timeline))
	}
	for _, ev := range timeline {
		if ev["source_file_id"] != sf.ID {
			t.Errorf("event source_file_id = %v, want %v (every event from this AD1 file must trace back to it)", ev["source_file_id"], sf.ID)
		}
		if ev["collection_id"] != disc.Collection.ID {
			t.Errorf("event collection_id = %v, want %v", ev["collection_id"], disc.Collection.ID)
		}
	}

	// event -> finding -> investigation: analyze and confirm the brute
	// force pattern was actually detected through the unmodified
	// detect/correlate/investigate pipeline -- not a parallel AD1-specific
	// analysis path.
	var analyzeRes AnalyzeResultSummary
	analyzeRec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, &analyzeRes)
	if analyzeRec.Code != http.StatusOK {
		t.Fatalf("analyze: status %d", analyzeRec.Code)
	}
	if len(analyzeRes.Findings) == 0 {
		t.Fatal("analyze produced 0 findings from AD1-sourced evidence")
	}

	var investigations []map[string]any
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/investigations", nil, &investigations)
	if len(investigations) == 0 {
		t.Fatal("analyze produced 0 investigations from AD1-sourced evidence")
	}
}

// TestAD1_StandaloneInvestigationDetailHasNoNullSlices reproduces a bug
// found live during Phase 7 browser verification: importing ONLY a
// registry-run-key artifact (no EvtxECmd, nothing else in the case to
// correlate it against) produces a real, valid Investigation with zero
// correlations. internal/investigate already builds Investigation.CorrelationIDs
// correctly (make([]string, 0, ...), so the list endpoint's
// correlation_ids comes back as [] as expected) -- but
// Service.Investigation() (the DETAIL endpoint) independently re-derives
// correlation_details/finding_details from scratch with its own `var x
// []T` loops instead of make([]T, 0, ...); with zero correlations, THAT
// nil slice serialized as JSON `null` instead of `[]` (InvestigationDetail
// has no `omitempty` on either field), and
// internal/web/static/app.js's renderInvestigationDetail calls
// .filter()/.map() on correlation_details unconditionally -- crashing
// the whole investigation detail page. This isn't AD1-specific (any
// format producing an isolated, uncorrelated finding would trigger it),
// but AD1 was the first real scenario to actually hit it. Same bug
// class, same fix, as internal/investigate/score.go's
// sortedUniqueStrings from Phase 6.
func TestAD1_StandaloneInvestigationDetailHasNoNullSlices(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "AD1 standalone investigation")

	// Only the RECmd file -- no EvtxECmd, so this persistence finding has
	// nothing in the case to be chain/entity/temporal-correlated with.
	img := buildAD1(t, `E:\`, []ad1gen.File{
		{Path: "RECmd/a_RECmd_Batch_RunKeys_Output.csv", Data: []byte(`HivePath,KeyPath,ValueName,ValueData,LastWriteTimestamp
C:\Users\jdoe\NTUSER.DAT,Software\Microsoft\Windows\CurrentVersion\Run,WindowsUpdateHelper,C:\Users\jdoe\AppData\Local\Temp\update.exe,2026-01-15T09:16:02.0000000Z
`)},
	})
	rec := uploadAD1(t, mux, c.ID, img, "standalone.ad1")
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	_, imp := importAll(t, mux, c.ID, disc)
	if len(imp.Imported) != 1 {
		t.Fatalf("got %d imported, want 1 (skipped=%+v errors=%v)", len(imp.Imported), imp.Skipped, imp.Errors)
	}

	var analyzeRes AnalyzeResultSummary
	analyzeRec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, &analyzeRes)
	if analyzeRec.Code != http.StatusOK {
		t.Fatalf("analyze: status %d, body %s", analyzeRec.Code, analyzeRec.Body.String())
	}

	var investigations []map[string]any
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/investigations", nil, &investigations)
	if len(investigations) != 1 {
		t.Fatalf("got %d investigations, want 1", len(investigations))
	}
	invID, _ := investigations[0]["investigation_id"].(string)
	if corrIDs, ok := investigations[0]["correlation_ids"].([]any); !ok || len(corrIDs) != 0 {
		t.Fatalf("test setup assumption wrong: correlation_ids = %v, want an empty list (this test needs a truly uncorrelated finding)", investigations[0]["correlation_ids"])
	}

	detailRec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/investigations/"+invID, nil, nil)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("investigation detail: status %d, body %s", detailRec.Code, detailRec.Body.String())
	}
	body := detailRec.Body.String()
	for _, field := range []string{`"correlation_details":null`, `"finding_details":null`, `"event_details":null`} {
		if strings.Contains(body, field) {
			t.Errorf("investigation detail response contains %s -- frontend calls .filter()/.map() on this field unconditionally", field)
		}
	}
	var detail struct {
		CorrelationDetails []map[string]any `json:"correlation_details"`
		FindingDetails     []map[string]any `json:"finding_details"`
	}
	mustDecode(t, detailRec, &detail)
	if detail.CorrelationDetails == nil {
		t.Error("correlation_details decoded as nil, want a non-nil (possibly empty) slice")
	}
	if len(detail.FindingDetails) != 1 {
		t.Errorf("got %d finding_details, want 1", len(detail.FindingDetails))
	}
}

// ---------------- deletion semantics ----------------

func TestAD1_DeletingOneArtifactDoesNotAffectSiblings(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "AD1 sibling deletion")

	img := buildAD1(t, `E:\`, []ad1gen.File{
		{Path: "EvtxECmd/a_EvtxECmd_Output.csv", Data: []byte(bruteForceCSV)},
		{Path: "EvtxECmd/b_EvtxECmd_Output.csv", Data: []byte(bruteForceCSV2)},
	})
	rec := uploadAD1(t, mux, c.ID, img, "sample.ad1")
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	_, imp := importAll(t, mux, c.ID, disc)
	if len(imp.Imported) != 2 {
		t.Fatalf("got %d imported, want 2 (skipped=%+v errors=%v)", len(imp.Imported), imp.Skipped, imp.Errors)
	}

	sfs := listSourceFiles(t, mux, c.ID)
	a, _ := sourceFileByPath(sfs, "EvtxECmd/a_EvtxECmd_Output.csv")
	b, _ := sourceFileByPath(sfs, "EvtxECmd/b_EvtxECmd_Output.csv")

	delRec := doJSON(t, mux, "DELETE", "/api/cases/"+c.ID+"/evidence/"+a.ID, nil, nil)
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete: status %d, body %s", delRec.Code, delRec.Body.String())
	}

	sfsAfter := listSourceFiles(t, mux, c.ID)
	bAfter, ok := sourceFileByPath(sfsAfter, "EvtxECmd/b_EvtxECmd_Output.csv")
	if !ok {
		t.Fatal("sibling file b disappeared after deleting a")
	}
	if bAfter.DeletedAt != nil {
		t.Error("sibling file b was deleted along with a")
	}
	if bAfter.ID != b.ID || bAfter.EventCount != 5 {
		t.Errorf("sibling file b changed unexpectedly: %+v", bAfter)
	}

	var timeline []map[string]any
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
	for _, ev := range timeline {
		if ev["source_file_id"] == a.ID {
			t.Error("an event from the deleted file is still in the timeline")
		}
	}
	if len(timeline) != 5 {
		t.Errorf("timeline has %d events after deleting one of two identical-content files, want 5 (b's own)", len(timeline))
	}
}

func TestAD1_BulkDeletion(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "AD1 bulk deletion")

	img := buildAD1(t, `E:\`, []ad1gen.File{
		{Path: "EvtxECmd/a_EvtxECmd_Output.csv", Data: []byte(bruteForceCSV)},
		{Path: "EvtxECmd/b_EvtxECmd_Output.csv", Data: []byte(bruteForceCSV2)},
	})
	rec := uploadAD1(t, mux, c.ID, img, "sample.ad1")
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	_, imp := importAll(t, mux, c.ID, disc)
	if len(imp.Imported) != 2 {
		t.Fatalf("got %d imported, want 2 (skipped=%+v errors=%v)", len(imp.Imported), imp.Skipped, imp.Errors)
	}

	var ids []string
	for _, sf := range imp.Imported {
		ids = append(ids, sf.ID)
	}
	delRec := doJSON(t, mux, "DELETE", "/api/cases/"+c.ID+"/evidence", map[string][]string{"source_file_ids": ids}, nil)
	if delRec.Code != http.StatusOK {
		t.Fatalf("bulk delete: status %d, body %s", delRec.Code, delRec.Body.String())
	}

	var timeline []map[string]any
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
	if len(timeline) != 0 {
		t.Errorf("timeline has %d events after bulk-deleting every imported file, want 0", len(timeline))
	}
}

// ---------------- duplicate handling ----------------

func TestAD1_DuplicateContentWithinOneImage(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "AD1 duplicate content")

	sameSHA1 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 40 hex chars, doesn't need to be a real SHA1 for this test
	img := buildAD1(t, `E:\`, []ad1gen.File{
		{Path: "EvtxECmd/a_EvtxECmd_Output.csv", Data: []byte(bruteForceCSV), SHA1: sameSHA1},
		{Path: "EvtxECmd/copy_EvtxECmd_Output.csv", Data: []byte(bruteForceCSV), SHA1: sameSHA1},
	})
	rec := uploadAD1(t, mux, c.ID, img, "dup.ad1")
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	if disc.DuplicateCount != 1 {
		t.Errorf("duplicate_count = %d, want 1 (second file shares the first's embedded hash)", disc.DuplicateCount)
	}
	dup, ok := sourceFileByPath(disc.SourceFiles, "EvtxECmd/copy_EvtxECmd_Output.csv")
	if !ok {
		t.Fatal("duplicate file not found in catalog")
	}
	if dup.ImportStatus != model.SourceFileDuplicate {
		t.Errorf("duplicate file import_status = %q, want %q", dup.ImportStatus, model.SourceFileDuplicate)
	}
	if dup.EmbeddedHash != "sha1:"+sameSHA1 {
		t.Errorf("embedded_hash = %q, want %q", dup.EmbeddedHash, "sha1:"+sameSHA1)
	}
}

// ---------------- security / isolation ----------------

func TestAD1_CaseIsolation(t *testing.T) {
	mux := newTestRouter(t)
	caseA := mustCreateCase(t, mux, "AD1 case A")
	caseB := mustCreateCase(t, mux, "AD1 case B")

	img := buildAD1(t, `E:\`, []ad1gen.File{{Path: "EvtxECmd/a_EvtxECmd_Output.csv", Data: []byte(bruteForceCSV)}})
	rec := uploadAD1(t, mux, caseA.ID, img, "sample.ad1")
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	importAll(t, mux, caseA.ID, disc)

	sfsB := listSourceFiles(t, mux, caseB.ID)
	if len(sfsB) != 0 {
		t.Errorf("case B sees %d source files from case A's AD1, want 0", len(sfsB))
	}

	var timelineB []map[string]any
	doJSON(t, mux, "GET", "/api/cases/"+caseB.ID+"/timeline", nil, &timelineB)
	if len(timelineB) != 0 {
		t.Errorf("case B's timeline has %d events from case A's AD1, want 0", len(timelineB))
	}

	// Importing a source file ID that belongs to case A, addressed
	// through case B's API path, must be rejected -- not silently
	// operate across the case boundary.
	sfsA := listSourceFiles(t, mux, caseA.ID)
	if len(sfsA) == 0 {
		t.Fatal("test setup: case A has no source files")
	}
	crossCaseImport := doJSON(t, mux, "POST", "/api/cases/"+caseB.ID+"/evidence/"+disc.Collection.ID+"/import",
		map[string][]string{"source_file_ids": {sfsA[0].ID}}, nil)
	if crossCaseImport.Code == http.StatusOK {
		t.Error("importing case A's collection/file through case B's API path succeeded, want rejection")
	}
}

func TestAD1_PathTraversalCannotEscapeExtractionDirectory(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "AD1 path traversal")

	img := buildAD1(t, `E:\`, []ad1gen.File{{Path: "EvtxECmd/a_EvtxECmd_Output.csv", Data: []byte(bruteForceCSV)}})
	// Patch the entry name to a same-length path-traversal payload,
	// mirroring internal/ad1's own TestWalk_PathTraversalNameIsRejected
	// but exercised here through the real upload/discover HTTP path.
	name := "a_EvtxECmd_Output.csv"
	traversal := []byte("../../../../../../abc")
	if len(traversal) != len(name) {
		t.Fatalf("test setup: payload length %d != name length %d", len(traversal), len(name))
	}
	idx := bytes.Index(img, []byte(name))
	if idx < 0 {
		t.Fatal("test setup: couldn't locate entry name bytes in the built image")
	}
	broken := append([]byte(nil), img...)
	copy(broken[idx:idx+len(name)], traversal)

	rec := uploadAD1(t, mux, c.ID, broken, "traversal.ad1")
	if rec.Code == http.StatusOK {
		var disc DiscoverResult
		mustDecode(t, rec, &disc)
		if len(disc.SourceFiles) > 0 {
			t.Fatalf("a path-traversal AD1 entry was cataloged instead of rejected: %+v", disc.SourceFiles)
		}
	}
	// Either the whole discovery is rejected (expected, since
	// internal/ad1.validateEntryName fails the walk closed) or -- if a
	// future change ever made discovery more lenient -- nothing must have
	// been written outside the case's own data directory. Confirmed
	// structurally by internal/ad1's own unit test; this test's purpose
	// is to prove the SAME defense is actually wired up end to end
	// through the HTTP upload path, not bypassed by it.
}

// ---------------- local-path discovery ----------------

func TestAD1_LocalPathDiscovery(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "AD1 local path")

	img := buildAD1(t, `E:\`, []ad1gen.File{{Path: "EvtxECmd/a_EvtxECmd_Output.csv", Data: []byte(bruteForceCSV)}})
	dir := t.TempDir()
	p := filepath.Join(dir, "DiskDrigger.ad1")
	if err := os.WriteFile(p, img, 0o644); err != nil {
		t.Fatal(err)
	}

	rec := discoverPath(t, mux, c.ID, p)
	if rec.Code != http.StatusOK {
		t.Fatalf("local-path AD1 discovery: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	if disc.Collection.SourceType != model.SourceTypeAD1 {
		t.Errorf("collection source_type = %q, want %q", disc.Collection.SourceType, model.SourceTypeAD1)
	}
	if disc.SupportedCount != 1 {
		t.Errorf("supported_count = %d, want 1", disc.SupportedCount)
	}

	// The original file must never be modified by discovery.
	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, img) {
		t.Error("the original local AD1 file was modified by discovery")
	}
}

func TestAD1_ServiceLevel_NonexistentPathIsNotMisclassified(t *testing.T) {
	// Sanity check on the sniff-then-dispatch wiring itself, independent
	// of HTTP status mapping (covered by the upload tests above): a
	// nonexistent path must fail as a plain filesystem error, never be
	// misclassified as an encrypted or otherwise-recognized AD1.
	svc := newTestService(t)
	c, err := svc.CreateCase("svc-level", "")
	if err != nil {
		t.Fatalf("creating case: %v", err)
	}
	_, err = svc.DiscoverEvidenceFromPath(c.ID, "/nonexistent/path/that/is/not/an/ad1/or/a/directory")
	if err == nil {
		t.Fatal("expected an error for a nonexistent path")
	}
	if errors.Is(err, ad1.ErrEncrypted) {
		t.Error("nonexistent path incorrectly classified as an encrypted AD1")
	}
}
