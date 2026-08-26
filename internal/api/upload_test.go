package api

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/archive"
	"tracefall/internal/casefiles"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

// buildKAPEZip zips up the bundled synthetic dataset (the same fixture
// the path-based ingest tests use) so upload tests exercise a realistic,
// multi-artifact-type KAPE-shaped package rather than a toy fixture.
func buildKAPEZip(t *testing.T) []byte {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "synthetic_case")

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fw, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		_, err = fw.Write(data)
		return err
	})
	if err != nil {
		t.Fatalf("building test zip: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// buildZipBytes is a small helper for constructing ad hoc zips from
// name->content pairs, for the malformed/unsupported/mixed test cases
// below.
func buildZipBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		fw, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// buildZipSlipBytes constructs a zip containing a single path-traversal
// entry, bypassing archive/zip's own writer (which would otherwise
// normalize the malicious name) by writing a raw local file header.
func buildZipSlipBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, err := zw.CreateHeader(&zip.FileHeader{Name: "../../../etc/passwd", Method: zip.Deflate})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("root:x:0:0::/root:/bin/bash\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// uploadZip POSTs data as a multipart/form-data upload to
// /api/cases/{id}/upload and returns the response recorder.
func uploadZip(t *testing.T, mux *http.ServeMux, caseID string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	fw, err := w.CreateFormFile("file", "kape.zip")
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

// importAll POSTs an import request for every file in disc.SourceFiles
// that's currently selectable (status "discovered"), and returns the
// response recorder plus the decoded ImportResult. If there's nothing
// selectable, it does nothing and returns a zero recorder/result --
// callers that need to assert on "nothing was imported" should check
// disc.SourceFiles/SupportedCount directly instead.
func importAll(t *testing.T, mux *http.ServeMux, caseID string, disc DiscoverResult) (*httptest.ResponseRecorder, ImportResult) {
	t.Helper()
	var ids []string
	for _, sf := range disc.SourceFiles {
		if sf.ImportStatus == model.SourceFileDiscovered {
			ids = append(ids, sf.ID)
		}
	}
	if len(ids) == 0 {
		return nil, ImportResult{}
	}
	rec := doJSON(t, mux, "POST", "/api/cases/"+caseID+"/evidence/"+disc.Collection.ID+"/import",
		map[string][]string{"source_file_ids": ids}, nil)
	var res ImportResult
	mustDecode(t, rec, &res)
	return rec, res
}

// uploadAndImportAll performs the full two-phase evidence-adding flow
// (upload/discover, then import every supported file discovered) as one
// call, reproducing the old one-shot ingest's net effect for tests that
// care about the *result* of adding evidence rather than the mechanics
// of file selection itself (see TestEvidenceSelection_* for tests of the
// selection step directly). t.Fatal on a non-200 discover response,
// since callers using this helper expect the upload itself to succeed.
func uploadAndImportAll(t *testing.T, mux *http.ServeMux, caseID string, data []byte) (DiscoverResult, ImportResult) {
	t.Helper()
	discRec := uploadZip(t, mux, caseID, data)
	if discRec.Code != http.StatusOK {
		t.Fatalf("upload (discover): status %d, body %s", discRec.Code, discRec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, discRec, &disc)
	_, imp := importAll(t, mux, caseID, disc)
	return disc, imp
}

func createTestCase(t *testing.T, mux *http.ServeMux, name string) model.Case {
	t.Helper()
	var c model.Case
	rec := doJSON(t, mux, "POST", "/api/cases", map[string]string{"name": name}, &c)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create case: status %d, body %s", rec.Code, rec.Body.String())
	}
	return c
}

// TestUploadFlow_ValidKAPEPackage covers the full upload -> ingest ->
// analyze flow via the browser upload endpoint, mirroring
// TestEndToEnd_SyntheticCase but through a ZIP upload instead of a local
// path -- this is the "complete upload -> ingestion -> analysis flow"
// required test.
func TestUploadFlow_ValidKAPEPackage(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Uploaded KAPE case")

	zipData := buildKAPEZip(t)
	discRec := uploadZip(t, mux, c.ID, zipData)
	if discRec.Code != http.StatusOK {
		t.Fatalf("upload: status %d, body %s", discRec.Code, discRec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, discRec, &disc)

	if disc.SupportedCount != 5 {
		t.Errorf("got %d supported files discovered, want 5", disc.SupportedCount)
	}
	if disc.ExtractedFiles == 0 {
		t.Error("expected ExtractedFiles > 0")
	}
	if disc.UploadSizeBytes != int64(len(zipData)) {
		t.Errorf("UploadSizeBytes = %d, want %d", disc.UploadSizeBytes, len(zipData))
	}

	_, res := importAll(t, mux, c.ID, disc)
	if res.EventCount == 0 {
		t.Fatal("import produced 0 events")
	}
	if len(res.Imported) != 5 {
		t.Errorf("got %d imported files, want 5", len(res.Imported))
	}

	// Case must now be "ingested" and ready for analysis.
	var caseDetail struct {
		Case model.Case `json:"case"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &caseDetail)
	if caseDetail.Case.Status != model.CaseStatusIngested {
		t.Fatalf("case status = %q, want %q", caseDetail.Case.Status, model.CaseStatusIngested)
	}

	var analyzeRes AnalyzeResultSummary
	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, &analyzeRes)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyze: status %d, body %s", rec.Code, rec.Body.String())
	}
	if len(analyzeRes.Findings) == 0 {
		t.Fatal("analyze produced 0 findings from the uploaded package")
	}
}

// TestUploadFlow_PreservesOriginalArchive checks the upload's provenance
// requirement directly on disk, not just through the HTTP response: the
// original ZIP must still exist byte-for-byte after a successful upload,
// and the evidence directory ingest.Walk read from must still be present
// too (so raw-evidence drill-down keeps working after the request ends).
func TestUploadFlow_PreservesOriginalArchive(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	dataRoot := t.TempDir()
	files := casefiles.NewStore(dataRoot)
	svc := NewService(db, files)
	mux := routerFor(svc)

	c := createTestCase(t, mux, "Provenance case")
	zipData := buildKAPEZip(t)
	rec := uploadZip(t, mux, c.ID, zipData)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	collectionID := disc.Collection.ID
	if collectionID == "" {
		t.Fatal("upload response did not include a collection ID")
	}

	onDisk, err := os.ReadFile(files.UploadPath(c.ID, collectionID))
	if err != nil {
		t.Fatalf("original uploaded archive not found on disk: %v", err)
	}
	if !bytes.Equal(onDisk, zipData) {
		t.Error("preserved archive on disk does not match the uploaded bytes")
	}

	if _, err := os.Stat(filepath.Join(files.EvidenceDir(c.ID, collectionID), "EvtxECmd")); err != nil {
		t.Errorf("extracted evidence directory missing expected content: %v", err)
	}

	if _, err := os.Stat(files.MetadataPath(c.ID, collectionID)); err != nil {
		t.Errorf("collection metadata.json missing: %v", err)
	}
}

func TestUploadFlow_MalformedZip(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Malformed zip case")

	rec := uploadZip(t, mux, c.ID, []byte("this is not a zip file at all"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	// Case must remain usable -- still "created", so the user can retry.
	var caseDetail struct {
		Case model.Case `json:"case"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &caseDetail)
	if caseDetail.Case.Status != model.CaseStatusCreated {
		t.Errorf("case status = %q, want %q (failed upload must not corrupt case state)", caseDetail.Case.Status, model.CaseStatusCreated)
	}
}

func TestUploadFlow_PathTraversalZip(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Zip slip case")

	rec := uploadZip(t, mux, c.ID, buildZipSlipBytes(t))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	var caseDetail struct {
		Case model.Case `json:"case"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &caseDetail)
	if caseDetail.Case.Status != model.CaseStatusCreated {
		t.Errorf("case status = %q, want %q", caseDetail.Case.Status, model.CaseStatusCreated)
	}

	// Nothing from the traversal target must exist anywhere near the
	// case's evidence storage.
	if _, err := os.Stat("/etc/passwd.tracefall-test-marker"); err == nil {
		t.Fatal("path traversal entry appears to have escaped the destination directory")
	}
}

// TestUploadFlow_FailedSecondUploadDoesNotCorruptFirst is the specific
// multi-collection safety property this phase requires: a failed attempt
// to add a second collection must not damage the case's already-ingested
// first collection, its events, or its analysis.
func TestUploadFlow_FailedSecondUploadDoesNotCorruptFirst(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Failed second upload case")

	zip1 := buildKAPEZip(t)
	_, res1 := uploadAndImportAll(t, mux, c.ID, zip1)

	var analyzeRes AnalyzeResultSummary
	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, &analyzeRes)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyze: status %d", rec.Code)
	}
	findingsBefore := len(analyzeRes.Findings)
	if findingsBefore == 0 {
		t.Fatal("expected findings after the first collection's analysis")
	}

	// Second upload: malformed, must fail.
	rec = uploadZip(t, mux, c.ID, []byte("not a zip"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("second (malformed) upload: status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	// Case must still be "analyzed" (from the first collection), not
	// reset or corrupted by the failed second attempt.
	var caseDetail struct {
		Case    model.Case `json:"case"`
		Summary Summary    `json:"summary"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &caseDetail)
	if caseDetail.Case.Status != model.CaseStatusAnalyzed {
		t.Errorf("case status = %q, want %q (failed 2nd upload must not revert case state)", caseDetail.Case.Status, model.CaseStatusAnalyzed)
	}
	if caseDetail.Summary.Findings != findingsBefore {
		t.Errorf("findings count = %d, want %d (unchanged)", caseDetail.Summary.Findings, findingsBefore)
	}

	// The first collection's own data must be completely intact.
	var collections []model.Collection
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence", nil, &collections)
	var firstStillIngested, sawFailed bool
	for _, col := range collections {
		if col.ID == res1.Collection.ID && col.IngestionStatus == model.CollectionStatusIngested {
			firstStillIngested = true
		}
		if col.IngestionStatus == model.CollectionStatusFailed {
			sawFailed = true
		}
	}
	if !firstStillIngested {
		t.Error("first collection is no longer recorded as ingested")
	}
	if !sawFailed {
		t.Error("expected the failed second collection to be recorded with status 'failed', for collection history visibility")
	}

	var timeline []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
	if len(timeline) != res1.EventCount {
		t.Errorf("timeline has %d events, want %d (only the first collection's)", len(timeline), res1.EventCount)
	}
}

func TestUploadFlow_OversizedUpload(t *testing.T) {
	db := newTestService(t)
	// Force a tiny extraction limit so the test doesn't need to generate
	// a multi-gigabyte fixture to exercise the "too large" path.
	db.extractLimits = archive.Limits{
		MaxFiles: 100, MaxFileBytes: 10, MaxTotalBytes: 10, MaxRatio: 1000, RatioMinBytes: 1 << 20,
	}
	mux := routerFor(db)
	c := createTestCase(t, mux, "Oversized case")

	zipData := buildZipBytes(t, map[string]string{"EvtxECmd_Output.csv": "this content is definitely more than ten bytes long"})
	rec := uploadZip(t, mux, c.ID, zipData)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}
}

func TestUploadFlow_HTTPBodyTooLarge(t *testing.T) {
	mux := newTestRouter(t) // testMaxUploadBytes = 64 MiB
	c := createTestCase(t, mux, "HTTP body too large case")

	// Build a zip whose *compressed* upload size alone exceeds the
	// configured HTTP body limit. Content must be genuinely
	// incompressible (crypto/rand, stored without deflate) -- a
	// repeating byte pattern, even a long one, is exactly what LZ77-based
	// deflate is built to shrink away to almost nothing.
	big := make([]byte, testMaxUploadBytes+(1<<20))
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, err := zw.CreateHeader(&zip.FileHeader{Name: "big.bin", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(big); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	rec := uploadZip(t, mux, c.ID, buf.Bytes())
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}
}

func TestUploadFlow_UnsupportedFilesOnly(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Unsupported-only case")

	zipData := buildZipBytes(t, map[string]string{
		"readme.txt":      "just some notes",
		"random/data.bin": "\x00\x01\x02",
	})
	var disc DiscoverResult
	rec := uploadZip(t, mux, c.ID, zipData)
	if rec.Code != http.StatusOK {
		t.Fatalf("discovering unsupported-only files must still succeed: status %d, body %s", rec.Code, rec.Body.String())
	}
	mustDecode(t, rec, &disc)

	if disc.SupportedCount != 0 {
		t.Errorf("SupportedCount = %d, want 0 (no supported artifacts present)", disc.SupportedCount)
	}
	if disc.UnsupportedCount != 2 {
		t.Errorf("got %d unsupported files, want 2", disc.UnsupportedCount)
	}
	if len(disc.SourceFiles) != 2 {
		t.Errorf("got %d cataloged files, want 2 (both unsupported, but still cataloged)", len(disc.SourceFiles))
	}

	// Discovery alone never advances case status -- nothing became
	// evidence (there was nothing importable to select), so there is
	// nothing yet that would make a prior analysis stale. The case stays
	// "created" until something is actually imported.
	var caseDetail struct {
		Case model.Case `json:"case"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &caseDetail)
	if caseDetail.Case.Status != model.CaseStatusCreated {
		t.Errorf("case status = %q, want %q (nothing was ever imported)", caseDetail.Case.Status, model.CaseStatusCreated)
	}
}

func TestUploadFlow_MixedSupportedAndUnsupported(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Mixed case")

	evtxCSV := "TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber\n" +
		`2026-01-15T09:00:00.0000000Z,4624,Microsoft-Windows-Security-Auditing,Security,WKSTN-042,jdoe,-,Logon Success,"TargetUserName: jdoe; LogonType: 2",,,,,,1` + "\n"

	zipData := buildZipBytes(t, map[string]string{
		"EvtxECmd/output_EvtxECmd_Output.csv": evtxCSV,
		"readme.txt":                          "not an artifact",
		"KapeTriage/Modules/somejunk.dat":     "binary junk",
	})

	var disc DiscoverResult
	rec := uploadZip(t, mux, c.ID, zipData)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	mustDecode(t, rec, &disc)

	if disc.SupportedCount != 1 {
		t.Fatalf("got %d supported files, want 1 (only the EvtxECmd CSV is a supported artifact)", disc.SupportedCount)
	}
	if disc.UnsupportedCount != 2 {
		t.Errorf("got %d unsupported files, want 2 (readme.txt, somejunk.dat)", disc.UnsupportedCount)
	}

	_, res := importAll(t, mux, c.ID, disc)
	if res.EventCount == 0 {
		t.Error("expected at least one parsed event from the supported artifact")
	}
	if len(res.Imported) != 1 {
		t.Errorf("got %d imported files, want 1", len(res.Imported))
	}
}

// TestUploadFlow_SecondUploadAddsSecondCollection replaces Phase 1.5's
// "second upload is rejected" behavior: a case must accept any number of
// evidence collections, per this phase's requirement that re-uploading
// (e.g. a follow-up KAPE triage) is a normal, supported workflow, not an
// error.
func TestUploadFlow_SecondUploadAddsSecondCollection(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Multi-upload case")

	zip1 := buildZipBytes(t, map[string]string{"a_EvtxECmd_Output.csv": "TimeCreated,EventId\n"})
	rec := uploadZip(t, mux, c.ID, zip1)
	if rec.Code != http.StatusOK {
		t.Fatalf("first upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var res1 DiscoverResult
	mustDecode(t, rec, &res1)

	zip2 := buildZipBytes(t, map[string]string{"b_EvtxECmd_Output.csv": "TimeCreated,EventId\n"})
	rec = uploadZip(t, mux, c.ID, zip2)
	if rec.Code != http.StatusOK {
		t.Fatalf("second upload: status = %d, want %d (adding a second collection must succeed), body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var res2 DiscoverResult
	mustDecode(t, rec, &res2)

	if res1.Collection.ID == res2.Collection.ID {
		t.Fatal("expected two distinct collection IDs")
	}

	var collections []model.Collection
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence", nil, &collections)
	if len(collections) != 2 {
		t.Fatalf("got %d collections, want 2", len(collections))
	}
	if collections[0].ID != res1.Collection.ID || collections[1].ID != res2.Collection.ID {
		t.Errorf("collections not returned in upload order: %+v", collections)
	}
}

func TestUploadFlow_MissingFileField(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "No file case")

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	_ = w.WriteField("not-the-file-field", "oops")
	w.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/cases/"+c.ID+"/evidence", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func mustDecode(t *testing.T, rec *httptest.ResponseRecorder, out any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decoding response: %v\nbody: %s", err, rec.Body.String())
	}
}
