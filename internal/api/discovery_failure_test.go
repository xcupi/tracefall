package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/model"
)

// The tests in this file cover one specific defect and its blast radius.
//
// Discovery used to create the collection row FIRST and catalog the
// evidence afterwards. Any failure while cataloging -- a path that
// doesn't exist, a corrupt AD1, a database error -- therefore left a
// permanent collection behind with status "failed" and zero files, and
// the investigator, who had successfully added nothing, was shown
// "Collection #1 / FAILED / 0 file(s) discovered".
//
// That row then broke two more things:
//
//   - it has no source files, so CollectionDetail served
//     `"source_files": null` (a nil Go slice), and the Evidence
//     Integrity panel's .map() over it threw "Cannot read properties of
//     null (reading 'map')", taking down the whole Evidence tab;
//   - the failure that produced it reached the client as HTTP 500
//     "internal error", because a filesystem error carried no sentinel
//     the handler could classify, so an investigator with a typo in a
//     path was told the server had broken.
//
// Discovery is now atomic (internal/store.Store.CreateCollectionWithSourceFiles):
// a collection and its complete catalog are committed in one
// transaction, or nothing is.

// errorMessage pulls the "error" field out of a failed API response.
func errorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding error body %q: %v", rec.Body.String(), err)
	}
	return body.Error
}

// TestDiscover_InvalidInputDoesNotCreateCollection is the regression
// test for the reported bug. Every one of these inputs used to leave a
// FAILED collection behind (or, for the ones that reached the walk,
// answer HTTP 500 "internal error" first and then leave one). The case
// must be left exactly as it was found: zero collections.
func TestDiscover_InvalidInputDoesNotCreateCollection(t *testing.T) {
	dir := t.TempDir()

	emptyDir := filepath.Join(dir, "empty")
	if err := os.Mkdir(emptyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	plainFile := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(plainFile, []byte("not evidence"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Correct AD1 magic, garbage body: recognized as an AD1 and then
	// rejected by the parser, which is the path that reaches furthest
	// into discovery before failing.
	corruptAD1 := filepath.Join(dir, "corrupt.ad1")
	body := append([]byte("ADSEGMENTEDFILE\x00"), make([]byte, 512)...)
	if err := os.WriteFile(corruptAD1, body, 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		path     string
		wantCode int
	}{
		{"nonexistent path", filepath.Join(dir, "no", "such", "place"), http.StatusBadRequest},
		{"empty directory", emptyDir, http.StatusBadRequest},
		{"unsupported single file", plainFile, http.StatusBadRequest},
		{"corrupt AD1", corruptAD1, http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := newTestRouter(t)
			c := mustCreateCase(t, mux, "Failure case: "+tc.name)

			rec := discoverPath(t, mux, c.ID, tc.path)
			if rec.Code != tc.wantCode {
				t.Errorf("status = %d, want %d; body %s", rec.Code, tc.wantCode, rec.Body.String())
			}
			if rec.Code == http.StatusInternalServerError {
				t.Errorf("an investigator-fixable input produced a 500: %s", rec.Body.String())
			}

			// The whole point of the fix.
			if cols := listCollections(t, mux, c.ID); len(cols) != 0 {
				t.Errorf("collections after failed discovery = %d, want 0 (got %+v)", len(cols), cols)
			}

			// No orphan source files either -- the catalog rows and the
			// collection row are committed together or not at all.
			var sources []model.SourceFile
			doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/sources", nil, &sources)
			if len(sources) != 0 {
				t.Errorf("orphan source files after failed discovery = %d, want 0", len(sources))
			}

			// The error has to tell the investigator something.
			if msg := errorMessage(t, rec); msg == "" || msg == "internal error" || msg == "internal server error" {
				t.Errorf("error message = %q, want something actionable", msg)
			}

			// Retrying the SAME evidence must not be blocked. The old
			// failed collection kept its archive_hash, so the duplicate
			// check matched it and answered "Evidence already exists ...
			// as Collection #1" -- permanently refusing evidence that
			// had never actually been added, and pointing the
			// investigator at a collection containing nothing.
			retry := discoverPath(t, mux, c.ID, tc.path)
			if retry.Code == http.StatusConflict {
				t.Errorf("retrying the same failed evidence was rejected as a duplicate: %s", retry.Body.String())
			}

			// The case is still usable afterwards: a valid discovery in
			// the same case still works.
			var disc DiscoverResult
			ok := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/ingest",
				map[string]string{"path": filepath.Join("..", "..", "testdata", "synthetic_case")}, &disc)
			if ok.Code != http.StatusOK {
				t.Fatalf("valid discovery after a failed one: status %d, body %s", ok.Code, ok.Body.String())
			}
			if cols := listCollections(t, mux, c.ID); len(cols) != 1 {
				t.Errorf("collections after recovery = %d, want exactly 1", len(cols))
			}
		})
	}
}

// TestDiscover_ValidDirectoryFromEmptyCase is the positive half: a
// brand-new case with nothing in it, discovering the bundled synthetic
// dataset, must produce exactly one non-failed collection whose files
// are all merely discovered -- nothing imported until the investigator
// selects.
func TestDiscover_ValidDirectoryFromEmptyCase(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Empty case discovery")

	if cols := listCollections(t, mux, c.ID); len(cols) != 0 {
		t.Fatalf("a brand-new case already has %d collection(s)", len(cols))
	}

	var disc DiscoverResult
	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/ingest",
		map[string]string{"path": filepath.Join("..", "..", "testdata", "synthetic_case")}, &disc)
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery: status %d, body %s", rec.Code, rec.Body.String())
	}

	cols := listCollections(t, mux, c.ID)
	if len(cols) != 1 {
		t.Fatalf("collections = %d, want exactly 1", len(cols))
	}
	if cols[0].IngestionStatus == model.CollectionStatusFailed {
		t.Errorf("collection status = %q, want anything but failed", cols[0].IngestionStatus)
	}
	if cols[0].FileCount == 0 {
		t.Error("collection reports 0 discovered files")
	}
	if cols[0].ImportedFileCount != 0 {
		t.Errorf("imported_file_count = %d, want 0 -- discovery must not import anything", cols[0].ImportedFileCount)
	}
	if disc.DiscoveredCount != len(disc.SourceFiles) {
		t.Errorf("discovered_count = %d but source_files has %d entries", disc.DiscoveredCount, len(disc.SourceFiles))
	}
	for _, sf := range disc.SourceFiles {
		if sf.ImportStatus == model.SourceFileImported {
			t.Errorf("file %q is already imported straight out of discovery", sf.Path)
		}
	}
}

// TestDiscover_ResponseArraysNeverNull pins the JSON contract the
// dashboard depends on. A nil Go slice serializes as `null`, and the
// dashboard calls .map/.filter/.join on these fields directly; the
// Evidence Integrity panel crashed on exactly this. Checked against the
// raw JSON, not the decoded struct, because encoding/json happily
// decodes both `null` and `[]` into the same nil-or-empty Go slice --
// only the wire form distinguishes them.
func TestDiscover_ResponseArraysNeverNull(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Array contract case")

	rec := discoverPath(t, mux, c.ID, filepath.Join("..", "..", "testdata", "synthetic_case"))
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery: status %d, body %s", rec.Code, rec.Body.String())
	}
	assertNoNullArrays(t, rec.Body.Bytes(), "discovery response", "source_files")

	var disc DiscoverResult
	mustDecode(t, rec, &disc)

	// The collection detail view -- the endpoint that actually crashed.
	detail := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID, nil, nil)
	if detail.Code != http.StatusOK {
		t.Fatalf("collection detail: status %d, body %s", detail.Code, detail.Body.String())
	}
	assertNoNullArrays(t, detail.Body.Bytes(), "collection detail", "hosts_observed", "parser_coverage")

	// The file list lives on its paged endpoint now; it must not serialize null.
	files := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID+"/files?page=1&page_size=10", nil, nil)
	if files.Code != http.StatusOK {
		t.Fatalf("collection file list: status %d, body %s", files.Code, files.Body.String())
	}
	assertNoNullArrays(t, files.Body.Bytes(), "collection file list", "items")

	// And the case-wide evidence list.
	list := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence", nil, nil)
	if got := list.Body.String(); got == "null\n" || got == "null" {
		t.Errorf("collection list serialized as null, want []")
	}
}

// TestCollectionDetail_ZeroFileCollectionServesEmptyArray is the direct
// reproduction of the null.map crash: a collection holding no source
// files at all must still serve `"source_files": []`. Before the fix
// this was `null` and the Evidence Integrity panel threw.
func TestCollectionDetail_ZeroFileCollectionServesEmptyArray(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	c := mustCreateCase(t, mux, "Zero-file collection case")

	// Written directly through the store: discovery itself can no longer
	// produce a collection like this, but databases written by earlier
	// versions contain them, and they still have to render.
	legacy := model.Collection{
		ID: "legacy-failed-collection", CaseID: c.ID, CreatedAt: c.CreatedAt,
		SourceType: model.SourceTypeLocalPath, IngestionStatus: model.CollectionStatusFailed,
	}
	if err := svc.store.SaveCollection(legacy); err != nil {
		t.Fatalf("seeding legacy collection: %v", err)
	}

	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+legacy.ID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("collection detail: status %d, body %s", rec.Code, rec.Body.String())
	}
	assertNoNullArrays(t, rec.Body.Bytes(), "legacy zero-file collection detail", "hosts_observed", "parser_coverage")

	// The file list is served by its own paged endpoint; an empty collection
	// must answer with "items": [] there, never null.
	files := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+legacy.ID+"/files?page=1&page_size=10", nil, nil)
	if files.Code != http.StatusOK {
		t.Fatalf("file list: status %d, body %s", files.Code, files.Body.String())
	}
	assertNoNullArrays(t, files.Body.Bytes(), "legacy zero-file collection file list", "items")
}

// TestDiscover_DuplicateDoesNotCreateCollection re-checks the duplicate
// path specifically against the restructured commit step: the collection
// is now created at the END of discovery, so the duplicate check has to
// still hold there. The existing collection must be untouched and the
// count must stay at one.
func TestDiscover_DuplicateDoesNotCreateCollection(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Duplicate discovery case")
	path := filepath.Join("..", "..", "testdata", "synthetic_case")

	var first DiscoverResult
	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/ingest", map[string]string{"path": path}, &first)
	if rec.Code != http.StatusOK {
		t.Fatalf("first discovery: status %d, body %s", rec.Code, rec.Body.String())
	}
	before := listCollections(t, mux, c.ID)

	dup := discoverPath(t, mux, c.ID, path)
	if dup.Code != http.StatusConflict {
		t.Errorf("duplicate discovery: status %d, want %d", dup.Code, http.StatusConflict)
	}

	after := listCollections(t, mux, c.ID)
	if len(after) != 1 {
		t.Fatalf("collections after duplicate = %d, want 1", len(after))
	}
	if after[0].ID != before[0].ID {
		t.Errorf("collection id changed: %q -> %q", before[0].ID, after[0].ID)
	}
	if after[0].FileCount != before[0].FileCount || after[0].IngestionStatus != before[0].IngestionStatus {
		t.Errorf("existing collection was modified by the duplicate attempt: %+v -> %+v", before[0], after[0])
	}
}

// TestDiscover_ErrorsAreClassifiedNotInternal pins the status contract
// from the frontend's point of view: an investigator-fixable problem is
// a 4xx with a message worth reading, never a 500 "internal error".
func TestDiscover_ErrorsAreClassifiedNotInternal(t *testing.T) {
	dir := t.TempDir()
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Error contract case")

	t.Run("missing path field", func(t *testing.T) {
		rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/ingest", map[string]string{"path": ""}, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("unknown case", func(t *testing.T) {
		rec := doJSON(t, mux, "POST", "/api/cases/no-such-case/ingest", map[string]string{"path": dir}, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("nonexistent path names the path", func(t *testing.T) {
		missing := filepath.Join(dir, "definitely-not-here")
		rec := discoverPath(t, mux, c.ID, missing)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
		}
		if msg := errorMessage(t, rec); msg == "" {
			t.Error("empty error message")
		}
	})
}

// assertNoNullArrays fails if any of the named top-level fields is JSON
// `null` or missing. Deliberately operates on the raw bytes: decoding
// into a Go struct erases the difference between `null` and `[]`, which
// is precisely the difference the dashboard crashes on.
func assertNoNullArrays(t *testing.T, raw []byte, what string, fields ...string) {
	t.Helper()
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("%s: decoding as an object: %v\nbody: %s", what, err, raw)
	}
	for _, f := range fields {
		v, ok := generic[f]
		if !ok {
			t.Errorf("%s: field %q is missing entirely", what, f)
			continue
		}
		if string(v) == "null" {
			t.Errorf("%s: field %q serialized as null, want [] -- the dashboard calls .map on it", what, f)
		}
	}
}
