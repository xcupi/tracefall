package api

import (
	"net/http"
	"path/filepath"
	"sync"
	"testing"

	"tracefall/internal/model"
)

// listCollections fetches a case's collections via the API, the same
// path the dashboard uses to render "Collection #N" cards and counts.
func listCollections(t *testing.T, mux *http.ServeMux, caseID string) []model.Collection {
	t.Helper()
	var collections []model.Collection
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/evidence", nil, &collections)
	if rec.Code != http.StatusOK {
		t.Fatalf("list collections: status %d, body %s", rec.Code, rec.Body.String())
	}
	return collections
}

// TestDuplicateEvidence_EndToEnd is the required end-to-end test for
// this change: create a case, add one piece of evidence, confirm the
// exact same evidence is rejected as a duplicate without creating a
// second collection or touching the first one, then confirm genuinely
// different evidence is still accepted normally.
func TestDuplicateEvidence_EndToEnd(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Duplicate evidence case")
	evidenceRoot := filepath.Join("..", "..", "testdata", "synthetic_case")

	// -- Add evidence #1 --
	var first DiscoverResult
	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/ingest", map[string]string{"path": evidenceRoot}, &first)
	if rec.Code != http.StatusOK {
		t.Fatalf("first ingest: status %d, body %s", rec.Code, rec.Body.String())
	}
	if collections := listCollections(t, mux, c.ID); len(collections) != 1 {
		t.Fatalf("collection count after first ingest = %d, want 1", len(collections))
	}
	_, firstImport := importAll(t, mux, c.ID, first)
	firstEventCount := firstImport.EventCount

	// -- Add the exact same evidence again --
	rec = doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/ingest", map[string]string{"path": evidenceRoot}, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate ingest: status %d, want %d, body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	var dupBody struct {
		Error                    string `json:"error"`
		DuplicateCollectionID    string `json:"duplicate_collection_id"`
		DuplicateCollectionLabel string `json:"duplicate_collection_label"`
	}
	mustDecode(t, rec, &dupBody)
	if dupBody.DuplicateCollectionID != first.Collection.ID {
		t.Errorf("duplicate_collection_id = %q, want %q", dupBody.DuplicateCollectionID, first.Collection.ID)
	}
	if dupBody.DuplicateCollectionLabel != "Collection #1" {
		t.Errorf("duplicate_collection_label = %q, want %q", dupBody.DuplicateCollectionLabel, "Collection #1")
	}

	// -- Collection count and event count must be unaffected --
	collections := listCollections(t, mux, c.ID)
	if len(collections) != 1 {
		t.Fatalf("collection count after duplicate ingest = %d, want 1 (still just Collection #1)", len(collections))
	}
	if collections[0].ID != first.Collection.ID || collections[0].ParsedEventCount != firstImport.Collection.ParsedEventCount {
		t.Errorf("existing collection changed after the rejected duplicate: got %+v, want unchanged from %+v", collections[0], firstImport.Collection)
	}
	var timeline []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
	if len(timeline) != firstEventCount {
		t.Fatalf("timeline has %d events after rejected duplicate, want %d (unchanged)", len(timeline), firstEventCount)
	}

	// -- Add genuinely different evidence: must succeed as Collection #2 --
	rec = uploadZip(t, mux, c.ID, buildExecutionCollectionZip(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("different evidence upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	if collections := listCollections(t, mux, c.ID); len(collections) != 2 {
		t.Fatalf("collection count after different evidence = %d, want 2", len(collections))
	}
}

// TestDuplicateEvidence_UploadRejected covers items 1-3, 5 of the
// duplicate-upload requirements directly against the upload endpoint:
// first upload succeeds, the exact same archive uploaded again is
// rejected with 409 identifying the existing collection, no second
// collection is created, and the existing collection is untouched.
func TestDuplicateEvidence_UploadRejected(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Upload dedup case")
	zipData := buildKAPEZip(t)

	rec := uploadZip(t, mux, c.ID, zipData)
	if rec.Code != http.StatusOK {
		t.Fatalf("first upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var first DiscoverResult
	mustDecode(t, rec, &first)

	rec = uploadZip(t, mux, c.ID, zipData)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate upload: status %d, want %d, body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	var dupBody struct {
		Error                    string `json:"error"`
		DuplicateCollectionID    string `json:"duplicate_collection_id"`
		DuplicateCollectionLabel string `json:"duplicate_collection_label"`
	}
	mustDecode(t, rec, &dupBody)
	if dupBody.DuplicateCollectionID != first.Collection.ID {
		t.Errorf("duplicate_collection_id = %q, want %q", dupBody.DuplicateCollectionID, first.Collection.ID)
	}
	if dupBody.DuplicateCollectionLabel != "Collection #1" {
		t.Errorf("duplicate_collection_label = %q, want %q", dupBody.DuplicateCollectionLabel, "Collection #1")
	}

	collections := listCollections(t, mux, c.ID)
	if len(collections) != 1 {
		t.Fatalf("collection count after duplicate = %d, want 1", len(collections))
	}
	if collections[0].ArchiveHash != first.Collection.ArchiveHash || collections[0].ParsedEventCount != first.Collection.ParsedEventCount {
		t.Errorf("existing collection changed after rejected duplicate: got %+v, want unchanged from %+v", collections[0], first.Collection)
	}
}

// TestDuplicateEvidence_NoEventsIngestedOnDuplicate covers item 4: a
// rejected duplicate must not extract, parse, or ingest anything -- the
// case's event count must be byte-for-byte unchanged by the attempt.
func TestDuplicateEvidence_NoEventsIngestedOnDuplicate(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "No dup events case")
	zipData := buildExecutionCollectionZip(t)

	rec := uploadZip(t, mux, c.ID, zipData)
	if rec.Code != http.StatusOK {
		t.Fatalf("first upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var timelineBefore []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timelineBefore)

	rec = uploadZip(t, mux, c.ID, zipData)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate upload: status %d, want %d", rec.Code, http.StatusConflict)
	}

	var timelineAfter []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timelineAfter)
	if len(timelineAfter) != len(timelineBefore) {
		t.Fatalf("timeline has %d events after rejected duplicate, want %d (unchanged)", len(timelineAfter), len(timelineBefore))
	}
}

// TestDuplicateEvidence_DifferentArchiveSucceeds covers item 6: two
// genuinely different archives (different bytes/hash) must both be
// accepted as separate collections, even though they're evidence for
// the same case.
func TestDuplicateEvidence_DifferentArchiveSucceeds(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Different archives case")

	rec := uploadZip(t, mux, c.ID, buildExecutionCollectionZip(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload #1: status %d, body %s", rec.Code, rec.Body.String())
	}
	rec = uploadZip(t, mux, c.ID, buildPersistenceCollectionZip(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload #2 (different archive): status %d, body %s", rec.Code, rec.Body.String())
	}

	if collections := listCollections(t, mux, c.ID); len(collections) != 2 {
		t.Fatalf("collection count = %d, want 2", len(collections))
	}
}

// TestDuplicateEvidence_LocalPathRejected covers item 7: adding the
// same local-path evidence source twice must be rejected the same way
// an uploaded duplicate is, before any (re-)ingestion happens.
func TestDuplicateEvidence_LocalPathRejected(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Local path dedup case")
	evidenceRoot := filepath.Join("..", "..", "testdata", "synthetic_case")

	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/ingest", map[string]string{"path": evidenceRoot}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("first path ingest: status %d, body %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/ingest", map[string]string{"path": evidenceRoot}, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate path ingest: status %d, want %d, body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}

	if collections := listCollections(t, mux, c.ID); len(collections) != 1 {
		t.Fatalf("collection count after duplicate path ingest = %d, want 1", len(collections))
	}
}

// TestDuplicateEvidence_ConcurrentUploads covers item 9 (race safety):
// many concurrent requests uploading the exact same archive to the same
// case must result in exactly one collection, not one-per-request. The
// SELECT-based pre-check alone (internal/api.Service.checkDuplicateEvidence)
// cannot guarantee this on its own -- see the (case_id, archive_hash)
// partial unique index in internal/store/schema.go, enforced via
// internal/api.Service.commitDiscovery -- so this test
// specifically exercises that race window by firing requests in
// parallel rather than sequentially. Run with -race to also catch any
// data races in the Go-level request handling itself.
func TestDuplicateEvidence_ConcurrentUploads(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "Concurrent dedup case")
	zipData := buildKAPEZip(t)

	const attempts = 8
	var wg sync.WaitGroup
	codes := make([]int, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := uploadZip(t, mux, c.ID, zipData)
			codes[i] = rec.Code
		}(i)
	}
	wg.Wait()

	var succeeded, conflicted int
	for _, code := range codes {
		switch code {
		case http.StatusOK:
			succeeded++
		case http.StatusConflict:
			conflicted++
		default:
			t.Errorf("unexpected status %d among concurrent uploads", code)
		}
	}
	if succeeded != 1 {
		t.Errorf("got %d successful concurrent uploads, want exactly 1", succeeded)
	}
	if conflicted != attempts-1 {
		t.Errorf("got %d conflicted concurrent uploads, want %d", conflicted, attempts-1)
	}

	if collections := listCollections(t, mux, c.ID); len(collections) != 1 {
		t.Fatalf("collection count after concurrent duplicate uploads = %d, want 1", len(collections))
	}
}
