package api

import (
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"tracefall/internal/casefiles"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

// These tests run the discovery API against an UPGRADED database -- one
// whose source_files table still carried the retired Phase 1 columns --
// because that is the only configuration in which the reported failure
// happens. Every existing API test opens a database created fresh from
// the current schema, where those columns never existed, which is
// exactly why a bug that made "Add Evidence" fail on every real upgraded
// install passed the entire suite.
//
// The store-level cause and its migration are covered by
// internal/store/migrate_legacy_columns_test.go. These go through the
// HTTP handler, so they also pin the status code and response body an
// investigator's browser actually receives.

// legacySourceFilesDDL is the original Phase 1 table: note row_count and
// ingested_at, NOT NULL with no default, which the current INSERT does
// not name.
const legacySourceFilesDDL = `CREATE TABLE source_files (
	id            TEXT PRIMARY KEY,
	case_id       TEXT NOT NULL REFERENCES cases(id),
	collection_id TEXT NOT NULL REFERENCES collections(id),
	path          TEXT NOT NULL,
	artifact_type TEXT NOT NULL,
	parser        TEXT NOT NULL,
	row_count     INTEGER NOT NULL,
	sha256        TEXT NOT NULL,
	ingested_at   TEXT NOT NULL
)`

// newUpgradedTestRouter returns a router backed by a database that was
// created under the old schema and then migrated by store.Open -- the
// shape a real install that has been running since Phase 1 has on disk.
func newUpgradedTestRouter(t *testing.T) http.Handler {
	t.Helper()
	path := filepath.Join(t.TempDir(), "upgraded.db")

	// Let the store build the current schema, then swap source_files
	// back to its historical shape so only that one table is legacy --
	// this uses the store's own exported API rather than duplicating its
	// schema here, which would drift.
	seed, err := store.Open(path)
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	seed.Close()

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DROP TABLE source_files`); err != nil {
		raw.Close()
		t.Fatalf("dropping source_files: %v", err)
	}
	if _, err := raw.Exec(legacySourceFilesDDL); err != nil {
		raw.Close()
		t.Fatalf("creating legacy source_files: %v", err)
	}
	raw.Close()

	db, err := store.Open(path) // runs migrate()
	if err != nil {
		t.Fatalf("opening upgraded database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	svc := NewService(db, casefiles.NewStore(t.TempDir()))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return dashboardLike(NewRouter(svc, logger, testMaxUploadBytes, false))
}

// TestDiscover_ValidDirectoryOnUpgradedDatabase is THE test for the
// reported bug, in the exact shape it was reported: a brand-new case on
// an upgraded install, discovering the bundled synthetic dataset.
//
// Before the fix this returned HTTP 500 {"error":"internal server error"}
// with "NOT NULL constraint failed: source_files.row_count" in the
// server log.
func TestDiscover_ValidDirectoryOnUpgradedDatabase(t *testing.T) {
	mux := newUpgradedTestRouter(t)
	c := mustCreateCase(t, mux, "Upgraded install case")

	if cols := listCollections(t, mux, c.ID); len(cols) != 0 {
		t.Fatalf("brand-new case already has %d collection(s)", len(cols))
	}

	var disc DiscoverResult
	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/ingest",
		map[string]string{"path": filepath.Join("..", "..", "testdata", "synthetic_case")}, &disc)
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery on an upgraded database: status %d, body %s", rec.Code, rec.Body.String())
	}

	// The numbers the investigator sees on screen.
	if disc.DiscoveredCount != 6 || disc.SupportedCount != 5 || disc.UnsupportedCount != 1 {
		t.Errorf("discovered/supported/unsupported = %d/%d/%d, want 6/5/1",
			disc.DiscoveredCount, disc.SupportedCount, disc.UnsupportedCount)
	}
	cols := listCollections(t, mux, c.ID)
	if len(cols) != 1 {
		t.Fatalf("collections = %d, want exactly 1", len(cols))
	}
	if cols[0].IngestionStatus != model.CollectionStatusPending {
		t.Errorf("status = %q, want %q", cols[0].IngestionStatus, model.CollectionStatusPending)
	}
	if cols[0].ImportedFileCount != 0 {
		t.Errorf("imported_file_count = %d, want 0 -- discovery imports nothing", cols[0].ImportedFileCount)
	}

	// And the evidence is genuinely usable afterwards: importing it is
	// the operation that would next hit the same INSERT path.
	_, imp := importAll(t, mux, c.ID, disc)
	if imp.EventCount == 0 {
		t.Error("importing discovered evidence produced no events on an upgraded database")
	}
}

// TestDiscover_RepeatedFailureDoesNotCreateCollection covers the
// investigator's actual behavior on hitting an error: clicking Discover
// again. Each attempt must fail identically and leave the case empty --
// no accumulating phantom collections.
func TestDiscover_RepeatedFailureDoesNotCreateCollection(t *testing.T) {
	mux := newUpgradedTestRouter(t)
	c := mustCreateCase(t, mux, "Repeated failure case")
	missing := filepath.Join(t.TempDir(), "not-here")

	var firstBody string
	for attempt := 1; attempt <= 3; attempt++ {
		rec := discoverPath(t, mux, c.ID, missing)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("attempt %d: status %d, want 400; body %s", attempt, rec.Code, rec.Body.String())
		}
		if attempt == 1 {
			firstBody = rec.Body.String()
		} else if rec.Body.String() != firstBody {
			t.Errorf("attempt %d returned a different error than the first: %s vs %s", attempt, rec.Body.String(), firstBody)
		}
		if cols := listCollections(t, mux, c.ID); len(cols) != 0 {
			t.Fatalf("attempt %d: collections = %d, want 0", attempt, len(cols))
		}
	}

	// The case is still perfectly usable after three failures.
	var disc DiscoverResult
	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/ingest",
		map[string]string{"path": filepath.Join("..", "..", "testdata", "synthetic_case")}, &disc)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid discovery after repeated failures: status %d, body %s", rec.Code, rec.Body.String())
	}
	if cols := listCollections(t, mux, c.ID); len(cols) != 1 {
		t.Errorf("collections = %d, want 1", len(cols))
	}
}

// TestDiscover_WrappedFilesystemErrorIsClassified pins the requirement
// that classification survives wrapping. An unreadable directory
// produces an *fs.PathError several wrappers deep (os.Open ->
// filepath.WalkDir -> ingest.Discover), and matching it needs errors.Is
// against the fs sentinel, not a type assertion or a string compare.
func TestDiscover_WrappedFilesystemErrorIsClassified(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 does not deny access")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "evidence.csv"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })

	mux := newUpgradedTestRouter(t)
	c := mustCreateCase(t, mux, "Unreadable path case")

	rec := discoverPath(t, mux, c.ID, locked)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unreadable directory: status %d, want 400 (a permission error is the investigator's to fix, not a server fault); body %s",
			rec.Code, rec.Body.String())
	}
	if msg := errorMessage(t, rec); msg == "internal server error" {
		t.Errorf("a wrapped fs.ErrPermission was not classified: %q", msg)
	}
	if cols := listCollections(t, mux, c.ID); len(cols) != 0 {
		t.Errorf("collections = %d, want 0", len(cols))
	}
}

// TestDiscover_CorruptAD1ReturnsClassifiedError checks the AD1-specific
// message: an image Tracefall RECOGNIZED but cannot read must say so,
// rather than claiming the format is unsupported.
func TestDiscover_CorruptAD1ReturnsClassifiedError(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "broken.ad1")
	body := append([]byte("ADSEGMENTEDFILE\x00"), make([]byte, 512)...)
	if err := os.WriteFile(corrupt, body, 0o644); err != nil {
		t.Fatal(err)
	}

	mux := newUpgradedTestRouter(t)
	c := mustCreateCase(t, mux, "Corrupt AD1 case")

	rec := discoverPath(t, mux, c.ID, corrupt)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("corrupt AD1: status %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	msg := errorMessage(t, rec)
	if msg == "internal server error" {
		t.Errorf("corrupt AD1 was not classified: %q", msg)
	}
	if !strings.Contains(strings.ToUpper(msg), "AD1") {
		t.Errorf("error %q does not identify the AD1 image as the problem", msg)
	}
	if cols := listCollections(t, mux, c.ID); len(cols) != 0 {
		t.Errorf("collections = %d, want 0", len(cols))
	}
}
