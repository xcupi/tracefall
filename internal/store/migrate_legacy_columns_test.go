package store

import (
	"database/sql"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"tracefall/internal/model"
)

// The tests in this file cover the defect that made an UPGRADED
// Tracefall install unable to add any evidence at all.
//
// source_files was created in Phase 1 with row_count and ingested_at
// declared NOT NULL with no DEFAULT. The evidence file model replaced
// them with event_count and discovered_at/imported_at, and
// backfillSourceFileEvidenceMetadata duly copied the data across -- but
// the columns themselves stayed, still NOT NULL, still without a
// default, and the current INSERT (sourceFileCols) does not list them,
// because on a database created by the current schema they don't exist.
//
// So on an upgraded database every INSERT into source_files failed with
//
//	NOT NULL constraint failed: source_files.row_count
//
// which the API reported as HTTP 500 "internal server error" the moment
// an investigator clicked Discover. Reads and updates worked, which is
// why every existing migration test passed: none of them inserted a new
// row after migrating. That is the specific gap
// TestMigrate_LegacyDatabaseAcceptsNewEvidence closes.

// legacySourceFilesDDL is the ORIGINAL Phase 1 table, reproduced exactly
// -- including the two NOT NULL columns with no default that caused the
// failure. Kept verbatim rather than generated: the point of these tests
// is to run against the real historical shape.
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

// newLegacyDatabase builds a database whose source_files table still has
// the retired columns, seeded with one already-imported file, and
// returns its path. It deliberately creates the CURRENT schema first and
// then swaps source_files for the legacy shape, so every other table is
// current and the test isolates this one table's migration.
func newLegacyDatabase(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.db")

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	if _, err := raw.Exec(schema); err != nil {
		t.Fatalf("applying current schema: %v", err)
	}
	if _, err := raw.Exec(`DROP TABLE source_files`); err != nil {
		t.Fatalf("dropping current source_files: %v", err)
	}
	if _, err := raw.Exec(legacySourceFilesDDL); err != nil {
		t.Fatalf("creating legacy source_files: %v", err)
	}
	now := time.Now().UTC().Format(timeLayout)
	if _, err := raw.Exec(`
		INSERT INTO cases (id, name, description, status, created_at, updated_at)
			VALUES ('c1', 'Legacy case', '', 'analyzed', ?, ?);
		INSERT INTO collections (id, case_id, created_at, source_type, ingestion_status)
			VALUES ('col1', 'c1', ?, 'local_path', 'ingested');
		INSERT INTO source_files (id, case_id, collection_id, path, artifact_type, parser, row_count, sha256, ingested_at)
			VALUES ('sf1', 'c1', 'col1', 'EvtxECmd/old.csv', 'windows_event_log', 'evtxcsv@1', 42, 'abc123', ?);
	`, now, now, now, now); err != nil {
		t.Fatalf("seeding legacy data: %v", err)
	}
	return path
}

// TestMigrate_LegacyDatabaseAcceptsNewEvidence is the direct
// reproduction: after migrating an upgraded database, inserting a NEW
// source file must succeed. Before the fix this failed with
// "NOT NULL constraint failed: source_files.row_count".
func TestMigrate_LegacyDatabaseAcceptsNewEvidence(t *testing.T) {
	path := newLegacyDatabase(t)

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open on legacy database: %v", err)
	}
	defer s.Close()

	// Exactly what discovery does: commit a collection and its catalog.
	now := time.Now().UTC()
	collection := model.Collection{
		ID: "col2", CaseID: "c1", CreatedAt: now,
		SourceType: model.SourceTypeLocalPath, ArchiveHash: "hash-of-new-evidence",
		IngestionStatus: model.CollectionStatusPending,
	}
	files := []model.SourceFile{{
		ID: "sf2", CaseID: "c1", CollectionID: "col2",
		OriginalFilename: "new.csv", Path: "EvtxECmd/new.csv",
		ArtifactType: "windows_event_log", Parser: "evtxcsv@1",
		Supported: true, SizeBytes: 100, SHA256: "def456",
		ImportStatus: model.SourceFileDiscovered, DiscoveredAt: now,
	}}
	if err := s.CreateCollectionWithSourceFiles(collection, files); err != nil {
		t.Fatalf("adding evidence to an upgraded database: %v", err)
	}

	got, err := s.ListSourceFilesByCollection("col2")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "sf2" {
		t.Fatalf("new source files = %+v, want exactly sf2", got)
	}
}

// TestMigrate_LegacyDataSurvivesColumnRetirement guards the rebuild
// itself: dropping and recreating a table is the one migration in this
// project that could lose evidence, so every pre-existing row and the
// values migrated out of the retired columns must come through intact.
func TestMigrate_LegacyDataSurvivesColumnRetirement(t *testing.T) {
	path := newLegacyDatabase(t)

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	sources, err := s.ListSourceFiles("c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 {
		t.Fatalf("source files after migration = %d, want 1 (the rebuild must not lose rows)", len(sources))
	}
	sf := sources[0]
	if sf.ID != "sf1" || sf.Path != "EvtxECmd/old.csv" || sf.SHA256 != "abc123" {
		t.Errorf("row not preserved verbatim: %+v", sf)
	}
	// row_count -> event_count, backfilled BEFORE the column was retired.
	if sf.EventCount != 42 {
		t.Errorf("event_count = %d, want 42 (migrated out of the retired row_count)", sf.EventCount)
	}
	// ingested_at -> discovered_at/imported_at.
	if sf.DiscoveredAt.IsZero() {
		t.Error("discovered_at not carried over from the retired ingested_at")
	}
	if sf.ImportStatus != model.SourceFileImported {
		t.Errorf("import_status = %q, want %q", sf.ImportStatus, model.SourceFileImported)
	}

	// The retired columns are actually gone.
	for _, col := range []string{"row_count", "ingested_at"} {
		exists, err := columnExists(s.db, "source_files", col)
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Errorf("column %q still present after migration", col)
		}
	}

	// And every index the table needs is back after the DROP/RENAME.
	for _, idx := range []string{
		"idx_source_files_case",
		"idx_source_files_collection",
		"idx_source_files_collection_sha256_active",
	} {
		var name string
		err := s.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name = ?`, idx).Scan(&name)
		if err != nil {
			t.Errorf("index %q missing after the table rebuild: %v", idx, err)
		}
	}
}

// TestMigrate_ColumnRetirementIsIdempotent -- every migration in this
// project runs on every startup, so the rebuild must be a no-op the
// second time and must not disturb the data.
func TestMigrate_ColumnRetirementIsIdempotent(t *testing.T) {
	path := newLegacyDatabase(t)

	for pass := 1; pass <= 3; pass++ {
		s, err := Open(path)
		if err != nil {
			t.Fatalf("pass %d: Open: %v", pass, err)
		}
		sources, err := s.ListSourceFiles("c1")
		if err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		if len(sources) != 1 || sources[0].EventCount != 42 {
			t.Fatalf("pass %d: data changed across migration passes: %+v", pass, sources)
		}
		s.Close()
	}
}

// TestMigrate_RebuiltSourceFilesMatchesFreshSchema is the drift guard
// referenced by retireLegacySourceFileColumns: the rebuild has to write
// out the table definition by hand (SQLite offers no "recreate this
// table without column X"), so nothing but a test stops it from slowly
// diverging from schema.go. Comparing a migrated database's table
// against a freshly created one catches that the moment it happens.
func TestMigrate_RebuiltSourceFilesMatchesFreshSchema(t *testing.T) {
	migrated, err := Open(newLegacyDatabase(t))
	if err != nil {
		t.Fatalf("Open (migrated): %v", err)
	}
	defer migrated.Close()

	fresh, err := Open(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatalf("Open (fresh): %v", err)
	}
	defer fresh.Close()

	if got, want := tableColumns(t, migrated.db), tableColumns(t, fresh.db); got != want {
		t.Errorf("migrated source_files does not match a freshly created one:\n migrated: %s\n fresh:    %s", got, want)
	}
}

// tableColumns renders source_files' columns as a stable, comparable
// string: name, type, not-null and default for each, so a difference in
// any of them fails the comparison. Column ORDER is deliberately
// normalized away -- it has no bearing on correctness here, since every
// query in this package names its columns explicitly.
func tableColumns(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info(source_files)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		out = append(out, strings.Join([]string{name, ctype, itoa(notnull), dflt.String, itoa(pk)}, ":"))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return strings.Join(out, " | ")
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	return "1"
}

// TestSchema_NoNotNullColumnOmittedFromInsert is the general form of the
// bug: any column declared NOT NULL without a DEFAULT that the package's
// own INSERT statement does not name will fail on every insert. It was
// true of source_files for two schema generations without anything
// noticing, so this checks the whole current schema rather than that one
// table.
func TestSchema_NoNotNullColumnOmittedFromInsert(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	inserted := map[string]string{
		"cases":              caseCols,
		"collections":        collectionCols,
		"source_files":       sourceFileCols,
		"events":             eventCols,
		"event_observations": observationCols,
		"findings":           findingCols,
	}
	for table, cols := range inserted {
		named := map[string]bool{}
		for _, c := range regexp.MustCompile(`[\s,]+`).Split(cols, -1) {
			if c = strings.TrimSpace(c); c != "" {
				named[c] = true
			}
		}
		rows, err := s.db.Query("PRAGMA table_info(" + table + ")")
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var cid, notnull, pk int
			var name, ctype string
			var dflt sql.NullString
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
				t.Fatal(err)
			}
			if notnull == 1 && !dflt.Valid && pk == 0 && !named[name] {
				t.Errorf("%s.%s is NOT NULL with no default but is not in the INSERT column list -- every insert into %s will fail", table, name, table)
			}
		}
		rows.Close()
	}
}
