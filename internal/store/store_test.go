package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"tracefall/internal/model"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// seedCaseAndSourceFile creates the "case-1" / "collection-1" / "sf-1"
// rows that events and findings in the tests below reference, satisfying
// the schema's foreign key constraints (see schema.go).
func seedCaseAndSourceFile(t *testing.T, s *Store) {
	t.Helper()
	now := time.Now().UTC()
	if err := s.CreateCase(model.Case{ID: "case-1", Name: "seed case", Status: model.CaseStatusCreated, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("seeding case: %v", err)
	}
	if err := s.SaveCollection(model.Collection{
		ID: "collection-1", CaseID: "case-1", CreatedAt: now, SourceType: model.SourceTypeLocalPath,
		IngestionStatus: model.CollectionStatusIngested,
	}); err != nil {
		t.Fatalf("seeding collection: %v", err)
	}
	if err := s.SaveSourceFiles([]model.SourceFile{{
		ID: "sf-1", CaseID: "case-1", CollectionID: "collection-1", OriginalFilename: "seed.csv", Path: "seed.csv",
		ArtifactType: model.ArtifactWindowsEventLog, Parser: "evtxcsv@1", Supported: true, EventCount: 1,
		SHA256: "deadbeef", ImportStatus: model.SourceFileImported, DiscoveredAt: now, ImportedAt: &now,
	}}); err != nil {
		t.Fatalf("seeding source file: %v", err)
	}
}

func TestCaseRoundTrip(t *testing.T) {
	s := openTest(t)
	now := time.Now().UTC().Truncate(time.Second)
	c := model.Case{ID: "case-1", Name: "Test case", Status: model.CaseStatusCreated, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateCase(c); err != nil {
		t.Fatalf("CreateCase: %v", err)
	}

	got, err := s.GetCase("case-1")
	if err != nil {
		t.Fatalf("GetCase: %v", err)
	}
	if got.Name != c.Name || got.Status != c.Status {
		t.Errorf("got %+v, want %+v", got, c)
	}

	if err := s.UpdateCaseStatus("case-1", model.CaseStatusIngested); err != nil {
		t.Fatalf("UpdateCaseStatus: %v", err)
	}
	got, _ = s.GetCase("case-1")
	if got.Status != model.CaseStatusIngested {
		t.Errorf("status after update = %q, want %q", got.Status, model.CaseStatusIngested)
	}

	list, err := s.ListCases()
	if err != nil {
		t.Fatalf("ListCases: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("got %d cases, want 1", len(list))
	}
}

// TestCreateCase_DuplicateName covers idx_cases_name_unique directly at
// the store level: a second case whose name only differs by whitespace
// and casing from an existing one must be rejected with ErrDuplicateCase
// (the internal/api layer builds its 409 response on top of this), and
// FindCaseByName must resolve back to the original case regardless of
// how the lookup name is trimmed/cased.
func TestCreateCase_DuplicateName(t *testing.T) {
	s := openTest(t)
	now := time.Now().UTC()
	if err := s.CreateCase(model.Case{ID: "case-1", Name: "WKSTN-042 Phishing Triage", Status: model.CaseStatusCreated, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("creating first case: %v", err)
	}

	err := s.CreateCase(model.Case{ID: "case-2", Name: "  wkstn-042 phishing triage  ", Status: model.CaseStatusCreated, CreatedAt: now, UpdatedAt: now})
	if !errors.Is(err, ErrDuplicateCase) {
		t.Fatalf("got err = %v, want ErrDuplicateCase", err)
	}

	list, err := s.ListCases()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("case count after rejected duplicate = %d, want 1", len(list))
	}

	existing, found, err := s.FindCaseByName(" WKSTN-042 PHISHING TRIAGE ")
	if err != nil {
		t.Fatalf("FindCaseByName: %v", err)
	}
	if !found || existing.ID != "case-1" {
		t.Fatalf("FindCaseByName = %+v, found=%v, want case-1", existing, found)
	}
}

// TestMigrate_DuplicateCaseNamesBlockStartup covers the migration safety
// requirement directly: a database that already contains two cases whose
// names collide once trimmed/case-folded (exactly what a real
// installation could have accumulated before this constraint existed)
// must not be silently fixed by deleting or merging either case. Open()
// must fail with an error that clearly identifies the problem, and both
// original case rows must remain completely untouched.
func TestMigrate_DuplicateCaseNamesBlockStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dupe-case-names.db")

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(schema); err != nil {
		t.Fatalf("applying schema: %v", err)
	}
	// Explicit column list (not positional VALUES) so this seed stays
	// correct regardless of how many Phase 6+ columns the current schema
	// adds to cases with a DEFAULT -- this test cares only about name
	// collision, not the full column set.
	_, err = raw.Exec(`
		INSERT INTO cases (id, name, description, status, created_at, updated_at) VALUES ('case-a', 'WKSTN-042 Phishing Triage', '', 'created', '2026-01-01T00:00:00.000000000Z', '2026-01-01T00:00:00.000000000Z');
		INSERT INTO cases (id, name, description, status, created_at, updated_at) VALUES ('case-b', '  wkstn-042 phishing triage  ', '', 'created', '2026-01-02T00:00:00.000000000Z', '2026-01-02T00:00:00.000000000Z');
	`)
	if err != nil {
		t.Fatalf("seeding duplicate-named legacy cases: %v", err)
	}
	raw.Close()

	if _, err := Open(path); err == nil {
		t.Fatal("Open on a database with duplicate case names must fail, not silently proceed")
	} else {
		msg := err.Error()
		for _, want := range []string{"case-a", "case-b", "duplicate"} {
			if !strings.Contains(msg, want) {
				t.Errorf("error message %q does not mention %q -- must clearly identify the problem", msg, want)
			}
		}
	}

	// Nothing was deleted or merged: both original rows are still there,
	// untouched -- Open() itself failed, so query through a raw
	// connection instead of a *Store.
	raw2, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw2.Close()
	var count int
	if err := raw2.QueryRow(`SELECT COUNT(*) FROM cases`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("case count after failed migration = %d, want 2 (both cases must remain, untouched)", count)
	}
}

func TestEventRoundTrip(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	ts := time.Date(2026, 1, 15, 9, 14, 47, 0, time.UTC)
	ev := model.Event{
		ID: "ev-1", CaseID: "case-1", CollectionID: "collection-1", Timestamp: ts, Host: "H1", User: "jdoe",
		EventType: model.EventProcessCreate, ProcessName: "powershell.exe",
		ArtifactType: model.ArtifactWindowsEventLog, SourceFileID: "sf-1", Parser: "evtxcsv@1",
		Confidence: 1.0, DedupHash: "hash-1", Extra: map[string]string{"logon_type": "2"},
	}
	if err := s.SaveEvents([]model.Event{ev}); err != nil {
		t.Fatalf("SaveEvents: %v", err)
	}

	got, err := s.GetEvent("ev-1")
	if err != nil {
		t.Fatalf("GetEvent: %v", err)
	}
	if !got.Timestamp.Equal(ts) {
		t.Errorf("timestamp = %v, want %v", got.Timestamp, ts)
	}
	if got.Extra["logon_type"] != "2" {
		t.Errorf("extra field not round-tripped: %+v", got.Extra)
	}

	list, err := s.ListEvents("case-1")
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("got %d events, want 1", len(list))
	}
}

func TestFindingsAndClearAnalysis(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	f := model.Finding{
		ID: "f-1", CaseID: "case-1", RuleID: "office-spawns-powershell", Title: "test finding",
		Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium,
		SupportingEvents: []string{"ev-1"}, Techniques: []string{"T1059.001"},
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(), CreatedAt: time.Now().UTC(),
	}
	if err := s.SaveFindings([]model.Finding{f}); err != nil {
		t.Fatalf("SaveFindings: %v", err)
	}

	list, err := s.ListFindings("case-1")
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(list) != 1 || list[0].Techniques[0] != "T1059.001" {
		t.Fatalf("got %+v", list)
	}

	if err := s.ClearAnalysis("case-1"); err != nil {
		t.Fatalf("ClearAnalysis: %v", err)
	}
	list, _ = s.ListFindings("case-1")
	if len(list) != 0 {
		t.Errorf("got %d findings after ClearAnalysis, want 0", len(list))
	}
}

func TestCollectionRoundTrip(t *testing.T) {
	s := openTest(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := s.CreateCase(model.Case{ID: "case-1", Name: "c", Status: model.CaseStatusCreated, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}

	c := model.Collection{
		ID: "collection-1", CaseID: "case-1", CreatedAt: now, SourceType: model.SourceTypeUpload,
		OriginalFilename: "kape.zip", ArchiveHash: "abc123", EvidenceDirectory: "/data/cases/case-1/collections/collection-1/evidence",
		IngestionStatus: model.CollectionStatusPending,
	}
	if err := s.SaveCollection(c); err != nil {
		t.Fatalf("SaveCollection: %v", err)
	}

	got, err := s.GetCollection("collection-1")
	if err != nil {
		t.Fatalf("GetCollection: %v", err)
	}
	if got.OriginalFilename != "kape.zip" || got.IngestionStatus != model.CollectionStatusPending {
		t.Fatalf("got %+v", got)
	}

	c.IngestionStatus = model.CollectionStatusIngested
	c.FileCount, c.SupportedFileCount, c.UnsupportedFileCount, c.ParsedEventCount = 10, 8, 2, 42
	if err := s.UpdateCollection(c); err != nil {
		t.Fatalf("UpdateCollection: %v", err)
	}
	got, _ = s.GetCollection("collection-1")
	if got.IngestionStatus != model.CollectionStatusIngested || got.ParsedEventCount != 42 {
		t.Fatalf("after update: got %+v", got)
	}

	// Second collection in the same case -- ListCollections must return
	// both, oldest first.
	c2 := model.Collection{ID: "collection-2", CaseID: "case-1", CreatedAt: now.Add(1 * time.Hour), SourceType: model.SourceTypeUpload, IngestionStatus: model.CollectionStatusIngested}
	if err := s.SaveCollection(c2); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListCollections("case-1")
	if err != nil {
		t.Fatalf("ListCollections: %v", err)
	}
	if len(list) != 2 || list[0].ID != "collection-1" || list[1].ID != "collection-2" {
		t.Fatalf("got %+v, want [collection-1, collection-2] in order", list)
	}
}

func TestEventObservations_RetainProvenanceAcrossCollections(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	now := time.Now().UTC()

	// A second collection with its own source file, observing the SAME
	// (deduplicated) event as collection-1.
	if err := s.SaveCollection(model.Collection{ID: "collection-2", CaseID: "case-1", CreatedAt: now, SourceType: model.SourceTypeUpload, IngestionStatus: model.CollectionStatusIngested}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSourceFiles([]model.SourceFile{{
		ID: "sf-2", CaseID: "case-1", CollectionID: "collection-2", OriginalFilename: "seed2.csv", Path: "seed2.csv",
		ArtifactType: model.ArtifactWindowsEventLog, Parser: "evtxcsv@1", Supported: true, EventCount: 1,
		SHA256: "beefdead", ImportStatus: model.SourceFileImported, DiscoveredAt: now, ImportedAt: &now,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvents([]model.Event{{
		ID: "ev-shared", CaseID: "case-1", CollectionID: "collection-1", Timestamp: now, EventType: model.EventLogonSuccess,
		ArtifactType: model.ArtifactWindowsEventLog, SourceFileID: "sf-1", Parser: "evtxcsv@1", Confidence: 1, DedupHash: "shared-hash",
	}}); err != nil {
		t.Fatal(err)
	}

	observations := []model.EventObservation{
		{ID: "obs-1", EventID: "ev-shared", CaseID: "case-1", CollectionID: "collection-1", SourceFileID: "sf-1", SourceReference: "row:1"},
		{ID: "obs-2", EventID: "ev-shared", CaseID: "case-1", CollectionID: "collection-2", SourceFileID: "sf-2", SourceReference: "row:1"},
	}
	if err := s.SaveEventObservations(observations); err != nil {
		t.Fatalf("SaveEventObservations: %v", err)
	}

	got, err := s.ListEventObservations("ev-shared")
	if err != nil {
		t.Fatalf("ListEventObservations: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d observations, want 2 (one per collection)", len(got))
	}
	collections := map[string]bool{got[0].CollectionID: true, got[1].CollectionID: true}
	if !collections["collection-1"] || !collections["collection-2"] {
		t.Errorf("expected observations from both collections, got %+v", got)
	}
}

func TestFindEventByDedupHash(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	ev := model.Event{
		ID: "ev-1", CaseID: "case-1", CollectionID: "collection-1", Timestamp: time.Now().UTC(),
		EventType: model.EventProcessCreate, ArtifactType: model.ArtifactWindowsEventLog,
		SourceFileID: "sf-1", Parser: "evtxcsv@1", Confidence: 1, DedupHash: "the-hash",
	}
	if err := s.SaveEvents([]model.Event{ev}); err != nil {
		t.Fatal(err)
	}

	got, found, err := s.FindEventByDedupHash("case-1", "the-hash")
	if err != nil {
		t.Fatalf("FindEventByDedupHash: %v", err)
	}
	if !found || got.ID != "ev-1" {
		t.Fatalf("found=%v got=%+v, want the seeded event", found, got)
	}

	_, found, err = s.FindEventByDedupHash("case-1", "no-such-hash")
	if err != nil {
		t.Fatalf("FindEventByDedupHash: %v", err)
	}
	if found {
		t.Error("expected no match for an unused hash")
	}

	// Scoped to the case: same hash in a different case must not match.
	if err := s.CreateCase(model.Case{ID: "case-2", Name: "other", Status: model.CaseStatusCreated, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	_, found, err = s.FindEventByDedupHash("case-2", "the-hash")
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Error("dedup lookup must be scoped per case, not global")
	}
}

// TestMigrate_LegacyDatabase simulates a database created before
// collections/dedup existed (no collections table, source_files/events
// missing collection_id and dedup_hash) and verifies Open() upgrades it
// in place: old evidence becomes visible as a synthesized "legacy"
// collection, and existing findings/events remain intact and queryable.
func TestMigrate_LegacyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// Build a pre-collections-era database by hand, mirroring the old
	// schema shape (no collections table, no collection_id/dedup_hash
	// columns).
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`
		CREATE TABLE cases (id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
		CREATE TABLE source_files (id TEXT PRIMARY KEY, case_id TEXT NOT NULL, path TEXT NOT NULL, artifact_type TEXT NOT NULL, parser TEXT NOT NULL, row_count INTEGER NOT NULL, sha256 TEXT NOT NULL, ingested_at TEXT NOT NULL);
		CREATE TABLE raw_evidence (id TEXT PRIMARY KEY, case_id TEXT NOT NULL, source_file_id TEXT NOT NULL, source_reference TEXT NOT NULL DEFAULT '', raw TEXT NOT NULL);
		CREATE TABLE events (id TEXT PRIMARY KEY, case_id TEXT NOT NULL, timestamp TEXT NOT NULL, host TEXT NOT NULL DEFAULT '', user TEXT NOT NULL DEFAULT '',
			event_type TEXT NOT NULL, provider TEXT NOT NULL DEFAULT '', event_id INTEGER NOT NULL DEFAULT 0,
			process_name TEXT NOT NULL DEFAULT '', process_path TEXT NOT NULL DEFAULT '', parent_process TEXT NOT NULL DEFAULT '', parent_process_path TEXT NOT NULL DEFAULT '',
			pid INTEGER NOT NULL DEFAULT 0, ppid INTEGER NOT NULL DEFAULT 0, command_line TEXT NOT NULL DEFAULT '',
			file_path TEXT NOT NULL DEFAULT '', registry_path TEXT NOT NULL DEFAULT '', network_source TEXT NOT NULL DEFAULT '', network_dest TEXT NOT NULL DEFAULT '', network_dest_port INTEGER NOT NULL DEFAULT 0,
			artifact_type TEXT NOT NULL, source_file_id TEXT NOT NULL, source_reference TEXT NOT NULL DEFAULT '', parser TEXT NOT NULL, confidence REAL NOT NULL DEFAULT 1.0, raw_evidence_id TEXT NOT NULL DEFAULT '', extra_json TEXT NOT NULL DEFAULT '{}');
		CREATE TABLE findings (id TEXT PRIMARY KEY, case_id TEXT NOT NULL, rule_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL, description TEXT NOT NULL,
			supporting_events_json TEXT NOT NULL DEFAULT '[]', techniques_json TEXT NOT NULL DEFAULT '[]', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, created_at TEXT NOT NULL);
		CREATE TABLE correlations (id TEXT PRIMARY KEY, case_id TEXT NOT NULL, type TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, event_ids_json TEXT NOT NULL DEFAULT '[]', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
	`)
	if err != nil {
		t.Fatalf("building legacy schema: %v", err)
	}
	_, err = raw.Exec(`
		INSERT INTO cases VALUES ('legacy-case', 'Legacy Case', '', 'analyzed', '2026-01-01T00:00:00.000000000Z', '2026-01-01T00:00:00.000000000Z');
		INSERT INTO source_files VALUES ('legacy-sf', 'legacy-case', 'old.csv', 'windows_event_log', 'evtxcsv@1', 1, 'deadbeef', '2026-01-01T00:00:00.000000000Z');
		INSERT INTO events VALUES ('legacy-ev', 'legacy-case', '2026-01-01T09:00:00.000000000Z', 'WKSTN-042', 'jdoe', 'logon_success', 'Security', 4624,
			'', '', '', '', 0, 0, '', '', '', '', '', 0, 'windows_event_log', 'legacy-sf', 'row:1', 'evtxcsv@1', 1.0, '', '{}');
		INSERT INTO findings VALUES ('legacy-f', 'legacy-case', 'some-rule', 'Legacy finding', 'high', 'medium', 'desc',
			'["legacy-ev"]', '[]', '2026-01-01T09:00:00.000000000Z', '2026-01-01T09:00:00.000000000Z', '2026-01-01T09:00:00.000000000Z');
	`)
	if err != nil {
		t.Fatalf("seeding legacy data: %v", err)
	}
	raw.Close()

	// Now open it through the current Store -- this must run the
	// migration and leave everything readable.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open on legacy database: %v", err)
	}
	defer s.Close()

	collections, err := s.ListCollections("legacy-case")
	if err != nil {
		t.Fatalf("ListCollections: %v", err)
	}
	if len(collections) != 1 {
		t.Fatalf("got %d synthesized collections, want 1", len(collections))
	}
	if collections[0].SourceType != model.SourceTypeLegacy {
		t.Errorf("source_type = %q, want %q", collections[0].SourceType, model.SourceTypeLegacy)
	}
	if collections[0].FileCount != 1 || collections[0].ParsedEventCount != 1 {
		t.Errorf("got %+v, want file_count=1 parsed_event_count=1", collections[0])
	}

	sources, err := s.ListSourceFiles("legacy-case")
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || sources[0].CollectionID != collections[0].ID {
		t.Fatalf("source file not backfilled with the legacy collection ID: %+v", sources)
	}

	// The evidence file model (discover -> select -> import, added after
	// collections/dedup already existed) must also backfill correctly on
	// this same legacy row: a pre-existing source_files row predates
	// import_status entirely, so it must be treated as already fully
	// imported under the old one-shot model, not as merely "discovered".
	legacySF := sources[0]
	if legacySF.ImportStatus != model.SourceFileImported {
		t.Errorf("legacy source file import_status = %q, want %q", legacySF.ImportStatus, model.SourceFileImported)
	}
	if !legacySF.Supported {
		t.Error("legacy source file not backfilled as supported")
	}
	if legacySF.EventCount != 1 {
		t.Errorf("legacy source file event_count = %d, want 1 (from the old row_count column)", legacySF.EventCount)
	}
	if legacySF.OriginalFilename != "old.csv" {
		t.Errorf("legacy source file original_filename = %q, want %q (derived from path)", legacySF.OriginalFilename, "old.csv")
	}
	if legacySF.DiscoveredAt.IsZero() || legacySF.ImportedAt == nil {
		t.Errorf("legacy source file discovered_at/imported_at not backfilled: %+v", legacySF)
	}
	if legacySF.DeletedAt != nil {
		t.Error("legacy source file should not be marked deleted")
	}

	ev, err := s.GetEvent("legacy-ev")
	if err != nil {
		t.Fatalf("GetEvent: %v", err)
	}
	if ev.CollectionID != collections[0].ID {
		t.Errorf("event collection_id = %q, want %q", ev.CollectionID, collections[0].ID)
	}
	if ev.DedupHash == "" {
		t.Error("expected dedup_hash to be backfilled for the legacy event")
	}
	if ev.Host != "WKSTN-042" || ev.EventType != model.EventLogonSuccess {
		t.Errorf("legacy event fields not preserved: %+v", ev)
	}

	findings, err := s.ListFindings("legacy-case")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].SupportingEvents[0] != "legacy-ev" {
		t.Fatalf("legacy finding not preserved: %+v", findings)
	}

	// Re-opening (a second migration pass) must not duplicate the
	// synthesized collection or otherwise change anything.
	s.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer s2.Close()
	collections2, err := s2.ListCollections("legacy-case")
	if err != nil {
		t.Fatal(err)
	}
	if len(collections2) != 1 {
		t.Fatalf("re-opening created %d collections, want still 1 (migration must be idempotent)", len(collections2))
	}
}
