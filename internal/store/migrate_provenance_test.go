package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"tracefall/internal/model"
)

// Phase 11 adds one table (analysis_runs) and one column
// (findings.analysis_run_id). Both must appear on an upgrade without
// disturbing existing rows, and neither may invent provenance for data
// that predates them.

// openLegacyFindingsDB creates a database whose findings table has NO
// analysis_run_id column -- the pre-Phase-11 shape -- with one finding
// already in it.
func openLegacyFindingsDB(t *testing.T) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	stmts := []string{
		`CREATE TABLE cases (id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'created', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		// The pre-Phase-11 findings table: no analysis_run_id.
		`CREATE TABLE findings (
			id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id), rule_id TEXT NOT NULL,
			title TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL, description TEXT NOT NULL,
			supporting_events_json TEXT NOT NULL DEFAULT '[]', techniques_json TEXT NOT NULL DEFAULT '[]',
			first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, created_at TEXT NOT NULL)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO cases (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		"case-1", "Legacy case", now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO findings
		(id, case_id, rule_id, title, severity, confidence, description, first_seen, last_seen, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"finding-1", "case-1", "rule-x", "Legacy finding", "high", "high", "from before run tracking",
		now, now, now); err != nil {
		t.Fatal(err)
	}
	return path, "case-1"
}

func TestMigrate_AddsAnalysisRunProvenanceToLegacyDatabase(t *testing.T) {
	path, caseID := openLegacyFindingsDB(t)

	s, err := Open(path)
	if err != nil {
		t.Fatalf("opening (migrating) a pre-Phase-11 database: %v", err)
	}
	defer s.Close()

	// The existing finding survives, and is honestly UNATTRIBUTED rather
	// than retrofitted to an invented run.
	findings, err := s.ListFindings(caseID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings after migration, want the 1 that existed", len(findings))
	}
	if findings[0].Title != "Legacy finding" {
		t.Errorf("existing finding was altered: %+v", findings[0])
	}
	if findings[0].AnalysisRunID != "" {
		t.Errorf("analysis_run_id = %q; a finding written before run tracking must stay unattributed, not be given an invented run",
			findings[0].AnalysisRunID)
	}

	// The new table exists and starts empty -- no runs were fabricated
	// for historical analysis that was never recorded.
	runs, err := s.ListAnalysisRuns(caseID)
	if err != nil {
		t.Fatalf("analysis_runs not usable after migration: %v", err)
	}
	if len(runs) != 0 {
		t.Errorf("migration invented %d analysis run(s) for a legacy database", len(runs))
	}
}

// A new run recorded on the upgraded database works end to end.
func TestMigrate_UpgradedDatabaseAcceptsNewRuns(t *testing.T) {
	path, caseID := openLegacyFindingsDB(t)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	started := time.Now().UTC().Truncate(time.Second)
	run := model.AnalysisRun{
		ID: "run-1", CaseID: caseID, StartedAt: started,
		Status: model.AnalysisRunRunning, ToolVersion: "Tracefall test",
	}
	if err := s.CreateAnalysisRun(run); err != nil {
		t.Fatalf("creating a run on an upgraded database: %v", err)
	}

	got, err := s.GetAnalysisRun("run-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.CompletedAt != nil {
		t.Error("a running run reports a completion time it never reached")
	}
	if got.Status != model.AnalysisRunRunning {
		t.Errorf("status = %q, want %q", got.Status, model.AnalysisRunRunning)
	}

	done := started.Add(2 * time.Second)
	if err := s.FinishAnalysisRun("run-1", model.AnalysisRunCompleted, done, 10, 3, 1, ""); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetAnalysisRun("run-1")
	if got.Status != model.AnalysisRunCompleted || got.CompletedAt == nil {
		t.Fatalf("run did not complete: %+v", got)
	}
	if got.FindingCount != 3 || got.EventCount != 10 || got.CorrelationCount != 1 {
		t.Errorf("counts not recorded: %+v", got)
	}
}

// A finished run must not be reopened or rewritten by a later call --
// the record of what happened is fixed once it happened.
func TestAnalysisRun_FinishedRunIsImmutable(t *testing.T) {
	path, caseID := openLegacyFindingsDB(t)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	started := time.Now().UTC().Truncate(time.Second)
	if err := s.CreateAnalysisRun(model.AnalysisRun{
		ID: "run-1", CaseID: caseID, StartedAt: started, Status: model.AnalysisRunRunning,
	}); err != nil {
		t.Fatal(err)
	}
	first := started.Add(time.Second)
	if err := s.FinishAnalysisRun("run-1", model.AnalysisRunCompleted, first, 10, 3, 1, ""); err != nil {
		t.Fatal(err)
	}
	before, _ := s.GetAnalysisRun("run-1")

	// A second attempt must be a no-op, not an overwrite.
	if err := s.FinishAnalysisRun("run-1", model.AnalysisRunFailed, first.Add(time.Hour), 99, 99, 99, "rewritten"); err != nil {
		t.Fatal(err)
	}
	after, _ := s.GetAnalysisRun("run-1")

	if after.Status != before.Status {
		t.Errorf("a completed run's status was rewritten: %q -> %q", before.Status, after.Status)
	}
	if after.FindingCount != before.FindingCount || after.Error != "" {
		t.Errorf("a completed run's record was rewritten: %+v", after)
	}
}

// Fresh databases must produce exactly the same shape as upgraded ones,
// or the two populations diverge silently.
func TestMigrate_FreshDatabaseHasProvenanceSchema(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.ListAnalysisRuns("no-such-case"); err != nil {
		t.Errorf("analysis_runs missing from a fresh database: %v", err)
	}
	ok, err := columnExists(s.db, "findings", "analysis_run_id")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("findings.analysis_run_id missing from a fresh database")
	}
}

// Migrating twice must be a no-op, since it runs on every startup.
func TestMigrate_ProvenanceMigrationIsIdempotent(t *testing.T) {
	path, caseID := openLegacyFindingsDB(t)
	for i := 0; i < 3; i++ {
		s, err := Open(path)
		if err != nil {
			t.Fatalf("open #%d: %v", i+1, err)
		}
		findings, err := s.ListFindings(caseID)
		if err != nil {
			t.Fatalf("open #%d listing findings: %v", i+1, err)
		}
		if len(findings) != 1 || findings[0].AnalysisRunID != "" {
			t.Fatalf("open #%d altered the legacy finding: %+v", i+1, findings)
		}
		s.Close()
	}
}
