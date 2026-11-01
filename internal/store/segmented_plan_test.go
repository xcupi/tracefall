package store

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// explainPlan returns the EXPLAIN QUERY PLAN detail lines of a query.
func explainPlan(t *testing.T, s *Store, q string, args ...any) []string {
	t.Helper()
	rows, err := s.db.Query(`EXPLAIN QUERY PLAN `+q, args...)
	if err != nil {
		t.Fatalf("explain %q: %v", q, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		out = append(out, detail)
	}
	return out
}

// The visibility predicate must be a per-row filter: it must not push the
// planner off the indexes the readers relied on, and the importing-source set
// must be served by its tiny partial index, not a scan of source_files.
func TestVisibilityPredicateKeepsIndexedAccessPaths(t *testing.T) {
	s := openTest(t)
	seedSegSources(t, s)
	ts, _ := time.Parse(time.RFC3339, segTimeA)
	for b := 0; b < 20; b++ {
		var evs []model.Event
		for i := 0; i < 1000; i++ {
			k := fmt.Sprintf("bulk-%d-%d", b, i)
			evs = append(evs, model.Event{ID: "ev-" + k, CaseID: segCase, CollectionID: segColl, Timestamp: ts.Add(time.Duration(b*1000+i) * time.Second),
				Host: "H", EventType: "bulk", ArtifactType: model.ArtifactMSSQLLog, SourceFileID: segBase, DedupHash: "dh-" + k})
		}
		if err := s.SaveEvents(evs); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`ANALYZE`); err != nil {
		t.Fatal(err)
	}
	queries := map[string]struct {
		q    string
		args []any
		want string // an index the event access path must still use
	}{
		"ListEvents order":   {`SELECT ` + eventCols + ` FROM events WHERE case_id = ? AND ` + srcVisible("source_file_id") + ` ORDER BY timestamp ASC`, []any{segCase}, "idx_events_case"},
		"dedup lookup":       {`SELECT ` + eventCols + ` FROM events WHERE case_id = ? AND dedup_hash = ? AND ` + srcVisible("source_file_id") + ` LIMIT 1`, []any{segCase, "dh-x"}, "idx_events_case_dedup"},
		"by id":              {`SELECT ` + eventCols + ` FROM events WHERE id = ? AND ` + srcVisible("source_file_id"), []any{"ev-x"}, "sqlite_autoindex_events_1"},
		"paged scope stream": {`SELECT ` + eventCols + ` FROM events WHERE collection_id = ? AND ` + srcVisible("source_file_id") + ` ORDER BY timestamp ASC, id ASC LIMIT 100`, []any{segColl}, ""},
	}
	var report strings.Builder
	for name, c := range queries {
		plan := explainPlan(t, s, c.q, c.args...)
		fmt.Fprintf(&report, "== %s\n", name)
		joined := strings.Join(plan, "\n")
		report.WriteString("   " + strings.ReplaceAll(joined, "\n", "\n   ") + "\n")
		if c.want != "" && !strings.Contains(joined, c.want) {
			t.Errorf("%s: plan no longer uses %s:\n%s", name, c.want, joined)
		}
		if !strings.Contains(joined, "idx_source_files_importing") {
			t.Errorf("%s: importing-source set is not served by idx_source_files_importing:\n%s", name, joined)
		}
	}
	t.Log("\n" + report.String())
}

// Opening an existing database that predates segmented admission adds the new
// tables and the tiny partial index without rewriting any evidence table.
func TestOpenAddsSegmentedAdmissionSchemaToAnExistingDatabase(t *testing.T) {
	path := t.TempDir() + "/old.db"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	seedSegSources(t, s)
	for _, stmt := range []string{`DROP TABLE source_import_segments`, `DROP TABLE source_import_outcomes`, `DROP INDEX idx_source_files_importing`} {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatalf("reopen old schema: %v", err)
	}
	defer s.Close()
	for _, name := range []string{"source_import_segments", "source_import_outcomes", "idx_source_files_importing"} {
		if n := rowCount(t, s, `SELECT COUNT(*) FROM sqlite_master WHERE name = ?`, name); n != 1 {
			t.Errorf("%s missing after migration", name)
		}
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM events`); n != 1 {
		t.Errorf("existing events changed: %d", n)
	}
	if err := s.BeginSegmentedImport(segSrcA); err != nil {
		t.Fatalf("segmented admission unusable on a migrated database: %v", err)
	}
}

// Case and collection deletion remove the bookkeeping rows too.
func TestDeletingACaseRemovesSegmentedAdmissionBookkeeping(t *testing.T) {
	s := openTest(t)
	seedSegSources(t, s)
	if err := s.BeginSegmentedImport(segSrcA); err != nil {
		t.Fatal(err)
	}
	commitSeg(t, s, segSrcA, 0, 2)
	if _, err := s.DeleteCaseWithCounts(segCase); err != nil {
		t.Fatalf("DeleteCaseWithCounts with a pending import: %v", err)
	}
	for _, tbl := range []string{"source_import_segments", "source_import_outcomes", "events", "raw_evidence", "event_observations"} {
		if n := rowCount(t, s, `SELECT COUNT(*) FROM `+tbl); n != 0 {
			t.Errorf("%s keeps %d rows after case deletion", tbl, n)
		}
	}
}
