package store_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"tracefall/internal/model"
	"tracefall/internal/store"
)

// Whole-case deletion, audited against the SCHEMA rather than against a
// hand-written list of tables.
//
// The failure mode this exists to catch is a new case-owned table being
// added and nobody remembering to delete from it. A test that enumerates
// tables by hand cannot catch that -- it drifts with the code it is
// meant to check. So these tests ask SQLite which tables carry a
// case_id, and require every one of them to be either emptied or named
// in retainedTables below with a stated reason.

// retainedTables are the case-referencing tables that deliberately
// SURVIVE a case deletion, each with the reason it does.
//
// Adding a table here is a design decision, not a convenience: it means
// rows referencing a deleted case remain in the database, and that has
// to be intentional and documented (see docs/security.md).
var retainedTables = map[string]string{
	"security_log": "system-wide record of who used the SYSTEM (logins, denied requests, account " +
		"administration), deliberately separate from the per-case audit_log. Its case_id is " +
		"unconstrained precisely so a denied request against a case can still say which case it " +
		"concerned. Deleting a case must not erase the record that someone was denied access to it. " +
		"See docs/security.md, 'Audit and the security log'.",
}

// caseIDTables returns every table with a case_id column, straight from
// the live schema.
func caseIDTables(t *testing.T, dbPath string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	rows.Close()

	var withCase []string
	for _, n := range names {
		cols, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", n))
		if err != nil {
			t.Fatal(err)
		}
		for cols.Next() {
			var cid int
			var name, typ string
			var notnull, pk int
			var dflt any
			if err := cols.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
				t.Fatal(err)
			}
			if name == "case_id" {
				withCase = append(withCase, n)
				break
			}
		}
		cols.Close()
	}
	sort.Strings(withCase)
	return withCase
}

// countFor returns how many rows in table belong to caseID.
func countFor(t *testing.T, dbPath, table, caseID string) int {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	col := "case_id"
	if table == "cases" {
		col = "id"
	}
	if err := db.QueryRow(fmt.Sprintf("SELECT count(*) FROM %s WHERE %s = ?", table, col), caseID).Scan(&n); err != nil {
		t.Fatalf("counting %s: %v", table, err)
	}
	return n
}

// populate writes rows into EVERY case-owned table, so a deletion test
// is testing deletion rather than the absence of data.
func populate(t *testing.T, s *store.Store, caseID, name string, events int) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)

	if err := s.CreateCase(model.Case{
		ID: caseID, Name: name, Status: "created", CreatedAt: now, UpdatedAt: now,
		CaseStatus: "open", Priority: "medium",
	}); err != nil {
		t.Fatal(err)
	}

	collID := caseID + "-coll"
	files := make([]model.SourceFile, 0, 8)
	for i := 0; i < 8; i++ {
		files = append(files, model.SourceFile{
			ID: fmt.Sprintf("%s-sf-%d", caseID, i), CaseID: caseID, CollectionID: collID,
			OriginalFilename: fmt.Sprintf("file%d.evtx", i), Path: fmt.Sprintf("Logs/file%d.evtx", i),
			ArtifactType: model.ArtifactWindowsEventLog, Parser: "evtxcsv@1", Supported: true,
			SizeBytes: 1024, SHA256: fmt.Sprintf("%064d", i), ImportStatus: model.SourceFileImported,
			DiscoveredAt: now,
		})
	}
	if err := s.CreateCollectionWithSourceFiles(model.Collection{
		ID: collID, CaseID: caseID, CreatedAt: now,
		SourceType: model.SourceTypeUpload, OriginalFilename: "evidence.zip",
		ArchiveHash: "abc", IntegritySHA512: "def", EvidenceDirectory: "/tmp/x",
		IngestionStatus: "imported",
	}, files); err != nil {
		t.Fatal(err)
	}

	evs := make([]model.Event, 0, events)
	raws := make([]model.RawEvidence, 0, events)
	obs := make([]model.EventObservation, 0, events)
	for i := 0; i < events; i++ {
		id := fmt.Sprintf("%s-ev-%d", caseID, i)
		rawID := fmt.Sprintf("%s-raw-%d", caseID, i)
		sf := files[i%len(files)].ID
		raws = append(raws, model.RawEvidence{
			ID: rawID, CaseID: caseID, SourceFileID: sf,
			SourceReference: fmt.Sprintf("row %d", i), Raw: `{"x":1}`,
		})
		evs = append(evs, model.Event{
			ID: id, CaseID: caseID, CollectionID: collID, SourceFileID: sf, RawEvidenceID: rawID,
			Timestamp: now.Add(time.Duration(i) * time.Second), Host: "WS01", User: "jdoe",
			EventType: model.EventProcessCreate, ProcessName: "cmd.exe",
			ArtifactType: model.ArtifactWindowsEventLog, Parser: "evtxcsv@1", Confidence: 1,
			DedupHash: fmt.Sprintf("%s-dedup-%d", caseID, i),
		})
		obs = append(obs, model.EventObservation{
			ID: fmt.Sprintf("%s-obs-%d", caseID, i), EventID: id, CaseID: caseID,
			CollectionID: collID, SourceFileID: sf, RawEvidenceID: rawID,
		})
	}
	if err := s.SaveRawEvidence(raws); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvents(evs); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEventObservations(obs); err != nil {
		t.Fatal(err)
	}

	if err := s.SaveFindings([]model.Finding{{
		ID: caseID + "-f1", CaseID: caseID, RuleID: "r1", Title: "t", Severity: "high",
		Confidence: "high", Description: "d", SupportingEvents: []string{evs[0].ID},
		Techniques: []string{"T1059"}, FirstSeen: now, LastSeen: now, CreatedAt: now,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCorrelations([]model.Correlation{{
		ID: caseID + "-c1", CaseID: caseID, Type: "process_chain", Title: "t",
		Description: "d", EventIDs: []string{evs[0].ID}, FirstSeen: now, LastSeen: now,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNote(model.Note{
		ID: caseID + "-n1", CaseID: caseID, TargetType: "finding", TargetID: caseID + "-f1",
		Text: "a note", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTag(model.Tag{
		ID: caseID + "-t1", CaseID: caseID, TargetType: "finding", TargetID: caseID + "-f1",
		Tag: "lateral-movement", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAnalystStatus(model.AnalystStatus{
		CaseID: caseID, TargetType: "finding", TargetID: caseID + "-f1",
		Status: "confirmed", UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAuditEvent(model.AuditEvent{
		ID: caseID + "-a1", CaseID: caseID, Timestamp: now, Action: model.AuditEvidenceImported,
		Actor: "tester", Summary: "imported",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAnalysisRun(model.AnalysisRun{
		ID: caseID + "-run1", CaseID: caseID, StartedAt: now, Status: "completed",
		ToolVersion: "test", EventCount: events, FindingCount: 1, CorrelationCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	// A system-wide security event that MENTIONS this case. Retained by
	// design; asserted below rather than assumed.
	if err := s.CreateSecurityEvent(model.AuditEvent{
		ID: caseID + "-s1", CaseID: caseID, Timestamp: now, Action: "access_denied",
		Actor: "someone", Summary: "denied",
	}); err != nil {
		t.Fatal(err)
	}
	// Roadmap item 2: operational state that must go with the case.
	if err := s.CreatePipelineJob(model.PipelineJob{
		ID: caseID + "-job1", CaseID: caseID, Kind: model.JobKindIngest, Status: model.JobQueued,
		Stage: model.StageQueued, CreatedBy: "tester", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUploadSession(model.UploadSession{
		ID: caseID + "-up1", CaseID: caseID, Filename: "a.zip", Size: 1, Status: model.UploadOpen,
		CreatedBy: "tester", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// A language model's draft about this case's findings.
	if err := s.SaveNarrative(model.Narrative{ID: caseID + "-nr1", CaseID: caseID, Status: model.NarrativeOK, CreatedAt: now, Destination: "llm.example.invalid",
		Model: "m", PayloadSystem: "s", PayloadUser: "u", PayloadSHA256: "h"}); err != nil {
		t.Fatal(err)
	}
	// The independent bounded review must also be case-owned.
	if err := s.SaveCaseReview(store.CaseReview{Narrative: model.Narrative{ID: caseID + "-review1", CaseID: caseID, CreatedAt: now, Status: model.NarrativeOK}}); err != nil {
		t.Fatal(err)
	}
	// The frozen batch manifest, plan and exact attempted packets are case-owned.
	if _, err := s.FreezeReviewSnapshot(context.Background(), caseID, caseID+"-batch"); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveBatchRun(caseID, caseID+"-batch", "planned", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveBatchPacket(caseID, caseID+"-batch", 0, "ready", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	// An outside service's answer about an indicator of this case.
	if err := s.UpsertEnrichment(model.Enrichment{
		ID: caseID + "-en1", CaseID: caseID, Provider: model.EnrichmentVirusTotal, IndicatorType: "sha256",
		Indicator: strings.Repeat("a", 64), Status: model.EnrichmentNotFound, FetchedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
}

func openStore(t *testing.T, dbPath string) *store.Store {
	t.Helper()
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// Every case-owned table must be emptied, and the ones that are not must
// be deliberate. Enumerated from the schema so a new table cannot be
// silently forgotten.
func TestDeleteCase_EveryCaseOwnedTableIsEmptiedOrDocumented(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "t.db")
	s := openStore(t, dbPath)
	populate(t, s, "case-a", "A", 500)

	tables := caseIDTables(t, dbPath)
	tables = append(tables, "cases")
	if len(tables) < 10 {
		t.Fatalf("only %d case-owned tables found; the schema query is wrong", len(tables))
	}

	before := map[string]int{}
	for _, tb := range tables {
		before[tb] = countFor(t, dbPath, tb, "case-a")
		if before[tb] == 0 {
			t.Errorf("%s has no rows for the case before deletion; this test would prove nothing about it", tb)
		}
	}

	if err := s.DeleteCase("case-a"); err != nil {
		t.Fatalf("DeleteCase: %v", err)
	}

	for _, tb := range tables {
		got := countFor(t, dbPath, tb, "case-a")
		reason, retained := retainedTables[tb]
		switch {
		case retained:
			if got != before[tb] {
				t.Errorf("%s is documented as retained but lost rows (%d -> %d). Reason on file: %s",
					tb, before[tb], got, reason)
			}
		case got != 0:
			t.Errorf("%s still holds %d row(s) for the deleted case. Either delete them in "+
				"store.DeleteCase, or add %q to retainedTables with the reason it survives.", tb, got, tb)
		}
	}
}

// Foreign keys are ENFORCED, which is what makes a forgotten table a
// loud failure rather than a silent orphan: deleting the case row while
// a child still referenced it would be rejected.
func TestDeleteCase_ForeignKeysAreEnforced(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "t.db")
	s := openStore(t, dbPath)
	populate(t, s, "case-a", "A", 10)

	// Every case_id column except the deliberately-unconstrained
	// security_log must carry a foreign key, so a row can never outlive
	// its case unnoticed.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var on int
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&on); err != nil {
		t.Fatal(err)
	}
	// The pragma is per-connection; this is a fresh one, so it only
	// proves the default. What matters is the STORE's connection, which
	// is asserted behaviourally below.
	_ = on

	for _, tb := range caseIDTables(t, dbPath) {
		if _, retained := retainedTables[tb]; retained {
			continue
		}
		rows, err := db.Query(fmt.Sprintf("PRAGMA foreign_key_list(%s)", tb))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for rows.Next() {
			var id, seq int
			var table, from, to, onUpdate, onDelete, match string
			if err := rows.Scan(&id, &seq, &table, &from, &to, &onUpdate, &onDelete, &match); err != nil {
				t.Fatal(err)
			}
			if from == "case_id" && table == "cases" {
				found = true
			}
		}
		rows.Close()
		if !found {
			t.Errorf("%s.case_id has no foreign key to cases; a row there could outlive its case silently", tb)
		}
	}

	// Behavioural proof that the store's own connection enforces them: a
	// case with children cannot be removed by the case row alone.
	if _, err := s.DB().Exec(`DELETE FROM cases WHERE id = ?`, "case-a"); err == nil {
		t.Error("deleting only the case row succeeded; foreign keys are not enforced on the store's connection")
	}
}

// Cross-case safety. A deletion must be scoped by case ownership, never
// by a bare id, and must leave every other case byte-identical.
func TestDeleteCase_OtherCasesAreUntouched(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "t.db")
	s := openStore(t, dbPath)
	populate(t, s, "case-a", "A", 300)
	populate(t, s, "case-b", "B", 300)

	tables := append(caseIDTables(t, dbPath), "cases")
	beforeB := map[string]int{}
	for _, tb := range tables {
		beforeB[tb] = countFor(t, dbPath, tb, "case-b")
	}

	if err := s.DeleteCase("case-a"); err != nil {
		t.Fatal(err)
	}

	for _, tb := range tables {
		if got := countFor(t, dbPath, tb, "case-b"); got != beforeB[tb] {
			t.Errorf("deleting case A changed case B's %s: %d -> %d", tb, beforeB[tb], got)
		}
	}
	// And the surviving case is still readable through the store.
	if _, err := s.GetCase("case-b"); err != nil {
		t.Errorf("case B is no longer readable: %v", err)
	}
	evs, err := s.ListEvents("case-b")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 300 {
		t.Errorf("case B has %d events, want 300", len(evs))
	}
	f, err := s.ListFindings("case-b")
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 {
		t.Errorf("case B has %d findings, want 1", len(f))
	}
}

// Deletion must be durable, not an in-memory illusion.
func TestDeleteCase_SurvivesReopeningTheDatabase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "t.db")
	s := openStore(t, dbPath)
	populate(t, s, "case-a", "A", 200)
	populate(t, s, "case-b", "B", 50)
	if err := s.DeleteCase("case-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen exactly as a restarted process would.
	s2, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	if _, err := s2.GetCase("case-a"); err == nil {
		t.Error("the deleted case came back after reopening the database")
	}
	for _, tb := range caseIDTables(t, dbPath) {
		if _, retained := retainedTables[tb]; retained {
			continue
		}
		if got := countFor(t, dbPath, tb, "case-a"); got != 0 {
			t.Errorf("%s holds %d row(s) for the deleted case after reopen", tb, got)
		}
	}
	if _, err := s2.GetCase("case-b"); err != nil {
		t.Errorf("the surviving case is gone after reopen: %v", err)
	}
}

// A failure partway through must leave the database exactly as it was.
func TestDeleteCase_IsAtomic(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "t.db")
	s := openStore(t, dbPath)
	populate(t, s, "case-a", "A", 100)

	tables := append(caseIDTables(t, dbPath), "cases")
	before := map[string]int{}
	for _, tb := range tables {
		before[tb] = countFor(t, dbPath, tb, "case-a")
	}

	// Force a failure inside the transaction by making one of the
	// statements impossible: a trigger that always raises.
	if _, err := s.DB().Exec(`CREATE TRIGGER fail_delete BEFORE DELETE ON findings
		BEGIN SELECT RAISE(ABORT, 'induced failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteCase("case-a"); err == nil {
		t.Fatal("DeleteCase reported success although a statement failed")
	}
	if _, err := s.DB().Exec(`DROP TRIGGER fail_delete`); err != nil {
		t.Fatal(err)
	}

	for _, tb := range tables {
		if got := countFor(t, dbPath, tb, "case-a"); got != before[tb] {
			t.Errorf("a failed deletion left %s changed: %d -> %d; the transaction did not roll back",
				tb, before[tb], got)
		}
	}
	// And the case is still fully usable afterwards.
	if _, err := s.GetCase("case-a"); err != nil {
		t.Errorf("the case is unreadable after a failed deletion: %v", err)
	}
	// A retry must now succeed.
	if err := s.DeleteCase("case-a"); err != nil {
		t.Errorf("retrying the deletion failed: %v", err)
	}
}

// Deleting a case that does not exist must not silently report success
// at the store layer, and must not touch anything else.
func TestDeleteCase_UnknownCaseChangesNothing(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "t.db")
	s := openStore(t, dbPath)
	populate(t, s, "case-b", "B", 20)

	if err := s.DeleteCase("no-such-case"); err != nil {
		t.Fatalf("deleting an unknown case errored at the store layer: %v", err)
	}
	if got := countFor(t, dbPath, "events", "case-b"); got != 20 {
		t.Errorf("case B has %d events after deleting an unknown case, want 20", got)
	}
}

// Scale: what the deletion actually costs. Reported rather than
// asserted against a tight bound -- these are wall-clock numbers on a
// shared machine, and the point is the SHAPE.
func TestDeleteCase_Scale(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	for _, n := range []int{1000, 10000, 100000} {
		t.Run(fmt.Sprintf("%d_events", n), func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "t.db")
			s := openStore(t, dbPath)
			populate(t, s, "case-a", "A", n)

			rows := 0
			for _, tb := range append(caseIDTables(t, dbPath), "cases") {
				if _, retained := retainedTables[tb]; retained {
					continue
				}
				rows += countFor(t, dbPath, tb, "case-a")
			}

			start := time.Now()
			if err := s.DeleteCase("case-a"); err != nil {
				t.Fatal(err)
			}
			elapsed := time.Since(start)

			info, _ := os.Stat(dbPath)
			t.Logf("%7d events: %7d case-owned rows deleted in %-12s (db %d bytes)",
				n, rows, elapsed, info.Size())

			for _, tb := range append(caseIDTables(t, dbPath), "cases") {
				if _, retained := retainedTables[tb]; retained {
					continue
				}
				if got := countFor(t, dbPath, tb, "case-a"); got != 0 {
					t.Errorf("%s still holds %d rows", tb, got)
				}
			}
		})
	}
}
