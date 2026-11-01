package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"tracefall/internal/model"
)

// Segmented-import contract tests. Fixtures are synthetic.

const (
	segCase  = "case-1"
	segColl  = "collection-1"
	segBase  = "sf-1" // already imported, visible
	segSrcA  = "src-a"
	segSrcB  = "src-b"
	segTimeA = "2025-03-01T10:00:00Z"
)

func seedSegSources(t *testing.T, s *Store) {
	t.Helper()
	seedCaseAndSourceFile(t, s)
	now := time.Now().UTC()
	var files []model.SourceFile
	for _, id := range []string{segSrcA, segSrcB} {
		files = append(files, model.SourceFile{
			ID: id, CaseID: segCase, CollectionID: segColl, OriginalFilename: id + ".log", Path: id + ".log",
			ArtifactType: model.ArtifactMSSQLLog, Parser: "mssql@1", Supported: true, SHA256: "h-" + id,
			ImportStatus: model.SourceFileDiscovered, DiscoveredAt: now,
		})
	}
	if err := s.SaveSourceFiles(files); err != nil {
		t.Fatalf("seed sources: %v", err)
	}
	ts, _ := time.Parse(time.RFC3339, segTimeA)
	if err := s.SaveRawEvidence([]model.RawEvidence{{ID: "raw-base", CaseID: segCase, SourceFileID: segBase, Raw: "base"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvents([]model.Event{{ID: "ev-base", CaseID: segCase, CollectionID: segColl, Timestamp: ts, Host: "HOST-BASE",
		EventType: "base", ArtifactType: model.ArtifactMSSQLLog, SourceFileID: segBase, RawEvidenceID: "raw-base", DedupHash: "dh-base"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEventObservations([]model.EventObservation{{ID: "ob-base", EventID: "ev-base", CaseID: segCase, CollectionID: segColl, SourceFileID: segBase, RawEvidenceID: "raw-base"}}); err != nil {
		t.Fatal(err)
	}
}

// segPayload builds n raw/event/observation triples whose ids and dedup hashes
// are unique per (source, segment, i).
func segPayload(src string, seg, n int) SegmentPayload {
	ts, _ := time.Parse(time.RFC3339, segTimeA)
	var p SegmentPayload
	for i := 0; i < n; i++ {
		k := fmt.Sprintf("%s-%d-%d", src, seg, i)
		p.Raw = append(p.Raw, model.RawEvidence{ID: "raw-" + k, CaseID: segCase, SourceFileID: src, Raw: "r" + k})
		p.Events = append(p.Events, model.Event{ID: "ev-" + k, CaseID: segCase, CollectionID: segColl, Timestamp: ts.Add(time.Duration(i) * time.Second),
			Host: "HOST-" + src, EventType: "seg", ArtifactType: model.ArtifactMSSQLLog, SourceFileID: src, RawEvidenceID: "raw-" + k, DedupHash: "dh-" + k})
		p.Observations = append(p.Observations, model.EventObservation{ID: "ob-" + k, EventID: "ev-" + k, CaseID: segCase, CollectionID: segColl, SourceFileID: src, RawEvidenceID: "raw-" + k})
	}
	return p
}

func commitSeg(t *testing.T, s *Store, src string, idx, n int) SegmentTotals {
	t.Helper()
	tot, err := s.CommitSegment(context.Background(), src, SegmentCheckpoint{Index: idx, ByteOffset: int64(idx+1) * 1000, Position: fmt.Sprintf("p%d", idx), Records: n}, segPayload(src, idx, n))
	if err != nil {
		t.Fatalf("CommitSegment(%s,%d): %v", src, idx, err)
	}
	return tot
}

func rowCount(t *testing.T, s *Store, q string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func srcStatus(t *testing.T, s *Store, id string) string {
	t.Helper()
	sf, err := s.GetSourceFile(id)
	if err != nil {
		t.Fatal(err)
	}
	return sf.ImportStatus
}

// visibleCounts runs every evidence reader and returns how many of the
// importing source's rows each can see (must be 0 while pending).
func visibleOf(t *testing.T, s *Store, src string) map[string]int {
	t.Helper()
	out := map[string]int{}
	count := func(name string, evs []model.Event) {
		for _, e := range evs {
			if e.SourceFileID == src {
				out[name]++
			}
		}
	}
	evs, err := s.ListEvents(segCase)
	if err != nil {
		t.Fatal(err)
	}
	count("ListEvents", evs)
	evs, err = s.ListEventsByCollection(segColl)
	if err != nil {
		t.Fatal(err)
	}
	count("ListEventsByCollection", evs)
	var fe []model.Event
	if err = s.ForEachEvent(segCase, func(e model.Event) error { fe = append(fe, e); return nil }); err != nil {
		t.Fatal(err)
	}
	count("ForEachEvent", fe)
	fe = nil
	if err = s.ForEachEventInCollection(segColl, func(e model.Event) error { fe = append(fe, e); return nil }); err != nil {
		t.Fatal(err)
	}
	count("ForEachEventInCollection", fe)
	fe = nil
	if err = s.ForEachEventLazy(segCase, func(string) bool { return true }, func(e model.Event) error { fe = append(fe, e); return nil }); err != nil {
		t.Fatal(err)
	}
	count("ForEachEventLazy", fe)
	loaded, err := s.EventSourceFor(segCase).Load(model.EventFilter{Types: []string{"seg", "base"}})
	if err != nil {
		t.Fatal(err)
	}
	count("EventSource.Load", loaded)
	refs, err := s.EventSourceFor(segCase).Refs()
	if err != nil {
		t.Fatal(err)
	}
	out["EventSource.Refs.total"] = len(refs)
	found, total, err := s.SearchEvents(EventQuery{CaseID: segCase, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	count("SearchEvents", found)
	out["SearchEvents.total"] = total
	n, err := s.CountEvents(segCase)
	if err != nil {
		t.Fatal(err)
	}
	out["CountEvents"] = n
	n, err = s.CountEventsByCollection(segColl)
	if err != nil {
		t.Fatal(err)
	}
	out["CountEventsByCollection"] = n
	facets, err := s.EventFacets(segCase)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range facets.Hosts {
		if h == "HOST-"+src {
			out["EventFacets.hosts"]++
		}
	}
	sum, err := s.SummarizeCollectionEvents(segColl)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range sum.Hosts {
		if h == "HOST-"+src {
			out["SummarizeCollectionEvents.hosts"]++
		}
	}
	hosts, err := s.CollectionHosts(segCase, segColl)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		if h == "HOST-"+src {
			out["CollectionHosts"]++
		}
	}
	names, err := s.CaseNames(segCase)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range names.Hosts {
		if h == "HOST-"+src {
			out["CaseNames.hosts"]++
		}
	}
	byID, err := s.EventsByIDs([]string{"ev-" + src + "-0-0"})
	if err != nil {
		t.Fatal(err)
	}
	out["EventsByIDs"] = len(byID)
	if _, err := s.GetEvent("ev-" + src + "-0-0"); err == nil {
		out["GetEvent"] = 1
	}
	if _, err := s.GetRawEvidence("raw-" + src + "-0-0"); err == nil {
		out["GetRawEvidence"] = 1
	}
	raws, err := s.ListRawEvidenceBySourceFile(src, 1000)
	if err != nil {
		t.Fatal(err)
	}
	out["ListRawEvidenceBySourceFile"] = len(raws)
	obs, err := s.ListEventObservationsBySourceFile(src)
	if err != nil {
		t.Fatal(err)
	}
	out["ListEventObservationsBySourceFile"] = len(obs)
	obs, err = s.ListEventObservations("ev-" + src + "-0-0")
	if err != nil {
		t.Fatal(err)
	}
	out["ListEventObservations"] = len(obs)
	hf, err := s.EventFieldsByKey(segCase, []string{"nothing"})
	if err != nil {
		t.Fatal(err)
	}
	out["EventFieldsByKey"] = len(hf)
	if ev, found, err := s.FindEventByDedupHash(segCase, "dh-"+src+"-0-0"); err != nil {
		t.Fatal(err)
	} else if found && ev.SourceFileID == src {
		out["FindEventByDedupHash"] = 1
	}
	return out
}

func TestPendingSourceRowsAreInvisibleToEveryReaderThenAppearAtFinalize(t *testing.T) {
	s := openTest(t)
	seedSegSources(t, s)
	if err := s.BeginSegmentedImport(segSrcA); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	commitSeg(t, s, segSrcA, 0, 3)
	tot := commitSeg(t, s, segSrcA, 1, 4)
	if tot.Segments != 2 || tot.Records != 7 || tot.Raw != 7 || tot.Events != 7 || tot.Observations != 7 {
		t.Fatalf("cumulative totals = %+v", tot)
	}
	if got := srcStatus(t, s, segSrcA); got != model.SourceFileImporting {
		t.Fatalf("status = %q, want importing", got)
	}
	if got := rowCount(t, s, `SELECT COUNT(*) FROM events WHERE source_file_id = ?`, segSrcA); got != 7 {
		t.Fatalf("raw table holds %d pending events, want 7 (rows must really be committed)", got)
	}
	for name, n := range visibleOf(t, s, segSrcA) {
		switch name {
		case "EventSource.Refs.total", "SearchEvents.total", "CountEvents", "CountEventsByCollection":
			if n != 1 {
				t.Errorf("%s = %d while pending, want only the 1 baseline event", name, n)
			}
		default:
			if n != 0 {
				t.Errorf("reader %s leaks %d pending rows", name, n)
			}
		}
	}
	// The baseline source must stay fully visible.
	if got := visibleOf(t, s, segBase)["ListEvents"]; got != 1 {
		t.Errorf("baseline invisible: ListEvents sees %d", got)
	}
	if err := s.FinalizeSegmentedImport(context.Background(), segSrcA, FinalizeExpectation{SegmentTotals: tot, ImportedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if got := srcStatus(t, s, segSrcA); got != model.SourceFileImported {
		t.Fatalf("status after finalize = %q", got)
	}
	v := visibleOf(t, s, segSrcA)
	if v["ListEvents"] != 7 || v["ForEachEvent"] != 7 || v["CountEvents"] != 8 || v["SearchEvents.total"] != 8 || v["ListEventObservationsBySourceFile"] != 7 || v["ListRawEvidenceBySourceFile"] != 7 {
		t.Errorf("after finalize readers see %v", v)
	}
	sf, _ := s.GetSourceFile(segSrcA)
	if sf.EventCount != 7 {
		t.Errorf("source event_count = %d, want parsed-record total 7", sf.EventCount)
	}
	if o, ok, err := s.SegmentedImportOutcome(segSrcA); err != nil || !ok || o.Outcome != "imported" || o.Segments != 2 || o.Events != 7 {
		t.Errorf("outcome = %+v ok=%v err=%v", o, ok, err)
	}
	c, _ := s.GetCase(segCase)
	if c.Status != model.CaseStatusIngested {
		t.Errorf("case status = %q, want ingested", c.Status)
	}
}

func TestAbortRemovesEverythingAndAllowsRetry(t *testing.T) {
	s := openTest(t)
	seedSegSources(t, s)
	if err := s.BeginSegmentedImport(segSrcA); err != nil {
		t.Fatal(err)
	}
	commitSeg(t, s, segSrcA, 0, 3)
	commitSeg(t, s, segSrcA, 1, 3)
	if err := s.AbortSegmentedImport(context.Background(), segSrcA, "synthetic failure"); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	for _, tbl := range []string{"events", "event_observations", "raw_evidence"} {
		if n := rowCount(t, s, `SELECT COUNT(*) FROM `+tbl+` WHERE source_file_id = ?`, segSrcA); n != 0 {
			t.Errorf("%s keeps %d aborted rows", tbl, n)
		}
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM source_import_segments WHERE source_file_id = ?`, segSrcA); n != 0 {
		t.Errorf("checkpoint rows remain: %d", n)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM events WHERE source_file_id = ?`, segBase); n != 1 {
		t.Errorf("abort damaged the baseline source: %d events", n)
	}
	if got := srcStatus(t, s, segSrcA); got != model.SourceFileFailed {
		t.Errorf("status = %q, want failed", got)
	}
	o, ok, err := s.SegmentedImportOutcome(segSrcA)
	if err != nil || !ok || o.Outcome != "aborted" || o.Reason != "synthetic failure" {
		t.Errorf("outcome = %+v ok=%v err=%v", o, ok, err)
	}
	// Existing retry contract: failed + no rows -> discovered, then a fresh Begin works.
	if retried, err := s.RetryFailedSource(segSrcA); err != nil || !retried {
		t.Fatalf("RetryFailedSource = %v, %v (aborted source must be retry-safe)", retried, err)
	}
	if err := s.BeginSegmentedImport(segSrcA); err != nil {
		t.Fatalf("second Begin: %v", err)
	}
	commitSeg(t, s, segSrcA, 0, 2)
}

func TestSegmentsMustArriveInOrderAndMatchTheSource(t *testing.T) {
	s := openTest(t)
	seedSegSources(t, s)
	ctx := context.Background()
	if _, err := s.CommitSegment(ctx, segSrcA, SegmentCheckpoint{Index: 0}, segPayload(segSrcA, 0, 1)); !errors.Is(err, ErrSourceNotAdmissible) {
		t.Errorf("commit before Begin: %v, want ErrSourceNotAdmissible", err)
	}
	if err := s.BeginSegmentedImport(segSrcA); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginSegmentedImport(segSrcA); !errors.Is(err, ErrSourceNotAdmissible) {
		t.Errorf("double Begin: %v", err)
	}
	if _, err := s.CommitSegment(ctx, segSrcA, SegmentCheckpoint{Index: 1}, segPayload(segSrcA, 1, 1)); !errors.Is(err, ErrSegmentOutOfOrder) {
		t.Errorf("skipped index: %v, want ErrSegmentOutOfOrder", err)
	}
	commitSeg(t, s, segSrcA, 0, 2)
	if _, err := s.CommitSegment(ctx, segSrcA, SegmentCheckpoint{Index: 0}, segPayload(segSrcA, 0, 1)); !errors.Is(err, ErrSegmentOutOfOrder) {
		t.Errorf("repeated index: %v", err)
	}
	bad := segPayload(segSrcA, 1, 2)
	bad.Events[1].SourceFileID = segSrcB
	before := rowCount(t, s, `SELECT COUNT(*) FROM events`)
	if _, err := s.CommitSegment(ctx, segSrcA, SegmentCheckpoint{Index: 1}, bad); err == nil {
		t.Error("a payload row attributed to another source was accepted")
	}
	if after := rowCount(t, s, `SELECT COUNT(*) FROM events`); after != before {
		t.Errorf("rejected segment left rows behind: %d -> %d", before, after)
	}
	if p, ok, err := s.SegmentedImportProgress(segSrcA); err != nil || !ok || p.Segments != 1 || p.Events != 2 || p.Position != "p0" {
		t.Errorf("progress after rejection = %+v ok=%v err=%v (checkpoint must equal committed rows)", p, ok, err)
	}
	// Only one importing source per case.
	if err := s.BeginSegmentedImport(segSrcB); !errors.Is(err, ErrSourceNotAdmissible) {
		t.Errorf("second concurrent importing source in one case: %v", err)
	}
	if has, err := s.CaseHasImportingSource(segCase); err != nil || !has {
		t.Errorf("CaseHasImportingSource = %v, %v", has, err)
	}
	// A segment cancelled before commit publishes nothing.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.CommitSegment(cctx, segSrcA, SegmentCheckpoint{Index: 1}, segPayload(segSrcA, 1, 2)); err == nil {
		t.Error("cancelled segment commit succeeded")
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM events WHERE source_file_id = ?`, segSrcA); n != 2 {
		t.Errorf("cancelled segment left rows: %d", n)
	}
}

func TestFinalizeRefusesAMismatchAndNeverPublishes(t *testing.T) {
	s := openTest(t)
	seedSegSources(t, s)
	ctx := context.Background()
	if err := s.BeginSegmentedImport(segSrcA); err != nil {
		t.Fatal(err)
	}
	tot := commitSeg(t, s, segSrcA, 0, 3)
	wrong := tot
	wrong.Events++
	if err := s.FinalizeSegmentedImport(ctx, segSrcA, FinalizeExpectation{SegmentTotals: wrong, ImportedAt: time.Now().UTC()}); !errors.Is(err, ErrFinalizeMismatch) {
		t.Errorf("expected-total mismatch: %v, want ErrFinalizeMismatch", err)
	}
	// Row tampering after the checkpoint (a lost row) must be detected too.
	if _, err := s.db.Exec(`DELETE FROM raw_evidence WHERE id = ?`, "raw-"+segSrcA+"-0-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.FinalizeSegmentedImport(ctx, segSrcA, FinalizeExpectation{SegmentTotals: tot, ImportedAt: time.Now().UTC()}); !errors.Is(err, ErrFinalizeMismatch) {
		t.Errorf("stored rows != checkpoint: %v, want ErrFinalizeMismatch", err)
	}
	if got := srcStatus(t, s, segSrcA); got != model.SourceFileImporting {
		t.Errorf("status after refused finalize = %q, want importing (never imported)", got)
	}
	if got := visibleOf(t, s, segSrcA)["ListEvents"]; got != 0 {
		t.Errorf("refused finalize published %d rows", got)
	}
}

func TestFinalizeRefusesVisibleDuplicateOfAnotherSource(t *testing.T) {
	s := openTest(t)
	seedSegSources(t, s)
	if err := s.BeginSegmentedImport(segSrcA); err != nil {
		t.Fatal(err)
	}
	p := segPayload(segSrcA, 0, 2)
	p.Events[0].DedupHash = "dh-base" // same hash as the visible baseline event
	if _, err := s.CommitSegment(context.Background(), segSrcA, SegmentCheckpoint{Index: 0, Records: 2}, p); err != nil {
		t.Fatal(err)
	}
	err := s.FinalizeSegmentedImport(context.Background(), segSrcA, FinalizeExpectation{
		SegmentTotals: SegmentTotals{Segments: 1, Records: 2, Raw: 2, Events: 2, Observations: 2}, ImportedAt: time.Now().UTC()})
	if !errors.Is(err, ErrFinalizeMismatch) {
		t.Errorf("duplicate of a visible event published: %v", err)
	}
	if got := srcStatus(t, s, segSrcA); got != model.SourceFileImporting {
		t.Errorf("status = %q", got)
	}
}

func TestDedupLookupSeesOwnPendingRowsButNotOthers(t *testing.T) {
	s := openTest(t)
	seedSegSources(t, s)
	if err := s.BeginSegmentedImport(segSrcA); err != nil {
		t.Fatal(err)
	}
	commitSeg(t, s, segSrcA, 0, 2)
	if _, found, _ := s.FindEventByDedupHash(segCase, "dh-"+segSrcA+"-0-0"); found {
		t.Error("public dedup lookup returned a pending row")
	}
	if ev, found, err := s.FindEventByDedupHashForImport(segCase, "dh-"+segSrcA+"-0-0", segSrcA); err != nil || !found || ev.SourceFileID != segSrcA {
		t.Errorf("importing source cannot see its own pending row: %+v %v %v", ev, found, err)
	}
	if _, found, _ := s.FindEventByDedupHashForImport(segCase, "dh-"+segSrcA+"-0-0", segSrcB); found {
		t.Error("a different source dedups against someone else's pending row")
	}
	if ev, found, err := s.FindEventByDedupHashForImport(segCase, "dh-base", segSrcA); err != nil || !found || ev.ID != "ev-base" {
		t.Errorf("importing source cannot see visible baseline rows: %+v %v %v", ev, found, err)
	}
}

func TestCrashLeavesCheckpointEqualToCommittedRowsAndRecoveryCleans(t *testing.T) {
	path := t.TempDir() + "/crash.db"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	seedSegSources(t, s)
	if err := s.BeginSegmentedImport(segSrcA); err != nil {
		t.Fatal(err)
	}
	commitSeg(t, s, segSrcA, 0, 3)
	// A segment whose transaction is open (never committed) when the process dies.
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO raw_evidence (id, case_id, source_file_id, source_reference, raw) VALUES ('half', ?, ?, '', 'x')`, segCase, segSrcA); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback() // what SQLite does for a dead process
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, ok, err := s.SegmentedImportProgress(segSrcA)
	if err != nil || !ok || p.Segments != 1 || p.Raw != 3 {
		t.Fatalf("progress after reopen = %+v ok=%v err=%v", p, ok, err)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM raw_evidence WHERE source_file_id = ?`, segSrcA); n != 3 {
		t.Errorf("raw rows after crash = %d, want exactly the committed 3", n)
	}
	if got := srcStatus(t, s, segSrcA); got != model.SourceFileImporting {
		t.Fatalf("status = %q", got)
	}
	// Live job: not touched. No live job: aborted and cleaned.
	rec, err := s.RecoverOrphanedImports(context.Background(), func(string) bool { return true })
	if err != nil || len(rec) != 0 {
		t.Errorf("recovery touched a live import: %v %v", rec, err)
	}
	rec, err = s.RecoverOrphanedImports(context.Background(), func(string) bool { return false })
	if err != nil || len(rec) != 1 || rec[0].SourceFileID != segSrcA || rec[0].Segments != 1 {
		t.Fatalf("recovery = %+v err=%v", rec, err)
	}
	if got := srcStatus(t, s, segSrcA); got != model.SourceFileFailed {
		t.Errorf("status after recovery = %q, want failed", got)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM events WHERE source_file_id = ?`, segSrcA); n != 0 {
		t.Errorf("recovery left %d events", n)
	}
	if o, ok, _ := s.SegmentedImportOutcome(segSrcA); !ok || o.Outcome != "aborted" || o.Reason == "" {
		t.Errorf("recovery outcome = %+v ok=%v (reason must be disclosed)", o, ok)
	}
}

func TestPendingRowsDoNotChangeImportCounts(t *testing.T) {
	s := openTest(t)
	seedSegSources(t, s)
	if err := s.BeginSegmentedImport(segSrcA); err != nil {
		t.Fatal(err)
	}
	commitSeg(t, s, segSrcA, 0, 5)
	ok, err := s.CollectionEventsAreSelfContained(segColl)
	if err != nil || !ok {
		t.Errorf("self-contained = %v, %v", ok, err)
	}
	files, err := s.ListSourceFilesByCollection(segColl)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.ID == segSrcA && (f.ImportStatus != model.SourceFileImporting || f.EventCount != 0) {
			t.Errorf("pending source row = status %q event_count %d", f.ImportStatus, f.EventCount)
		}
	}
}
