package api

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
)

func TestMSSQLXEPersistedExports(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("SQL exported observations", "")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	raw := "event_time,action_id,succeeded,statement\n2026-01-02 03:04:05,SL,1,SELECT FakeSecretForRaw123\n2026-01-02 03:04:05,SL,1,SELECT FakeSecretForRaw123\n"
	if err := os.WriteFile(filepath.Join(root, "capture.sqlaudit.csv"), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	d, err := svc.DiscoverEvidenceFromPath(c.ID, root)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := svc.EvidenceFileIDs(c.ID, d.Collection.ID, EvidenceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	imp, err := svc.ImportEvidence(c.ID, d.Collection.ID, ids)
	if err != nil {
		t.Fatal(err)
	}
	if imp.EventCount != 2 || len(imp.ParseFailures) != 0 {
		t.Fatalf("import %#v", imp)
	}
	events, err := svc.store.ListEvents(c.ID)
	if err != nil || len(events) != 2 {
		t.Fatalf("persisted=%d err=%v", len(events), err)
	}
	for _, e := range events {
		if e.Host != "" || e.PID != 0 {
			t.Fatal("invented host/process")
		}
		r, err := svc.store.GetRawEvidence(e.RawEvidenceID)
		if err != nil || !strings.Contains(r.Raw, "FakeSecretForRaw123") {
			t.Fatal("raw evidence lost", err)
		}
		ref := eventRef(e, nil)
		if strings.Contains(fmt.Sprint(ref), "FakeSecretForRaw123") {
			t.Fatal("raw SQL leaked into summary")
		}
	}
	files, err := svc.store.ListSourceFilesByCollection(d.Collection.ID)
	if err != nil || len(files) != 1 || files[0].ParseCoverage == nil || len(files[0].ParseCoverage.Notes) == 0 {
		t.Fatal("source coverage lost", err)
	}
	// Recollections retain separate observations without extra representatives.
	root2 := t.TempDir()
	os.WriteFile(filepath.Join(root2, "capture.sqlaudit.csv"), []byte(raw), 0600)
	os.WriteFile(filepath.Join(root2, "acquisition-note.txt"), []byte("second acquisition"), 0600)
	d2, err := svc.DiscoverEvidenceFromPath(c.ID, root2)
	if err != nil {
		t.Fatal(err)
	}
	ids2, err := svc.EvidenceFileIDs(c.ID, d2.Collection.ID, EvidenceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.ImportEvidence(c.ID, d2.Collection.ID, ids2); err != nil {
		t.Fatal(err)
	}
	after, err := svc.store.ListEvents(c.ID)
	if err != nil || len(after) != 2 {
		t.Fatalf("recollection representatives=%d err=%v", len(after), err)
	}
	for _, e := range after {
		p, err := svc.EventProvenance(c.ID, e.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Observations) != 2 {
			t.Fatalf("observations=%d", len(p.Observations))
		}
		if p.Observations[0].RawEvidenceID == p.Observations[1].RawEvidenceID {
			t.Fatal("raw recollection identity collapsed")
		}
	}
	t.Logf("persisted representatives=%d, recollection observations per event=2, raw records and coverage retained", len(events))
}
func TestRealMSSQLXEPersisted(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_MSSQL_XEL")
	if path == "" {
		t.Skip("TRACEFALL_REAL_MSSQL_XEL not set")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(b)) != "79aad08f9efc149d96f89282a3eea9431aadb63845219e02bb45dfa4e2c11d75" {
		t.Fatal("fixture hash mismatch")
	}
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "capture.xel"), b, 0600)
	ingest.SetParserRunner(ingest.Subprocess{Exe: "/nonexistent-go-worker"})
	defer ingest.SetParserRunner(nil)
	svc := newTestService(t)
	c, err := svc.CreateCase("SQL offline binary", "")
	if err != nil {
		t.Fatal(err)
	}
	d, err := svc.DiscoverEvidenceFromPath(c.ID, root)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := svc.EvidenceFileIDs(c.ID, d.Collection.ID, EvidenceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	imp, err := svc.ImportEvidence(c.ID, d.Collection.ID, ids)
	if err != nil {
		t.Fatal(err)
	}
	if imp.EventCount != 149 || len(imp.ParseFailures) != 0 {
		t.Fatalf("import %#v", imp)
	}
	events, err := svc.store.ListEvents(c.ID)
	if err != nil || len(events) != 149 {
		t.Fatalf("persisted=%d err=%v", len(events), err)
	}
	for _, e := range events {
		if e.ArtifactType != model.ArtifactMSSQLExtendedEvents || e.Host != "" || e.PID != 0 {
			t.Fatal("attribution/type changed")
		}
		if _, err := svc.store.GetRawEvidence(e.RawEvidenceID); err != nil {
			t.Fatal(err)
		}
	}
	report, err := svc.buildReport(c.ID, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	defer report.release()
	t.Logf("discovered=%d imported=%d persisted=%d; source-linked raw evidence retrieved; report built", len(ids), imp.EventCount, len(events))
}
