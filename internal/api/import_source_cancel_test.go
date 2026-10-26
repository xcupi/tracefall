package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/ingest"
	"tracefall/internal/model"
)

func TestPersistSourceCancellationRollsBackAndRetries(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("source cancellation", "")
	if err != nil {
		t.Fatal(err)
	}
	// Reuse discovery rather than bypassing source ownership/foreign keys.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ERRORLOG"), []byte("2025-01-02 03:04:05.00 Server Microsoft SQL Server informational message\n"), 0600); err != nil {
		t.Fatal(err)
	}
	d, err := svc.DiscoverEvidenceFromPath(c.ID, root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := svc.store.ListSourceFilesByCollection(d.Collection.ID)
	if err != nil || len(files) != 1 {
		t.Fatalf("discover: %v", err)
	}
	spool, err := newParsedSpool(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.close()
	for i := 0; i < 3; i++ {
		ref := fmt.Sprintf("line:%d", i+1)
		raw := model.RawEvidence{ID: fmt.Sprintf("raw-%d", i), CaseID: c.ID, SourceFileID: files[0].ID, SourceReference: ref, Raw: "record"}
		ev := model.Event{ID: fmt.Sprintf("ev-%d", i), CaseID: c.ID, CollectionID: d.Collection.ID, SourceFileID: files[0].ID, SourceReference: ref, RawEvidenceID: raw.ID, ArtifactType: model.ArtifactMSSQLLog, EventType: "sql_log"}
		if err := spool.append(ingest.ParsedFile{Events: []model.Event{ev}, Raw: []model.RawEvidence{raw}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := spool.finishWrite(); err != nil {
		t.Fatal(err)
	}
	pf := pendingImport{sourceFile: files[0], spool: spool}
	checks := 0
	t.Logf("discovered source status=%s supported=%v", files[0].ImportStatus, files[0].Supported)
	_, _, err = svc.persistSource(context.Background(), pf, c.ID, d.Collection.ID, func() bool { checks++; return checks >= 2 })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel during source: %v", err)
	}
	for _, table := range []string{"events", "raw_evidence", "event_observations"} {
		var n int
		if err := svc.store.DB().QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("cancel leaked %s: %d", table, n)
		}
	}
	sf, err := svc.store.GetSourceFile(files[0].ID)
	if err != nil || sf.ImportStatus != model.SourceFileDiscovered {
		t.Fatalf("cancel status=%s err=%v", sf.ImportStatus, err)
	}
	n, applied, err := svc.persistSource(context.Background(), pf, c.ID, d.Collection.ID, func() bool { return false })
	if err != nil || !applied || n != 3 {
		t.Fatalf("retry new=%d applied=%v err=%v", n, applied, err)
	}
}
