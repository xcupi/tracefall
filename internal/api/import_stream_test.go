package api

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSQLLargeStreamImport(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("bounded import", "")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	f, err := os.Create(filepath.Join(root, "ERRORLOG"))
	if err != nil {
		t.Fatal(err)
	}
	const count = 1300
	for i := 0; i < count; i++ {
		if _, err := fmt.Fprintf(f, "2025-01-02 03:04:05.00 Server Microsoft SQL Server %d %s\n", i, strings.Repeat("x", 52000)); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	disc, err := svc.DiscoverEvidenceFromPath(c.ID, root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := svc.store.ListSourceFilesByCollection(disc.Collection.ID)
	if err != nil || len(files) != 1 {
		t.Fatalf("discover: %v %d", err, len(files))
	}
	result, err := svc.ImportEvidence(c.ID, disc.Collection.ID, []string{files[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ParseFailures) != 0 || result.EventCount != count || result.NewEventCount != count {
		t.Fatalf("import emitted=%d new=%d failures=%d", result.EventCount, result.NewEventCount, len(result.ParseFailures))
	}
	sf, err := svc.store.GetSourceFile(files[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if sf.ParseCoverage == nil || sf.ParseCoverage.RecordsRead != count || sf.ParseCoverage.LimitReached {
		t.Fatalf("coverage: %+v", sf.ParseCoverage)
	}
	obs, err := svc.store.ListEventObservationsBySourceFile(sf.ID)
	if err != nil || len(obs) != count {
		t.Fatalf("observations=%d err=%v", len(obs), err)
	}
}

func TestSQLStreamRecordLimitIsVisible(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("record budget", "")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "ERRORLOG"), []byte("2025-01-02 03:04:05.00 Server Microsoft SQL Server "+strings.Repeat("x", 1<<20)), 0600); err != nil {
		t.Fatal(err)
	}
	disc, err := svc.DiscoverEvidenceFromPath(c.ID, root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := svc.store.ListSourceFilesByCollection(disc.Collection.ID)
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.ImportEvidence(c.ID, disc.Collection.ID, []string{files[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ParseFailures) != 1 || result.ParseFailures[0].Category != ParseFailureLimit || len(result.Imported) != 0 || result.EventCount != 0 {
		t.Fatalf("limit not disclosed: failures=%+v imported=%d count=%d", result.ParseFailures, len(result.Imported), result.EventCount)
	}
}

func TestSQLStreamRetainsTiesAndRecollection(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("stream identity", "")
	if err != nil {
		t.Fatal(err)
	}
	for acquisition := 0; acquisition < 2; acquisition++ {
		root := t.TempDir()
		text := strings.Repeat("2025-01-02 03:04:05Z Server Microsoft SQL Server message\n", 300)
		if err = os.WriteFile(filepath.Join(root, "ERRORLOG"), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, "note.txt"), []byte(fmt.Sprint(acquisition)), 0600); err != nil {
			t.Fatal(err)
		}
		d, err := svc.DiscoverEvidenceFromPath(c.ID, root)
		if err != nil {
			t.Fatal(err)
		}
		files, err := svc.store.ListSourceFilesByCollection(d.Collection.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, sf := range files {
			if !sf.Supported {
				continue
			}
			result, err := svc.ImportEvidence(c.ID, d.Collection.ID, []string{sf.ID})
			if err != nil {
				t.Fatal(err)
			}
			wantNew := 300
			if acquisition == 1 {
				wantNew = 0
			}
			if result.EventCount != 300 || result.NewEventCount != wantNew || result.DuplicateEventCount != 300-wantNew {
				t.Fatalf("acquisition %d new=%d duplicate=%d parsed=%d", acquisition, result.NewEventCount, result.DuplicateEventCount, result.EventCount)
			}
			observations, err := svc.store.ListEventObservationsBySourceFile(sf.ID)
			if err != nil || len(observations) != 300 {
				t.Fatalf("observations=%d err=%v", len(observations), err)
			}
		}
	}
}
