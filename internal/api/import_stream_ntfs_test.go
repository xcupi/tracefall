package api

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
	"tracefall/internal/ingest"
	"tracefall/internal/ntfs/mftgen"
)

func TestNativeStreamIsolatedPersistence(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ingest.SetParserRunner(ingest.Subprocess{Exe: exe, Sandbox: ingest.FindSandbox()})
	defer ingest.SetParserRunner(nil)
	for _, kind := range []string{"mft", "usn"} {
		t.Run(kind, func(t *testing.T) {
			svc := newTestService(t)
			c, err := svc.CreateCase("native stream", "")
			if err != nil {
				t.Fatal(err)
			}
			at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			times := mftgen.Times{Created: at, Modified: at, Changed: at, Accessed: at}
			var data []byte
			name := "$MFT"
			expected := 0
			if kind == "mft" {
				files := mftgen.SystemRecords(times)
				for i := 0; i < 300; i++ {
					files = append(files, mftgen.File{RecordNumber: uint64(64 + i), SequenceNumber: 1, SI: times, Names: []mftgen.Name{{Name: "same.txt", Namespace: 1, ParentRef: 5, ParentSeq: 5}}})
				}
				data = mftgen.Build(files)
				expected = (len(files)) * 4
			} else {
				name = "$J"
				var rows []mftgen.UsnEntry
				for i := 0; i < 1300; i++ {
					rows = append(rows, mftgen.UsnEntry{FileRecord: 64, FileSequence: 1, ParentRecord: 5, ParentSeq: 5, Usn: uint64(i + 1), Timestamp: at, Reason: 0x100, FileName: "same.txt"})
				}
				data = mftgen.BuildUsnJournal(0, rows)
				expected = len(rows)
			}
			for pass := 0; pass < 2; pass++ {
				root := t.TempDir()
				if err = os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(root, "note.txt"), []byte(fmt.Sprint(pass)), 0600); err != nil {
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
					wantNew := expected
					if pass == 1 {
						wantNew = 0
					}
					if len(result.ParseFailures) != 0 || result.EventCount != expected || result.NewEventCount != wantNew || result.DuplicateEventCount != expected-wantNew {
						t.Fatalf("pass %d count %d new %d duplicate %d expected %d failures %+v", pass, result.EventCount, result.NewEventCount, result.DuplicateEventCount, expected, result.ParseFailures)
					}
					stored, err := svc.store.GetSourceFile(sf.ID)
					if err != nil || stored.ParseCoverage == nil || stored.ParseCoverage.RecordsFailed != 0 {
						t.Fatal("coverage", stored, err)
					}
					observations, err := svc.store.ListEventObservationsBySourceFile(sf.ID)
					if err != nil || len(observations) != expected {
						t.Fatal("observation count", len(observations), err)
					}
				}
			}
		})
	}
}
