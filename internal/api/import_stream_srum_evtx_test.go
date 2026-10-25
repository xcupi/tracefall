package api

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
	"tracefall/internal/ese/esegen"
	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/ingest"
)

// Exercise real isolation, identity stamping, spool, enrichment and persistence
// for records that tie on time but have distinct source-record identities.
func TestSRUMEVTXStreamIsolatedPersistence(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ingest.SetParserRunner(ingest.Subprocess{Exe: exe, Sandbox: ingest.FindSandbox()})
	defer ingest.SetParserRunner(nil)
	for _, kind := range []string{"srum", "evtx"} {
		t.Run(kind, func(t *testing.T) {
			svc := newTestService(t)
			c, err := svc.CreateCase("bounded stream", "")
			if err != nil {
				t.Fatal(err)
			}
			const count = 1300
			name := "SRUDB.dat"
			var data []byte
			if kind == "srum" {
				rows := make([]esegen.Record, count)
				for i := range rows {
					rows[i] = esegen.Record{Fixed: map[uint32][]byte{1: esegen.Le32(uint32(i + 1))}}
				}
				data = esegen.Build([]esegen.Table{{Name: "SruDbIdMapTable", Columns: []esegen.Column{{ID: 1, Name: "IdIndex", Type: esegen.Int32}}}, {Name: "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}", Columns: []esegen.Column{{ID: 1, Name: "AutoIncId", Type: esegen.Int32}}, Records: rows, LeafCapacity: 16}}, esegen.Options{})
			} else {
				name = "events.evtx"
				rows := make([]evtxgen.Event, count)
				for i := range rows {
					rows[i] = evtxgen.Event{RecordID: uint64(i + 1), Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security", Computer: "host01", EventID: 4624, Data: map[string]string{"TargetUserName": "alice"}}
				}
				data = evtxgen.Build(rows)
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
					wantNew := count
					if pass == 1 {
						wantNew = 0
					}
					if len(result.ParseFailures) != 0 || result.EventCount != count || result.NewEventCount != wantNew || result.DuplicateEventCount != count-wantNew {
						t.Fatalf("pass %d: %+v", pass, result)
					}
					stored, err := svc.store.GetSourceFile(sf.ID)
					if err != nil || stored.ParseCoverage == nil || stored.ParseCoverage.Mapped != count || stored.ParseCoverage.RecordsFailed != 0 {
						t.Fatal("coverage", stored, err)
					}
					observations, err := svc.store.ListEventObservationsBySourceFile(sf.ID)
					if err != nil || len(observations) != count {
						t.Fatal("observations", len(observations), err)
					}
				}
			}
		})
	}
}
