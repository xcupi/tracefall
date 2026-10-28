package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"tracefall/internal/model"
)

// A fixed synthetic production-boundary oracle, also run against the frozen base.
func citedFixture(t *testing.T) (*Service, string, time.Time) {
	t.Helper()
	s := newTestService(t)
	now := time.Date(2025, 2, 3, 4, 5, 6, 0, time.UTC)
	for _, id := range []string{"report-case", "other-case"} {
		if err := s.store.CreateCase(model.Case{ID: id, Name: id, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
		col := model.Collection{ID: id + "-collection", CaseID: id, SourceType: model.SourceTypeUpload, OriginalFilename: "collection.zip", CreatedAt: now}
		sf := model.SourceFile{ID: id + "-source", CaseID: id, CollectionID: col.ID, Path: "events.txt", ImportStatus: model.SourceFileImported}
		if err := s.store.CreateCollectionWithSourceFiles(col, []model.SourceFile{sf}); err != nil {
			t.Fatal(err)
		}
	}
	events := []model.Event{}
	ids := []string{}
	for i := 0; i < 520; i++ {
		id := fmt.Sprintf("event-%03d", i)
		ts := now.Add(time.Duration(520-i) * time.Second)
		if i%17 == 0 {
			ts = time.Time{}
		}
		events = append(events, model.Event{ID: id, CaseID: "report-case", CollectionID: "report-case-collection", SourceFileID: "report-case-source", DedupHash: id, Timestamp: ts, EventType: model.EventProcessCreate, ArtifactType: model.ArtifactWindowsEventLog, Host: fmt.Sprintf("host-%d", i%3), User: fmt.Sprintf("user-%d", i%4), SourceReference: id, CommandLine: "echo <tag>&\"quoted\"", Extra: map[string]string{"raw": "<>&\u2028\u2029\n\x00", "record": id}})
		ids = append(ids, id)
	}
	events = append(events, model.Event{ID: "foreign", CaseID: "other-case", CollectionID: "other-case-collection", SourceFileID: "other-case-source", DedupHash: "foreign", CommandLine: "FOREIGN-PRIVATE-CONTENT"})
	if err := s.store.SaveEvents(events); err != nil {
		t.Fatal(err)
	}
	// Repeated ids inside and across IN chunks; unresolved and whitespace tokens.
	ids = append(ids, "event-000", "event-000", "event-519", "missing", "foreign", " event-002 ", " ")
	if err := s.store.SaveFindings([]model.Finding{{ID: "finding", CaseID: "report-case", RuleID: "retired-fixture", SupportingEvents: []string{"event-519", "event-001", "missing", "foreign"}, FirstSeen: now, LastSeen: now, CreatedAt: now}}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SaveCorrelations([]model.Correlation{{ID: "correlation", CaseID: "report-case", EventIDs: ids, FirstSeen: now, LastSeen: now}}); err != nil {
		t.Fatal(err)
	}
	return s, "report-case", now
}

func citedFileBytes(t *testing.T, data []byte, path string) []byte {
	t.Helper()
	if path == "" {
		return data
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReport_CitedBytesOracle(t *testing.T) {
	s, id, now := citedFixture(t)
	fs, _ := s.store.ListFindings(id)
	cs, _ := s.store.ListCorrelations(id)
	ids := findingEventIDs(fs)
	for _, c := range cs {
		ids = append(ids, c.EventIDs...)
	}
	old, err := s.store.EventsByIDs(ids)
	if err != nil {
		t.Fatal(err)
	}
	resolved := make([]model.Event, 0, len(old))
	for _, e := range old {
		if e.CaseID == id {
			resolved = append(resolved, e)
		}
	}
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].ID < resolved[j].ID })
	want, err := json.MarshalIndent(resolved, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.buildReport(id, now)
	if err != nil {
		t.Fatal(err)
	}
	defer b.release()
	for _, f := range b.Files {
		if f.Name == "cited-events.json" {
			got := citedFileBytes(t, f.Data, f.Path)
			if !bytes.Equal(got, want) {
				t.Fatal("cited bytes differ from old 500-ID multiset contract")
			}
		}
	}
	if bytes.Contains(b.HTML, []byte("FOREIGN-PRIVATE-CONTENT")) {
		t.Fatal("cross-case privacy leak")
	}
	if dir := os.Getenv("TF_CITED_ORACLE_OUT"); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, f := range b.Files {
			if err := os.WriteFile(filepath.Join(dir, f.Name), citedFileBytes(t, f.Data, f.Path), 0600); err != nil {
				t.Fatal(err)
			}
		}
		for name, data := range map[string][]byte{"report.html": b.HTML, "manifest.json": b.ManifestJSON} {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		data, err := json.MarshalIndent(b.Data, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "data.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "report.zip")
		if _, _, err := writeBundleFile(path, now, b); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReport_CitedAttachmentIsSpooled(t *testing.T) {
	s, id, now := citedFixture(t)
	b, err := s.buildReport(id, now)
	if err != nil {
		t.Fatal(err)
	}
	defer b.release()
	for _, f := range b.Files {
		if f.Name == "cited-events.json" {
			if f.Path == "" || len(f.Data) != 0 {
				t.Fatal("cited-events must be disk spooled, not a retained whole JSON array")
			}
			return
		}
	}
	t.Fatal("missing cited attachment")
}
