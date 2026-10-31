package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
	"tracefall/internal/casefiles"
	"tracefall/internal/store"

	"tracefall/internal/model"
)

func investigationCacheFixture(t *testing.T) (*Service, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "context.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := NewService(db, casefiles.NewStore(t.TempDir()))
	id := "context-case"
	now := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	if e := s.store.CreateCase(model.Case{ID: id, Name: id, CreatedAt: now, UpdatedAt: now}); e != nil {
		t.Fatal(e)
	}
	col := model.Collection{ID: "col", CaseID: id, CreatedAt: now}
	sf := model.SourceFile{ID: "src", CaseID: id, CollectionID: col.ID, Path: "synthetic.txt"}
	if e := s.store.CreateCollectionWithSourceFiles(col, []model.SourceFile{sf}); e != nil {
		t.Fatal(e)
	}
	if e := s.store.SaveEvents([]model.Event{{ID: "e", CaseID: id, CollectionID: col.ID, SourceFileID: sf.ID, DedupHash: "e", Timestamp: now, EventType: model.EventProcessCreate, ArtifactType: model.ArtifactWindowsEventLog, Host: "host01", User: "alice", ProcessName: "shell.exe"}}); e != nil {
		t.Fatal(e)
	}
	if e := s.store.SaveFindings([]model.Finding{{ID: "f", CaseID: id, RuleID: "powershell-encoded-command", Title: "Recorded execution", Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, SupportingEvents: []string{"e"}, FirstSeen: now, LastSeen: now, CreatedAt: now}}); e != nil {
		t.Fatal(e)
	}
	return s, id, path
}

func TestInvestigationContextDetailReuse(t *testing.T) {
	s, id, _ := investigationCacheFixture(t)
	invs, e := s.Investigations(id)
	if e != nil || len(invs) != 1 {
		t.Fatalf("fixture investigations=%d err=%v", len(invs), e)
	}
	first, e := s.Investigation(id, invs[0].ID)
	if e != nil {
		t.Fatal(e)
	}
	if s.investigationModels == nil || len(s.investigationModels.models) == 0 {
		t.Fatal("detail did not retain reusable investigation models")
	}
	second, e := s.WithRequest(context.Background()).Investigation(id, invs[0].ID)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Fatal("warm detail JSON differs from cold")
	}
}

func TestInvestigationContextDetailCancellation(t *testing.T) {
	s, id, _ := investigationCacheFixture(t)
	invs, e := s.Investigations(id)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = s.WithRequest(ctx).Investigation(id, invs[0].ID)
	if e != context.Canceled {
		t.Fatalf("cancelled detail err=%v", e)
	}
}

func assertInvestigationContextFresh(t *testing.T, s *Service, id string) InvestigationDetail {
	t.Helper()
	ref, e := s.investigationsFromAllEvents(id)
	if e != nil || len(ref) != 1 {
		t.Fatalf("reference count=%d err=%v", len(ref), e)
	}
	got, e := s.Investigation(id, ref[0].ID)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := json.Marshal(ref[0])
	b, _ := json.Marshal(got.Investigation)
	if string(a) != string(b) {
		t.Fatal("cached model differs from full-event reference")
	}
	cold := *s
	cold.investigationModels = &investigationModelCache{}
	want, e := cold.Investigation(id, ref[0].ID)
	if e != nil {
		t.Fatal(e)
	}
	a, _ = json.Marshal(want)
	b, _ = json.Marshal(got)
	if string(a) != string(b) {
		t.Fatal("cached detail differs from fresh detail")
	}
	return got
}

func TestInvestigationContextInvalidation(t *testing.T) {
	s, id, path := investigationCacheFixture(t)
	first := assertInvestigationContextFresh(t, s, id)
	ext, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer ext.Close()
	exec := func(q string) {
		t.Helper()
		if _, e := ext.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	exec(`UPDATE events SET host='host02', user='carol', extra_json='{"domain":"example.test","os_current_build":"200"}' WHERE id='e'`)
	next := assertInvestigationContextFresh(t, s, id)
	if len(next.Hosts) != 1 || next.Hosts[0] != "host02" || next.Hosts[0] == first.Hosts[0] {
		t.Fatal("same-count event/identity update stale")
	}
	exec(`UPDATE findings SET severity='low', title='Changed recorded execution', techniques_json='["T1059"]' WHERE id='f'`)
	next = assertInvestigationContextFresh(t, s, id)
	if next.FindingDetails[0].Title != "Changed recorded execution" {
		t.Fatal("finding update stale")
	}
	if e = s.store.SaveCorrelations([]model.Correlation{{ID: "r", CaseID: id, Type: model.CorrelationActivityChain, Title: "Recorded association", EventIDs: []string{"e"}}}); e != nil {
		t.Fatal(e)
	}
	next = assertInvestigationContextFresh(t, s, id)
	if len(next.CorrelationDetails) != 1 {
		t.Fatal("correlation insertion stale")
	}
	exec(`UPDATE correlations SET title='Changed association', description='Recorded description' WHERE id='r'`)
	next = assertInvestigationContextFresh(t, s, id)
	if next.CorrelationDetails[0].Title != "Changed association" {
		t.Fatal("same-count correlation update stale")
	}
	if e = s.store.ClearAnalysis(id); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Investigation(id, first.ID); e == nil {
		t.Fatal("analysis removal retained old detail")
	}
	if e = s.store.SaveFindings([]model.Finding{{ID: "f", CaseID: id, RuleID: "powershell-encoded-command", SupportingEvents: []string{"e"}, Title: "Reanalysis", Severity: model.SeverityMedium}}); e != nil {
		t.Fatal(e)
	}
	next = assertInvestigationContextFresh(t, s, id)
	if next.FindingDetails[0].Title != "Reanalysis" {
		t.Fatal("reanalysis stale")
	}
	if e = s.store.SaveFindings([]model.Finding{{ID: "rolled-back", CaseID: id}, {ID: "f", CaseID: id}}); e == nil {
		t.Fatal("expected duplicate rollback")
	}
	next = assertInvestigationContextFresh(t, s, id)
	if len(next.FindingDetails) != 1 {
		t.Fatal("rolled back row escaped")
	}
	if e = s.store.DeleteCase(id); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Investigation(id, first.ID); e == nil {
		t.Fatal("deleted case retained old detail")
	}
	if e = s.store.CreateCase(model.Case{ID: id, Name: id}); e != nil {
		t.Fatal(e)
	}
	if e = s.store.SaveFindings([]model.Finding{{ID: "f", CaseID: id, RuleID: "powershell-encoded-command", Title: "Recreated", SupportingEvents: []string{"e"}, Severity: model.SeverityLow}}); e != nil {
		t.Fatal(e)
	}
	next = assertInvestigationContextFresh(t, s, id)
	if next.FindingDetails[0].Title != "Recreated" || len(next.EventDetails) != 0 {
		t.Fatal("recreated case retained old context")
	}
}

func TestInvestigationContextHTTPHonorsCancellation(t *testing.T) {
	s, id, _ := investigationCacheFixture(t)
	invs, e := s.Investigations(id)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodGet, "/api/cases/"+id+"/investigations/"+invs[0].ID, nil).WithContext(ctx)
	response := httptest.NewRecorder()
	routerFor(s).ServeHTTP(response, request)
	if response.Code == http.StatusOK || len(s.investigationModels.models) != 0 {
		t.Fatal("HTTP cancellation did not reach detail computation")
	}
}

func TestInvestigationContextReopenedStore(t *testing.T) {
	s, id, path := investigationCacheFixture(t)
	assertInvestigationContextFresh(t, s, id)
	if e := s.store.Close(); e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(`UPDATE events SET host='host03' WHERE id='e'`); e != nil {
		t.Fatal(e)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	replacement, e := store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer replacement.Close()
	s.store = replacement
	got := assertInvestigationContextFresh(t, s, id)
	if len(got.Hosts) != 1 || got.Hosts[0] != "host03" {
		t.Fatal("reopened database used old models")
	}
}

func TestInvestigationContextCaseIsolation(t *testing.T) {
	s, id, _ := investigationCacheFixture(t)
	first := assertInvestigationContextFresh(t, s, id)
	other := "other-context-case"
	if e := s.store.CreateCase(model.Case{ID: other, Name: other}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Investigation(other, first.ID); e == nil {
		t.Fatal("cross-case detail resolved")
	}
	assertInvestigationContextFresh(t, s, id)
}

func TestInvestigationContextMutationDuringBuild(t *testing.T) {
	s, id, _ := investigationCacheFixture(t)
	_, e := s.investigationModels.get(context.Background(), id, s.store.ChangeToken, func() ([]model.Investigation, error) {
		models, e := s.Investigations(id)
		if e != nil {
			return nil, e
		}
		return models, s.store.ClearAnalysis(id)
	})
	if e != nil {
		t.Fatal(e)
	}
	if len(s.investigationModels.models) != 0 {
		t.Fatal("mixed-revision computation published")
	}
}

func TestInvestigationContextConcurrentDetails(t *testing.T) {
	s, id, _ := investigationCacheFixture(t)
	invs, e := s.Investigations(id)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, e := s.WithRequest(context.Background()).Investigation(id, invs[0].ID)
			if e != nil {
				t.Error(e)
				return
			}
			if len(d.Hosts) != 1 || d.Hosts[0] != "host01" {
				t.Error("shared detail mutated")
			}
			if len(d.EventIDs) > 0 {
				d.EventIDs[0] = "local"
			}
			d.Hosts[0] = "local"
		}()
	}
	wg.Wait()
	assertInvestigationContextFresh(t, s, id)
}
