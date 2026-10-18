package api

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"tracefall/internal/model"
)

// Characterization for CollectionDetail's event-derived summary (hosts,
// time range, undated count). It pins the behavior the UI relies on, on data
// built so a wrong implementation fails visibly:
//   - an empty host is not a host, and duplicate hosts appear once, sorted;
//   - zero-timestamp (undated) events are counted, never ranged;
//   - a whole-second timestamp and a fractional one that sort differently as
//     text must still order by time (10:00:00Z is earlier than 10:00:00.5Z).
func TestCollectionDetail_SummaryFromEvents(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	c := createTestCase(t, mux, "Summary characterization")

	col := model.Collection{
		ID: "11111111-2222-4333-8444-555555555555", CaseID: c.ID,
		SourceType: model.SourceTypeDiskImage, IngestionStatus: model.CollectionStatusPending,
	}
	sf := model.SourceFile{
		ID: "sf-1", CaseID: c.ID, CollectionID: col.ID, OriginalFilename: "Security.evtx",
		Path: "vol1/Windows/System32/winevt/Logs/Security.evtx", ImportStatus: model.SourceFileImported,
		Supported: true, Parser: "evtx@1", ArtifactType: "windows_event_log",
	}
	if err := svc.store.CreateCollectionWithSourceFiles(col, []model.SourceFile{sf}); err != nil {
		t.Fatalf("create collection: %v", err)
	}

	at := func(s string) time.Time {
		t.Helper()
		v, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatal(err)
		}
		return v.UTC()
	}
	mk := func(id, host string, ts time.Time) model.Event {
		return model.Event{
			ID: id, CaseID: c.ID, CollectionID: col.ID, SourceFileID: sf.ID, Timestamp: ts, Host: host,
			EventType: "test", DedupHash: "dedup-" + id,
		}
	}
	events := []model.Event{
		mk("ev-a", "WKSTN-B", at("2024-01-02T10:00:00Z")),
		mk("ev-b", "", at("2024-01-02T10:00:00.5Z")),
		mk("ev-c", "WKSTN-A", at("2024-01-03T00:00:00Z")),
		mk("ev-u1", "WKSTN-A", time.Time{}),
		mk("ev-u2", "", time.Time{}),
		mk("ev-d", "WKSTN-B", at("2024-01-02T11:30:00Z")),
	}
	if err := svc.store.SaveEvents(events); err != nil {
		t.Fatalf("save events: %v", err)
	}

	detail, err := svc.CollectionDetail(c.ID, col.ID)
	if err != nil {
		t.Fatalf("CollectionDetail: %v", err)
	}
	if want := []string{"WKSTN-A", "WKSTN-B"}; len(detail.HostsObserved) != len(want) ||
		detail.HostsObserved[0] != want[0] || detail.HostsObserved[1] != want[1] {
		t.Errorf("hosts_observed = %v, want %v", detail.HostsObserved, want)
	}
	if detail.UndatedEvents != 2 {
		t.Errorf("undated_events = %d, want 2", detail.UndatedEvents)
	}
	if detail.EarliestEvent == nil || !detail.EarliestEvent.Equal(at("2024-01-02T10:00:00Z")) {
		t.Errorf("earliest_event = %v, want 2024-01-02T10:00:00Z (whole second is earlier than .5)", detail.EarliestEvent)
	}
	if detail.LatestEvent == nil || !detail.LatestEvent.Equal(at("2024-01-03T00:00:00Z")) {
		t.Errorf("latest_event = %v, want 2024-01-03T00:00:00Z", detail.LatestEvent)
	}
}

// Keeps the HTTP contract honest for the same collection: the detail still
// answers 200 and carries the summary fields the UI reads.
func TestCollectionDetail_HTTPCarriesTheSummary(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	c := createTestCase(t, mux, "Summary HTTP")
	col := model.Collection{
		ID: "66666666-7777-4888-8999-000000000000", CaseID: c.ID,
		SourceType: model.SourceTypeDiskImage, IngestionStatus: model.CollectionStatusPending,
	}
	if err := svc.store.CreateCollectionWithSourceFiles(col, nil); err != nil {
		t.Fatal(err)
	}
	var detail CollectionDetail
	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+col.ID, nil, &detail)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	if detail.HostsObserved == nil {
		t.Error("hosts_observed must be an array, not null, for an empty collection")
	}
}

// collectionFileList reads a collection's whole file list through the paged
// endpoint, the way the UI does, following every page. Tests use it wherever
// they used to read CollectionDetail.SourceFiles.
func collectionFileList(t *testing.T, mux http.Handler, caseID, collectionID string) []TriagedSourceFile {
	t.Helper()
	var out []TriagedSourceFile
	for page := 1; ; page++ {
		var pg EvidenceFilePage
		url := "/api/cases/" + caseID + "/evidence/" + collectionID + "/files?page=" + strconv.Itoa(page) + "&page_size=250"
		rec := doJSON(t, mux, "GET", url, nil, &pg)
		if rec.Code != http.StatusOK {
			t.Fatalf("list files page %d: status %d, body %s", page, rec.Code, rec.Body.String())
		}
		out = append(out, pg.Items...)
		if page >= pg.TotalPages || pg.TotalPages == 0 {
			return out
		}
	}
}
