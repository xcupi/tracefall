package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/narrative"
)

// Normalized synthetic persistence/HTTP proof, not native-reader validation.
func TestReport_MetadataCoveragePersistenceAndReview(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	c := mustCreateCase(t, mux, "Synthetic coverage")
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	col := model.Collection{ID: "col01", CaseID: c.ID, CreatedAt: now, SourceType: model.SourceTypeDiskImage, ArchiveHash: "synthetic", EvidenceDirectory: "synthetic"}
	if err := svc.store.SaveCollection(col); err != nil {
		t.Fatal(err)
	}
	historical := []string{
		`{"hive_replay":{"state":"clean"}}`,
		`{"hive_replay":{"state":"not_recoverable","reason":"sequence gap"},"notes":["registry recovery incomplete"]}`,
		`{"hive_replay":{"state":"replayed","logs_applied":["SYSTEM.LOG1"]}}`,
		`{}`, `{"emitted_events":0,"notes":["explicit zero"]}`,
		`{"records_read":3,"mapped":2,"unmapped":1}`, `null`,
		`{"notes":["reader caveat"]}`,
	}
	var rows []model.SourceFile
	for i, raw := range historical {
		var cov *model.ParseCoverage
		if err := json.Unmarshal([]byte(raw), &cov); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, model.SourceFile{ID: fmt.Sprintf("s%d", i), SHA256: fmt.Sprintf("%064x", i+1), CaseID: c.ID, CollectionID: col.ID, Path: fmt.Sprintf("vol1/hive%d", i), ArtifactType: model.ArtifactRegistryHive, Supported: true, ImportStatus: model.SourceFileImported, DiscoveredAt: now, ParseCoverage: cov})
	}
	if err := svc.store.SaveSourceFiles(rows); err != nil {
		t.Fatal(err)
	}
	raw := model.RawEvidence{ID: "raw01", CaseID: c.ID, SourceFileID: "s1", SourceReference: "key:1", Raw: `literal registry value: 00ff; no inferred execution`}
	if err := svc.store.SaveRawEvidence([]model.RawEvidence{raw}); err != nil {
		t.Fatal(err)
	}
	event := model.Event{ID: "e1", CaseID: c.ID, CollectionID: col.ID, SourceFileID: "s1", RawEvidenceID: raw.ID, SourceReference: raw.SourceReference, ArtifactType: model.ArtifactRegistryHive, EventType: "registry_value", Extra: map[string]string{"hive_state": "not_recoverable", "hive_recovery": "sequence gap"}}
	if err := svc.store.SaveEvents([]model.Event{event}); err != nil {
		t.Fatal(err)
	}
	storedEvent, err := svc.store.GetEvent(event.ID)
	if err != nil {
		t.Fatal(err)
	}
	before, err := svc.store.ListSourceFiles(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := svc.store.FreezeReviewSnapshot(context.Background(), c.ID, "run01")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Coverage.ParseCoverageNotRecorded != 5 || snap.SourceParseGaps != 1 {
		t.Fatalf("snapshot coverage=%+v gaps=%d", snap.Coverage, snap.SourceParseGaps)
	}
	input := narrative.ReviewInput{CaseID: c.ID, Sources: before, Events: []model.Event{storedEvent}}
	packet, err := narrative.PrepareReview(input)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Coverage.ParseCoverageNotRecorded != 5 {
		t.Fatalf("review coverage=%+v", packet.Coverage)
	}
	if strings.Count(packet.User, "parse_coverage=not_recorded") != 5 {
		t.Fatal(packet.User)
	}
	if strings.Count(packet.User, "parse_coverage=recorded records_read=0") != 2 || !strings.Contains(packet.User, "records_read=3 mapped=2 unmapped=1") {
		t.Fatal(packet.User)
	}
	for i := range rows {
		got, err := svc.store.GetSourceFile(rows[i].ID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.ParseCoverage, rows[i].ParseCoverage) {
			t.Fatalf("coverage changed: %+v", got)
		}
	}
	var page EvidenceFilePage
	listing := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+col.ID+"/files?page=1&page_size=50", nil, &page)
	if listing.Code != http.StatusOK || len(page.Items) != len(rows) {
		t.Fatalf("source API HTTP=%d rows=%d", listing.Code, len(page.Items))
	}
	for _, item := range page.Items {
		var want *model.ParseCoverage
		found := false
		for _, row := range rows {
			if row.ID == item.ID {
				want = row.ParseCoverage
				found = true
				break
			}
		}
		if !found || !reflect.DeepEqual(item.ParseCoverage, want) {
			t.Fatalf("source API changed coverage for %s: %+v", item.ID, item.ParseCoverage)
		}
	}
	server := httptest.NewServer(mux)
	defer server.Close()
	url := server.URL + "/api/cases/" + c.ID + "/report.html"
	response, err := server.Client().Get(url)
	if err != nil {
		t.Fatal(err)
	}
	html, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("report HTTP=%d error=%v", response.StatusCode, err)
	}
	address := server.Listener.Addr().String()
	server.Close()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("owned HTTP report listener left open")
	}
	t.Logf("compiled synthetic HTTP report %s returned 200; listener %s verified closed", url, address)
	for _, want := range []string{"not_recoverable", "replayed", "registry recovery incomplete", "reader caveat", "read=3 mapped=2 unmapped=1"} {
		if !strings.Contains(string(html), want) {
			t.Errorf("report lost %q", want)
		}
	}
	after, err := svc.store.ListSourceFiles(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("report mutated exact stored source inputs")
	}
	n, err := svc.store.CountEvents(c.ID)
	if err != nil || n != 1 {
		t.Fatalf("stored event count changed: %d %v", n, err)
	}
	afterEvent, err := svc.store.GetEvent(event.ID)
	if err != nil || !reflect.DeepEqual(storedEvent, afterEvent) {
		t.Fatalf("event changed: %+v %v", afterEvent, err)
	}
	afterRaw, err := svc.store.GetRawEvidence(raw.ID)
	if err != nil || !reflect.DeepEqual(raw, afterRaw) {
		t.Fatalf("raw evidence changed: %+v %v", afterRaw, err)
	}
	t.Log("synthetic report HTTP 200; historical coverage retained; store/review not_recorded=5; recorded-zero=2; measured read=3 mapped=2 unmapped=1; report caveats retained; report metadata-zero presentation remains a separate unclosed gate")
}
