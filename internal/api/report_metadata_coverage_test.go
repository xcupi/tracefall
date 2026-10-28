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
		`{"companion_of":"SYSTEM"}`,
	}
	var rows []model.SourceFile
	for i, raw := range historical {
		var cov *model.ParseCoverage
		if err := json.Unmarshal([]byte(raw), &cov); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, model.SourceFile{ID: fmt.Sprintf("s%d", i), SHA256: fmt.Sprintf("%064x", i+1), CaseID: c.ID, CollectionID: col.ID, Path: fmt.Sprintf("vol1/hive%d", i), ArtifactType: model.ArtifactRegistryHive, Supported: true, ImportStatus: model.SourceFileImported, DiscoveredAt: now, ParseCoverage: cov})
	}
	rows[len(rows)-1].ArtifactType = model.ArtifactRegistryTransactionLog
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
	if snap.Coverage.ParseCoverageNotRecorded != 6 || snap.SourceParseGaps != 1 {
		t.Fatalf("snapshot coverage=%+v gaps=%d", snap.Coverage, snap.SourceParseGaps)
	}
	input := narrative.ReviewInput{CaseID: c.ID, Sources: before, Events: []model.Event{storedEvent}}
	packet, err := narrative.PrepareReview(input)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Coverage.ParseCoverageNotRecorded != 6 {
		t.Fatalf("review coverage=%+v", packet.Coverage)
	}
	if strings.Count(packet.User, "parse_coverage=not_recorded") != 6 {
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
	var apiRows []model.SourceFile
	for _, item := range page.Items {
		apiRows = append(apiRows, item.SourceFile)
	}
	assertCoverageUI(t, apiRows)
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
	if strings.Count(string(html), "parse coverage: not recorded") != 4 {
		t.Errorf("HTML lost metadata-only diagnostics")
	}
	if strings.Count(string(html), "read=0 mapped=0") != 2 {
		t.Errorf("HTML fabricated/lost measured zero diagnostics")
	}
	for _, want := range []string{"hive_replay=clean", "hive_replay=replayed", "hive_replay=not_recoverable", "notes_present=true"} {
		if !strings.Contains(packet.User, want) {
			t.Errorf("packet lost %q", want)
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
	// Successful synthetic model responses must not turn unknown source
	// measurements into a complete case review. This exercises terminal
	// runner classification, not only the snapshot's counters.
	stub := newLLMStub(t, svc, true)
	stub.answer = func(string) (int, string) { return 200, chatBody("Coverage is bounded. [K1]") }
	plan, err := svc.PlanReviewBatches(c.ID, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Snapshot.Coverage.ParseCoverageNotRecorded != 6 || plan.Snapshot.SourceParseGaps != 1 || stub.count() != 0 {
		t.Fatalf("plan coverage=%+v sends=%d", plan.Snapshot, stub.count())
	}
	if _, err := svc.StartReviewBatches(c.ID, plan.ID, plan.PlanKey, false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		plan, err = svc.readBatchPlan(c.ID, plan.ID)
		if err != nil {
			t.Fatal(err)
		}
		svc.batches.mu.Lock()
		active := svc.batches.runs[c.ID] != nil
		svc.batches.mu.Unlock()
		if plan.State != "running" && !active {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if plan.State != "partial" || stub.count() == 0 {
		t.Fatalf("unknown metrics falsely complete or provider failed: state=%s reason=%s sends=%d", plan.State, plan.Reason, stub.count())
	}
	packets, err := svc.store.BatchPackets(c.ID, plan.ID, -1, 20)
	if err != nil {
		t.Fatal(err)
	}
	succeeded := 0
	for _, raw := range packets {
		var p ReviewBatchPacket
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		if p.State == "succeeded" {
			succeeded++
		} else if p.State == "failed" {
			t.Fatalf("synthetic provider packet failed: %s", p.Error)
		}
	}
	if succeeded == 0 {
		t.Fatal("no successful packets")
	}
	t.Logf("mixed metadata terminal review state=%s, successful packets=%d; not_recorded=%d numeric gaps=%d", plan.State, succeeded, plan.Snapshot.Coverage.ParseCoverageNotRecorded, plan.Snapshot.SourceParseGaps)
	t.Log("synthetic report HTTP 200; historical coverage retained; store/review not_recorded=6; recorded-zero=2; measured read=3 mapped=2 unmapped=1; report, packet and all four UI consumers retain metadata caveats without fabricated zero")
}
