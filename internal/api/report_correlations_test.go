package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/report"
)

func TestReport_CorrelationOnlyEvidenceIsLoadedAndRendered(t *testing.T) {
	svc := newTestService(t)
	c := mustCreateCase(t, routerFor(svc), "Correlated activity")
	col := model.Collection{ID: "clock-collection", CaseID: c.ID, SourceType: model.SourceTypeUpload, OriginalFilename: "traffic.zip"}
	sf := model.SourceFile{ID: "clock-source", CaseID: c.ID, CollectionID: col.ID, Path: "traffic.pcap", ArtifactType: model.ArtifactNetworkCapture, ImportStatus: model.SourceFileImported}
	if err := svc.store.CreateCollectionWithSourceFiles(col, []model.SourceFile{sf}); err != nil {
		t.Fatal(err)
	}
	ev := model.Event{ID: "correlation-only-event", CaseID: c.ID, CollectionID: col.ID, SourceFileID: sf.ID, ArtifactType: model.ArtifactNetworkCapture, DedupHash: "clock-dedup", EventType: model.EventClockObservation,
		SourceReference: "clock:1", NetworkSource: "203.0.113.5", Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Extra: map[string]string{"subject_ip": "203.0.113.5", "observed_utc": "2025-01-01T01:00:00Z", "capture_utc": "2025-01-01T00:00:00Z"}}
	if err := svc.store.SaveEvents([]model.Event{ev}); err != nil {
		t.Fatal(err)
	}
	cor := model.Correlation{ID: "clock-link", CaseID: c.ID, Type: model.CorrelationClockSkew, Title: "Clock offset estimate", Description: "The capture clock differs from the subject clock.", EventIDs: []string{ev.ID}, FirstSeen: ev.Timestamp, LastSeen: ev.Timestamp}
	if err := svc.store.SaveCorrelations([]model.Correlation{cor}); err != nil {
		t.Fatal(err)
	}
	b, err := svc.buildReport(c.ID, ev.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	defer b.release()
	for _, want := range []string{"6. Correlated activity", cor.Title, cor.Description, ev.ID, ev.SourceReference} {
		if !strings.Contains(string(b.HTML), want) {
			t.Errorf("report omits %q", want)
		}
	}
	if len(b.Data.Timeline.Key) != 1 {
		t.Errorf("correlation-only key evidence lost: %+v", b.Data.Timeline.Key)
	}
	var found bool
	for _, f := range b.Files {
		if f.Name != "correlations.json" {
			continue
		}
		found = true
		var got []model.Correlation
		if err := json.Unmarshal(citedFileBytes(t, f.Data, f.Path), &got); err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || len(got[0].EventIDs) != 1 || got[0].EventIDs[0] != ev.ID {
			t.Fatalf("attachment loses references: %+v", got)
		}
	}
	if !found {
		t.Error("bundle lacks the full correlations.json reference list")
	}
}

func TestReport_BundleRetainsObservationDetailsPastBothHTMLCaps(t *testing.T) {
	svc := newTestService(t)
	c := mustCreateCase(t, routerFor(svc), "Long correlation")
	col := model.Collection{ID: "long-collection", CaseID: c.ID, SourceType: model.SourceTypeUpload, OriginalFilename: "traffic.zip"}
	sf := model.SourceFile{ID: "long-source", CaseID: c.ID, CollectionID: col.ID, Path: "traffic.pcap", ArtifactType: model.ArtifactNetworkCapture, ImportStatus: model.SourceFileImported}
	if err := svc.store.CreateCollectionWithSourceFiles(col, []model.SourceFile{sf}); err != nil {
		t.Fatal(err)
	}
	var events []model.Event
	var ids []string
	for i := 0; i < 301; i++ {
		id := fmt.Sprintf("long-event-%03d", i)
		ids = append(ids, id)
		events = append(events, model.Event{ID: id, CaseID: c.ID, CollectionID: col.ID, SourceFileID: sf.ID, DedupHash: id, Timestamp: time.Date(2025, 1, 1, 0, 0, i, 0, time.UTC), EventType: model.EventWebRequest, ArtifactType: model.ArtifactNetworkCapture, SourceReference: fmt.Sprintf("http:%d", i+1), Extra: map[string]string{"uri": fmt.Sprintf("/object-%d", i), "response_sha256": strings.Repeat("cd", 32)}})
	}
	if err := svc.store.SaveEvents(events); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.SaveCorrelations([]model.Correlation{{ID: "long-correlation", CaseID: c.ID, EventIDs: ids}}); err != nil {
		t.Fatal(err)
	}
	b, err := svc.buildReport(c.ID, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	defer b.release()
	if bytes.Contains(b.HTML, []byte("long-event-300")) {
		t.Fatal("fixture did not exercise HTML omission")
	}
	for _, f := range b.Files {
		if f.Name != "cited-events.json" {
			continue
		}
		var got []model.Event
		if err := json.Unmarshal(citedFileBytes(t, f.Data, f.Path), &got); err != nil {
			t.Fatal(err)
		}
		if len(got) != 301 || got[300].ID != "long-event-300" || got[300].SourceReference != "http:301" || got[300].Extra["uri"] != "/object-300" || got[300].Extra["response_sha256"] != strings.Repeat("cd", 32) {
			t.Fatal("omitted evidence loses its original fields")
		}
		return
	}
	t.Fatal("no cited-events.json attachment")
}

func TestReport_UnresolvedEvidenceIsNotCalledAnOmittedEvent(t *testing.T) {
	svc := newTestService(t)
	c := model.Case{ID: "case-one"}
	events := []model.Event{{ID: "foreign", CaseID: "other-case", CommandLine: "PRIVATE-FOREIGN-CONTENT"}}
	var ids []string
	for i := 0; i < 12; i++ {
		id := fmt.Sprintf("e-%02d", i)
		ids = append(ids, id)
		events = append(events, model.Event{ID: id, CaseID: c.ID, EventType: model.EventClockObservation, FilePath: "safe.txt"})
	}
	ids = append(ids, "gone", "foreign")
	d := svc.assembleReportData(reportInputs{c: c, events: events, timeline: &timelineAgg{}, correlations: []model.Correlation{{ID: "c1", EventIDs: ids}}})
	if len(d.Correlations) != 1 {
		t.Fatal("missing relationship")
	}
	r := d.Correlations[0]
	if r.MissingEvents != 2 || r.EventsOmitted != 2 || len(r.Events) != 10 || r.EventCount != 14 {
		t.Fatalf("wrong accounting: %+v", r)
	}
	for _, e := range d.Timeline.Key {
		if e.ID == "foreign" {
			t.Error("cross-case evidence leaked")
		}
	}
	html, err := report.Render(d)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(html, []byte("PRIVATE-FOREIGN-CONTENT")) || !bytes.Contains(html, []byte("Evidence incomplete")) {
		t.Fatal("missing evidence must be explicit and foreign data withheld")
	}
}
