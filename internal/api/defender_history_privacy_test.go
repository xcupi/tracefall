package api

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
	"tracefall/internal/model"
)

// Characterizes default report/event-list privacy; explicit raw-evidence
// inspection remains available to the authorized local examiner.
func TestDefenderHistoryDefaultProjectionsKeepPrivateRaw(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	c := mustCreateCase(t, mux, "Neutral history privacy")
	const secret = "neutral-credential-canary-history"
	col := model.Collection{ID: "history-collection", CaseID: c.ID, CreatedAt: time.Now()}
	if err := svc.store.SaveCollection(col); err != nil {
		t.Fatal(err)
	}
	sf := model.SourceFile{ID: "history-source", CaseID: c.ID, CollectionID: col.ID, Path: "DetectionHistory/neutral", ArtifactType: model.ArtifactDefenderHistory}
	if err := svc.store.SaveSourceFiles([]model.SourceFile{sf}); err != nil {
		t.Fatal(err)
	}
	raw := model.RawEvidence{ID: "history-raw", CaseID: c.ID, SourceFileID: "history-source", Raw: `{"private_resource":"` + secret + `"}`}
	if err := svc.store.SaveRawEvidence([]model.RawEvidence{raw}); err != nil {
		t.Fatal(err)
	}
	e := model.Event{ID: "history", CaseID: c.ID, CollectionID: col.ID, SourceFileID: sf.ID, ArtifactType: model.ArtifactDefenderHistory, EventType: model.EventAntimalwareHistory, RawEvidenceID: raw.ID, Extra: map[string]string{"detection_id": "12345678-1234-5678-90ab-cdef01020304"}}
	if err := svc.store.SaveEvents([]model.Event{e}); err != nil {
		t.Fatal(err)
	}
	b, err := svc.buildReport(c.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer b.release()
	if bytes.Contains(b.HTML, []byte(secret)) {
		t.Fatal("raw leaked into default HTML")
	}
	for _, f := range b.Files {
		if bytes.Contains(f.Data, []byte(secret)) {
			t.Fatal("raw leaked into report attachment")
		}
	}
	var body any
	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events", nil, &body)
	v, _ := json.Marshal(body)
	if rec.Code != 200 || bytes.Contains(v, []byte(secret)) {
		t.Fatal("raw leaked into default event API")
	}
	stored, err := svc.store.GetRawEvidence(raw.ID)
	if err != nil || stored.Raw != raw.Raw {
		t.Fatal("private raw evidence not preserved")
	}
}
