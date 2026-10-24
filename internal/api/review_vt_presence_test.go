package api

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"tracefall/internal/model"
	"tracefall/internal/narrative"
	"tracefall/internal/store"
)

// Exercise historical bytes through the real store and HTTP readbacks before
// handing their coverage to the same renderer used by single/packet/synthesis.
func TestUI_ReviewVTHistoricalStoredPresence(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	c := createTestCase(t, mux, "Synthetic historical review")
	raw := `{"narrative":{"id":"historical-single","case_id":"` + c.ID + `","status":"ok"},"coverage":{"events_total":1}}`
	if _, err := svc.store.DB().Exec(`INSERT INTO case_reviews(id,case_id,created_at,record_json) VALUES(?,?,?,?)`, "historical-single", c.ID, "2023-01-01T00:00:00Z", raw); err != nil {
		t.Fatal(err)
	}
	plan := map[string]any{"id": "historical-plan", "case_id": c.ID, "state": "planned", "snapshot": map[string]any{"coverage": map[string]any{"events_total": 1}}}
	if err := svc.store.SaveBatchRun(c.ID, "historical-plan", "planned", plan); err != nil {
		t.Fatal(err)
	}
	for seq, kind := range []string{"event", "synthesis"} {
		if err := svc.store.SaveBatchPacket(c.ID, "historical-plan", seq, "succeeded", map[string]any{"seq": seq, "kind": kind, "state": "succeeded", "coverage": map[string]any{"events_total": 1}}); err != nil {
			t.Fatal(err)
		}
	}
	base := "/api/cases/" + c.ID + "/enrich/case-review"
	var single, readPlan, history, packets map[string]any
	for _, r := range []struct {
		path string
		dst  *map[string]any
	}{{base, &single}, {base + "/batches/historical-plan", &readPlan}, {base + "/batches/history", &history}, {base + "/batches/historical-plan/packets", &packets}} {
		if rec := doJSON(t, mux, "GET", r.path, nil, r.dst); rec.Code != 200 {
			t.Fatalf("%s: %d %s", r.path, rec.Code, rec.Body.String())
		}
	}
	coverage := []any{single["latest"].(map[string]any)["coverage"], readPlan, readPlan["snapshot"].(map[string]any)["coverage"]}
	hp := history["plans"].([]any)[0].(map[string]any)
	coverage = append(coverage, hp, hp["snapshot"].(map[string]any)["coverage"])
	for _, p := range packets["packets"].([]any) {
		coverage = append(coverage, p.(map[string]any)["coverage"])
	}
	src, err := os.ReadFile("../web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(src), "function renderStoredVTCoverage(")
	rest := string(src)[start:]
	if loc := regexp.MustCompile(`\n(?:async )?function `).FindStringIndex(rest); loc != nil {
		rest = rest[:loc[0]]
	}
	b, _ := json.Marshal(coverage)
	script := rest + "\nconst assert=require('node:assert/strict');const rows=" + string(b) + `;for(const c of rows){const html=renderStoredVTCoverage(c);assert.match(html,/included not recorded/);assert.ok(!/included 0/.test(html),html);}`
	if out, err := exec.Command("node", "-e", script).CombinedOutput(); err != nil {
		t.Fatalf("historical stored API -> renderer: %v\n%s", err, out)
	}
	for i, c := range coverage[:5] {
		if c.(map[string]any)["vt_recorded"] != false {
			t.Errorf("typed old location %d must serialize vt_recorded=false: %+v", i, c)
		}
	}
	if dir := os.Getenv("TRACEFALL_TEST_VT_PRESENCE_DIR"); dir != "" {
		b, _ := json.Marshal(map[string]any{"single": single, "plan": readPlan, "history": history, "packets": packets})
		if err := os.WriteFile(filepath.Join(dir, "historical.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Reading must never backfill historical stored bytes.
	var after string
	if err := svc.store.DB().QueryRow(`SELECT record_json FROM case_reviews WHERE id=?`, "historical-single").Scan(&after); err != nil || after != raw {
		t.Fatalf("historical bytes changed: %v", err)
	}
}

func TestReviewVTNewZeroCensusPresence(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	newLLMStub(t, svc, true)
	id := caseWithFindings(t, svc, mux, nil)
	pr, err := svc.prepareCaseReview(id)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := svc.PlanReviewBatches(id, defaultBatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := svc.store.BatchPackets(id, plan.ID, -1, 100)
	if err != nil {
		t.Fatal(err)
	}
	objects := []any{pr.Coverage, plan, plan.Snapshot.Coverage}
	for _, raw := range rows {
		var p ReviewBatchPacket
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		if p.State == "ready" {
			objects = append(objects, p.Coverage)
		}
	}
	for i, o := range objects {
		b, _ := json.Marshal(o)
		var c map[string]any
		json.Unmarshal(b, &c)
		if c["vt_recorded"] != true || c["vt_included"] != float64(0) || c["vt_omitted"] != float64(0) {
			t.Errorf("new zero location %d: %s", i, b)
		}
	}
	events, err := svc.store.ListEvents(id)
	if err != nil {
		t.Fatal(err)
	}
	synthesis, prepared, _, err := svc.prepareBatchSynthesis(plan, []ReviewBatchPacket{{Seq: 0, Kind: "event", State: "succeeded", Sentences: []narrative.Sentence{{Text: "Recorded observation.", Cites: []narrative.Cite{{Kind: "event", ID: events[0].ID}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(prepared.Coverage)
	var cv map[string]any
	json.Unmarshal(b, &cv)
	if cv["vt_recorded"] != true || cv["vt_total"] != float64(0) {
		t.Fatalf("new zero synthesis: %s", b)
	}
	synthesis.Seq = plan.TotalBatches
	synthesis.State = "succeeded"
	if err := svc.store.SaveBatchPacket(id, plan.ID, synthesis.Seq, synthesis.State, synthesis); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.SaveCaseReview(store.CaseReview{Coverage: pr.Coverage, Narrative: model.Narrative{ID: "zero-single", CaseID: id, Status: model.NarrativeOK, CreatedAt: time.Now().UTC(), SentencesJSON: "[]"}}); err != nil {
		t.Fatal(err)
	}
	base := "/api/cases/" + id + "/enrich/case-review"
	var single, readPlan, history, packets map[string]any
	for _, r := range []struct {
		path string
		dst  *map[string]any
	}{{base, &single}, {base + "/batches/" + plan.ID, &readPlan}, {base + "/batches/history", &history}, {base + "/batches/" + plan.ID + "/packets", &packets}} {
		if rec := doJSON(t, mux, "GET", r.path, nil, r.dst); rec.Code != 200 {
			t.Fatalf("new zero API %s: %d", r.path, rec.Code)
		}
	}
	if dir := os.Getenv("TRACEFALL_TEST_VT_PRESENCE_DIR"); dir != "" {
		b, _ := json.Marshal(map[string]any{"single": single, "plan": readPlan, "history": history, "packets": packets})
		if err := os.WriteFile(filepath.Join(dir, "zero.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
