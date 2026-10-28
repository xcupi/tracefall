package api

import (
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// Historical JSON is intentionally absent the optional metric. Exercise store,
// typed API/history readback and the real latest-review renderer without backfill.
func TestUI_ReviewProseOmissionStoredPresence(t *testing.T) {
	for _, metric := range []string{"", `,"prose_values_omitted":0`, `,"prose_values_omitted":1`} {
		t.Run(metric, func(t *testing.T) {
			mux, svc := newTestRouterWithService(t)
			c := createTestCase(t, mux, "Synthetic review disclosure")
			coverage := json.RawMessage(`{"events_total":1,"command_lines_omitted":0` + metric + `}`)
			raw := `{"narrative":{"id":"stored-single","case_id":"` + c.ID + `","status":"ok","sentences":"[]"},"coverage":` + string(coverage) + `}`
			if _, err := svc.store.DB().Exec(`INSERT INTO case_reviews(id,case_id,created_at,record_json) VALUES(?,?,?,?)`, "stored-single", c.ID, "2023-01-01T00:00:00Z", raw); err != nil {
				t.Fatal(err)
			}
			if err := svc.store.SaveBatchRun(c.ID, "stored-plan", "planned", map[string]any{"id": "stored-plan", "case_id": c.ID, "state": "planned"}); err != nil {
				t.Fatal(err)
			}
			for seq, kind := range []string{"event", "synthesis"} {
				if err := svc.store.SaveBatchPacket(c.ID, "stored-plan", seq, "succeeded", map[string]any{"seq": seq, "kind": kind, "state": "succeeded", "coverage": coverage}); err != nil {
					t.Fatal(err)
				}
			}
			base := "/api/cases/" + c.ID + "/enrich/case-review"
			var single, history, packets map[string]any
			for _, r := range []struct {
				path string
				dst  *map[string]any
			}{{base, &single}, {base + "/batches/history", &history}, {base + "/batches/stored-plan/packets", &packets}} {
				if rec := doJSON(t, mux, "GET", r.path, nil, r.dst); rec.Code != 200 {
					t.Fatalf("readback %s: %d %s", r.path, rec.Code, rec.Body.String())
				}
			}
			if len(history["plans"].([]any)) != 1 {
				t.Fatal("missing stored plan history")
			}
			rows := []any{single["latest"].(map[string]any)["coverage"]}
			for _, p := range packets["packets"].([]any) {
				rows = append(rows, p.(map[string]any)["coverage"])
			}
			for _, row := range rows {
				cv := row.(map[string]any)
				v, present := cv["prose_values_omitted"]
				if (metric != "") != present {
					t.Fatalf("optional presence changed: %+v", cv)
				}
				if metric != "" && v != float64(strings.Count(metric, ":1")) {
					t.Fatalf("recorded count changed: %+v", cv)
				}
			}
			src, err := os.ReadFile("../web/static/app.js")
			if err != nil {
				t.Fatal(err)
			}
			extract := func(name string) string {
				start := strings.Index(string(src), "function "+name+"(")
				if start < 0 {
					return ""
				}
				rest := string(src)[start:]
				if loc := regexp.MustCompile(`\n(?:async )?function `).FindStringIndex(rest); loc != nil {
					rest = rest[:loc[0]]
				}
				return rest
			}
			script := ""
			for _, name := range []string{"esc", "externalCitation", "renderStoredVTCoverage", "renderReviewPrivacyOmissions", "renderReviewClaimGroups", "renderCaseReviewSection"} {
				script += extract(name) + "\n"
			}
			b, _ := json.Marshal(rows)
			script += "const assert=require('node:assert/strict');const rows=" + string(b) + `;for(const c of rows){const html=renderCaseReviewSection({latest:{status:'ok',coverage:c,sentences:[]}});assert.ok(html.length>0);assert.match(html,/Command lines omitted by privacy guards: 0/);const count=c.prose_values_omitted??'not recorded';assert.ok(html.includes('Prose values omitted by privacy guards: '+count),html);assert.ok(!html.includes('body guard'));if(count===1)assert.match(html,/Incomplete input/);else assert.ok(!html.includes('<strong>Incomplete input:</strong>'));}for(const c of [{},{prose_values_omitted:null},{prose_values_omitted:-1},{prose_values_omitted:'<img src=x>'}]){const html=renderReviewPrivacyOmissions(c);assert.match(html,/Prose values omitted by privacy guards: not recorded/);assert.ok(!html.includes('<img'));assert.ok(!html.includes('<strong>Incomplete input:</strong>'));}assert.match(renderReviewPrivacyOmissions({command_lines_omitted:1,prose_values_omitted:0}),/Incomplete input/);`
			if out, err := exec.Command("node", "-e", script).CombinedOutput(); err != nil {
				t.Fatalf("stored API -> renderer: %v\n%s", err, out)
			}
			var after string
			if err := svc.store.DB().QueryRow(`SELECT record_json FROM case_reviews WHERE id=?`, "stored-single").Scan(&after); err != nil || after != raw {
				t.Fatalf("stored history backfilled: %v", err)
			}
		})
	}
}
