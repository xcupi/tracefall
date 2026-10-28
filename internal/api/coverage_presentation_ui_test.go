package api

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"tracefall/internal/model"
)

// Deliberate parity contract: JS must mirror model.ParseCoverage.Measured,
// including historical {}, metadata-only and each nonzero measurement field.
func TestUI_ParseCoverageMeasuredParity(t *testing.T) {
	raws := []string{`null`, `{}`, `{"emitted_events":0}`, `{"notes":["reader caveat"]}`, `{"hive_replay":{"state":"clean"}}`, `{"hive_replay":{"state":"replayed"}}`, `{"hive_replay":{"state":"not_recoverable"},"notes":["recovery caveat"]}`, `{"companion_of":"SYSTEM"}`, `{"unknown_future":0,"another_unknown":false}`, `{"by_event":[{}],"notes":["caveat"]}`, `{"limit_reached":true,"notes":["caveat"]}`}
	for _, key := range []string{"records_read", "mapped", "unmapped", "undated", "records_failed", "chunks_read", "chunks_failed", "unlisted_records"} {
		raws = append(raws, `{"`+key+`":1,"notes":["caveat"]}`)
	}
	var rows []model.SourceFile
	for _, raw := range raws {
		var c *model.ParseCoverage
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, model.SourceFile{ParseCoverage: c, ImportStatus: model.SourceFileImported})
	}
	assertCoverageUI(t, rows)
}

func assertCoverageUI(t *testing.T, rows []model.SourceFile) {
	t.Helper()
	type fixture struct {
		Source   model.SourceFile `json:"source"`
		Measured bool             `json:"measured"`
	}
	var fixtures []fixture
	for _, row := range rows {
		fixtures = append(fixtures, fixture{row, row.ParseCoverage.Measured()})
	}
	data, err := json.Marshal(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	src := appJS(t)
	js := `const assert=require('node:assert/strict'); const esc=s=>String(s).replaceAll('<','&lt;');
 const artifactLabel=s=>s, fmtCount=String, fmtTime=String, fmtBytes=String, collectionLabel=String;
 const PRIORITY_LABELS={},EVIDENCE_STATUS_LABELS={},SOURCE_FILE_STATUS_LABELS={},LEGACY_UNAVAILABLE='not recorded';
 const evidenceStatusValue=f=>f.import_status,capabilityClassification=()=>'',renderCapabilityBoundary=()=>'',renderProvenanceCollection=()=>'',renderSourceFileRecords=()=>'';
 `
	for _, name := range []string{"parseCoverageText", "noEventNote", "evidenceDetails", "renderSourceFileProvenance"} {
		js += "function " + name + "(" + functionBody(t, src, "function "+name+"(") + "\n"
	}
	js += "\nconst fixtures=" + string(data) + `; const failures=[]; for(const {source:s,measured} of fixtures) {
 const text=parseCoverageText(s.parse_coverage);
 const outputs=[['coverage helper',text],['no-event note',noEventNote(s,0)],['evidence details/dialog',evidenceDetails(s)],['source provenance',renderSourceFileProvenance({source_file:s,event_count:0,finding_count:0})]];
 for(const [consumer,out] of outputs) {try {
 assert.ok(out.length>0); if(measured) assert.match(out,/read=\d+ mapped=\d+/); else {assert.match(out,/coverage.*not recorded/i);assert.doesNotMatch(out,/read=0|mapped=0|zero mapped events/);}
 if(s.parse_coverage?.hive_replay) assert.ok(out.includes(s.parse_coverage.hive_replay.state),out);
 if(s.parse_coverage?.notes?.length) assert.ok(out.includes(s.parse_coverage.notes[0]),out);
 } catch(e) {failures.push(consumer+': '+e.message);} }
 } assert.deepEqual(failures,[]); assert.match(parseCoverageText({notes:['caveat'],future:0,future_flag:false}),/Coverage not recorded/); console.log('coverage parity and all four consumers: '+fixtures.length+' fixtures');`
	out, err := exec.Command("node", "-e", js).CombinedOutput()
	if err != nil {
		t.Fatalf("coverage UI assertion: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "coverage parity and all four consumers:") {
		t.Fatal("Node assertions did not execute")
	}
	t.Log(strings.TrimSpace(string(out)))
}
