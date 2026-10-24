package api

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func TestUI_ReviewVTFrozenCitation(t *testing.T) {
	b, err := os.ReadFile("../web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	extract := func(name string) string {
		t.Helper()
		start := strings.Index(src, "function "+name+"(")
		if start < 0 {
			t.Fatalf("missing %s", name)
		}
		rest := src[start:]
		if loc := regexp.MustCompile(`\n(?:async )?function `).FindStringIndex(rest); loc != nil {
			rest = rest[:loc[0]]
		}
		return rest
	}
	script := extract("esc") + "\n" + extract("externalCitation") + "\n" + extract("renderStoredVTCoverage") + "\n" + extract("renderStoredVTSource") + "\n" + extract("renderReviewClaimGroups") + "\n" + extract("renderCaseReviewSection") + `
const assert=require('node:assert/strict');
const single=externalCitation('enrichment','original/<id>',{reviewID:'review/full'});
assert.match(single,/data-source-kind="enrichment"/,'Stored enrichment is an actionable source');
assert.match(single,/data-review-id="review\/full"/);
assert.ok(!single.includes('<id>'));
assert.match(externalCitation('enrichment','id',{runID:'run/full'}),/data-run-id="run\/full"/);
assert.match(externalCitation('enrichment','id'),/unavailable/i);
assert.match(externalCitation('enrichment','id',{reviewID:'r',runID:'b'}),/unavailable/i);
assert.ok(!externalCitation('enrichment','id').includes('<button'));
assert.match(renderCaseReviewSection({latest:{status:'ok',stale:true,sentences:[]}}),/Stale:[^<]*stored VirusTotal/,'Stale input warning includes stored VT changes');
const oldCoverage=renderCaseReviewSection({latest:{status:'ok',coverage:{events_total:'<img src=x>',vt_total:'<img src=x>'},sentences:[]}});
assert.ok(!oldCoverage.includes('<img'),'All coverage DTO values are escaped or treated as unknown');
assert.ok(!oldCoverage.includes('undefined'),'Missing coverage values are not recorded');
const missing=renderStoredVTCoverage({vt_included:0});assert.match(missing,/included not recorded/);assert.match(missing,/total not recorded/);
assert.match(renderStoredVTCoverage({vt_recorded:true,vt_included:0}),/included 0/);
assert.match(renderStoredVTCoverage({vt_recorded:false,vt_included:0}),/included not recorded/);
const hostile=renderStoredVTSource({status:'found',indicator:'<img>',fetched_at:'<svg>',verdicts_recorded:true,malicious:'<img>',error:'SECRET',source_event_ids:['<event>']});assert.ok(!hostile.includes('<img'));assert.ok(!hostile.includes('<svg>'));assert.ok(!hostile.includes('SECRET'));assert.match(hostile,/malicious: not recorded/);
assert.match(renderStoredVTSource({status:'constructor'}),/Status not recorded/);
`
	if out, err := exec.Command("node", "-e", script).CombinedOutput(); err != nil {
		t.Fatalf("citation assertions: %v\n%s", err, out)
	}
}
