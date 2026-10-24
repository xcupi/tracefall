package api

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Execute the actual shared renderer even when no browser is installed.
func TestUI_ReviewClaimTypesNeverInferLegacyTypes(t *testing.T) {
	b, err := os.ReadFile("../web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	extract := func(name string) string {
		t.Helper()
		start := strings.Index(src, "function "+name+"(")
		if start < 0 {
			t.Fatalf("missing renderer %s", name)
		}
		rest := src[start:]
		if end := strings.Index(rest, "\nfunction "); end >= 0 {
			rest = rest[:end]
		}
		return rest
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node is required for UI behavior assertions")
	}
	script := extract("esc") + "\n" + extract("externalCitation") + "\n" + extract("renderReviewClaimGroups") + `
const assert = require('node:assert/strict');
const html = renderReviewClaimGroups([
 {kind:'observation', text:'Recorded only', cites:[{kind:'event',id:'original-event-id'}]},
 {text:'observation | old text', cites:[]},
 {kind:'UNKNOWN', text:'<img onerror=unsafe>', cites:[]},
 {kind:'unclassified', text:'Unclassified explicitly', cites:[]}
]);
assert.ok(html.length > 0);
assert.match(html, /data-claim-kind="observation"/);
assert.match(html, /Unclassified \/ not type-checked[\s\S]*\(3\)/);
assert.ok(html.indexOf('observation | old text') > html.indexOf('data-claim-kind="unclassified"'));
assert.ok(!html.includes('<img'));
assert.ok(html.includes('&lt;img'));
assert.match(html, /data-source-id="original-event-id"/);
assert.match(html, /not truth-validated/);
assert.ok(!renderReviewClaimGroups([]).includes('data-claim-kind='));
`
	if out, err := exec.Command(node, "-e", script).CombinedOutput(); err != nil {
		t.Fatalf("renderer assertions: %v\n%s", err, out)
	}
	summary := extract("renderNarrativeSection")
	if strings.Contains(summary, "renderReviewClaimGroups") {
		t.Fatal("Summary must not be reclassified")
	}
}
