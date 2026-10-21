package api

import (
	"os/exec"
	"strings"
	"testing"
)

func TestUI_ParseCoverageDoesNotCallUnmappedRecordsEmptyEvidence(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node unavailable")
	}
	src := appJS(t)
	js := "const esc=s=>String(s);\n"
	if strings.Contains(string(src), "function parseCoverageText(") {
		js += "function parseCoverageText(" + functionBody(t, src, "function parseCoverageText(") + "\n"
	}
	js += "function noEventNote(" + functionBody(t, src, "function noEventNote(") + "\nconsole.log(noEventNote({import_status:'imported',parse_coverage:{records_read:1,mapped:0,unmapped:1,undated:0,records_failed:0,chunks_failed:0,limit_reached:false}},0))"
	out, err := exec.Command("node", "-e", js).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	if !strings.Contains(string(out), "unmapped=1") {
		t.Fatalf("misleading zero-event note: %s", out)
	}
}
