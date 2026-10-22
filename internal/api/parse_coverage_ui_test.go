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

func TestUI_SQLZeroCoverageNotes(t *testing.T) {
	src := appJS(t)
	js := "function parseCoverageText(" + functionBody(t, src, "function parseCoverageText(") + "\nconsole.log(parseCoverageText({records_read:0,mapped:0,notes:['PARTIAL export; NOT-VERIFIED native audit']}))"
	out, err := exec.Command("node", "-e", js).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "PARTIAL export; NOT-VERIFIED native audit") {
		t.Fatalf("lost caveat: %s", out)
	}
}
