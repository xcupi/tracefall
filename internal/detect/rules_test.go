package detect

import (
	"testing"
	"time"

	"tracefall/internal/model"
)

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func hasFindingFrom(findings []model.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestOfficeSpawnsPowerShell(t *testing.T) {
	events := []model.Event{
		{ID: "1", EventType: model.EventProcessCreate, ParentProcessName: "winword.exe", ProcessName: "powershell.exe", Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	findings := officeSpawnsPowerShell{}.Evaluate(events)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != model.SeverityHigh {
		t.Errorf("severity = %q, want high", findings[0].Severity)
	}

	// A non-Office parent must not trigger the rule.
	clean := []model.Event{
		{ID: "2", EventType: model.EventProcessCreate, ParentProcessName: "explorer.exe", ProcessName: "powershell.exe", Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	if got := (officeSpawnsPowerShell{}).Evaluate(clean); len(got) != 0 {
		t.Errorf("got %d findings for non-Office parent, want 0", len(got))
	}
}

func TestPowershellEncodedCommand(t *testing.T) {
	suspicious := []model.Event{
		{ID: "1", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", CommandLine: "powershell.exe -nop -w hidden -enc AAAA", Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	findings := powershellEncodedCommand{}.Evaluate(suspicious)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != model.SeverityHigh {
		t.Errorf("severity = %q, want high for 2+ indicators", findings[0].Severity)
	}

	clean := []model.Event{
		{ID: "2", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", CommandLine: "powershell.exe -File script.ps1", Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	if got := (powershellEncodedCommand{}).Evaluate(clean); len(got) != 0 {
		t.Errorf("got %d findings for a clean command line, want 0", len(got))
	}
}

func TestNewRegistryRunKey_SuspiciousPathRaisesSeverity(t *testing.T) {
	benign := []model.Event{
		{ID: "1", EventType: model.EventRegistryRunKey, FilePath: `C:\Program Files\Vendor\app.exe`, Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	f := newRegistryRunKey{}.Evaluate(benign)
	if len(f) != 1 || f[0].Severity != model.SeverityLow {
		t.Fatalf("benign run key: got %+v, want 1 low-severity finding", f)
	}

	suspicious := []model.Event{
		{ID: "2", EventType: model.EventRegistryRunKey, FilePath: `C:\Users\jdoe\AppData\Local\Temp\update.exe`, Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	f2 := newRegistryRunKey{}.Evaluate(suspicious)
	if len(f2) != 1 || f2[0].Severity != model.SeverityHigh {
		t.Fatalf("suspicious-path run key: got %+v, want 1 high-severity finding", f2)
	}
}

func TestBruteForceThenSuccess(t *testing.T) {
	base := mustTime("2026-01-15T14:00:00Z")
	events := []model.Event{
		{ID: "1", EventType: model.EventLogonFailure, Host: "H1", User: "svc", Timestamp: base},
		{ID: "2", EventType: model.EventLogonFailure, Host: "H1", User: "svc", Timestamp: base.Add(1 * time.Minute)},
		{ID: "3", EventType: model.EventLogonFailure, Host: "H1", User: "svc", Timestamp: base.Add(2 * time.Minute)},
		{ID: "4", EventType: model.EventLogonSuccess, Host: "H1", User: "svc", Timestamp: base.Add(3 * time.Minute)},
	}
	findings := bruteForceThenSuccess{}.Evaluate(events)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if len(findings[0].SupportingEvents) != 4 {
		t.Errorf("got %d supporting events, want 4 (3 failures + success)", len(findings[0].SupportingEvents))
	}

	// Below threshold: only 2 failures should not fire.
	below := events[:2]
	below = append(below, events[3]) // 2 failures + success
	if got := (bruteForceThenSuccess{}).Evaluate(below); len(got) != 0 {
		t.Errorf("got %d findings for below-threshold failures, want 0", len(got))
	}

	// No subsequent success: should not fire.
	noSuccess := events[:3]
	if got := (bruteForceThenSuccess{}).Evaluate(noSuccess); len(got) != 0 {
		t.Errorf("got %d findings with no success following, want 0", len(got))
	}
}

func TestExecutionThenPersistence_OneFindingPerPersistenceEvent(t *testing.T) {
	base := mustTime("2026-01-15T09:15:10Z")
	events := []model.Event{
		{ID: "create", EventType: model.EventProcessCreate, Host: "H1", ProcessName: "update.exe", Timestamp: base},
		{ID: "prefetch", EventType: model.EventPrefetchExecution, Host: "H1", ProcessName: "update.exe", Timestamp: base.Add(1 * time.Second)},
		{ID: "regkey", EventType: model.EventRegistryRunKey, Host: "H1", ProcessName: "update.exe", Timestamp: base.Add(52 * time.Second)},
	}
	findings := executionThenPersistence{}.Evaluate(events)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want exactly 1 (deduped across process_create + prefetch matches)", len(findings))
	}
	// Process-create is authoritative and should be preferred over prefetch.
	if findings[0].SupportingEvents[0] != "create" {
		t.Errorf("supporting event 0 = %q, want the process_create event (authoritative over prefetch)", findings[0].SupportingEvents[0])
	}

	// Outside the persistence window: should not fire.
	tooLate := []model.Event{
		{ID: "create", EventType: model.EventProcessCreate, Host: "H1", ProcessName: "update.exe", Timestamp: base},
		{ID: "regkey", EventType: model.EventRegistryRunKey, Host: "H1", ProcessName: "update.exe", Timestamp: base.Add(1 * time.Hour)},
	}
	if got := (executionThenPersistence{}).Evaluate(tooLate); len(got) != 0 {
		t.Errorf("got %d findings outside the persistence window, want 0", len(got))
	}
}

func TestSuspiciousProcessChain(t *testing.T) {
	events := []model.Event{
		{ID: "1", EventType: model.EventProcessCreate, ParentProcessName: "powershell.exe", ProcessName: "update.exe", ProcessPath: `C:\Users\jdoe\AppData\Local\Temp\update.exe`, Timestamp: mustTime("2026-01-15T09:15:10Z")},
	}
	if got := (suspiciousProcessChain{}).Evaluate(events); len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}

	benign := []model.Event{
		{ID: "2", EventType: model.EventProcessCreate, ParentProcessName: "powershell.exe", ProcessName: "notepad.exe", ProcessPath: `C:\Windows\System32\notepad.exe`, Timestamp: mustTime("2026-01-15T09:15:10Z")},
	}
	if got := (suspiciousProcessChain{}).Evaluate(benign); len(got) != 0 {
		t.Errorf("got %d findings for a standard-path child process, want 0", len(got))
	}
}

func TestRun_DeterministicOrdering(t *testing.T) {
	events := []model.Event{
		{ID: "1", EventType: model.EventProcessCreate, ParentProcessName: "winword.exe", ProcessName: "powershell.exe", Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	f1 := Run("case-1", events)
	f2 := Run("case-1", events)
	if len(f1) != len(f2) {
		t.Fatalf("non-deterministic finding count: %d vs %d", len(f1), len(f2))
	}
	for i := range f1 {
		if f1[i].RuleID != f2[i].RuleID || f1[i].Title != f2[i].Title {
			t.Errorf("non-deterministic ordering at index %d: %q vs %q", i, f1[i].Title, f2[i].Title)
		}
	}
	if !hasFindingFrom(f1, "office-spawns-powershell") {
		t.Error("expected office-spawns-powershell finding")
	}
}
