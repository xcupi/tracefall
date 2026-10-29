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

// TestBruteForceThenSuccess_CrossesUTCMidnight is a Phase 6 time-handling
// audit test: a burst of failures/success spanning a UTC calendar-day
// boundary must be detected identically to one that doesn't -- all
// windowing here is pure elapsed-duration arithmetic on time.Time values
// (time.Sub/Before/After), never calendar-day-aware, so midnight has no
// special significance. This test exists to make that property explicit
// and regression-tested, not just asserted in a comment.
func TestBruteForceThenSuccess_CrossesUTCMidnight(t *testing.T) {
	base := mustTime("2026-01-15T23:58:00Z") // 2 minutes before UTC midnight
	events := []model.Event{
		{ID: "1", EventType: model.EventLogonFailure, Host: "H1", User: "svc", Timestamp: base},
		{ID: "2", EventType: model.EventLogonFailure, Host: "H1", User: "svc", Timestamp: base.Add(1 * time.Minute)}, // 23:59
		{ID: "3", EventType: model.EventLogonFailure, Host: "H1", User: "svc", Timestamp: base.Add(2 * time.Minute)}, // 00:00 the next day
		{ID: "4", EventType: model.EventLogonSuccess, Host: "H1", User: "svc", Timestamp: base.Add(3 * time.Minute)}, // 00:01
	}
	findings := bruteForceThenSuccess{}.Evaluate(events)
	if len(findings) != 1 {
		t.Fatalf("got %d findings for a burst crossing UTC midnight, want 1 (midnight must not break windowing)", len(findings))
	}
	if len(findings[0].SupportingEvents) != 4 {
		t.Errorf("got %d supporting events, want 4", len(findings[0].SupportingEvents))
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
		{ID: "create", EventType: model.EventProcessCreate, CaseID: "case", CollectionID: "acq", Host: "H1", ProcessName: "update.exe", Timestamp: base},
		{ID: "prefetch", EventType: model.EventPrefetchExecution, CaseID: "case", CollectionID: "acq", Host: "H1", ProcessName: "update.exe", Timestamp: base.Add(1 * time.Second)},
		{ID: "regkey", EventType: model.EventRegistryRunKey, CaseID: "case", CollectionID: "acq", Host: "H1", ProcessName: "update.exe", Timestamp: base.Add(52 * time.Second)},
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
		{ID: "create", EventType: model.EventProcessCreate, CaseID: "case", CollectionID: "acq", Host: "H1", ProcessName: "update.exe", Timestamp: base},
		{ID: "regkey", EventType: model.EventRegistryRunKey, CaseID: "case", CollectionID: "acq", Host: "H1", ProcessName: "update.exe", Timestamp: base.Add(1 * time.Hour)},
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

// TestRun_FindingIDsAreStableAcrossReanalysis is a Phase 6 regression
// test: Finding.ID must be byte-identical across two separate Run() calls
// on unchanged evidence (a content-derived hash, not a random UUID) --
// see engine.go's doc comment. This is what lets analyst workflow state
// (status/notes/tags, stored in tables separate from findings so
// re-analysis doesn't wipe them) survive a no-op re-analysis instead of
// being silently orphaned every time /analyze is called again.
func TestRun_FindingIDsAreStableAcrossReanalysis(t *testing.T) {
	events := []model.Event{
		{ID: "1", EventType: model.EventProcessCreate, ParentProcessName: "winword.exe", ProcessName: "powershell.exe", Timestamp: mustTime("2026-01-15T09:14:47Z")},
		{ID: "2", EventType: model.EventLogonFailure, Host: "H1", User: "svc", Timestamp: mustTime("2026-01-15T14:00:00Z")},
	}
	f1 := Run("case-1", events)
	f2 := Run("case-1", events)
	if len(f1) == 0 {
		t.Fatal("expected at least one finding")
	}
	if len(f1) != len(f2) {
		t.Fatalf("non-deterministic finding count across runs: %d vs %d", len(f1), len(f2))
	}
	for i := range f1 {
		if f1[i].ID != f2[i].ID {
			t.Errorf("finding %d: ID differs across runs on unchanged evidence: %q vs %q (rule %s)", i, f1[i].ID, f2[i].ID, f1[i].RuleID)
		}
		if f1[i].ID == "" {
			t.Errorf("finding %d: empty ID", i)
		}
	}

	// A genuinely different case ID (different evidence context) must
	// produce different finding IDs, even for the same rule/events --
	// findings must never collide across cases.
	f3 := Run("case-2", events)
	if len(f3) > 0 && f3[0].ID == f1[0].ID {
		t.Error("findings from different cases produced the same ID")
	}
}

// =====================================================================
// Phase 4 rule tests -- positive, negative, and insufficient-evidence
// cases for each new rule, per Phase 4H's testing requirements.
// =====================================================================

func TestOfficeSpawnsScriptInterpreter(t *testing.T) {
	cmd := []model.Event{
		{ID: "1", EventType: model.EventProcessCreate, ParentProcessName: "winword.exe", ProcessName: "cmd.exe", Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	f := officeSpawnsScriptInterpreter{}.Evaluate(cmd)
	if len(f) != 1 {
		t.Fatalf("cmd.exe from Office: got %d findings, want 1", len(f))
	}
	if !containsStr(f[0].Techniques, "T1059.003") {
		t.Errorf("cmd.exe techniques = %v, want T1059.003", f[0].Techniques)
	}

	mshta := []model.Event{
		{ID: "2", EventType: model.EventProcessCreate, ParentProcessName: "excel.exe", ProcessName: "mshta.exe", Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	f2 := officeSpawnsScriptInterpreter{}.Evaluate(mshta)
	if len(f2) != 1 || !containsStr(f2[0].Techniques, "T1218.005") {
		t.Fatalf("mshta.exe from Office: got %+v, want 1 finding mapping T1218.005", f2)
	}

	vbs := []model.Event{
		{ID: "3", EventType: model.EventProcessCreate, ParentProcessName: "winword.exe", ProcessName: "wscript.exe", CommandLine: `wscript.exe payload.vbs`, Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	f3 := officeSpawnsScriptInterpreter{}.Evaluate(vbs)
	if len(f3) != 1 || !containsStr(f3[0].Techniques, "T1059.005") {
		t.Fatalf("wscript.exe running a .vbs: got %+v, want T1059.005", f3)
	}

	// wscript.exe with no resolvable script extension must NOT be assigned
	// a specific scripting-language sub-technique -- "do not map ATT&CK
	// based purely on process names".
	ambiguous := []model.Event{
		{ID: "4", EventType: model.EventProcessCreate, ParentProcessName: "winword.exe", ProcessName: "wscript.exe", CommandLine: `wscript.exe //B //Nologo payload`, Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	f4 := officeSpawnsScriptInterpreter{}.Evaluate(ambiguous)
	if len(f4) != 1 {
		t.Fatalf("got %d findings, want 1", len(f4))
	}
	if containsStr(f4[0].Techniques, "T1059.005") || containsStr(f4[0].Techniques, "T1059.007") {
		t.Errorf("techniques = %v, must not guess a specific scripting language from process name alone", f4[0].Techniques)
	}

	// Non-Office parent must not fire (already covered by
	// officeSpawnsPowerShell's negative test for the PowerShell case).
	clean := []model.Event{
		{ID: "5", EventType: model.EventProcessCreate, ParentProcessName: "explorer.exe", ProcessName: "cmd.exe", Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	if got := (officeSpawnsScriptInterpreter{}).Evaluate(clean); len(got) != 0 {
		t.Errorf("got %d findings for non-Office parent, want 0", len(got))
	}
}

func TestSuspiciousParentChildLineage(t *testing.T) {
	servicesChild := []model.Event{
		{ID: "1", EventType: model.EventProcessCreate, ParentProcessName: "services.exe", ProcessName: "weirdsvc.exe", ProcessPath: `C:\Users\Public\weirdsvc.exe`, Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	f := suspiciousParentChildLineage{}.Evaluate(servicesChild)
	if len(f) != 1 || f[0].Severity != model.SeverityHigh {
		t.Fatalf("services.exe -> suspicious-path child: got %+v, want 1 high-severity finding", f)
	}

	// services.exe spawning an ordinary, standard-path process must NOT fire.
	servicesBenign := []model.Event{
		{ID: "2", EventType: model.EventProcessCreate, ParentProcessName: "services.exe", ProcessName: "svchost.exe", ProcessPath: `C:\Windows\System32\svchost.exe`, Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	if got := (suspiciousParentChildLineage{}).Evaluate(servicesBenign); len(got) != 0 {
		t.Errorf("got %d findings for services.exe -> standard-path svchost.exe, want 0", len(got))
	}

	// explorer.exe -> cmd.exe with no corroboration: low severity, not
	// silently ignored, and specifically NOT high -- an administrator
	// opening a command prompt must not be treated as equally suspicious
	// as a corroborated case.
	explorerBenign := []model.Event{
		{ID: "3", EventType: model.EventProcessCreate, ParentProcessName: "explorer.exe", ProcessName: "cmd.exe", ProcessPath: `C:\Windows\System32\cmd.exe`, Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	f3 := suspiciousParentChildLineage{}.Evaluate(explorerBenign)
	if len(f3) != 1 || f3[0].Severity == model.SeverityHigh {
		t.Fatalf("explorer.exe -> plain cmd.exe: got %+v, want low/medium severity, not high (benign admin action)", f3)
	}

	// explorer.exe -> powershell.exe WITH a suspicious indicator: escalated.
	explorerSuspicious := []model.Event{
		{ID: "4", EventType: model.EventProcessCreate, ParentProcessName: "explorer.exe", ProcessName: "powershell.exe", CommandLine: "powershell.exe -enc AAAA", Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	f4 := suspiciousParentChildLineage{}.Evaluate(explorerSuspicious)
	if len(f4) != 1 || f4[0].Severity == model.SeverityLow {
		t.Fatalf("explorer.exe -> encoded powershell: got %+v, want escalated severity", f4)
	}

	// svchost.exe with no child process name recorded should not fire
	// (insufficient evidence to say anything happened).
	insufficient := []model.Event{
		{ID: "5", EventType: model.EventProcessCreate, ParentProcessName: "svchost.exe", ProcessName: "", Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	if got := (suspiciousParentChildLineage{}).Evaluate(insufficient); len(got) != 0 {
		t.Errorf("got %d findings for an empty child process name, want 0", len(got))
	}
}

func TestServicePersistence(t *testing.T) {
	benign := []model.Event{
		{ID: "1", EventType: model.EventServiceInstall, FilePath: `C:\Program Files\Vendor\svc.exe`, Extra: map[string]string{"service_name": "VendorSvc"}, Timestamp: mustTime("2026-01-15T09:22:00Z")},
	}
	f := servicePersistence{}.Evaluate(benign)
	if len(f) != 1 || f[0].Severity != model.SeverityLow {
		t.Fatalf("standard-path service install: got %+v, want 1 low-severity finding", f)
	}
	if !containsStr(f[0].Techniques, "T1543.003") {
		t.Errorf("techniques = %v, want T1543.003", f[0].Techniques)
	}

	suspicious := []model.Event{
		{ID: "2", EventType: model.EventServiceInstall, FilePath: `C:\Users\Public\svc.exe`, ProcessName: "svc.exe", Extra: map[string]string{"service_name": "WeirdSvc"}, Timestamp: mustTime("2026-01-15T09:22:00Z")},
	}
	f2 := servicePersistence{}.Evaluate(suspicious)
	if len(f2) != 1 || f2[0].Severity != model.SeverityHigh {
		t.Fatalf("suspicious-path service install: got %+v, want 1 high-severity finding", f2)
	}
}

func TestRegistryPersistenceExtended(t *testing.T) {
	winlogon := []model.Event{
		{ID: "1", EventType: model.EventRegistryPersistence, RegistryPath: `HKLM\...\Winlogon\Shell`, FilePath: `C:\Windows\explorer.exe`, Extra: map[string]string{"registry_persistence_type": "winlogon"}, Timestamp: mustTime("2026-01-15T09:16:05Z")},
	}
	f := registryPersistenceExtended{}.Evaluate(winlogon)
	if len(f) != 1 || f[0].Severity != model.SeverityHigh {
		t.Fatalf("winlogon hijack: got %+v, want 1 high-severity finding", f)
	}
	if !containsStr(f[0].Techniques, "T1547.004") {
		t.Errorf("techniques = %v, want T1547.004", f[0].Techniques)
	}

	appinit := []model.Event{
		{ID: "2", EventType: model.EventRegistryPersistence, RegistryPath: `HKLM\...\Windows\AppInit_DLLs`, FilePath: `C:\Program Files\Vendor\hook.dll`, Extra: map[string]string{"registry_persistence_type": "appinit_dlls"}, Timestamp: mustTime("2026-01-15T09:16:05Z")},
	}
	f2 := registryPersistenceExtended{}.Evaluate(appinit)
	if len(f2) != 1 {
		t.Fatalf("got %d findings, want 1", len(f2))
	}
	// Standard-path AppInit_DLLs entry: not escalated to high on path alone.
	if f2[0].Severity == model.SeverityHigh {
		t.Errorf("standard-path AppInit_DLLs: got severity %q, want not-high", f2[0].Severity)
	}
}

func TestExplicitCredentialUse(t *testing.T) {
	events := []model.Event{
		{ID: "1", EventType: model.EventLogonExplicitCreds, User: "jdoe", Host: "H1", Extra: map[string]string{"target_user_name": "svc-backup"}, Timestamp: mustTime("2026-01-15T09:20:00Z")},
	}
	f := explicitCredentialUse{}.Evaluate(events)
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
	// Always low/low alone -- a single 4648 is routine (RunAs, mapped
	// drives, scheduled tasks) and must never be reported as a verdict.
	if f[0].Severity != model.SeverityLow || f[0].Confidence != model.ConfidenceLow {
		t.Errorf("severity/confidence = %s/%s, want low/low for a single explicit-credential logon", f[0].Severity, f[0].Confidence)
	}
	if !containsStr(f[0].Techniques, "T1078") {
		t.Errorf("techniques = %v, want T1078", f[0].Techniques)
	}

	if got := (explicitCredentialUse{}).Evaluate(nil); len(got) != 0 {
		t.Errorf("got %d findings for no events, want 0", len(got))
	}
}

func TestPrivilegedLogonObserved(t *testing.T) {
	events := []model.Event{
		{ID: "1", EventType: model.EventPrivilegedLogon, User: "svc-backup", Host: "H1", Timestamp: mustTime("2026-01-15T09:20:05Z")},
	}
	f := privilegedLogonObserved{}.Evaluate(events)
	if len(f) != 1 || f[0].Severity != model.SeverityLow {
		t.Fatalf("got %+v, want 1 low-severity finding (administrative logons are routine alone)", f)
	}
}

func TestNetworkAfterExecution(t *testing.T) {
	base := mustTime("2026-01-15T09:15:00Z")
	// PowerShell execution followed by a connection shortly after --
	// medium by default (many legitimate reasons), port/destination never
	// factor into severity.
	events := []model.Event{
		{ID: "exec", EventType: model.EventProcessCreate, Host: "H1", ProcessName: "powershell.exe", ProcessPath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Timestamp: base},
		{ID: "net", EventType: model.EventNetworkConnection, Host: "H1", ProcessName: "powershell.exe", NetworkDest: "203.0.113.77", NetworkDestPort: 8081, Timestamp: base.Add(30 * time.Second)},
	}
	f := networkAfterExecution{}.Evaluate(events)
	if len(f) != 1 || f[0].Severity != model.SeverityMedium {
		t.Fatalf("got %+v, want 1 medium-severity finding", f)
	}

	// A plain, standard-path, non-interpreter process making a network
	// connection must NOT fire -- e.g. a browser or update client.
	benign := []model.Event{
		{ID: "exec2", EventType: model.EventProcessCreate, Host: "H1", ProcessName: "chrome.exe", ProcessPath: `C:\Program Files\Google\Chrome\Application\chrome.exe`, Timestamp: base},
		{ID: "net2", EventType: model.EventNetworkConnection, Host: "H1", ProcessName: "chrome.exe", NetworkDest: "203.0.113.77", NetworkDestPort: 443, Timestamp: base.Add(30 * time.Second)},
	}
	if got := (networkAfterExecution{}).Evaluate(benign); len(got) != 0 {
		t.Errorf("got %d findings for a standard-path non-interpreter process, want 0", len(got))
	}

	// PowerShell on a well-known port (443) must not be treated
	// differently than an unusual port -- confirms port plays no role.
	wellKnownPort := []model.Event{
		{ID: "exec3", EventType: model.EventProcessCreate, Host: "H1", ProcessName: "powershell.exe", ProcessPath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Timestamp: base},
		{ID: "net3", EventType: model.EventNetworkConnection, Host: "H1", ProcessName: "powershell.exe", NetworkDest: "203.0.113.77", NetworkDestPort: 443, Timestamp: base.Add(30 * time.Second)},
	}
	f3 := networkAfterExecution{}.Evaluate(wellKnownPort)
	if len(f3) != 1 || f3[0].Severity != model.SeverityMedium {
		t.Fatalf("got %+v, want the same medium severity regardless of port 443 vs 8081", f3)
	}

	// Outside the window: should not fire.
	tooLate := []model.Event{
		{ID: "exec4", EventType: model.EventProcessCreate, Host: "H1", ProcessName: "powershell.exe", Timestamp: base},
		{ID: "net4", EventType: model.EventNetworkConnection, Host: "H1", ProcessName: "powershell.exe", NetworkDest: "203.0.113.77", Timestamp: base.Add(1 * time.Hour)},
	}
	if got := (networkAfterExecution{}).Evaluate(tooLate); len(got) != 0 {
		t.Errorf("got %d findings outside the network-after-exec window, want 0", len(got))
	}
}

func TestRemoteLogonObserved(t *testing.T) {
	rdp := []model.Event{
		{ID: "1", EventType: model.EventLogonSuccess, User: "jdoe", Host: "H1", Extra: map[string]string{"logon_type": "10"}, Timestamp: mustTime("2026-01-15T09:00:00Z")},
	}
	f := remoteLogonObserved{}.Evaluate(rdp)
	if len(f) != 1 || f[0].Severity != model.SeverityLow {
		t.Fatalf("got %+v, want 1 low-severity RDP finding", f)
	}
	if !containsStr(f[0].Techniques, "T1021.001") {
		t.Errorf("techniques = %v, want T1021.001", f[0].Techniques)
	}

	// LogonType 3 (Network) is ambiguous (SMB/WinRM/many protocols) and
	// must NOT be mapped to T1021.001.
	network := []model.Event{
		{ID: "2", EventType: model.EventLogonSuccess, User: "jdoe", Host: "H1", Extra: map[string]string{"logon_type": "3"}, Timestamp: mustTime("2026-01-15T09:00:00Z")},
	}
	if got := (remoteLogonObserved{}).Evaluate(network); len(got) != 0 {
		t.Errorf("got %d findings for LogonType 3 (ambiguous protocol), want 0", len(got))
	}

	// Interactive (LogonType 2) must not fire either.
	interactive := []model.Event{
		{ID: "3", EventType: model.EventLogonSuccess, User: "jdoe", Host: "H1", Extra: map[string]string{"logon_type": "2"}, Timestamp: mustTime("2026-01-15T09:00:00Z")},
	}
	if got := (remoteLogonObserved{}).Evaluate(interactive); len(got) != 0 {
		t.Errorf("got %d findings for an interactive logon, want 0", len(got))
	}
}

// TestExecutionThenPersistence_ExtendedPersistenceTypes confirms Phase
// 4's broadened persistence set (registry persistence beyond Run keys,
// and service installation) is picked up by the existing
// execution-then-persistence temporal rule, not just Run keys/scheduled
// tasks.
func TestExecutionThenPersistence_ExtendedPersistenceTypes(t *testing.T) {
	base := mustTime("2026-01-15T09:15:10Z")
	events := []model.Event{
		{ID: "create", EventType: model.EventProcessCreate, CaseID: "case", CollectionID: "acq", Host: "H1", ProcessName: "svc.exe", Timestamp: base},
		{ID: "svcinstall", EventType: model.EventServiceInstall, CaseID: "case", CollectionID: "acq", Host: "H1", ProcessName: "svc.exe", Extra: map[string]string{"service_name": "WeirdSvc"}, Timestamp: base.Add(30 * time.Second)},
	}
	f := executionThenPersistence{}.Evaluate(events)
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1 for execution followed by service install", len(f))
	}
	if !containsStr(f[0].Techniques, "T1543.003") {
		t.Errorf("techniques = %v, want T1543.003 for service-install persistence", f[0].Techniques)
	}
}

// TestBenignAdministrativeActivity_DoesNotBecomeHighConfidence is Phase
// 4F/4G's required negative-space validation: a plausible day of ordinary
// IT administrative activity -- standard-path software installs, RDP
// administration, an explicit-credential mapped drive, a scheduled
// maintenance task, PowerShell running an unremarkable local script --
// must not produce any high-severity, high-confidence finding across the
// full Phase 4 rule set. Individual low-confidence observations are fine
// and expected; a false HIGH/HIGH verdict on pure benign administrative
// evidence would be exactly the failure mode this phase explicitly
// guards against.
func TestBenignAdministrativeActivity_DoesNotBecomeHighConfidence(t *testing.T) {
	base := mustTime("2026-01-15T10:00:00Z")
	events := []model.Event{
		// Admin RDPs in.
		{ID: "logon", EventType: model.EventLogonSuccess, Host: "WKSTN-100", User: "admin", Extra: map[string]string{"logon_type": "10"}, Timestamp: base},
		// Admin is granted privileges at logon (routine for an admin account).
		{ID: "priv", EventType: model.EventPrivilegedLogon, Host: "WKSTN-100", User: "admin", Timestamp: base.Add(1 * time.Second)},
		// Admin uses a mapped drive with alternate credentials.
		{ID: "explicit", EventType: model.EventLogonExplicitCreds, Host: "WKSTN-100", User: "admin", ProcessPath: `C:\Windows\explorer.exe`, Extra: map[string]string{"target_user_name": "fileshare-svc", "target_server_name": "FILESRV01"}, Timestamp: base.Add(2 * time.Second)},
		// Admin installs a standard piece of software (standard path, no
		// script interpreter involved).
		{ID: "install", EventType: model.EventProcessCreate, Host: "WKSTN-100", User: "admin", ProcessName: "setup.exe", ProcessPath: `C:\Program Files\Vendor\setup.exe`, ParentProcessName: "explorer.exe", Timestamp: base.Add(1 * time.Minute)},
		// A scheduled maintenance task from a standard location.
		{ID: "task", EventType: model.EventScheduledTaskCreate, Host: "WKSTN-100", User: "SYSTEM", ProcessName: "cleanmgr.exe", ProcessPath: `C:\Windows\System32\cleanmgr.exe`, CommandLine: `C:\Windows\System32\cleanmgr.exe /sagerun:1`, Timestamp: base.Add(2 * time.Minute)},
		// A benign PowerShell invocation with no suspicious indicators.
		{ID: "ps", EventType: model.EventProcessCreate, Host: "WKSTN-100", User: "admin", ProcessName: "powershell.exe", ProcessPath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, CommandLine: `powershell.exe -File C:\Scripts\Get-DiskSpace.ps1`, ParentProcessName: "explorer.exe", Timestamp: base.Add(3 * time.Minute)},
		// A standard Windows Update service install.
		{ID: "svc", EventType: model.EventServiceInstall, Host: "WKSTN-100", ProcessName: "usoclient.exe", FilePath: `C:\Windows\System32\usoclient.exe`, Extra: map[string]string{"service_name": "UsoSvc", "start_type": "auto start"}, Timestamp: base.Add(4 * time.Minute)},
	}

	findings := Run("case-benign", events)
	for _, f := range findings {
		if f.Severity == model.SeverityHigh || f.Severity == model.SeverityCritical {
			if f.Confidence == model.ConfidenceHigh {
				t.Errorf("benign administrative activity produced a high-severity/high-confidence finding: %s (%s): %s", f.RuleID, f.Title, f.Description)
			}
		}
	}
}

func containsStr(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}
