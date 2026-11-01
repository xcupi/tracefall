package winevent_test

import (
	"fmt"
	"strings"
	"testing"

	"tracefall/internal/parsers/winevent"
)

func secIn(id int, d map[string]string) winevent.Input {
	return winevent.Input{Channel: "Security", Provider: securityProvider, EventID: id, Data: d}
}

func exit4689() map[string]string {
	return map[string]string{
		"SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectUserName": "alice", "SubjectDomainName": "LAB", "SubjectLogonId": "0x3e7a1",
		"Status": "0x0", "ProcessId": "0x1a2c", "ProcessName": `C:\Windows\System32\cmd.exe`,
	}
}

func TestSecurity4689_ProcessExit(t *testing.T) {
	in := secIn(4689, exit4689())
	e, ok := g02Direct(in)
	if !ok {
		t.Fatal("4689 not mapped")
	}
	g02Expect(t, e, "process_exit", "alice", "", map[string]string{
		"logon_id": "0x3e7a1", "subject_domain": "LAB", "actor_sid": "S-1-5-21-1-2-3-1001", "exit_status": "0x0",
		"process_path": `C:\Windows\System32\cmd.exe`,
	})
	if e.PID != 6700 || e.ProcessName != "cmd.exe" || e.ProcessPath != `C:\Windows\System32\cmd.exe` {
		t.Errorf("pid/name/path = %d/%q/%q", e.PID, e.ProcessName, e.ProcessPath)
	}
	for _, c := range []string{"does not establish", "reuse"} {
		if !strings.Contains(e.Extra["limitations"], c) {
			t.Errorf("limitations lacks %q: %q", c, e.Extra["limitations"])
		}
	}
	g02Parity(t, in)
	g02Gate(t, in)
	// Status "0x0" and a non-zero status are recorded exactly; a missing Status is not zero.
	for _, s := range []string{"0x0", "0xc000013a", "0", "", "-"} {
		d := exit4689()
		d["Status"] = s
		if e, _ := g02Direct(secIn(4689, d)); func() bool { v, r := e.Extra["exit_status"]; return !r || v != s }() {
			t.Errorf("status %q not recorded literally: %q", s, e.Extra["exit_status"])
		}
	}
	d := exit4689()
	delete(d, "Status")
	if e, _ := g02Direct(secIn(4689, d)); func() bool { _, r := e.Extra["exit_status"]; return r }() {
		t.Error("absent Status invented")
	}
	if _, ok := g02Direct(secIn(4689, map[string]string{"SubjectUserName": "alice", "Status": "0x0"})); ok {
		t.Error("4689 without a process mapped")
	}
}

// 4689 carries what a 4688 carries (PID, logon id, executable path) under the
// same fields so a reader can match them; this change performs NO join.
func TestSecurity4689_FieldsAlignWith4688(t *testing.T) {
	create, ok := g02Direct(secIn(4688, map[string]string{
		"SubjectUserName": "alice", "SubjectDomainName": "LAB", "SubjectLogonId": "0x3e7a1", "NewProcessId": "0x1a2c",
		"NewProcessName": `C:\Windows\System32\cmd.exe`, "ProcessId": "0x400", "ParentProcessName": `C:\Windows\explorer.exe`, "CommandLine": "cmd.exe /c exit",
	}))
	if !ok {
		t.Fatal("4688 not mapped")
	}
	exit, _ := g02Direct(secIn(4689, exit4689()))
	if create.PID != exit.PID || create.ProcessPath != exit.ProcessPath || create.Extra["logon_id"] != exit.Extra["logon_id"] || create.User != exit.User {
		t.Errorf("4688/4689 keys do not line up: %d/%q/%q vs %d/%q/%q", create.PID, create.ProcessPath, create.Extra["logon_id"], exit.PID, exit.ProcessPath, exit.Extra["logon_id"])
	}
	if exit.Extra["parent_process_id"] != "" || exit.CommandLine != "" || exit.ParentProcessName != "" || exit.PPID != 0 {
		t.Errorf("4689 must not carry process-creation attribution: %+v", exit)
	}
}

func adj4703() map[string]string {
	return map[string]string{
		"SubjectUserSid": "S-1-5-18", "SubjectUserName": "HOST01$", "SubjectDomainName": "LAB", "SubjectLogonId": "0x3e7",
		"TargetUserSid": "S-1-5-21-1-2-3-1001", "TargetUserName": "alice", "TargetDomainName": "LAB", "TargetLogonId": "0x3e7a1",
		"ProcessName": `C:\Windows\System32\svchost.exe`, "ProcessId": "0x2f0",
		"EnabledPrivilegeList": "SeDebugPrivilege\n\t\t\tSeChangeNotifyPrivilege", "DisabledPrivilegeList": "-",
	}
}

func TestSecurity4703_TokenRightAdjusted(t *testing.T) {
	in := secIn(4703, adj4703())
	e, ok := g02Direct(in)
	if !ok {
		t.Fatal("4703 not mapped")
	}
	g02Expect(t, e, "token_right_adjusted", "HOST01$", "", map[string]string{
		"logon_id": "0x3e7", "actor_domain": "LAB", "actor_sid": "S-1-5-18",
		"target_user_name": "alice", "target_domain": "LAB", "target_user_sid": "S-1-5-21-1-2-3-1001", "target_logon_id": "0x3e7a1",
		"enabled_privileges": "SeDebugPrivilege,SeChangeNotifyPrivilege", "disabled_privileges": "-",
		"process_path": `C:\Windows\System32\svchost.exe`,
	})
	if e.PID != 752 || e.ProcessName != "svchost.exe" {
		t.Errorf("pid/name = %d/%q", e.PID, e.ProcessName)
	}
	for _, c := range []string{"does not establish", "escalation"} {
		if !strings.Contains(e.Extra["limitations"], c) {
			t.Errorf("limitations lacks %q: %q", c, e.Extra["limitations"])
		}
	}
	g02Parity(t, in)
	g02Gate(t, in)
	// "-" (recorded none) and "" are preserved; a missing list is absent.
	d := adj4703()
	d["DisabledPrivilegeList"] = ""
	if e, _ := g02Direct(secIn(4703, d)); func() bool { v, r := e.Extra["disabled_privileges"]; return !r || v != "" }() {
		t.Error("empty list not preserved")
	}
	delete(d, "DisabledPrivilegeList")
	if e, _ := g02Direct(secIn(4703, d)); func() bool { _, r := e.Extra["disabled_privileges"]; return r }() {
		t.Error("absent list invented")
	}
	// A long list is bounded and said so.
	var names []string
	for i := 0; i < 400; i++ {
		names = append(names, fmt.Sprintf("SePrivilegeNumber%03d", i))
	}
	d = adj4703()
	d["EnabledPrivilegeList"] = strings.Join(names, "\n\t\t\t")
	e, _ = g02Direct(secIn(4703, d))
	if n := len(e.Extra["enabled_privileges"]); n == 0 || n > 1100 || e.Extra["enabled_privileges_truncated"] != "true" {
		t.Errorf("privilege list len %d truncated=%q", n, e.Extra["enabled_privileges_truncated"])
	}
	if _, ok := g02Direct(secIn(4703, map[string]string{"SubjectUserName": "x", "ProcessName": `C:\x.exe`})); ok {
		t.Error("4703 with no privilege list mapped")
	}
	// Distinct privilege sets at one instant stay distinct.
	other := adj4703()
	other["EnabledPrivilegeList"] = "SeBackupPrivilege"
	g02Distinct(t, in, secIn(4703, other))
	other = adj4703()
	other["DisabledPrivilegeList"] = "SeDebugPrivilege"
	g02Distinct(t, in, secIn(4703, other))
	// Same ID, different provider: untouched.
	if e, ok := g02Direct(winevent.Input{Channel: "Security", Provider: "Other", EventID: 4703, Data: adj4703()}); ok || e.EventType != "" {
		t.Error("4703 mapped under another provider")
	}
}

func TestSecurity4689Identity(t *testing.T) {
	a := exit4689()
	b := exit4689()
	b["Status"] = "0xc000013a"
	g02Distinct(t, secIn(4689, a), secIn(4689, b))
	c := exit4689()
	c["ProcessName"] = `C:\Windows\System32\other.exe`
	g02Distinct(t, secIn(4689, a), secIn(4689, c))
	d := exit4689()
	d["SubjectLogonId"] = "0x3e7a2"
	g02Distinct(t, secIn(4689, a), secIn(4689, d))
}

// ---- PowerShell 4100 ----

const (
	psOpChannel  = "Microsoft-Windows-PowerShell/Operational"
	psOpProvider = "Microsoft-Windows-PowerShell"
)

func ps4100() map[string]string {
	ctx := strings.Join([]string{
		"        Severity = Warning",
		"        Host Name = ConsoleHost",
		"        Host Version = 5.1.19041.1",
		"        Host ID = {AAAAAAAA-0000-4000-8000-000000000031}",
		`        Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File C:\Users\alice\run.ps1`,
		"        Engine Version = 5.1.19041.1",
		"        Runspace ID = {AAAAAAAA-0000-4000-8000-000000000032}",
		"        Pipeline ID = 7",
		"        Command Name = Get-Missing",
		"        Command Type = Cmdlet",
		`        Script Name = C:\Users\alice\run.ps1`,
		"        Command Path = ",
		"        Sequence Number = 15",
		`        User = LAB\alice`,
		"        Connected User = ",
		"        Shell ID = Microsoft.PowerShell",
		"",
	}, "\n")
	return map[string]string{
		"ContextInfo": ctx, "UserData": "",
		"Payload": "Error Message = The term 'Get-Missing' is not recognized\nFully Qualified Error ID = CommandNotFoundException",
	}
}

func psIn(d map[string]string) winevent.Input {
	return winevent.Input{Channel: psOpChannel, Provider: psOpProvider, EventID: 4100, Data: d}
}

func TestPowerShell4100_PipelineError(t *testing.T) {
	in := psIn(ps4100())
	e, ok := g02Direct(in)
	if !ok {
		t.Fatal("4100 not mapped")
	}
	g02Expect(t, e, "powershell_pipeline_error", `LAB\alice`, "", map[string]string{
		"severity": "Warning", "host_name": "ConsoleHost", "command_name": "Get-Missing", "command_type": "Cmdlet",
		"script_name": `C:\Users\alice\run.ps1`, "pipeline_id": "7", "runspace_id": "{AAAAAAAA-0000-4000-8000-000000000032}",
		"sequence_number": "15", "context_user": `LAB\alice`, "connected_user": "", "command_path": "",
		"host_application":         `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File C:\Users\alice\run.ps1`,
		"error_message":            "The term 'Get-Missing' is not recognized",
		"fully_qualified_error_id": "CommandNotFoundException",
	})
	if e.CommandLine != "" {
		t.Errorf("an error record is not a command: CommandLine = %q", e.CommandLine)
	}
	for _, c := range []string{"does not establish", "not a command"} {
		if !strings.Contains(e.Extra["limitations"], c) {
			t.Errorf("limitations lacks %q: %q", c, e.Extra["limitations"])
		}
	}
	if !strings.Contains(e.Extra["context_info"], "Severity = Warning") {
		t.Errorf("bounded context_info missing: %q", e.Extra["context_info"])
	}
	g02Parity(t, in)
	g02Gate(t, in)
}

func TestPowerShell4100_BoundedRedactedAndPartial(t *testing.T) {
	d := ps4100()
	d["ContextInfo"] = strings.Replace(d["ContextInfo"], "-File C:", "--password=hunter2 -File C:", 1)
	d["Payload"] = "Error Message = connect failed password=hunter2\nFully Qualified Error ID = X"
	e, _ := g02Direct(psIn(d))
	for _, k := range []string{"host_application", "error_message", "context_info"} {
		if strings.Contains(e.Extra[k], "hunter2") {
			t.Errorf("%s kept a secret: %q", k, e.Extra[k])
		}
	}
	d = ps4100()
	d["ContextInfo"] = "        Severity = Warning\n" + strings.Repeat("        Filler Line = "+strings.Repeat("Q", 200)+"\n", 400)
	d["Payload"] = "Error Message = " + strings.Repeat("E", 20000)
	e, _ = g02Direct(psIn(d))
	if n := len(e.Extra["context_info"]); n == 0 || n > 520 {
		t.Errorf("context_info len %d is not bounded", n)
	}
	if n := len(e.Extra["error_message"]); n == 0 || n > 520 {
		t.Errorf("error_message len %d is not bounded", n)
	}
	// Labels not in the record stay absent; a payload without a fully qualified id has none.
	e, _ = g02Direct(psIn(map[string]string{"ContextInfo": "        Severity = Error\n", "Payload": "Error Message = boom"}))
	for _, k := range []string{"host_name", "command_name", "script_name", "fully_qualified_error_id", "context_user"} {
		if _, rec := e.Extra[k]; rec {
			t.Errorf("%s was invented", k)
		}
	}
	if e.Extra["severity"] != "Error" || e.Extra["error_message"] != "boom" {
		t.Errorf("partial record lost its fields: %+v", e.Extra)
	}
	if _, ok := g02Direct(psIn(map[string]string{"ContextInfo": "", "UserData": "", "Payload": ""})); ok {
		t.Error("empty 4100 mapped")
	}
	// Distinct pipelines/errors at the same instant stay distinct.
	other := ps4100()
	other["Payload"] = "Error Message = another\nFully Qualified Error ID = Other"
	g02Distinct(t, psIn(ps4100()), psIn(other))
}

// Lifecycle noise is deliberately not mapped, nor is 4100 under another provider/channel.
func TestPowerShellLifecycleIDsStayUnmapped(t *testing.T) {
	for _, id := range []int{8196, 12039, 40961, 40962, 53504} {
		if e, ok := g02Direct(winevent.Input{Channel: psOpChannel, Provider: psOpProvider, EventID: id, Data: map[string]string{"param1": "a", "param2": "b"}}); ok || e.EventType != "" {
			t.Errorf("%d mapped", id)
		}
	}
	for _, in := range []winevent.Input{
		{Channel: "Windows PowerShell", Provider: "PowerShell", EventID: 4100, Data: ps4100()},
		{Channel: psOpChannel, Provider: "Other", EventID: 4100, Data: ps4100()},
	} {
		if e, ok := g02Direct(in); ok || e.EventType != "" {
			t.Errorf("4100 mapped for %s/%s", in.Channel, in.Provider)
		}
	}
}
