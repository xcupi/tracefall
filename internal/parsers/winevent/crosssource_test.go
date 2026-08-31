package winevent_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/model"
	nativeevtx "tracefall/internal/parsers/evtx"
	"tracefall/internal/parsers/evtxcsv"
)

// These tests are the Phase 14 guarantee, and the reason
// internal/parsers/winevent exists at all.
//
// The same Windows event record can reach Tracefall two ways: as a raw
// .evtx read natively, or as a row in an EvtxECmd CSV export of that
// same log (possibly inside a ZIP, or inside an AD1). If those two paths
// normalized the record differently -- even in one field that
// Event.ComputeDedupHash covers -- the identical evidence would land as
// TWO events, and every detection rule, correlation and investigation
// would count it twice. An investigator would see a doubled timeline
// with no way to tell which half was real.
//
// So the requirement is precise: identical underlying record ⇒ identical
// DedupHash ⇒ one Event with one EventObservation per source file.
// Provenance is preserved; the count is not inflated.

var crossTime = time.Date(2026, 1, 15, 9, 15, 30, 0, time.UTC)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeBytes(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const csvHeader = "TimeCreated,EventId,Provider,Channel,ComputerName,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,RecordNumber\n"

// TestCrossSource_SameRecordDeduplicates walks the event families both
// sources can carry and requires an identical dedup identity from each.
func TestCrossSource_SameRecordDeduplicates(t *testing.T) {
	cases := []struct {
		name     string
		channel  string
		provider string
		eventID  int
		data     map[string]string
		payload  string
	}{
		{
			name: "Security 4624", channel: "Security", provider: "Microsoft-Windows-Security-Auditing", eventID: 4624,
			data:    map[string]string{"TargetUserName": "jdoe", "LogonType": "3", "IpAddress": "10.4.2.15"},
			payload: "TargetUserName: jdoe; LogonType: 3; IpAddress: 10.4.2.15",
		},
		{
			name: "Security 4625", channel: "Security", provider: "Microsoft-Windows-Security-Auditing", eventID: 4625,
			data:    map[string]string{"TargetUserName": "administrator", "LogonType": "3", "IpAddress": "10.9.9.9"},
			payload: "TargetUserName: administrator; LogonType: 3; IpAddress: 10.9.9.9",
		},
		{
			name: "Security 4672", channel: "Security", provider: "Microsoft-Windows-Security-Auditing", eventID: 4672,
			data:    map[string]string{"SubjectUserName": "administrator", "PrivilegeList": "SeDebugPrivilege"},
			payload: "SubjectUserName: administrator; PrivilegeList: SeDebugPrivilege",
		},
		{
			name: "Security 4776", channel: "Security", provider: "Microsoft-Windows-Security-Auditing", eventID: 4776,
			data:    map[string]string{"TargetUserName": "jdoe", "Workstation": "WKSTN-042"},
			payload: "TargetUserName: jdoe; Workstation: WKSTN-042",
		},
		{
			name: "System 7045 service install", channel: "System", provider: "Service Control Manager", eventID: 7045,
			data:    map[string]string{"ServiceName": "AcmeSvc", "ImagePath": `C:\Windows\Temp\acme.exe`},
			payload: `ServiceName: AcmeSvc; ImagePath: C:\Windows\Temp\acme.exe`,
		},
		{
			name: "Sysmon 1 process create", channel: "Microsoft-Windows-Sysmon/Operational", provider: "Sysmon", eventID: 1,
			data: map[string]string{
				"Image": `C:\Temp\update.exe`, "ParentImage": `C:\Windows\System32\cmd.exe`,
				"ProcessId": "8260", "ParentProcessId": "1000",
			},
			payload: `Image: C:\Temp\update.exe; ParentImage: C:\Windows\System32\cmd.exe; ProcessId: 8260; ParentProcessId: 1000`,
		},
		{
			name: "Sysmon 3 network connect", channel: "Microsoft-Windows-Sysmon/Operational", provider: "Sysmon", eventID: 3,
			data: map[string]string{
				"Image": `C:\Temp\update.exe`, "DestinationIp": "203.0.113.77", "DestinationPort": "443", "ProcessId": "8260",
			},
			payload: `Image: C:\Temp\update.exe; DestinationIp: 203.0.113.77; DestinationPort: 443; ProcessId: 8260`,
		},
		{
			name: "Sysmon 22 DNS query", channel: "Microsoft-Windows-Sysmon/Operational", provider: "Sysmon", eventID: 22,
			data:    map[string]string{"Image": `C:\Temp\update.exe`, "QueryName": "c2.example.test"},
			payload: `Image: C:\Temp\update.exe; QueryName: c2.example.test`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Source A: the raw event log.
			logPath := writeBytes(t, "Security.evtx", evtxgen.Build([]evtxgen.Event{{
				RecordID: 1, Timestamp: crossTime,
				Provider: tc.provider, Channel: tc.channel, Computer: "WKSTN-042",
				EventID: tc.eventID, Data: tc.data,
			}}))
			nativeRes, err := nativeevtx.New().Parse(logPath)
			if err != nil {
				t.Fatalf("native parse: %v", err)
			}
			if len(nativeRes.Events) != 1 {
				t.Fatalf("native produced %d events, want 1", len(nativeRes.Events))
			}

			// Source B: EvtxECmd's CSV export of that same record.
			// csvField, not %q: Go quoting would escape the backslashes in
			// a Windows path, which CSV does not do -- and the resulting
			// mangled path would make this test fail for a reason that has
			// nothing to do with the parsers.
			csv := csvHeader + fmt.Sprintf("%s,%d,%s,%s,WKSTN-042,,-,Desc,%s,,,,,,1\n",
				crossTime.Format("2006-01-02T15:04:05.0000000Z"), tc.eventID, tc.provider, tc.channel, csvField(tc.payload))
			csvRes, err := evtxcsv.New().Parse(writeFile(t, "20260115_EvtxECmd_Output.csv", csv))
			if err != nil {
				t.Fatalf("csv parse: %v", err)
			}
			if len(csvRes.Events) != 1 {
				t.Fatalf("csv produced %d events, want 1", len(csvRes.Events))
			}

			native, csvEvent := nativeRes.Events[0], csvRes.Events[0]

			// The identity must match exactly.
			if a, b := native.ComputeDedupHash(), csvEvent.ComputeDedupHash(); a != b {
				t.Errorf("dedup hashes differ, so this one record would be counted twice:\n"+
					"  native: %s\n  csv:    %s\n"+
					"  native event: type=%q host=%q user=%q proc=%q parent=%q pid=%d ppid=%d file=%q reg=%q dest=%q:%d\n"+
					"  csv event:    type=%q host=%q user=%q proc=%q parent=%q pid=%d ppid=%d file=%q reg=%q dest=%q:%d",
					a, b,
					native.EventType, native.Host, native.User, native.ProcessName, native.ParentProcessName,
					native.PID, native.PPID, native.FilePath, native.RegistryPath, native.NetworkDest, native.NetworkDestPort,
					csvEvent.EventType, csvEvent.Host, csvEvent.User, csvEvent.ProcessName, csvEvent.ParentProcessName,
					csvEvent.PID, csvEvent.PPID, csvEvent.FilePath, csvEvent.RegistryPath, csvEvent.NetworkDest, csvEvent.NetworkDestPort)
			}

			// Provenance must NOT match: that is what distinguishes the two
			// observations of the one event, and what deletion works on.
			if native.Parser == csvEvent.Parser {
				t.Errorf("both events claim parser %q; each observation must record which source it came from", native.Parser)
			}
			if native.SourceReference == csvEvent.SourceReference {
				t.Errorf("both events have SourceReference %q; they point into different files", native.SourceReference)
			}
		})
	}
}

// The dedup hash must be sensitive to what actually differs. If two
// genuinely different records collapsed together, evidence would be
// LOST -- the opposite failure, and a worse one.
func TestCrossSource_DifferentRecordsStayDistinct(t *testing.T) {
	base := func(user string, at time.Time) model.Event {
		log := writeBytes(t, "Security.evtx", evtxgen.Build([]evtxgen.Event{{
			RecordID: 1, Timestamp: at,
			Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security", Computer: "WKSTN-042",
			EventID: 4624, Data: map[string]string{"TargetUserName": user, "LogonType": "3"},
		}}))
		res, err := nativeevtx.New().Parse(log)
		if err != nil {
			t.Fatal(err)
		}
		return res.Events[0]
	}

	same := base("jdoe", crossTime)
	otherUser := base("asmith", crossTime)
	otherTime := base("jdoe", crossTime.Add(time.Second))

	if same.ComputeDedupHash() == otherUser.ComputeDedupHash() {
		t.Error("logons by different users collapsed to one identity")
	}
	if same.ComputeDedupHash() == otherTime.ComputeDedupHash() {
		t.Error("logons at different times collapsed to one identity")
	}
}

// A native .evtx and a registry hive describe different artifact types,
// and artifact type is part of event identity -- so registry evidence
// never silently merges with event-log evidence.
func TestCrossSource_RegistryAndEventLogStayDistinct(t *testing.T) {
	log := writeBytes(t, "Security.evtx", evtxgen.Build([]evtxgen.Event{{
		RecordID: 1, Timestamp: crossTime,
		Provider: "Sysmon", Channel: "Microsoft-Windows-Sysmon/Operational", Computer: "WKSTN-042",
		EventID: 13, Data: map[string]string{
			"TargetObject": `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater`,
			"Details":      `C:\Temp\updater.exe`,
		},
	}}))
	res, err := nativeevtx.New().Parse(log)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(res.Events))
	}
	sysmonRegistry := res.Events[0]

	if sysmonRegistry.ArtifactType != model.ArtifactWindowsEventLog {
		t.Errorf("ArtifactType = %q, want %q", sysmonRegistry.ArtifactType, model.ArtifactWindowsEventLog)
	}
	// A hive snapshot of the same key carries ArtifactRegistryHive, so
	// even with identical key path and timestamp the identities differ.
	hiveEvent := sysmonRegistry
	hiveEvent.ArtifactType = model.ArtifactRegistryHive
	if sysmonRegistry.ComputeDedupHash() == hiveEvent.ComputeDedupHash() {
		t.Error("a Sysmon registry event and a hive snapshot collapsed to one identity despite different artifact types")
	}
}

// csvField quotes a value the way CSV does: wrap in double quotes and
// double any embedded quote. Backslashes are literal.
func csvField(v string) string {
	return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
}
