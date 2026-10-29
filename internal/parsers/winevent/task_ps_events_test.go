package winevent_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/model"
	native "tracefall/internal/parsers/evtx"
	"tracefall/internal/parsers/winevent"
)

const (
	taskChannel  = "Microsoft-Windows-TaskScheduler/Operational"
	taskProvider = "Microsoft-Windows-TaskScheduler"
	psChannel    = "Windows PowerShell"
	psProvider   = "PowerShell"
)

// Event 202 reports an action failure; the code text does not determine outcome.
func TestTaskSchedulerActionFailure(t *testing.T) {
	for _, code := range []string{"2147942402", "0", "0x00000000", "1", "unknown", "not-a-number", "-", "0000", ""} {
		t.Run(fmt.Sprintf("code=%q", code), func(t *testing.T) {
			data := map[string]string{"TaskName": `\Maintenance\Cleanup`, "TaskInstanceId": "{aAbBcCdD-0000-0000-0000-000000000001}", "ActionName": `C:\Tools\cleanup.exe`, "EnginePID": "00900", "ResultCode": code}
			assertServerMapping(t, winevent.Input{Channel: taskChannel, Provider: taskProvider, EventID: 202, Data: data}, model.EventScheduledTaskRun, "", "", map[string]string{"action": "task_action_failed", "outcome": "failure", "result_code": code, "task_name": data["TaskName"], "task_instance_id": data["TaskInstanceId"], "action_name": data["ActionName"], "engine_pid": "00900"})
		})
	}
	for _, code := range []string{" 0000 ", "-", "", "malformed:0"} {
		e := model.Event{User: "logging-account"}
		if !winevent.Normalize(&e, winevent.Input{Channel: taskChannel, Provider: taskProvider, EventID: 202, Data: map[string]string{"ResultCode": code}}) || e.Extra["result_code"] != code || e.User != "" {
			t.Fatal("shared input literal/unknown actor not preserved")
		}
		if _, recorded := e.Extra["result_code"]; !recorded {
			t.Fatal("explicit empty token lost")
		}
	}
	for _, data := range []map[string]string{nil, {}, {"TaskName": "  task  ", "TaskInstanceId": "{partial}", "EnginePID": "not-pid"}} {
		e := model.Event{Extra: map[string]string{"timestamp_partial": "Oct 20 12:34"}}
		if !winevent.Normalize(&e, winevent.Input{Channel: taskChannel, Provider: taskProvider, EventID: 202, Data: data}) {
			t.Fatal("partial record should retain the scheduler observation")
		}
		if _, ok := e.Extra["result_code"]; ok {
			t.Fatal("missing ResultCode must not be invented")
		}
		for src, dst := range map[string]string{"TaskName": "task_name", "TaskInstanceId": "task_instance_id", "EnginePID": "engine_pid"} {
			if e.Extra[dst] != data[src] {
				t.Errorf("%s not retained literally", src)
			}
		}
		if e.Extra["outcome"] != "failure" || e.Extra["action"] != "task_action_failed" || !e.Timestamp.IsZero() || e.Extra["timestamp_partial"] != "Oct 20 12:34" {
			t.Fatal("partial fields must not fabricate a time or change the reported outcome")
		}
		if e.User != "" || e.ProcessName != "" || e.CommandLine != "" || e.Extra["process_id"] != "" || e.Extra["privileges"] != "" {
			t.Fatal("action failure is not actor, process-launch or privilege evidence")
		}
		for _, caveat := range []string{"scheduler-reported", "payload", "causality", "maliciousness"} {
			if !strings.Contains(e.Extra["limitations"], caveat) {
				t.Errorf("missing caveat %q", caveat)
			}
		}
	}
}

func TestTaskSchedulerActionFailureRedaction(t *testing.T) {
	for _, id := range []int{200, 201, 202} {
		e := model.Event{}
		if !winevent.Normalize(&e, winevent.Input{Channel: taskChannel, Provider: taskProvider, EventID: id, Data: map[string]string{"ActionName": "net user alice DummySecret123 /add", "UserContext": "alice"}}) {
			t.Fatal("not mapped")
		}
		if strings.Contains(e.Extra["action_name"], "DummySecret123") || e.Extra["action_name"] == "" || e.CommandLine != "" || e.User != "" {
			t.Fatal("action redaction/actor boundary violated")
		}
	}
}

func TestTaskSchedulerExecutionRecords(t *testing.T) {
	for _, tc := range []struct {
		id     int
		user   string
		data   map[string]string
		action string
		want   map[string]string
	}{
		{100, "LAB\\alice", map[string]string{"TaskName": `\Maintenance\Cleanup`, "UserContext": `LAB\alice`, "InstanceId": "{11111111-2222-3333-4444-555555555555}"}, "task_started",
			map[string]string{"task_name": `\Maintenance\Cleanup`, "user_context": `LAB\alice`, "task_instance_id": "{11111111-2222-3333-4444-555555555555}"}},
		{102, "LAB\\alice", map[string]string{"TaskName": `\Maintenance\Cleanup`, "UserContext": `LAB\alice`, "InstanceId": "{11111111-2222-3333-4444-555555555555}"}, "task_completed",
			map[string]string{"task_name": `\Maintenance\Cleanup`, "task_instance_id": "{11111111-2222-3333-4444-555555555555}"}},
		{129, "", map[string]string{"TaskName": `\Maintenance\Cleanup`, "Path": `C:\Tools\cleanup.exe`, "ProcessID": "4242", "Priority": "8"}, "task_process_launched",
			map[string]string{"task_name": `\Maintenance\Cleanup`, "process_id": "4242", "process_path": `C:\Tools\cleanup.exe`}},
		{200, "", map[string]string{"TaskName": `\Maintenance\Cleanup`, "TaskInstanceId": "{11111111-2222-3333-4444-555555555555}", "ActionName": `C:\Tools\cleanup.exe`, "EnginePID": "900"}, "task_action_started",
			map[string]string{"task_name": `\Maintenance\Cleanup`, "task_instance_id": "{11111111-2222-3333-4444-555555555555}", "action_name": `C:\Tools\cleanup.exe`}},
		{201, "", map[string]string{"TaskName": `\Maintenance\Cleanup`, "TaskInstanceId": "{11111111-2222-3333-4444-555555555555}", "ActionName": `C:\Tools\cleanup.exe`, "ResultCode": "2147942401", "EnginePID": "900"}, "task_action_completed",
			map[string]string{"task_name": `\Maintenance\Cleanup`, "task_instance_id": "{11111111-2222-3333-4444-555555555555}", "action_name": `C:\Tools\cleanup.exe`, "result_code": "2147942401"}},
	} {
		t.Run(fmt.Sprint(tc.id), func(t *testing.T) {
			tc.want["action"] = tc.action
			tc.want["outcome"] = "observed"
			assertServerMapping(t, winevent.Input{Channel: taskChannel, Provider: taskProvider, EventID: tc.id, Data: tc.data}, "scheduled_task_run", tc.user, "", tc.want)
		})
	}
}

// Configuration records are not execution: they keep the configuration type.
func TestTaskSchedulerConfigurationRecordsAreNotExecution(t *testing.T) {
	for _, tc := range []struct {
		id     int
		action string
	}{{106, "task_registered"}, {140, "task_updated"}, {141, "task_deleted"}, {142, "task_disabled"}} {
		t.Run(fmt.Sprint(tc.id), func(t *testing.T) {
			assertServerMapping(t, winevent.Input{Channel: taskChannel, Provider: taskProvider, EventID: tc.id, Data: map[string]string{"TaskName": `\Maintenance\Cleanup`, "UserName": `LAB\alice`}}, "scheduled_task_change", `LAB\alice`, "",
				map[string]string{"action": tc.action, "task_name": `\Maintenance\Cleanup`})
			ev := parseNative(t, []evtxgen.Event{{RecordID: 1, Timestamp: crossTime, Computer: "host01", Channel: taskChannel, Provider: taskProvider, EventID: tc.id, Data: map[string]string{"TaskName": `\T`}}})[0]
			if !strings.Contains(ev.Extra["limitations"], "does not establish") && !strings.Contains(ev.Extra["limitations"], "not establish") {
				t.Errorf("limitations must disclaim execution: %q", ev.Extra["limitations"])
			}
		})
	}
}

func parseNative(t *testing.T, recs []evtxgen.Event) []model.Event {
	t.Helper()
	res, err := native.New().Parse(writeBytes(t, "Log.evtx", evtxgen.Build(recs)))
	if err != nil {
		t.Fatal(err)
	}
	return res.Events
}

// Records of one task instance correlate by InstanceId but are never merged.
func TestTaskSchedulerInstanceCorrelationDoesNotMerge(t *testing.T) {
	inst := "{aaaaaaaa-0000-0000-0000-000000000001}"
	evs := parseNative(t, []evtxgen.Event{
		{RecordID: 10, Timestamp: crossTime, Computer: "host01", Channel: taskChannel, Provider: taskProvider, EventID: 100, Data: map[string]string{"TaskName": `\T`, "UserContext": "alice", "InstanceId": inst}},
		{RecordID: 11, Timestamp: crossTime, Computer: "host01", Channel: taskChannel, Provider: taskProvider, EventID: 200, Data: map[string]string{"TaskName": `\T`, "TaskInstanceId": inst, "ActionName": "a.exe"}},
		{RecordID: 12, Timestamp: crossTime, Computer: "host01", Channel: taskChannel, Provider: taskProvider, EventID: 102, Data: map[string]string{"TaskName": `\T`, "UserContext": "alice", "InstanceId": inst}},
	})
	if len(evs) != 3 {
		t.Fatalf("got %d events, want 3 unmerged", len(evs))
	}
	seen := map[string]bool{}
	for _, e := range evs {
		if e.Extra["task_instance_id"] != inst {
			t.Errorf("instance id = %q", e.Extra["task_instance_id"])
		}
		h := e.ComputeDedupHash()
		if seen[h] {
			t.Error("distinct records share a dedup hash")
		}
		seen[h] = true
	}
}

// Two records identical in content and time but with different record numbers stay distinct.
func TestTaskPSRecordNumberIdentity(t *testing.T) {
	for _, tc := range []struct {
		ch, prov string
		id       int
		data     map[string]string
	}{
		{taskChannel, taskProvider, 100, map[string]string{"TaskName": `\T`, "UserContext": "alice", "InstanceId": "{x}"}},
		{psChannel, psProvider, 400, map[string]string{"Data1": "Available", "Data2": "None", "Data3": "HostName=ConsoleHost\nEngineVersion=5.1.1"}},
	} {
		evs := parseNative(t, []evtxgen.Event{
			{RecordID: 1, Timestamp: crossTime, Computer: "host01", Channel: tc.ch, Provider: tc.prov, EventID: tc.id, Data: tc.data},
			{RecordID: 2, Timestamp: crossTime, Computer: "host01", Channel: tc.ch, Provider: tc.prov, EventID: tc.id, Data: tc.data},
			{RecordID: 1, Timestamp: crossTime, Computer: "host01", Channel: tc.ch, Provider: tc.prov, EventID: tc.id, Data: tc.data},
		})
		if len(evs) != 3 {
			t.Fatalf("%d: got %d events", tc.id, len(evs))
		}
		if evs[0].ComputeDedupHash() == evs[1].ComputeDedupHash() {
			t.Errorf("%d: distinct record numbers collapsed", tc.id)
		}
		if evs[0].ComputeDedupHash() != evs[2].ComputeDedupHash() {
			t.Errorf("%d: same record number did not deduplicate", tc.id)
		}
	}
}

// A record without a timestamp stays undated.
func TestTaskPSUndatedStaysUndated(t *testing.T) {
	evs := parseNative(t, []evtxgen.Event{{RecordID: 5, Computer: "host01", Channel: taskChannel, Provider: taskProvider, EventID: 100, Data: map[string]string{"TaskName": `\T`, "InstanceId": "{x}"}}})
	if len(evs) != 1 {
		t.Fatalf("got %d events", len(evs))
	}
	if !evs[0].Timestamp.IsZero() && evs[0].Timestamp.Year() > 1700 {
		t.Errorf("undated record got timestamp %v", evs[0].Timestamp)
	}
	_ = time.Time{}
}

const psDetail = "NewEngineState=Available\r\n\tPreviousEngineState=None\r\n\r\n\tSequenceNumber=13\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1.14393.0\r\n\tHostId=aaaa\r\n\tEngineVersion=5.1.14393.0\r\n\tRunspaceId=bbbb\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine="

func TestPowerShellEngineLifecycle(t *testing.T) {
	host := `HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile`
	for _, tc := range []struct {
		id     int
		data   map[string]string
		action string
		want   map[string]string
	}{
		{400, map[string]string{"Data1": "Available", "Data2": "None", "Data3": psDetail + "\r\n\t" + host}, "engine_started",
			map[string]string{"host_name": "ConsoleHost", "engine_version": "5.1.14393.0", "host_application": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile`}},
		{403, map[string]string{"Data1": "Stopped", "Data2": "Available", "Data3": strings.Replace(psDetail, "NewEngineState=Available", "NewEngineState=Stopped", 1)}, "engine_stopped",
			map[string]string{"host_name": "ConsoleHost", "engine_version": "5.1.14393.0"}},
		{600, map[string]string{"Data1": "Registry", "Data2": "Started", "Data3": "ProviderName=Registry\r\n\tNewProviderState=Started\r\n\r\n\tSequenceNumber=1\r\n\r\n\tHostName=ConsoleHost\r\n\tEngineVersion=5.1.14393.0"}, "provider_started",
			map[string]string{"host_name": "ConsoleHost", "engine_version": "5.1.14393.0", "provider_name": "Registry"}},
	} {
		t.Run(fmt.Sprint(tc.id), func(t *testing.T) {
			tc.want["action"] = tc.action
			tc.want["outcome"] = "observed"
			assertServerMapping(t, winevent.Input{Channel: psChannel, Provider: psProvider, EventID: tc.id, Data: tc.data}, "powershell_engine_lifecycle", "", "", tc.want)
			ev := parseNative(t, []evtxgen.Event{{RecordID: 1, Timestamp: crossTime, Computer: "host01", Channel: psChannel, Provider: psProvider, EventID: tc.id, Data: tc.data}})[0]
			if ev.CommandLine != "" {
				t.Errorf("lifecycle record must not populate CommandLine: %q", ev.CommandLine)
			}
			if !strings.Contains(ev.Extra["limitations"], "not proof") {
				t.Errorf("limitations must state lifecycle is not proof of what ran: %q", ev.Extra["limitations"])
			}
		})
	}
}

func TestPowerShellEngineRedactsHostApplication(t *testing.T) {
	data := map[string]string{"Data3": "HostName=ConsoleHost\r\n\tHostApplication=cmd.exe /c net user alice Secret123Pw /add\r\n\tEngineVersion=5.1"}
	ev := parseNative(t, []evtxgen.Event{{RecordID: 1, Timestamp: crossTime, Computer: "host01", Channel: psChannel, Provider: psProvider, EventID: 400, Data: data}})[0]
	for k, v := range ev.Extra {
		if strings.Contains(v, "Secret123Pw") {
			t.Errorf("secret leaked in Extra[%s]=%q", k, v)
		}
	}
	if ev.Extra["host_application"] == "" {
		t.Error("host_application should be kept (redacted)")
	}
}

func TestPowerShellEngineParsingIsBounded(t *testing.T) {
	big := "HostName=ConsoleHost\r\n\tHostApplication=" + strings.Repeat("A", 1<<20) + "\r\n\tEngineVersion=5.1"
	ev := &model.Event{Extra: map[string]string{}}
	if !winevent.Normalize(ev, winevent.Input{Channel: psChannel, Provider: psProvider, EventID: 400, Data: map[string]string{"Data3": big}}) {
		t.Fatal("not mapped")
	}
	if n := len(ev.Extra["host_application"]); n > 2048 {
		t.Errorf("host_application unbounded: %d bytes", n)
	}
	if ev.Extra["host_name"] != "ConsoleHost" {
		t.Errorf("host_name = %q", ev.Extra["host_name"])
	}
}

// The reserved IDs must not be reinterpreted on a wrong provider or channel.
func TestTaskPSWrongProviderChannelNegative(t *testing.T) {
	for _, id := range []int{100, 102, 106, 129, 140, 141, 142, 200, 201, 202, 400, 403, 600} {
		for _, bad := range []winevent.Input{
			{Channel: "Application", Provider: "Unrelated-Provider", EventID: id},
			{Channel: taskChannel, Provider: psProvider, EventID: id},
			{Channel: psChannel, Provider: taskProvider, EventID: id},
			{Channel: "System", Provider: taskProvider, EventID: id},
			{Channel: "Microsoft-Windows-PowerShell/Operational", Provider: psProvider, EventID: id},
		} {
			e := model.Event{Extra: map[string]string{}}
			if winevent.Normalize(&e, bad) {
				t.Errorf("id %d accepted on %s / %s", id, bad.Channel, bad.Provider)
			}
		}
	}
}
