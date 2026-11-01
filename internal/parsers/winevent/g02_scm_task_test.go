package winevent_test

import (
	"strings"
	"testing"

	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/parsers/winevent"
)

const (
	scmChannel  = "System"
	scmProvider = "Service Control Manager"
)

func scmInput(id int, data map[string]string) winevent.Input {
	return winevent.Input{Channel: scmChannel, Provider: scmProvider, EventID: id, Data: data}
}

// 7031 is positional. Each value below is distinct so a shifted index cannot
// hide: param1 service, param2 times terminated, param3 delay in ms, param4 the
// recovery action code, param5 the recovery action text.
func TestSCM7031_PositionalContract(t *testing.T) {
	data := map[string]string{"param1": "Example Service", "param2": "2", "param3": "5000", "param4": "3", "param5": "Run a program"}
	in := scmInput(7031, data)
	e, ok := g02Direct(in)
	if !ok {
		t.Fatal("7031 not mapped")
	}
	g02Expect(t, e, "service_message", "", "", map[string]string{
		"service_name": "Example Service", "termination_count": "2", "corrective_action_delay_ms": "5000",
		"recovery_action_code": "3", "recovery_action": "Run a program",
		"action": "service_terminated_unexpectedly", "outcome": "observed",
	}, "service_error_ref", "service_state", "start_type")
	for _, c := range []string{"does not establish", "attack"} {
		if !strings.Contains(e.Extra["limitations"], c) {
			t.Errorf("limitations lacks %q: %q", c, e.Extra["limitations"])
		}
	}
	g02Parity(t, in)
	g02Gate(t, in)
	// A zero count and an empty action text are recorded values, not absence.
	e, _ = g02Direct(scmInput(7031, map[string]string{"param1": "S", "param2": "0", "param3": "0", "param4": "0", "param5": ""}))
	for k, v := range map[string]string{"termination_count": "0", "corrective_action_delay_ms": "0", "recovery_action_code": "0", "recovery_action": ""} {
		if got, rec := e.Extra[k]; !rec || got != v {
			t.Errorf("%s = %q recorded=%v, want literal %q", k, got, rec, v)
		}
	}
	// A record missing trailing params keeps only what it carries.
	e, _ = g02Direct(scmInput(7031, map[string]string{"param1": "S", "param2": "1"}))
	for _, k := range []string{"corrective_action_delay_ms", "recovery_action_code", "recovery_action"} {
		if _, rec := e.Extra[k]; rec {
			t.Errorf("%s must be absent when the record lacks it", k)
		}
	}
	// Without a service the record is under-specified.
	for _, d := range []map[string]string{{}, {"param2": "1", "param3": "5000"}, {"param1": " "}, {"Data1": "Example Service"}} {
		if _, ok := g02Direct(scmInput(7031, d)); ok {
			t.Errorf("under-specified 7031 mapped: %v", d)
		}
	}
	// The binary tail the real layout carries is not a parameter.
	e, _ = g02Direct(scmInput(7031, map[string]string{"param1": "S", "Data6": "53004500"}))
	if e.Extra["service_name"] != "S" {
		t.Error("unnamed binary tail disturbed param1")
	}
}

func TestSCM7024_PositionalContract(t *testing.T) {
	data := map[string]string{"param1": "Example Service", "param2": "%%1067"}
	in := scmInput(7024, data)
	e, ok := g02Direct(in)
	if !ok {
		t.Fatal("7024 not mapped")
	}
	g02Expect(t, e, "service_message", "", "", map[string]string{
		"service_name": "Example Service", "service_error_ref": "%%1067", "action": "service_terminated_with_error", "outcome": "observed",
	}, "termination_count", "corrective_action_delay_ms", "recovery_action_code", "recovery_action")
	if !strings.Contains(e.Extra["limitations"], "does not establish") {
		t.Error("limitations must disclaim intent")
	}
	g02Parity(t, in)
	g02Gate(t, in)
	// param3.. of a 7031 layout must not be read by 7024, nor param2 as a count.
	e, _ = g02Direct(scmInput(7024, map[string]string{"param1": "S", "param2": "%%5", "param3": "5000", "param5": "x"}))
	if _, rec := e.Extra["corrective_action_delay_ms"]; rec {
		t.Error("7024 read a 7031 position")
	}
	if _, ok := g02Direct(scmInput(7024, map[string]string{"param2": "%%5"})); ok {
		t.Error("7024 without a service mapped")
	}
}

// The same IDs under another provider or channel are not Service Control
// Manager records, and the existing 7036/7040 mapping is unchanged.
func TestSCM_OtherProvidersAndExistingIDs(t *testing.T) {
	for _, id := range []int{7031, 7024} {
		for _, bad := range []winevent.Input{
			{Channel: "Application", Provider: scmProvider, EventID: id, Data: map[string]string{"param1": "S"}},
			{Channel: scmChannel, Provider: "Some-Other-Provider", EventID: id, Data: map[string]string{"param1": "S"}},
		} {
			if e, ok := g02Direct(bad); ok || e.EventType != "" {
				t.Errorf("id %d mapped for %s/%s", id, bad.Channel, bad.Provider)
			}
		}
	}
	e, ok := g02Direct(scmInput(7036, map[string]string{"param1": "Example Service", "param2": "running"}))
	if !ok || e.Extra["action"] != "service_state_changed" || e.Extra["service_state"] != "running" {
		t.Errorf("7036 changed: %+v", e.Extra)
	}
}

func TestSCMIdentity(t *testing.T) {
	g02Distinct(t, scmInput(7031, map[string]string{"param1": "Service A", "param2": "1", "param3": "30000", "param4": "1", "param5": "Restart the service"}),
		scmInput(7031, map[string]string{"param1": "Service B", "param2": "1", "param3": "30000", "param4": "1", "param5": "Restart the service"}))
	g02Distinct(t, scmInput(7031, map[string]string{"param1": "Service A", "param2": "1", "param3": "30000", "param4": "1", "param5": "Restart the service"}),
		scmInput(7031, map[string]string{"param1": "Service A", "param2": "2", "param3": "30000", "param4": "1", "param5": "Restart the service"}))
	g02Distinct(t, scmInput(7024, map[string]string{"param1": "Service A", "param2": "%%1"}), scmInput(7024, map[string]string{"param1": "Service A", "param2": "%%2"}))
}

// ---- Task Scheduler 107 / 108 / 110 / 119 / 322 ----

const inst1 = "{AAAAAAAA-0000-4000-8000-000000000001}"

func taskIn(id int, data map[string]string) winevent.Input {
	return winevent.Input{Channel: taskChannel, Provider: taskProvider, EventID: id, Data: data}
}

// Microsoft's message templates (Task Scheduler event table) say 107 launched
// an instance "due to a time trigger", 108 "triggered by an event trigger",
// 110 "for user", 119 "due to user logon", and 322 "did not launch ... because
// instance ... of the same task is already running". The type is NOT
// scheduled_task_run: a trigger or an ignored launch is not a recorded run.
func TestTaskLaunchRecords(t *testing.T) {
	for _, tc := range []struct {
		id      int
		data    map[string]string
		user    string
		want    map[string]string
		absent  []string
		meaning string
	}{
		{107, map[string]string{"TaskName": `\Maintenance\Cleanup`, "InstanceId": inst1}, "",
			map[string]string{"action": "task_launched_time_trigger", "task_name": `\Maintenance\Cleanup`, "task_instance_id": inst1, "outcome": "observed"},
			[]string{"user_context", "logon_user", "existing_instance_id"}, "time trigger"},
		{108, map[string]string{"TaskName": `\Maintenance\Cleanup`, "InstanceId": inst1}, "",
			map[string]string{"action": "task_launched_event_trigger", "task_name": `\Maintenance\Cleanup`, "task_instance_id": inst1, "outcome": "observed"},
			[]string{"user_context", "logon_user", "existing_instance_id"}, "event trigger"},
		{110, map[string]string{"TaskName": `\Maintenance\Cleanup`, "InstanceId": inst1, "UserContext": `LAB\alice`}, `LAB\alice`,
			map[string]string{"action": "task_launched_for_user", "task_name": `\Maintenance\Cleanup`, "task_instance_id": inst1, "user_context": `LAB\alice`, "outcome": "observed"},
			[]string{"logon_user", "existing_instance_id"}, "for user"},
		{119, map[string]string{"TaskName": `\Maintenance\Cleanup`, "UserName": `LAB\alice`, "InstanceId": inst1}, `LAB\alice`,
			map[string]string{"action": "task_launched_logon_trigger", "task_name": `\Maintenance\Cleanup`, "task_instance_id": inst1, "logon_user": `LAB\alice`, "outcome": "observed"},
			[]string{"user_context", "existing_instance_id"}, "logon"},
		{322, map[string]string{"TaskName": `\Maintenance\Cleanup`, "TaskInstanceId": inst1}, "",
			map[string]string{"action": "task_launch_ignored_instance_running", "task_name": `\Maintenance\Cleanup`, "existing_instance_id": inst1, "outcome": "ignored"},
			[]string{"task_instance_id", "user_context", "logon_user"}, "ignored"},
	} {
		t.Run(string(rune('0'+tc.id%10))+"/"+tc.meaning, func(t *testing.T) {
			in := taskIn(tc.id, tc.data)
			e, ok := g02Direct(in)
			if !ok {
				t.Fatal("not mapped")
			}
			g02Expect(t, e, "scheduled_task_launch", tc.user, "", tc.want, tc.absent...)
			if !strings.Contains(strings.ToLower(e.Extra["evidence_meaning"]), tc.meaning) {
				t.Errorf("meaning lacks %q: %q", tc.meaning, e.Extra["evidence_meaning"])
			}
			for _, c := range []string{"does not establish"} {
				if !strings.Contains(e.Extra["limitations"], c) {
					t.Errorf("limitations lacks %q: %q", c, e.Extra["limitations"])
				}
			}
			g02Parity(t, in)
			g02Gate(t, in)
		})
	}
	// 322 must never read as a run, and says so.
	e, _ := g02Direct(taskIn(322, map[string]string{"TaskName": `\T`, "TaskInstanceId": inst1}))
	if !strings.Contains(e.Extra["limitations"], "not launch") && !strings.Contains(e.Extra["limitations"], "did not run") {
		t.Errorf("322 limitations must say the launch did not happen: %q", e.Extra["limitations"])
	}
	// Absent InstanceId stays absent; a recorded empty one stays empty.
	e, _ = g02Direct(taskIn(107, map[string]string{"TaskName": `\T`}))
	if _, rec := e.Extra["task_instance_id"]; rec {
		t.Error("absent InstanceId was invented")
	}
	e, _ = g02Direct(taskIn(110, map[string]string{"TaskName": `\T`, "InstanceId": "", "UserContext": ""}))
	if v, rec := e.Extra["task_instance_id"]; !rec || v != "" {
		t.Errorf("empty InstanceId not preserved: %q %v", v, rec)
	}
	if v, rec := e.Extra["user_context"]; !rec || v != "" {
		t.Errorf("empty UserContext not preserved: %q %v", v, rec)
	}
	// 322 carries TaskInstanceId; 107 carries InstanceId. A 107 with the 322 name is not read.
	if e, _ := g02Direct(taskIn(107, map[string]string{"TaskName": `\T`, "TaskInstanceId": inst1})); e.Extra["task_instance_id"] != "" {
		t.Error("107 read the 322 field name")
	}
	if e, _ := g02Direct(taskIn(322, map[string]string{"TaskName": `\T`, "InstanceId": inst1})); e.Extra["existing_instance_id"] != "" {
		t.Error("322 read the 107 field name")
	}
	for _, id := range []int{107, 108, 110, 119, 322} {
		for _, d := range []map[string]string{{}, {"InstanceId": inst1}, {"TaskName": "  "}} {
			if _, ok := g02Direct(taskIn(id, d)); ok {
				t.Errorf("under-specified %d mapped: %v", id, d)
			}
		}
	}
}

func TestTaskLaunchIdentityAndExistingMappingsUnchanged(t *testing.T) {
	g02Distinct(t, taskIn(107, map[string]string{"TaskName": `\T`, "InstanceId": inst1}), taskIn(107, map[string]string{"TaskName": `\T`, "InstanceId": "{AAAAAAAA-0000-4000-8000-000000000002}"}))
	g02Distinct(t, taskIn(107, map[string]string{"TaskName": `\T1`, "InstanceId": inst1}), taskIn(107, map[string]string{"TaskName": `\T2`, "InstanceId": inst1}))
	g02Distinct(t, taskIn(322, map[string]string{"TaskName": `\T`, "TaskInstanceId": inst1}), taskIn(322, map[string]string{"TaskName": `\T`, "TaskInstanceId": "{AAAAAAAA-0000-4000-8000-000000000002}"}))
	// 107 and 322 of the same task and instance are different kinds of record.
	g02Distinct(t, taskIn(107, map[string]string{"TaskName": `\T`, "InstanceId": inst1}), taskIn(108, map[string]string{"TaskName": `\T`, "InstanceId": inst1}))
	// 100 stays a task run, 106 stays a configuration change.
	evs := parseNative(t, []evtxgen.Event{
		{RecordID: 1, Timestamp: crossTime, Computer: "host01", Channel: taskChannel, Provider: taskProvider, EventID: 100, Data: map[string]string{"TaskName": `\T`, "UserContext": "alice", "InstanceId": inst1}},
		{RecordID: 2, Timestamp: crossTime, Computer: "host01", Channel: taskChannel, Provider: taskProvider, EventID: 106, Data: map[string]string{"TaskName": `\T`, "UserName": "alice"}},
	})
	if len(evs) != 2 || evs[0].EventType != "scheduled_task_run" || evs[1].EventType != "scheduled_task_change" {
		t.Fatalf("existing task mappings changed: %+v", evs)
	}
}
