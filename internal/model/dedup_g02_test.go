package model

import (
	"testing"
	"time"
)

// g02LegacyWindowsEvents are Windows event-log events of types that existed
// before the G02 coverage work. Their dedup identity must not change.
func g02LegacyWindowsEvents() map[string]Event {
	ts := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	base := func(typ string, id int, extra map[string]string) Event {
		extra["evtx_record_id"] = "42"
		return Event{EventType: typ, Timestamp: ts, Host: "HOST01", User: "alice", ArtifactType: ArtifactWindowsEventLog, Provider: "System", EventID: id, Extra: extra}
	}
	return map[string]Event{
		"service_message_7036": base(EventServiceMessage, 7036, map[string]string{"service_name": "Example Service", "service_state": "running", "action": "service_state_changed", "outcome": "observed"}),
		"service_message_7040": base(EventServiceMessage, 7040, map[string]string{"service_name": "Example Service", "old_start_type": "auto start", "start_type": "demand start", "action": "service_start_type_changed"}),
		"task_run_100":         base(EventScheduledTaskRun, 100, map[string]string{"task_name": `\T`, "task_instance_id": "{x}", "user_context": "alice", "action": "task_started"}),
		"task_change_106":      base(EventScheduledTaskChange, 106, map[string]string{"task_name": `\T`, "action": "task_registered"}),
		"antimalware_action":   base(EventAntimalwareAction, 1117, map[string]string{"threat_name": "Example", "action_name": "Remove", "config_category": "x", "old_value": "y", "feature_name": "z"}),
		"process_create_4688":  base(EventProcessCreate, 4688, map[string]string{"logon_id": "0x3e7", "subject_domain": "LAB", "process_path": `C:\x.exe`, "exit_status": "0x0"}),
		"event_log_cleared":    base(EventLogCleared, 1102, map[string]string{"cleared_channel": "Security", "action": "log_cleared"}),
		"audit_policy_change":  base(EventAuditPolicyChange, 4719, map[string]string{"audit_policy_changes": "x", "action": "audit_policy_changed"}),
	}
}

// These hashes were computed by the ORIGINAL ComputeDedupHash (the base commit
// of the G02 coverage work) over the fixtures above. New identity keys apply
// only to the new event types, so every one of these must stay byte-identical.
var g02PinnedLegacyHashes = map[string]string{
	"antimalware_action":   "17c17c1286fc1366a9c67d8b0718ff51635ec21b5bc22392daaceb8e8c08149f",
	"audit_policy_change":  "9194637c53d69290f8243cc1942171dc29260af850f00decce09b5b206245e75",
	"event_log_cleared":    "3a41bce87413d4f2c2afdf106c96292291f5c21040bfa77bb5c90fa7e617b154",
	"process_create_4688":  "8627ef4bf2f3311eec4e4ed4f3d7d58aad064847427bde51d15d3265b65ef2aa",
	"service_message_7036": "671089a5f12929c500989fa06d15cd5310bfab7997b98c1b2b82ec5317df85c2",
	"service_message_7040": "90317b5c71dfb2620ae52da141d54105ba7f8ff6fc15f53abba5f382e1df5a7b",
	"task_change_106":      "beb77fce15a86f08951e6c77cd4ce93a1c1ae4b860d9a0934735437b315c6efd",
	"task_run_100":         "7c7b1bcdaaba40983d4b8b1f762108eb6080e3fc69d60f6934a7feb5f894231e",
}

func TestDedupHash_G02LegacyWindowsIdentityUnchanged(t *testing.T) {
	events := g02LegacyWindowsEvents()
	for name, want := range g02PinnedLegacyHashes {
		if got := events[name].ComputeDedupHash(); got != want {
			t.Errorf("%s: dedup identity changed from the historical value\n got %s\nwant %s", name, got, want)
		}
	}
}

func g02New(typ string, id int, extra map[string]string) Event {
	extra["evtx_record_id"] = "42"
	return Event{EventType: typ, Timestamp: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC), Host: "HOST01", ArtifactType: ArtifactWindowsEventLog, Provider: "chan", EventID: id, Extra: extra}
}

// Two records of a new kind that differ only in one identifying field must not
// collapse, and an identical recollection must still collapse. Each case also
// ties on time, host, user and process, and carries the same record number, so
// only the named field can tell them apart.
func TestDedupHash_G02NewTypesKeepDistinguishingFields(t *testing.T) {
	for _, tc := range []struct {
		typ   string
		id    int
		field string
	}{
		{EventAntimalwareConfigChange, 5007, "new_value"}, {EventAntimalwareConfigChange, 5004, "configuration"},
		{EventAntimalwareHistoryDeleted, 1013, "history_deleted_time_recorded"},
		{EventWMIActivity, 5858, "operation"}, {EventWMIActivity, 5860, "query"}, {EventWMIActivity, 5858, "result_code"},
		{EventScheduledTaskLaunch, 107, "task_instance_id"}, {EventScheduledTaskLaunch, 322, "existing_instance_id"}, {EventScheduledTaskLaunch, 107, "task_name"},
		{EventSMBSecurity, 551, "session_id"}, {EventSMBSecurity, 551, "status"}, {EventSMBSecurity, 551, "client_name"},
		{EventTokenRightAdjusted, 4703, "enabled_privileges"}, {EventTokenRightAdjusted, 4703, "disabled_privileges"},
		{EventProcessExit, 4689, "exit_status"},
		{EventPowerShellPipelineError, 4100, "error_message"}, {EventPowerShellPipelineError, 4100, "pipeline_id"},
		{EventServiceMessage, 7031, "service_name"}, {EventServiceMessage, 7031, "termination_count"}, {EventServiceMessage, 7024, "service_error_ref"},
	} {
		t.Run(tc.typ+"/"+tc.field, func(t *testing.T) {
			a := g02New(tc.typ, tc.id, map[string]string{tc.field: "one"})
			b := g02New(tc.typ, tc.id, map[string]string{tc.field: "two"})
			c := g02New(tc.typ, tc.id, map[string]string{tc.field: "one"})
			if a.ComputeDedupHash() == b.ComputeDedupHash() {
				t.Error("two records differing only in this field collapse")
			}
			if a.ComputeDedupHash() != c.ComputeDedupHash() {
				t.Error("an identical recollection no longer collapses")
			}
		})
	}
}

// Service message identity changes only for the two new IDs, never for 7036/7040.
func TestDedupHash_G02ServiceMessageScope(t *testing.T) {
	for _, id := range []int{7036, 7040} {
		a := g02New(EventServiceMessage, id, map[string]string{"service_name": "A", "termination_count": "1"})
		b := g02New(EventServiceMessage, id, map[string]string{"service_name": "B", "termination_count": "2"})
		if a.ComputeDedupHash() != b.ComputeDedupHash() {
			t.Errorf("id %d: identity must not read the new keys", id)
		}
	}
}
