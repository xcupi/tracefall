package winevent

import (
	"sort"
	"strings"

	"tracefall/internal/cmdsem"
	"tracefall/internal/model"
)

const taskSchedulerProvider = "Microsoft-Windows-TaskScheduler"
const taskSchedulerChannel = "Microsoft-Windows-TaskScheduler/Operational"
const classicPowerShellProvider = "PowerShell"
const classicPowerShellChannel = "Windows PowerShell"

// Bounds for parsing the classic PowerShell Data strings.
const (
	psMaxValueBytes = 16 << 10 // bytes of one Data value that are scanned
	psMaxLines      = 64       // lines scanned per Data value
	psMaxFieldBytes = 512      // bytes kept for one extracted field
)

// normalizeTaskPSEvent maps Task Scheduler and classic PowerShell records.
// These IDs are reserved: on any other provider or channel they are claimed
// but not mapped, so they are never reinterpreted.
func normalizeTaskPSEvent(ev *model.Event, in Input) (handled, mapped bool) {
	p := in.Data
	is := func(channel, provider string) bool {
		return strings.EqualFold(in.Channel, channel) && strings.EqualFold(in.Provider, provider)
	}
	switch in.EventID {
	case 100, 102, 129, 200, 201:
		if !is(taskSchedulerChannel, taskSchedulerProvider) {
			return true, false
		}
		ev.EventType = model.EventScheduledTaskRun
		setExtra(ev, "task_name", p["TaskName"])
		setExtra(ev, "task_instance_id", firstNonEmpty(p["InstanceId"], p["TaskInstanceId"]))
		ev.Extra["outcome"] = "observed"
		var meaning string
		switch in.EventID {
		case 100, 102:
			ev.User = strings.TrimSpace(dashToEmpty(p["UserContext"]))
			setExtra(ev, "user_context", p["UserContext"])
			if in.EventID == 100 {
				ev.Extra["action"] = "task_started"
				meaning = "Task Scheduler recorded that a task instance started."
			} else {
				ev.Extra["action"] = "task_completed"
				meaning = "Task Scheduler recorded that a task instance completed."
			}
		case 129:
			ev.Extra["action"] = "task_process_launched"
			setExtra(ev, "process_id", p["ProcessID"])
			setExtra(ev, "process_path", cmdsem.Redact(p["Path"]))
			setExtra(ev, "priority", p["Priority"])
			meaning = "Task Scheduler recorded that it launched a process for the task."
		case 200, 201:
			setExtra(ev, "action_name", cmdsem.Redact(p["ActionName"]))
			setExtra(ev, "engine_pid", p["EnginePID"])
			if in.EventID == 200 {
				ev.Extra["action"] = "task_action_started"
				meaning = "Task Scheduler recorded that a task action started."
			} else {
				ev.Extra["action"] = "task_action_completed"
				setExtra(ev, "result_code", p["ResultCode"])
				meaning = "Task Scheduler recorded that a task action completed, with the result code shown."
			}
		}
		ev.Extra["evidence_meaning"] = meaning
		ev.Extra["limitations"] = "A scheduler-side observation of one record. Records sharing task_instance_id are correlated by that value only and are not merged; a missing record is not proof the step did not happen. Does not show what the launched program did, and a result code is retained as recorded without interpretation. Action text is redacted and may be incomplete. 129 carries no instance id."
	case 106, 140, 141, 142:
		if !is(taskSchedulerChannel, taskSchedulerProvider) {
			return true, false
		}
		ev.EventType = model.EventScheduledTaskChange
		ev.User = strings.TrimSpace(dashToEmpty(p["UserName"]))
		setExtra(ev, "task_name", p["TaskName"])
		ev.Extra["action"] = map[int]string{106: "task_registered", 140: "task_updated", 141: "task_deleted", 142: "task_disabled"}[in.EventID]
		ev.Extra["outcome"] = "observed"
		ev.Extra["evidence_meaning"] = "Task Scheduler recorded a task configuration change: " + ev.Extra["action"] + "."
		ev.Extra["limitations"] = "Configuration only; does not establish that the task ran or what its actions did. The user shown is as recorded by the scheduler."
	case 400, 403, 600:
		if !is(classicPowerShellChannel, classicPowerShellProvider) {
			return true, false
		}
		ev.EventType = model.EventPowerShellEngineLifecycle
		fields := psDataFields(p)
		setExtra(ev, "host_name", fields["HostName"])
		setExtra(ev, "host_version", fields["HostVersion"])
		setExtra(ev, "engine_version", fields["EngineVersion"])
		setExtra(ev, "host_application", cmdsem.Redact(fields["HostApplication"]))
		switch in.EventID {
		case 400:
			ev.Extra["action"] = "engine_started"
			setExtra(ev, "new_engine_state", fields["NewEngineState"])
		case 403:
			ev.Extra["action"] = "engine_stopped"
			setExtra(ev, "new_engine_state", fields["NewEngineState"])
		case 600:
			ev.Extra["action"] = "provider_started"
			setExtra(ev, "provider_name", fields["ProviderName"])
			setExtra(ev, "new_provider_state", fields["NewProviderState"])
		}
		ev.Extra["outcome"] = "observed"
		ev.Extra["evidence_meaning"] = "Windows PowerShell recorded an engine lifecycle change: " + ev.Extra["action"] + "."
		ev.Extra["limitations"] = "Engine lifecycle record, not proof of what was executed; it carries no script or command content. HostApplication is the hosting process command line as recorded (redacted, bounded), not a command the engine ran. Fields come from a free-text Data string parsed within fixed size limits."
	default:
		return false, false
	}
	return true, true
}

// psDataFields extracts Key=Value lines from the positional Data values of a
// classic PowerShell record, within fixed size limits. The first occurrence of
// a key wins, scanning the Data values in sorted-key order.
func psDataFields(p map[string]string) map[string]string {
	want := map[string]bool{"HostName": true, "HostVersion": true, "EngineVersion": true, "HostApplication": true,
		"NewEngineState": true, "ProviderName": true, "NewProviderState": true}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := map[string]string{}
	for _, k := range keys {
		v := p[k]
		if len(v) > psMaxValueBytes {
			v = v[:psMaxValueBytes]
		}
		for i, line := range strings.Split(v, "\n") {
			if i >= psMaxLines {
				break
			}
			name, val, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok || !want[name] {
				continue
			}
			if _, seen := out[name]; seen {
				continue
			}
			out[name] = truncateExtra(strings.TrimSpace(val), psMaxFieldBytes)
		}
	}
	return out
}
