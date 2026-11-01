package winevent

import (
	"strings"
	"tracefall/internal/model"
	"tracefall/internal/normalize"
)

const securityProvider = "Microsoft-Windows-Security-Auditing"
const remoteConnectionProvider = "Microsoft-Windows-TerminalServices-RemoteConnectionManager"
const localSessionProvider = "Microsoft-Windows-TerminalServices-LocalSessionManager"

// privilegeListBytes bounds a stored privilege list; the full list is in the raw evidence.
const privilegeListBytes = 1024

// handled reserves these IDs even on a wrong provider/channel: falling through
// to an ID-only mapping would silently reinterpret unrelated application data.
func normalizeServerEvent(ev *model.Event, in Input) (handled, mapped bool) {
	p := in.Data
	is := func(channel, provider string) bool {
		return strings.EqualFold(in.Channel, channel) && strings.EqualFold(in.Provider, provider)
	}
	switch in.EventID {
	case 4771:
		if !is("Security", securityProvider) {
			return true, false
		}
		ev.EventType = model.EventLogonFailure
		ev.User = p["TargetUserName"]
		ev.NetworkSource = p["IpAddress"]
		for k, v := range map[string]string{"target_user_sid": p["TargetSid"], "target_domain": p["TargetDomainName"], "source_port": p["IpPort"], "failure_reason": p["Status"], "service_name": p["ServiceName"], "pre_auth_type": p["PreAuthType"], "ticket_options": p["TicketOptions"]} {
			setExtra(ev, k, v)
		}
		ev.Extra["auth_package"] = "Kerberos"
		ev.Extra["auth_stage"] = "preauthentication"
		ev.Extra["action"] = "kerberos_preauthentication_failed"
		ev.Extra["outcome"] = "failure"
		ev.Extra["evidence_meaning"] = "The KDC recorded a Kerberos preauthentication failure."
		ev.Extra["limitations"] = "A failed preauthentication attempt, not a successful login or proof of credential guessing; status may reflect expired credentials, clock skew, or other errors."
	case 4741, 4742, 4743:
		if !is("Security", securityProvider) {
			return true, false
		}
		// Reuse the account mapper after enforcing this provider/channel gate.
		return false, false
	case 1102, 104, 4719:
		switch in.EventID {
		case 1102:
			if !is("Security", "Microsoft-Windows-Eventlog") {
				return true, false
			}
		case 104:
			if !is("System", "Microsoft-Windows-Eventlog") {
				return true, false
			}
		case 4719:
			if !is("Security", securityProvider) {
				return true, false
			}
		}
		ev.User = p["SubjectUserName"]
		for k, v := range map[string]string{"actor_domain": p["SubjectDomainName"], "actor_sid": p["SubjectUserSid"], "logon_id": p["SubjectLogonId"]} {
			setExtra(ev, k, v)
		}
		ev.Extra["outcome"] = "success"
		if in.EventID == 4719 {
			ev.EventType = model.EventAuditPolicyChange
			ev.Extra["action"] = "audit_policy_changed"
			for k, v := range map[string]string{"audit_category_id": p["CategoryId"], "audit_subcategory_id": p["SubcategoryId"], "audit_subcategory_guid": p["SubcategoryGuid"], "audit_policy_changes": p["AuditPolicyChanges"]} {
				setExtra(ev, k, v)
			}
			ev.Extra["evidence_meaning"] = "Security auditing recorded a system audit policy change."
			ev.Extra["limitations"] = "May be authorized administration or Group Policy. Change tokens are retained verbatim; presence alone does not establish reduced auditing, malicious intent, or the effective policy afterwards."
		} else {
			ev.EventType = model.EventLogCleared
			ev.Extra["action"] = "log_cleared"
			if in.EventID == 1102 {
				ev.Extra["cleared_channel"] = "Security"
			} else {
				setExtra(ev, "cleared_channel", p["Channel"])
			}
			setExtra(ev, "backup_path", p["BackupPath"])
			ev.Extra["evidence_meaning"] = "Windows Event Log recorded that an event log was cleared."
			ev.Extra["limitations"] = "May be authorized maintenance. Does not establish malicious intent, which records were lost, whether backups exist, or completeness of the supplied logs; a backup path is not proof of a recoverable backup."
		}
	case 4697:
		if !is("Security", securityProvider) {
			return true, false
		}
		ev.EventType = model.EventServiceInstall
		ev.User = p["SubjectUserName"]
		for k, v := range map[string]string{"actor_domain": p["SubjectDomainName"], "actor_sid": p["SubjectUserSid"], "logon_id": p["SubjectLogonId"], "service_name": p["ServiceName"], "service_account": p["ServiceAccount"], "service_type": p["ServiceType"], "start_type": p["ServiceStartType"]} {
			setExtra(ev, k, v)
		}
		ev.FilePath = p["ServiceFileName"]
		ev.ProcessPath = ev.FilePath
		ev.ProcessName = normalize.ExecutableFromCommandLine(ev.FilePath)
		ev.Extra["action"] = "service_installed"
		ev.Extra["outcome"] = "success"
		ev.Extra["evidence_meaning"] = "Security auditing recorded installation of a service by the subject account."
		ev.Extra["limitations"] = "Installation/configuration does not prove the service started or its binary executed. Service account is not the installing actor."
	case 7036, 7040, 7031, 7024:
		if !is("System", "Service Control Manager") {
			return true, false
		}
		if (in.EventID == 7031 || in.EventID == 7024) && strings.TrimSpace(p["param1"]) == "" {
			return true, false // no service named: under-specified.
		}
		ev.EventType = model.EventServiceMessage
		ev.User = "" // SCM does not record an actor in these payloads.
		switch in.EventID {
		case 7036:
			setExtra(ev, "service_name", p["param1"])
			setExtra(ev, "service_state", p["param2"])
			ev.Extra["action"] = "service_state_changed"
			ev.Extra["outcome"] = "observed"
			ev.Extra["evidence_meaning"] = "Service Control Manager recorded the reported service state."
		case 7040:
			setExtra(ev, "service_name", firstNonEmpty(p["param4"], p["param1"]))
			setExtra(ev, "service_display_name", p["param1"])
			setExtra(ev, "old_start_type", p["param2"])
			setExtra(ev, "start_type", p["param3"])
			ev.Extra["action"] = "service_start_type_changed"
			ev.Extra["outcome"] = "success"
			ev.Extra["evidence_meaning"] = "Service Control Manager recorded a service start-type configuration change."
		case 7031:
			// Positional layout (provider message template: "The %1 service
			// terminated unexpectedly. It has done this %2 time(s). The following
			// corrective action will be taken in %3 milliseconds: %5."). param4 is
			// not in the message text; real records carry the recovery action
			// code there, alongside its text in param5.
			ev.Extra["service_name"] = strings.TrimSpace(p["param1"])
			setRecorded(ev, "termination_count", p, "param2")
			setRecorded(ev, "corrective_action_delay_ms", p, "param3")
			setRecorded(ev, "recovery_action_code", p, "param4")
			setRecorded(ev, "recovery_action", p, "param5")
			ev.Extra["action"] = "service_terminated_unexpectedly"
			ev.Extra["outcome"] = "observed"
			ev.Extra["evidence_meaning"] = "Service Control Manager recorded that the named service terminated unexpectedly, how many times it had done so, and the corrective action it would take."
		case 7024:
			// "The %1 service terminated with service-specific error %2." Real
			// records carry %2 as a message-table reference (%%NNNN) naming the
			// error text, which is retained as recorded, not decoded.
			ev.Extra["service_name"] = strings.TrimSpace(p["param1"])
			setRecorded(ev, "service_error_ref", p, "param2")
			ev.Extra["action"] = "service_terminated_with_error"
			ev.Extra["outcome"] = "observed"
			ev.Extra["evidence_meaning"] = "Service Control Manager recorded that the named service terminated with the error reference shown."
		}
		ev.Extra["limitations"] = "Does not identify the requesting actor or prove payload execution or successful task execution. State and start-type strings are retained as recorded, including localized values."
		if in.EventID == 7031 || in.EventID == 7024 {
			ev.Extra["limitations"] = "A service termination record does not establish an attack, an actor, a cause, or that any recovery action succeeded; services stop for many ordinary reasons. The service is named as the Service Control Manager displayed it. Parameter values are retained as recorded, including localized text and message-table references."
		}
	case 4698, 4699, 4700, 4701, 4702:
		if !is("Security", securityProvider) {
			return true, false
		}
		ev.EventType = model.EventScheduledTaskChange
		if in.EventID == 4698 {
			ev.EventType = model.EventScheduledTaskCreate
		}
		ev.User = p["SubjectUserName"]
		for k, v := range map[string]string{"actor_domain": p["SubjectDomainName"], "actor_sid": p["SubjectUserSid"], "logon_id": p["SubjectLogonId"], "task_name": p["TaskName"], "client_process_id": p["ClientProcessId"], "parent_process_id": p["ParentProcessId"]} {
			setExtra(ev, k, v)
		}
		ev.Extra["action"] = map[int]string{4698: "task_created", 4699: "task_deleted", 4700: "task_enabled", 4701: "task_disabled", 4702: "task_updated"}[in.EventID]
		ev.Extra["outcome"] = "success"
		ev.Extra["evidence_meaning"] = "Security auditing recorded a scheduled task configuration change: " + ev.Extra["action"] + "."
		ev.Extra["limitations"] = "Configuration only; does not establish that the task ran or its actions succeeded. Task XML remains in raw evidence, not command-line fields, because it can contain credentials."
	case 1149:
		if !is(remoteConnectionProvider+"/Operational", remoteConnectionProvider) {
			return true, false
		}
		ev.EventType = model.EventRemoteAuthentication
		ev.User = p["Param1"]
		ev.NetworkSource = p["Param3"]
		setExtra(ev, "target_domain", p["Param2"])
		ev.Extra["action"] = "authentication_succeeded"
		ev.Extra["outcome"] = "success"
		ev.Extra["evidence_meaning"] = "Remote Desktop Services recorded successful user authentication."
		ev.Extra["limitations"] = "Authentication stage only; does not prove a usable desktop, unrestricted logon, or subsequent activity."
	case 21, 24, 25:
		if !is(localSessionProvider+"/Operational", localSessionProvider) {
			return true, false
		}
		ev.EventType = model.EventSessionChange
		ev.User = p["User"]
		ev.NetworkSource = p["Address"]
		setExtra(ev, "session_id", p["SessionID"])
		ev.Extra["action"] = map[int]string{21: "session_logon", 24: "session_disconnected", 25: "session_reconnected"}[in.EventID]
		if in.EventID == 21 {
			ev.EventType = model.EventSessionStart
		}
		ev.Extra["outcome"] = "success"
		ev.Extra["evidence_meaning"] = "Terminal Services recorded a session transition: " + ev.Extra["action"] + "."
		ev.Extra["limitations"] = "Does not prove an unrestricted usable desktop or activity within the session; disconnection is not logoff. Address may be LOCAL, not a remote IP."
	case 4778, 4779:
		if !is("Security", securityProvider) {
			return true, false
		}
		ev.EventType = model.EventSessionChange
		ev.User = p["AccountName"]
		ev.NetworkSource = p["ClientAddress"]
		for k, v := range map[string]string{"target_domain": p["AccountDomain"], "logon_id": p["LogonID"], "session_name": p["SessionName"], "client_name": p["ClientName"]} {
			setExtra(ev, k, v)
		}
		ev.Extra["action"] = map[int]string{4778: "session_reconnected", 4779: "session_disconnected"}[in.EventID]
		ev.Extra["outcome"] = "success"
		ev.Extra["evidence_meaning"] = "Security auditing recorded a Window Station session transition: " + ev.Extra["action"] + "."
		ev.Extra["limitations"] = "Reconnection is not a new unrestricted login; disconnection is not logoff. A session name alone does not establish RDP transport."
	case 4689:
		if !is("Security", securityProvider) {
			return true, false
		}
		if strings.TrimSpace(p["ProcessId"]) == "" && strings.TrimSpace(p["ProcessName"]) == "" {
			return true, false // no process identified: under-specified.
		}
		ev.EventType = model.EventProcessExit
		ev.User = dashToEmpty(strings.TrimSpace(p["SubjectUserName"]))
		// Same keys a 4688 carries (PID as decimal, executable path, logon id) so
		// a reader can match an exit to a creation; no join is performed here.
		ev.ProcessPath = p["ProcessName"]
		ev.ProcessName = normalize.ProcessName(p["ProcessName"])
		ev.PID = normalize.Int64(hexOrDec(p["ProcessId"]))
		setExtra(ev, "process_path", p["ProcessName"])
		setExtra(ev, "logon_id", p["SubjectLogonId"])
		setExtra(ev, "subject_domain", p["SubjectDomainName"])
		setExtra(ev, "actor_sid", p["SubjectUserSid"])
		setRecorded(ev, "exit_status", p, "Status")
		ev.Extra["action"] = "process_exited"
		ev.Extra["outcome"] = "observed"
		ev.Extra["evidence_meaning"] = "Security auditing recorded that the process with this ID and image path exited, with the exit status shown."
		ev.Extra["limitations"] = "This record does not establish when the process started, which creation record it belongs to, or why it exited. Process IDs are reused: match to a process_create only by the same PID within one host where no other creation or exit of that PID intervenes. The logon id is the session recorded on this exit record and may differ from the session shown on the creation record. The exit status is retained as recorded, without interpretation."
	case 4703:
		if !is("Security", securityProvider) {
			return true, false
		}
		_, hasEnabled := p["EnabledPrivilegeList"]
		_, hasDisabled := p["DisabledPrivilegeList"]
		if !hasEnabled && !hasDisabled {
			return true, false // nothing adjusted is recorded: under-specified.
		}
		ev.EventType = model.EventTokenRightAdjusted
		ev.User = dashToEmpty(strings.TrimSpace(p["SubjectUserName"]))
		ev.ProcessPath = p["ProcessName"]
		ev.ProcessName = normalize.ProcessName(p["ProcessName"])
		ev.PID = normalize.Int64(hexOrDec(p["ProcessId"]))
		setExtra(ev, "process_path", p["ProcessName"])
		for k, v := range map[string]string{"logon_id": p["SubjectLogonId"], "actor_domain": p["SubjectDomainName"], "actor_sid": p["SubjectUserSid"],
			"target_user_name": p["TargetUserName"], "target_domain": p["TargetDomainName"], "target_user_sid": p["TargetUserSid"], "target_logon_id": p["TargetLogonId"]} {
			setExtra(ev, k, v)
		}
		for src, dst := range map[string]string{"EnabledPrivilegeList": "enabled_privileges", "DisabledPrivilegeList": "disabled_privileges"} {
			if v, recorded := p[src]; recorded {
				list := strings.Join(strings.Fields(v), ",")
				if len(list) > privilegeListBytes {
					list = list[:privilegeListBytes]
					ev.Extra[dst+"_truncated"] = "true"
				}
				ev.Extra[dst] = list
			}
		}
		ev.Extra["action"] = "token_privileges_adjusted"
		ev.Extra["outcome"] = "success"
		ev.Extra["evidence_meaning"] = "Security auditing recorded that privileges in the target account's token were enabled or disabled by the process shown."
		ev.Extra["limitations"] = "This record does not establish privilege escalation, misuse of a privilege, or malicious intent: services and applications adjust token privileges routinely, and the record does not say which privilege was used. Privilege names are retained as recorded (a dash means none was recorded in that list)."
	default:
		return false, false
	}
	return true, true
}
