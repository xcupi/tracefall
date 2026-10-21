package winevent

import (
	"strings"
	"tracefall/internal/model"
	"tracefall/internal/normalize"
)

const securityProvider = "Microsoft-Windows-Security-Auditing"
const remoteConnectionProvider = "Microsoft-Windows-TerminalServices-RemoteConnectionManager"
const localSessionProvider = "Microsoft-Windows-TerminalServices-LocalSessionManager"

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
	case 7036, 7040:
		if !is("System", "Service Control Manager") {
			return true, false
		}
		ev.EventType = model.EventServiceMessage
		ev.User = "" // SCM does not record an actor in these payloads.
		if in.EventID == 7036 {
			setExtra(ev, "service_name", p["param1"])
			setExtra(ev, "service_state", p["param2"])
			ev.Extra["action"] = "service_state_changed"
			ev.Extra["outcome"] = "observed"
			ev.Extra["evidence_meaning"] = "Service Control Manager recorded the reported service state."
		} else {
			setExtra(ev, "service_name", firstNonEmpty(p["param4"], p["param1"]))
			setExtra(ev, "service_display_name", p["param1"])
			setExtra(ev, "old_start_type", p["param2"])
			setExtra(ev, "start_type", p["param3"])
			ev.Extra["action"] = "service_start_type_changed"
			ev.Extra["outcome"] = "success"
			ev.Extra["evidence_meaning"] = "Service Control Manager recorded a service start-type configuration change."
		}
		ev.Extra["limitations"] = "Does not identify the requesting actor or prove payload execution or successful task execution. State and start-type strings are retained as recorded, including localized values."
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
	default:
		return false, false
	}
	return true, true
}
