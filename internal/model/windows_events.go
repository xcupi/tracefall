package model

// Windows remote authentication and session transitions are deliberately not
// logon_success: authentication does not prove an unrestricted usable desktop,
// and reconnection/disconnection does not create/terminate the logon session.
const (
	EventRemoteAuthentication = "remote_authentication"
	EventSessionChange        = "session_change"
	// Task changes describe configuration, never successful execution.
	EventScheduledTaskChange = "scheduled_task_change"
	// Task Scheduler execution-side records (started/completed/process
	// launched/action started/action completed): observations, never merged.
	EventScheduledTaskRun = "scheduled_task_run"
	// Classic PowerShell engine/provider lifecycle records; not proof of
	// what was executed.
	EventPowerShellEngineLifecycle = "powershell_engine_lifecycle"
	// These are recorded actions, not findings of malicious intent.
	EventLogCleared        = "event_log_cleared"
	EventAuditPolicyChange = "audit_policy_change"

	// Defender configuration and history records (Operational 5004/5007/1013).
	// They record that the engine's configuration changed, or that its stored
	// detection history was deleted; neither names an actor or a cause.
	EventAntimalwareConfigChange   = "antimalware_configuration_change"
	EventAntimalwareHistoryDeleted = "antimalware_history_deleted"
	// WMI-Activity client failures and temporary event consumers (5858/5860):
	// attempt/registration evidence, never proof of execution or intent.
	EventWMIActivity = "wmi_activity"
	// Task Scheduler trigger/launch-request records (107/108/110/119/322).
	// Distinct from scheduled_task_run: a launch request that was ignored (322)
	// or a trigger firing is not a recorded task run.
	EventScheduledTaskLaunch = "scheduled_task_launch"
	// SMB server security audit records (551/1009).
	EventSMBSecurity = "smb_security_event"
	// Security 4703 (token privileges adjusted) and 4689 (process exited).
	EventTokenRightAdjusted = "token_right_adjusted"
	EventProcessExit        = "process_exit"
	// PowerShell 4100: an error raised while a pipeline executed.
	EventPowerShellPipelineError = "powershell_pipeline_error"
)

// windowsIdentityExtras returns the Extra keys that distinguish two records of
// the event types added for G02 when Windows events tie on time, host, user
// and process. The hash appends them ONLY for these types (and the two service
// termination IDs), so the identity of every historical Windows event is
// unchanged. The values are the fields that make one real record differ from
// another of the same kind; they are never source-file or collection identity.
func windowsIdentityExtras(e Event) []string {
	switch e.EventType {
	case EventAntimalwareConfigChange:
		return []string{"config_category", "config_setting", "old_value", "new_value", "feature_name", "configuration", "feature_id"}
	case EventAntimalwareHistoryDeleted:
		return []string{"history_deleted_time_recorded", "user_domain", "user_sid"}
	case EventWMIActivity:
		return []string{"action", "client_machine", "client_process_id", "namespace", "query", "operation_id", "operation", "result_code", "component", "possible_cause"}
	case EventScheduledTaskLaunch:
		return []string{"action", "task_name", "task_instance_id", "existing_instance_id", "user_context", "logon_user"}
	case EventSMBSecurity:
		return []string{"action", "session_id", "session_guid", "connection_guid", "client_name", "client_address_recorded", "status", "translated_status", "spn", "reason_code"}
	case EventTokenRightAdjusted:
		return []string{"target_logon_id", "enabled_privileges", "disabled_privileges"}
	case EventProcessExit:
		return []string{"exit_status", "process_path"}
	case EventPowerShellPipelineError:
		return []string{"severity", "host_name", "host_application", "command_name", "script_name", "pipeline_id", "runspace_id", "sequence_number", "error_message", "fully_qualified_error_id"}
	case EventServiceMessage:
		// Service Control Manager 7031/7024 only; 7036/7040 keep their identity.
		if e.EventID == 7031 || e.EventID == 7024 {
			return []string{"action", "service_name", "termination_count", "corrective_action_delay_ms", "recovery_action_code", "recovery_action", "service_error_ref"}
		}
	}
	return nil
}
