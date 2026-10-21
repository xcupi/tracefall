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
)
