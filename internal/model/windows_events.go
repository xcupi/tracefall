package model

// Windows remote authentication and session transitions are deliberately not
// logon_success: authentication does not prove an unrestricted usable desktop,
// and reconnection/disconnection does not create/terminate the logon session.
const (
	EventRemoteAuthentication = "remote_authentication"
	EventSessionChange        = "session_change"
	// Task changes describe configuration, never successful execution.
	EventScheduledTaskChange = "scheduled_task_change"
	// These are recorded actions, not findings of malicious intent.
	EventLogCleared        = "event_log_cleared"
	EventAuditPolicyChange = "audit_policy_change"
)
