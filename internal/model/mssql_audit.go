package model

// Audit records describe the selected audit action and permission outcome, not
// completed queries or OS execution. Exports are a different, partial evidence form.
const (
	ArtifactMSSQLExtendedEvents = "mssql_extended_events"
	ArtifactMSSQLAudit          = "mssql_audit"
	EventMSSQLXE                = "mssql_xe_event"
	EventMSSQLAudit             = "mssql_audit_event"
)
