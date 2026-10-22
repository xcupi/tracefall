package model

// SQL text logs record messages, not arbitrary SQL execution or OS effects.
// Zone-less timestamps stay local readings in Extra and do not become instants.
const (
	ArtifactMSSQLLog     = "mssql_error_log"
	ArtifactSQLAgentLog  = "sql_agent_log"
	ArtifactSQLInstance  = "sql_instance_configuration"
	EventSQLMessage      = "sql_message"
	EventSQLLoginFailed  = "sql_login_failed"
	EventSQLLoginSuccess = "sql_login_success"
	EventSQLAgentMessage = "sql_agent_message"
	// EventSQLInstance is recorded configuration, never observed execution.
	EventSQLInstance = "sql_instance_configuration"
)
