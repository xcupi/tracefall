package api

import (
	"strings"
	"testing"

	"tracefall/internal/model"
)

// A finding that cites a SQL event must show what the event says. Without these
// fields the report's evidence block carried only a timestamp. Statement text is NEVER shown: it can carry data no redaction pattern
// recognizes, and it remains in raw evidence.
func TestReportEventDetails_SQLEventsShowTheirEvidenceFields(t *testing.T) {
	cases := []struct {
		name  string
		event model.Event
		want  []string
		not   []string
	}{
		{"login failed", model.Event{EventType: model.EventSQLLoginFailed, Extra: map[string]string{"login": "alice", "client": "203.0.113.5", "outcome": "failed", "message": "Login failed for user 'alice'. Reason: Password did not match that for the login provided. [CLIENT: 203.0.113.5]", "sql_source": "Logon"}},
			[]string{"alice", "203.0.113.5", "failed", "Password did not match"}, nil},
		{"agent", model.Event{EventType: model.EventSQLAgentMessage, Extra: map[string]string{"agent_message_id": "208", "message": "Job step finished"}}, []string{"208", "Job step finished"}, nil},
		{"audit", model.Event{EventType: model.EventMSSQLAudit, Extra: map[string]string{"sql_action": "LGIF", "sql_outcome": "login_failed", "sql_outcome_basis": "audit succeeded; documented login action", "sql_principal": "alice", "sql_client_ip": "203.0.113.5", "sql_statement": "CREATE LOGIN bob WITH PASSWORD='Sup3rSecret!'", "sql_instance": "HOST01"}},
			[]string{"LGIF", "login_failed", "alice", "203.0.113.5", "HOST01"}, []string{"Sup3rSecret!", "CREATE LOGIN"}},
		{"xe", model.Event{EventType: model.EventMSSQLXE, Extra: map[string]string{"sql_principal": "alice", "sql_statement": "EXEC sp_x @rmtpassword='Hunter2pw'"}}, []string{"alice"}, []string{"Hunter2pw", "sp_x"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var all strings.Builder
			for _, kv := range reportEventDetails(c.event) {
				all.WriteString(kv.Key + "=" + kv.Value + "\n")
			}
			text := all.String()
			for _, w := range c.want {
				if !strings.Contains(text, w) {
					t.Errorf("report details lack %q:\n%s", w, text)
				}
			}
			for _, n := range c.not {
				if strings.Contains(text, n) {
					t.Errorf("report details leak %q:\n%s", n, text)
				}
			}
		})
	}
}
