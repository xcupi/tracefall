package api

import (
	"tracefall/internal/cmdsem"
	"tracefall/internal/model"
	"tracefall/internal/report"
)

// Only explicit evidentiary fields leave the event's Extra map. Stable order
// keeps rendering deterministic; hashes are not cut with the prose summary.
func reportEventDetails(e model.Event) []report.KV {
	keys := []string{"timestamp_basis", "timestamp_local", "timestamp_partial", "timestamp_note", "evidence_clock"}
	switch e.EventType {
	case model.EventWebRequest:
		keys = append(keys, "method", "request_in_capture", "response_utc", "http_host", "uri", "status", "filename", "file_signature", "reassembly", "reassembly_note", "response_sha256", "response_size", "partial_content", "hash_of", "records_outcome")
	case model.EventClockObservation:
		keys = append(keys, "source", "role", "subject_ip", "peer_ip", "observed_utc", "capture_utc", "meaning")
	case model.EventMemoryFileContent:
		keys = append(keys, "sha256", "file_signature", "memory_cache", "recovered_bytes", "zero_pages", "sparse", "sparse_note", "inspection_truncated", "pe_machine", "pe_sections", "pe_import_count", "pe_injection_apis", "indicators", "indicators_withheld", "indicator_meaning", "observation")
	case model.EventNetworkConnection:
		keys = append(keys, "protocol", "application", "connections", "established", "client_port", "session", "packets", "bytes", "packets_to_server", "packets_to_client", "last_seen_utc", "rdp_cookie_user", "rdp_note", "meaning")
	case model.EventAccountChange:
		keys = append(keys, "action", "object_type", "object_name", "target_user_name", "target_domain", "member_sid", "records_outcome")
	case model.EventDNSQuery:
		keys = append(keys, "dns_query", "query_in_capture", "response_utc", "query_type", "answers", "resolver", "answered", "meaning")
	case model.EventMemoryConsoleScreen:
		keys = append(keys, "screen_lines", "screen_text_truncated", "observation")
	case model.EventMemoryConsole:
		keys = append(keys, "observation", "meaning")
	case model.EventSQLMessage, model.EventSQLAgentMessage, model.EventSQLLoginFailed, model.EventSQLLoginSuccess:
		keys = append(keys, "sql_source", "login", "client", "outcome", "error_number", "severity", "state", "agent_message_id", "sqlstate", "message")
	case model.EventMSSQLAudit, model.EventMSSQLXE:
		// sql_statement is deliberately absent: statement text can carry data no
		// pattern recognizes. It stays in raw evidence, cited by sql_record_sha256.
		keys = append(keys, "sql_evidence_form", "sql_instance", "sql_action", "sql_outcome", "sql_outcome_basis", "sql_principal", "sql_client_ip", "sql_client_hostname", "sql_client_application", "sql_database", "sql_object", "sql_session_id", "sql_fragment_note", "sql_record_sha256")
	}
	var out []report.KV
	for _, k := range keys {
		if v := e.Extra[k]; v != "" {
			out = append(out, report.KV{Key: k, Value: cmdsem.Redact(v)})
		}
	}
	return out
}
