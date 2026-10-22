package winevent

import (
	"encoding/json"
	"strings"
	"tracefall/internal/cmdsem"
	"tracefall/internal/model"
	"tracefall/internal/parsers/mssql"
)

// normalizeMSSQLEvent is provider/channel gated: these IDs are not global.
// Positional insertion strings are retained without guessing their semantics.
func normalizeMSSQLEvent(e *model.Event, in Input) (bool, bool) {
	p := strings.ToLower(in.Provider)
	engine := p == "mssqlserver" || strings.HasPrefix(p, "mssql$") && len(p) > 6
	agent := p == "sqlserveragent" || strings.HasPrefix(p, "sqlagent$") && len(p) > 9
	if !engine && !agent {
		return false, false
	}
	if !strings.EqualFold(in.Channel, "Application") {
		return true, false
	}
	if in.Description != "" {
		e.Extra["rendered_description"] = cmdsem.Redact(in.Description)
	}
	e.EventType = model.EventSQLMessage
	if agent {
		e.EventType = model.EventSQLAgentMessage
	}
	instance := "MSSQLSERVER"
	if i := strings.IndexByte(in.Provider, '$'); i >= 0 {
		instance = in.Provider[i+1:]
	}
	e.Extra["instance"] = instance
	e.Extra["instance_basis"] = "Application event provider"
	for k, v := range in.Data {
		e.Extra["sql_data."+k] = v
	}
	data, _ := json.Marshal(in.Data)
	e.Extra["sql_record_data"] = string(data)
	if message := in.Data["Message"]; message != "" {
		mssql.ApplyMessage(e, message)
	}
	if engine && in.EventID == 18456 {
		e.EventType = model.EventSQLLoginFailed
		e.Extra["outcome"] = "failed"
		e.Extra["error_number"] = "18456"
	}
	// Named values only; insertion-string order differs by SQL message/version.
	for _, pair := range [][2]string{{"LoginName", "login"}, {"ClientIP", "client"}, {"DatabaseName", "database"}, {"ErrorNumber", "error_number"}, {"Severity", "severity"}, {"State", "state"}} {
		if v := in.Data[pair[0]]; v != "" {
			e.Extra[pair[1]] = v
		}
	}
	if e.Extra["login"] != "" {
		e.User = e.Extra["login"]
	}
	if e.Extra["client"] != "" {
		e.NetworkSource = e.Extra["client"]
	}
	return true, true
}
