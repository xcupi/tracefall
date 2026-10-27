package correlate

import (
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/hostid"
	"tracefall/internal/model"
)

// Private contract strings avoid changing the reader/model integration surface.
const (
	sqlXEEvent           = "mssql_xe_event"
	sqlAuditEvent        = "mssql_audit_event"
	sqlClientDiagnostic  = "mssql_client_diagnostic"
	sqlClientCorrelation = "sql_client_connection"
	sqlOSCorrelation     = "sql_os_execution"
)

var sqlGUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func sqlGUID(s string) bool {
	return sqlGUIDPattern.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}

func sqlEvidence(caseID string, e model.Event) bool {
	return e.CaseID == caseID && caseID != "" && e.ID != "" && e.Host != "" && e.CollectionID != "" && e.SourceFileID != "" && e.SourceReference != "" && e.ArtifactType != model.ArtifactMemoryAnalysis && processTime(e)
}

func sqlRecord(e model.Event) bool {
	return (e.EventType == sqlXEEvent && e.ArtifactType == "mssql_extended_events") || (e.EventType == sqlAuditEvent && e.ArtifactType == "mssql_audit")
}

// A bounded lifetime is deliberately required, even with a GUID. Missing exit
// evidence is not interpreted as proof that a process remained alive.
func sqlAlive(p model.Event, at time.Time) bool {
	end, err := time.Parse(time.RFC3339Nano, p.Extra["exit_time"])
	return err == nil && processTime(p) && p.Timestamp.Before(at) && at.Before(end)
}

func buildSQLWindows(caseID string, events []model.Event) []model.Correlation {
	// Resolve before narrowing inputs: unreferenced names and machine metadata
	// are identity blockers too. A diagnostic's server label can only refer to
	// an independently observed host in this case/acquisition; it is not itself
	// alias proof. Keep comparison keys separate from immutable recorded fields.
	names := hostid.AcquisitionNames(events)
	recordedKey := func(caseID, collection, host string) string {
		return caseID + "\x00" + collection + "\x00" + strings.ToLower(strings.TrimSpace(host))
	}
	// Collapse repeated delivery of the same immutable event. Conflicting
	// versions of an ID make the evidence set unsuitable for deterministic joins.
	unique := map[string]model.Event{}
	for _, e := range events {
		if e.EventType != sqlXEEvent && e.EventType != sqlAuditEvent && e.EventType != sqlClientDiagnostic && e.EventType != model.EventProcessCreate {
			continue
		}
		if old, ok := unique[e.ID]; ok && !reflect.DeepEqual(old, e) {
			return nil
		}
		unique[e.ID] = e
	}
	known := map[string]string{}
	for _, e := range unique {
		known[recordedKey(e.CaseID, e.CollectionID, e.Host)] = names[e.ID]
	}
	serverKeys := map[string]string{}
	for _, e := range unique {
		if e.EventType == sqlClientDiagnostic {
			serverKeys[e.ID] = known[recordedKey(e.CaseID, e.CollectionID, e.Extra["sql_server_host"])]
		}
	}
	events = make([]model.Event, 0, len(unique))
	for _, e := range unique {
		e.Host = names[e.ID]
		events = append(events, e)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].ID < events[j].ID })
	var out []model.Correlation
	for _, s := range events {
		if !sqlRecord(s) || !sqlEvidence(caseID, s) || s.Extra["sql_instance"] == "" || !sqlGUID(s.Extra["sql_client_connection_id"]) {
			continue
		}
		diagnostics := 0
		for _, d := range events {
			if d.EventType == sqlClientDiagnostic && d.CaseID == s.CaseID && d.CollectionID == s.CollectionID && strings.EqualFold(d.Extra["sql_client_connection_id"], s.Extra["sql_client_connection_id"]) {
				diagnostics++
			}
		}
		if diagnostics != 1 {
			continue
		}
		for _, d := range events {
			if d.EventType != sqlClientDiagnostic || d.ArtifactType != "windows_sql_client_diagnostic" || !sqlEvidence(caseID, d) || d.CollectionID != s.CollectionID || serverKeys[d.ID] != s.Host || d.Extra["sql_instance"] != s.Extra["sql_instance"] || d.SourceFileID == s.SourceFileID || !strings.EqualFold(s.Extra["sql_client_connection_id"], d.Extra["sql_client_connection_id"]) || !sqlGUID(d.Extra["process_guid"]) || d.PID <= 0 {
				continue
			}
			for _, p := range events {
				if p.EventType != model.EventProcessCreate || !sqlEvidence(caseID, p) || p.ArtifactType != model.ArtifactWindowsEventLog || p.Host != d.Host || p.CollectionID != d.CollectionID || p.PID != d.PID || !strings.EqualFold(p.Extra["process_guid"], d.Extra["process_guid"]) || !sqlAlive(p, d.Timestamp) || !sqlAlive(p, s.Timestamp) {
					continue
				}
				if !sqlUniqueProcess(p, d.Timestamp, events) || !sqlUniqueProcess(p, s.Timestamp, events) {
					continue
				}
				out = append(out, model.Correlation{Type: sqlClientCorrelation, Title: "SQL connection / Windows client process", Description: "An exact recorded client connection ID links SQL evidence and an independently collected client diagnostic record to a Windows process within its bounded lifetime. Client-supplied hostname and PID are not used as identity. This is a connection correlation, not proof of intent or SQL-triggered execution; no ordering between the two trace records is asserted.", EventIDs: []string{p.ID, s.ID, d.ID}, FirstSeen: p.Timestamp, LastSeen: maxSQLTime(s.Timestamp, d.Timestamp)})
			}
		}
	}
	out = append(out, buildSQLOS(caseID, events)...)
	return out
}

// Only one literal xp_cmdshell invocation is understood, never a substring
// mention, variable expansion, job name or arbitrary SQL batch.
var sqlShellPattern = regexp.MustCompile(`(?i)^\s*EXEC\s+(?:master\.\.|sys\.|dbo\.)?xp_cmdshell\s+N?'((?:[^']|'')*)'\s*;?\s*$`)

func buildSQLOS(caseID string, events []model.Event) []model.Correlation {
	var candidates []model.Correlation
	sqlCounts, childCounts := map[string]int{}, map[string]int{}
	for _, s := range events {
		if !sqlRecord(s) || !sqlEvidence(caseID, s) || s.Extra["sql_instance"] == "" {
			continue
		}
		// Unknown means unknown, not success. Only these explicit non-denial
		// values are understood; new outcome vocabularies must be reviewed.
		switch s.Extra["sql_outcome"] {
		case "", "unknown", "permission_allowed", "allowed", "success", "succeeded":
		default:
			continue
		}
		m := sqlShellPattern.FindStringSubmatch(s.Extra["sql_statement"])
		if len(m) != 2 || m[1] == "" {
			continue
		}
		command := strings.ReplaceAll(m[1], "''", "'")
		for _, p := range events {
			if p.EventType != model.EventProcessCreate || p.ArtifactType != model.ArtifactWindowsEventLog || !sqlEvidence(caseID, p) || p.Host != s.Host || p.CollectionID != s.CollectionID || p.ProcessName != "sqlservr.exe" || p.PID <= 0 || s.Extra["sql_server_pid"] != strconv.FormatInt(p.PID, 10) || p.Extra["sql_instance"] != s.Extra["sql_instance"] || !sqlAlive(p, s.Timestamp) || !sqlUniqueProcess(p, s.Timestamp, events) {
				continue
			}
			for _, c := range events {
				if c.EventType != model.EventProcessCreate || c.ArtifactType != model.ArtifactWindowsEventLog || !sqlEvidence(caseID, c) || c.Host != s.Host || c.CollectionID != s.CollectionID || c.SourceFileID == s.SourceFileID || c.PID <= 0 || c.PID == p.PID || (c.PPID != 0 && c.PPID != p.PID) || (c.PPID == 0 && c.Extra["parent_process_guid"] == "") || c.CommandLine != "cmd.exe /c "+command || c.ProcessName != "cmd.exe" || !s.Timestamp.Before(c.Timestamp) || c.Timestamp.Sub(s.Timestamp) > 5*time.Second || !sqlAlive(p, c.Timestamp) || !sqlUniqueProcess(p, c.Timestamp, events) {
					continue
				}
				if c.ParentProcessName != "" && c.ParentProcessName != p.ProcessName {
					continue
				}
				if g := c.Extra["parent_process_guid"]; g != "" && (!sqlGUID(g) || !sqlGUID(p.Extra["process_guid"]) || !strings.EqualFold(g, p.Extra["process_guid"])) {
					continue
				}
				candidates = append(candidates, model.Correlation{Type: sqlOSCorrelation, Title: "SQL request / Windows process creation", Description: "A literal SQL OS-command request corresponds exactly to an observed Windows process command and recorded sqlservr parent identity within its bounded lifetime. The recorded SQL timestamp precedes process creation. This is an evidence-linked correlation, not proof that the request caused execution or that the activity was malicious. A permission check alone is not execution. Command and statement text are omitted from this summary to avoid disclosing credentials; consult the cited immutable records.", EventIDs: []string{p.ID, s.ID, c.ID}, FirstSeen: p.Timestamp, LastSeen: c.Timestamp})
				sqlCounts[s.ID]++
				childCounts[c.ID]++
			}
		}
	}
	var out []model.Correlation
	for _, c := range candidates {
		if sqlCounts[c.EventIDs[1]] == 1 && childCounts[c.EventIDs[2]] == 1 {
			out = append(out, c)
		}
	}
	return out
}

func maxSQLTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// Contradictory PID lifetimes override a matching GUID. Unknown times and
// unbounded competing instances cannot establish which process was alive.
func sqlUniqueProcess(p model.Event, at time.Time, events []model.Event) bool {
	count := 0
	for _, q := range events {
		if q.EventType != model.EventProcessCreate || q.CaseID != p.CaseID || q.CollectionID != p.CollectionID || q.Host != p.Host || q.ArtifactType == model.ArtifactMemoryAnalysis {
			continue
		}
		if q.PID != p.PID && !(sqlGUID(p.Extra["process_guid"]) && strings.EqualFold(q.Extra["process_guid"], p.Extra["process_guid"])) {
			continue
		}
		if !processTime(q) || q.Timestamp.Equal(at) {
			return false
		}
		if !q.Timestamp.Before(at) {
			continue
		}
		end, err := time.Parse(time.RFC3339Nano, q.Extra["exit_time"])
		if err != nil {
			return false
		}
		if at.Before(end) {
			count++
		}
	}
	return count == 1
}
