// Package mssqlxe reads explicitly named SQL exports and optional offline XE files.
package mssqlxe

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"github.com/google/uuid"

	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const maxBytes = 16 << 20
const maxRecords = 10000
const maxLine = 1 << 20

type Parser struct{ Audit bool }

func New() *Parser      { return &Parser{} }
func NewAudit() *Parser { return &Parser{Audit: true} }
func (p Parser) Name() string {
	if p.Audit {
		return "mssqlaudit@1"
	}
	return "mssqlxe@1"
}
func (p Parser) ArtifactType() string {
	if p.Audit {
		return model.ArtifactMSSQLAudit
	}
	return model.ArtifactMSSQLExtendedEvents
}
func (p Parser) Detect(s string) bool {
	s = strings.ToLower(s)
	if p.Audit {
		return strings.HasSuffix(s, ".sqlaudit.csv") || strings.HasSuffix(s, ".sqlaudit")
	}
	return strings.HasSuffix(s, ".xel") || strings.HasSuffix(s, ".xel.xml") || strings.HasSuffix(s, ".xel.jsonl")
}
func (p Parser) Parse(path string) (parsers.ParseResult, error) {
	return p.ParseWithContext(path, parsers.ParseContext{})
}
func (p Parser) ParseWithContext(path string, c parsers.ParseContext) (parsers.ParseResult, error) {
	if p.OwnSandbox(path) {
		return p.binary(path, c)
	}
	f, err := os.Open(path)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if len(b) > maxBytes {
		return parsers.ParseResult{}, fmt.Errorf("mssqlxe: input cap")
	}
	r := parsers.ParseResult{Coverage: &model.ParseCoverage{}}
	if !p.Audit {
		r, err := p.exports(b, path, c)
		if err == nil {
			exportNote(&r)
		}
		return r, err
	}
	cr := csv.NewReader(bytes.NewReader(b))
	h, err := cr.Read()
	if err != nil {
		return r, err
	}
	have := map[string]bool{}
	for _, k := range h {
		if have[k] {
			return r, fmt.Errorf("duplicate column")
		}
		have[k] = true
	}
	if !have["event_time"] || !have["action_id"] {
		return r, fmt.Errorf("mssqlxe: expected fn_get_audit_file export columns")
	}
	for {
		start := cr.InputOffset()
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return r, err
		}
		if len(r.Events) >= maxRecords || cr.InputOffset()-start > maxLine {
			return parsers.ParseResult{}, fmt.Errorf("mssqlxe: record/line cap")
		}
		fields := map[string]string{}
		for i, k := range h {
			fields[k] = row[i]
		}
		raw := string(b[start:cr.InputOffset()])
		p.append(&r, c, fields, raw, "")
	}
	exportNote(&r)
	return r, nil
}
func (p Parser) append(r *parsers.ParseResult, c parsers.ParseContext, f map[string]string, raw, outer string) {
	ref := "record:" + strconv.Itoa(len(r.Events)+1)
	e := model.Event{ArtifactType: p.ArtifactType(), EventType: model.EventMSSQLXE, Parser: p.Name(), FilePath: c.EvidencePath, SourceReference: ref, Extra: map[string]string{"sql_outcome": "unknown", "sql_outcome_basis": "not recorded", "sql_evidence_form": "export_partial"}}
	e.Extra["sql_record_sha256"] = fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))
	if p.Audit {
		e.EventType = model.EventMSSQLAudit
	}
	for k, v := range f {
		e.Extra["sql_field_"+k] = v
	}
	for _, kv := range [][2]string{{"server_instance_name", "sql_instance"}, {"session_id", "sql_session_id"}, {"client_pid", "sql_client_pid"}, {"client_hostname", "sql_client_hostname"}, {"client_ip", "sql_client_ip"}, {"application_name", "sql_client_application"}, {"statement", "sql_statement"}, {"action_id", "sql_action"}, {"client_connection_id", "sql_client_connection_id"}, {"server_pid", "sql_server_pid"}, {"server_principal_name", "sql_principal"}, {"server_principal_sid", "sql_principal_sid"}, {"database_name", "sql_database"}, {"schema_name", "sql_schema"}, {"object_name", "sql_object"}} {
		if v, ok := f[kv[0]]; ok {
			e.Extra[kv[1]] = v
		}
	}
	if !p.Audit {
		if e.Extra["sql_statement"] == "" {
			if v, ok := f["sql_text"]; ok {
				e.Extra["sql_statement"] = v
			}
		}
		if e.Extra["sql_client_application"] == "" {
			if v, ok := f["client_app_name"]; ok {
				e.Extra["sql_client_application"] = v
			}
		}
	}
	if p.Audit {
		if n, err := strconv.ParseUint(f["action_id"], 10, 32); err == nil {
			var code [4]byte
			for i := range code {
				code[i] = byte(n >> (8 * i))
			}
			e.Extra["sql_action"] = strings.TrimRight(string(code[:]), " ")
		}
	}
	// A varchar(4) action code is space padded ("AL  "); the padding is not part
	// of the code.
	if a := strings.TrimRight(e.Extra["sql_action"], " "); a != e.Extra["sql_action"] {
		e.Extra["sql_action"] = a
	}
	if v := f["attach_activity_id"]; v != "" {
		if i := strings.LastIndexByte(v, ':'); i > 0 {
			if _, err := uuid.Parse(v[:i]); err == nil {
				if _, err := strconv.ParseUint(v[i+1:], 10, 64); err == nil {
					e.Extra["sql_activity_id"] = v[:i]
					e.Extra["sql_activity_sequence"] = v[i+1:]
				}
			}
		}
	}
	stamp := outer
	if p.Audit {
		stamp = f["event_time"]
		if stamp != "" {
			s := strings.Replace(stamp, " ", "T", 1)
			if t, err := time.Parse("2006-01-02T15:04:05.999999999", s); err == nil {
				e.Timestamp = t
				e.Extra["timestamp_basis"] = "SQL Audit event_time documented UTC"
			}
		}
	}
	if e.Timestamp.IsZero() && stamp != "" {
		if t, err := time.Parse(time.RFC3339Nano, stamp); err == nil {
			e.Timestamp = t
			e.Extra["timestamp_basis"] = "explicit offset"
		} else {
			e.Extra["timestamp_local"] = stamp
			e.Extra["timestamp_basis"] = "offset not recorded"
		}
	}
	if outer != "" {
		e.Extra["sql_xe_timestamp"] = outer
	}
	if p.Audit {
		if v, ok := f["succeeded"]; ok && (v == "1" || v == "0" || strings.EqualFold(v, "true") || strings.EqualFold(v, "false")) {
			allowed := v == "1" || strings.EqualFold(v, "true")
			e.Extra["sql_outcome"] = "permission_check_denied"
			if allowed {
				e.Extra["sql_outcome"] = "permission_check_allowed"
			}
			e.Extra["sql_outcome_basis"] = "audit succeeded; non-login permission check only"
			if e.Extra["sql_action"] == "LGIS" || e.Extra["sql_action"] == "LGIF" {
				e.Extra["sql_outcome"] = "login_failed"
				if allowed {
					e.Extra["sql_outcome"] = "login_success"
				}
				e.Extra["sql_outcome_basis"] = "audit succeeded; documented login action"
			}
			// A user-defined audit event is written by a caller through
			// sp_audit_write, which supplies the flag itself. It records what
			// the caller reported, not a permission check SQL Server made.
			if e.Extra["sql_action"] == "UDAU" {
				e.Extra["sql_outcome"] = "user_defined_reported_failure"
				if allowed {
					e.Extra["sql_outcome"] = "user_defined_reported_success"
				}
				e.Extra["sql_outcome_basis"] = "caller-supplied flag of a user-defined audit event; not a permission check"
			}
		}
		if f["sequence_number"] != "" {
			e.Extra["sql_fragment_note"] = "sequence row retained separately; completeness unknown; not reconstructed"
		}
	}
	r.Events = append(r.Events, e)
	r.Raw = append(r.Raw, model.RawEvidence{Raw: raw, SourceReference: ref})
	r.Coverage.RecordsRead++
	r.Coverage.Mapped++
	if e.Timestamp.IsZero() {
		r.Coverage.Undated++
	}
}

func exportNote(r *parsers.ParseResult) {
	r.Coverage.Notes = []string{"PARTIAL exported evidence; not native binary equivalence; export method/completeness not verified; no records is not absence of activity"}
	r.Raw = append(r.Raw, model.RawEvidence{SourceReference: "export:coverage", Raw: "PARTIAL exported evidence, not native binary equivalence; export method/completeness not verified; no records is not absence of activity"})
}
