// Package mssql reads SQL Server text logs without assigning a zone to local clocks.
package mssql

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const maxBytes = 64 << 20

var engineLine = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+(\S+)\s+(.*)$`)
var agentLine = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - ([?!+]) \[(\d+)\] (.*)$`)
var errorFields = regexp.MustCompile(`Error: (\d+), Severity: (\d+), State: (\d+)`)
var login = regexp.MustCompile(`(?i)^(?:SQLServer Error: \d+,\s*)?Login (failed|succeeded) for user '([^']*)'`)
var serverName = regexp.MustCompile(`(?i)Server name is '([^']+)'`)
var errorNumber = regexp.MustCompile(`(?i)Error: (\d+)`)
var sqlState = regexp.MustCompile(`\[SQLSTATE ([^\]]+)\]`)
var client = regexp.MustCompile(`(?i)\[CLIENT: ([^\]]*)\]`)

var engineName = regexp.MustCompile(`(?i)^errorlog(?:\.[0-9]+)?$`)
var agentName = regexp.MustCompile(`(?i)^sqlagent\.(out|[0-9]+|out\.[0-9]+)$`)

// Parser selects engine or Agent text record layouts.
type Parser struct{ Agent bool }

func NewAgent() *Parser { return &Parser{Agent: true} }
func (p Parser) Detect(s string) bool {
	s = strings.ReplaceAll(s, `\`, "/")
	s = s[strings.LastIndex(s, "/")+1:]
	if p.Agent {
		return agentName.MatchString(s)
	}
	return engineName.MatchString(s)
}
func (p Parser) ConfirmContent(b []byte) bool {
	// A sniff may end halfway through a UTF-16 code unit.
	if len(b) > 2 && b[0] == 255 && b[1] == 254 && len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	s, err := decode(b)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimRight(l, "\r")
		if p.Agent {
			if agentLine.MatchString(l) {
				return true
			}
		} else if m := engineLine.FindStringSubmatch(l); m != nil {
			low := strings.ToLower(m[3])
			if errorFields.MatchString(m[3]) || login.MatchString(m[3]) || strings.Contains(low, "microsoft sql server") || strings.Contains(low, "sql server is") || strings.Contains(low, "server name is") {
				return true
			}
		}
	}
	return false
}
func New() *Parser { return &Parser{} }
func (p Parser) Name() string {
	if p.Agent {
		return "sqlagent@1"
	}
	return "mssql@1"
}
func (p Parser) ArtifactType() string {
	if p.Agent {
		return model.ArtifactSQLAgentLog
	}
	return model.ArtifactMSSQLLog
}
func (p Parser) Parse(path string) (parsers.ParseResult, error) {
	return p.ParseWithContext(path, parsers.ParseContext{})
}

// ApplyMessage extracts only fields explicitly present in an English SQL message.
// It does not turn insertion strings or a generic logon mention into an outcome.
func ApplyMessage(e *model.Event, message string) {
	if x := errorFields.FindStringSubmatch(message); x != nil {
		e.Extra["error_number"] = x[1]
		e.Extra["severity"] = x[2]
		e.Extra["state"] = x[3]
	}
	if x := login.FindStringSubmatch(message); x != nil {
		e.User = x[2]
		e.Extra["login"] = x[2]
		if strings.EqualFold(x[1], "failed") {
			e.EventType = model.EventSQLLoginFailed
			e.Extra["outcome"] = "failed"
		} else {
			e.EventType = model.EventSQLLoginSuccess
			e.Extra["outcome"] = "success"
		}
	}
	if x := client.FindStringSubmatch(message); x != nil {
		e.NetworkSource = x[1]
		e.Extra["client"] = x[1]
	}

	if x := errorNumber.FindStringSubmatch(message); x != nil {
		e.Extra["error_number"] = x[1]
	}
	if x := sqlState.FindStringSubmatch(message); x != nil {
		e.Extra["sqlstate"] = x[1]
	}
}

func decode(b []byte) (string, error) {
	if len(b) >= 2 && b[0] == 255 && b[1] == 254 {
		if len(b)%2 != 0 {
			return "", fmt.Errorf("mssql: truncated UTF-16LE")
		}
		u := make([]uint16, (len(b)-2)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(b[2+i*2:])
		}
		for i := 0; i < len(u); i++ {
			if u[i] >= 0xD800 && u[i] <= 0xDBFF {
				if i+1 >= len(u) || u[i+1] < 0xDC00 || u[i+1] > 0xDFFF {
					return "", fmt.Errorf("mssql: invalid UTF-16LE surrogate")
				}
				i++
			} else if u[i] >= 0xDC00 && u[i] <= 0xDFFF {
				return "", fmt.Errorf("mssql: invalid UTF-16LE surrogate")
			}
		}
		return string(utf16.Decode(u)), nil
	}
	s := strings.TrimPrefix(string(b), "\ufeff")
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("mssql: invalid UTF-8")
	}
	return s, nil
}

func (p Parser) ParseWithContext(path string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
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
		return parsers.ParseResult{}, fmt.Errorf("mssql: file exceeds %d bytes", maxBytes)
	}
	text, err := decode(b)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	var out parsers.ParseResult
	recorded := ""
	ambiguous := false
	lines := strings.SplitAfter(text, "\n")
	for _, line := range lines {
		entry := engineLine.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
		if entry == nil || !strings.EqualFold(entry[2], "Server") || !strings.HasPrefix(strings.ToLower(entry[3]), "server name is '") {
			continue
		}
		m := serverName.FindStringSubmatch(entry[3])
		if m == nil {
			continue
		}
		if recorded != "" && !strings.EqualFold(recorded, m[1]) {
			ambiguous = true
		}
		recorded = m[1]
	}
	// Builders avoid quadratic concatenation on many continuation lines.
	var recordText, messageText strings.Builder
	finish := func() {
		if len(out.Events) > 0 {
			i := len(out.Events) - 1
			out.Raw[i].Raw = recordText.String()
			out.Events[i].Extra["message"] = messageText.String()
		}
	}
	for n, line := range lines {
		m := engineLine.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
		var agentID string
		if p.Agent {
			a := agentLine.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
			m = nil
			if a != nil {
				m = []string{a[0], a[1], a[2], a[4]}
				agentID = a[3]
			}
		}
		if m == nil {
			if len(out.Events) > 0 {
				recordText.WriteString(line)
				messageText.WriteString(strings.TrimRight(line, "\r\n") + "\n")
			}
			continue
		}
		finish()
		recordText.Reset()
		messageText.Reset()
		recordText.WriteString(line)
		messageText.WriteString(m[3])
		ref := "line:" + strconv.Itoa(n+1)
		e := model.Event{FilePath: ctx.EvidencePath, EventType: model.EventSQLMessage, ArtifactType: p.ArtifactType(), Parser: p.Name(), SourceReference: ref, Confidence: 0.95, Extra: map[string]string{"timestamp_local": m[1], "timestamp_basis": "local time; offset not recorded", "message": m[3], "sql_source": m[2]}}
		if recorded != "" && !ambiguous {
			e.Extra["server_name"] = recorded
			if i := strings.IndexByte(recorded, '\\'); i >= 0 {
				e.Extra["instance"] = recorded[i+1:]
			} else {
				e.Extra["instance"] = "MSSQLSERVER"
			}
			e.Extra["instance_basis"] = "recorded server name"
		}
		if p.Agent {
			e.EventType = model.EventSQLAgentMessage
			e.Extra["agent_message_id"] = agentID
		}
		if ts, err := time.Parse(time.RFC3339Nano, strings.Replace(m[1], " ", "T", 1)); err == nil {
			e.Timestamp = ts
			delete(e.Extra, "timestamp_local")
			e.Extra["timestamp_original"] = m[1]
			e.Extra["timestamp_basis"] = "explicit offset"
		}
		out.Events = append(out.Events, e)
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ref, Raw: line})
	}
	finish()
	for i := range out.Events {
		ApplyMessage(&out.Events[i], out.Events[i].Extra["message"])
	}
	return out, nil
}
