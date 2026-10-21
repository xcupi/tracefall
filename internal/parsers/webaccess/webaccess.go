// Package webaccess parses web server access logs in Common Log Format and
// Combined Log Format (Apache httpd, and every server that writes the same
// layout).
//
//	203.0.113.7 - alice [19/Apr/2010:06:36:15 -0700] "GET /feed/ HTTP/1.1" 200 16605 "-" "agent"
//
// # What is emitted
//
// One web_request event per line that has this layout: the client address,
// the authenticated user if the server logged one, the method, the URL
// exactly as logged, the status, the response size, and for the Combined
// format the referrer and the user agent. Anything the server appended
// after the user agent (a request id, the time taken) is kept as text in
// Extra["trailing_fields"] rather than guessed at.
//
// # Time
//
// The timestamp carries a UTC offset, so the event has a real UTC time. The
// offset is the one the server wrote and is kept in Extra["log_utc_offset"].
//
// # What a line does not prove
//
// A line says the server received a request and answered it with a status.
// It does not show what the request did, and a request that looks like an
// attack is only an attempt: a 200 is not proof the attack worked, and a 404
// is not proof it failed on a server that answers every path. The URL is
// kept raw. Decoding and classifying it is a detection step, not a parsing
// one, so the evidence is never altered.
//
// A line that does not have the layout is skipped and counted in
// Extra["unparsed_lines"] of the first event, so a log of another format
// yields nothing rather than wrong events. The error log is a different
// format and is not parsed here.
package webaccess

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "webaccess@1"

const maxFileBytes = 256 << 20

const maxFieldLen = 4096

// line is the Common Log Format with the Combined extension optional and a
// free-form tail. The quoted fields allow backslash escapes, which is how
// Apache writes a quote inside a value.
var line = regexp.MustCompile(`^(\S+) (\S+) (\S+) \[([0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4})\] "((?:[^"\\]|\\.)*)" ([0-9]{3}|-) ([0-9]+|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?(.*)$`)

// access names. Apache's own are access.log / access_log; virtual hosts add
// a prefix or suffix (www-access.log, other_vhosts_access.log).
var nameRe = regexp.MustCompile(`(?i)^(?:.*[-_.])?access[-_.]?log(?:\.[0-9]+)?$`)

// Parser implements parsers.ArtifactParser.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactWebAccessLog }

// Detect matches the usual access log names, plain or numbered-rotated.
// Compressed rotations are not claimed.
func (Parser) Detect(relPath string) bool {
	base := filepath.Base(strings.ReplaceAll(relPath, `\`, "/"))
	if strings.HasSuffix(strings.ToLower(base), ".gz") {
		return false
	}
	return nameRe.MatchString(base)
}

// DetectContent recognises a log by its first line when the name does not
// decide. The layout is specific enough (address, bracketed date with an
// offset, a quoted request, a status) that no other text file matches it.
func (Parser) DetectContent(header []byte) bool {
	first := string(header)
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	first = strings.TrimRight(first, "\r")
	// A header cut off mid-line cannot be judged.
	if i := strings.IndexByte(string(header), '\n'); i < 0 {
		return false
	}
	return line.MatchString(first)
}

func (p Parser) ConfirmContent(header []byte) bool { return p.DetectContent(header) }

// Parse reads an access log with no evidence path.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	return p.ParseWithContext(absPath, parsers.ParseContext{})
}

// ParseWithContext reads the file in file order.
func (p Parser) ParseWithContext(absPath string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if info.Size() > maxFileBytes {
		return parsers.ParseResult{}, fmt.Errorf("webaccess: file exceeds %d bytes", maxFileBytes)
	}
	raw, err := os.ReadFile(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	text := strings.ToValidUTF8(string(raw), "\uFFFD")

	sourceName := filepath.Base(absPath)
	var out parsers.ParseResult
	unparsed := 0
	for i, l := range strings.Split(text, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" {
			continue
		}
		m := line.FindStringSubmatch(l)
		if m == nil {
			unparsed++
			continue
		}
		ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[4])
		if err != nil {
			unparsed++
			continue
		}
		method, uri, proto := splitRequest(unescape(m[5]))
		ref := "line:" + strconv.Itoa(i+1)
		extra := map[string]string{
			"method":          method,
			"uri":             clip(uri, maxFieldLen),
			"protocol":        proto,
			"request_line":    clip(unescape(m[5]), maxFieldLen),
			"status":          dash(m[6]),
			"bytes":           dash(m[7]),
			"log_utc_offset":  m[4][strings.LastIndexByte(m[4], ' ')+1:],
			"line_number":     strconv.Itoa(i + 1),
			"history_file":    sourceName,
			"records_outcome": "false: the line records the status the server returned, not what the request did",
		}
		if m[8] != "" || m[9] != "" {
			extra["referrer"] = clip(dash(unescape(m[8])), maxFieldLen)
			extra["user_agent"] = clip(dash(unescape(m[9])), maxFieldLen)
		}
		if tail := strings.TrimSpace(m[10]); tail != "" {
			extra["trailing_fields"] = clip(tail, 256)
		}
		user := m[3]
		if user == "-" {
			user = ""
		}
		out.Events = append(out.Events, model.Event{
			Timestamp:       ts.UTC(),
			EventType:       model.EventWebRequest,
			User:            user,
			NetworkSource:   m[1],
			ArtifactType:    model.ArtifactWebAccessLog,
			Parser:          parserName,
			FilePath:        sourceName,
			SourceReference: ref,
			Confidence:      0.95,
			Extra:           extra,
		})
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ref, Raw: l})
	}
	if unparsed > 0 && len(out.Events) > 0 {
		out.Events[0].Extra["unparsed_lines"] = strconv.Itoa(unparsed)
	}
	return out, nil
}

// splitRequest splits `METHOD URI PROTO`. A request line that does not have
// that shape (a probe sending garbage, a bare "-") keeps the whole text as
// the URI so nothing is dropped.
func splitRequest(r string) (method, uri, proto string) {
	f := strings.Fields(r)
	if len(f) >= 3 && strings.HasPrefix(strings.ToUpper(f[len(f)-1]), "HTTP/") {
		return strings.ToUpper(f[0]), strings.Join(f[1:len(f)-1], " "), strings.ToUpper(f[len(f)-1])
	}
	if len(f) == 2 {
		return strings.ToUpper(f[0]), f[1], ""
	}
	return "", r, ""
}

// unescape reverses the backslash escapes Apache writes inside a quoted
// field (\" and \\). Other sequences, \xHH among them, are kept as text.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
