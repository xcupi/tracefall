// Package iislog reads IIS W3C extended logs (u_exYYMMDD.log).
//
// A line is one request IIS answered. It records what was asked and the status
// IIS returned, not what the request did on the server: a 200 on an uploaded
// script proves the script was served, not what it ran. Timestamps are UTC
// regardless of the server's time zone (Microsoft documents this for the W3C
// format; it is not something a single log file can confirm).
//
// The columns are named by the log's own "#Fields:" directive, which can change
// part-way through a file, so nothing here depends on column position. A row
// that arrives before any Fields directive, or whose column count disagrees with
// the directive in force, is counted as unparsed and never guessed at.
package iislog

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "iislog@1"

const (
	maxFileBytes = 1 << 30 // read as a stream, so this bounds work, not memory
	maxLineBytes = 64 << 10
	maxRawBytes  = 8 << 10
	maxEvents    = 5_000_000
)

var nameRe = regexp.MustCompile(`(?i)^u_(?:ex|in|nc)[0-9a-z_-]*\.log$`)

type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactIISLog }

// Detect claims the IIS log file names. FTP site logs share the name pattern but
// carry FTP verbs, and HTTP.sys error logs have a different layout; neither is
// claimed here.
func (Parser) Detect(relPath string) bool {
	p := strings.ToLower(strings.ReplaceAll(relPath, `\`, "/"))
	if strings.Contains(p, "/ftpsvc") || strings.Contains(p, "/httperr/") {
		return false
	}
	return nameRe.MatchString(filepath.Base(p))
}

// fieldsOf returns the column names of the first complete #Fields line in a
// header, or nil. The last element of a split header has no newline after it and
// may be cut mid-line, so it is never judged.
func fieldsOf(header []byte) map[string]bool {
	text := strings.TrimPrefix(string(header), "\xef\xbb\xbf")
	lines := strings.Split(text, "\n")
	for _, l := range lines[:len(lines)-1] {
		l = strings.TrimRight(l, "\r")
		if strings.HasPrefix(l, "#Fields:") {
			set := map[string]bool{}
			for _, f := range strings.Fields(strings.TrimPrefix(l, "#Fields:")) {
				set[f] = true
			}
			return set
		}
	}
	return nil
}

// webColumns reports whether the columns are those of an IIS site log and not of
// the FTP site log, which shares the folder and several column names.
func webColumns(f map[string]bool) bool {
	return f["cs-uri-stem"] && f["sc-status"] && !f["x-session"] && !f["x-fullpath"]
}

// DetectContent claims a file by its columns alone. Because FTP logs share the
// column names, it also needs one column that only a web log carries.
func (Parser) DetectContent(header []byte) bool {
	f := fieldsOf(header)
	if !webColumns(f) {
		return false
	}
	return f["cs(User-Agent)"] || f["cs-uri-query"] || f["cs-version"] || f["cs-host"] || f["cs(Referer)"]
}

// ConfirmContent is asked about a file already claimed by its name; it only
// rules out what is clearly not a web log.
func (Parser) ConfirmContent(header []byte) bool { return webColumns(fieldsOf(header)) }

func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	return p.ParseWithContext(absPath, parsers.ParseContext{})
}

func (Parser) ParseWithContext(absPath string, _ parsers.ParseContext) (parsers.ParseResult, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if st.Size() > maxFileBytes {
		return parsers.ParseResult{}, fmt.Errorf("iislog: file exceeds %d bytes", int64(maxFileBytes))
	}

	sourceName := filepath.Base(absPath)
	rd := bufio.NewReaderSize(f, 1<<16)
	var (
		out      parsers.ParseResult
		fields   []string
		software string
		unparsed int
		lineNo   int
		first    = true
	)
	for {
		line, tooLong, err := readLine(rd)
		if err == io.EOF && line == "" && !tooLong {
			break
		}
		lineNo++
		if first {
			line = strings.TrimPrefix(line, "\xef\xbb\xbf")
			first = false
		}
		switch {
		case tooLong:
			unparsed++
		case strings.TrimSpace(line) == "":
		case strings.HasPrefix(line, "#Fields:"):
			fields = strings.Fields(strings.TrimPrefix(line, "#Fields:"))
		case strings.HasPrefix(line, "#Software:"):
			software = strings.TrimSpace(strings.TrimPrefix(line, "#Software:"))
		case strings.HasPrefix(line, "#"):
		case fields == nil:
			unparsed++ // no Fields directive yet: the columns are unknown
		default:
			if len(out.Events) >= maxEvents {
				return out, fmt.Errorf("iislog: more than %d requests; stopped", maxEvents)
			}
			text := strings.ToValidUTF8(line, "\uFFFD")
			ev, ok := parseRow(text, fields, lineNo, sourceName, software)
			if !ok {
				unparsed++
			} else {
				out.Events = append(out.Events, ev)
				out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ev.SourceReference, Raw: clip(text, maxRawBytes)})
			}
		}
		if err != nil {
			break
		}
	}
	if unparsed > 0 && len(out.Events) > 0 {
		out.Events[0].Extra["unparsed_lines"] = strconv.Itoa(unparsed)
	}
	return out, nil
}

// readLine returns one line without its terminator. A line longer than
// maxLineBytes is consumed to its end and reported as tooLong, so the next line
// still parses.
func readLine(rd *bufio.Reader) (line string, tooLong bool, err error) {
	var b []byte
	for {
		chunk, isPrefix, e := rd.ReadLine()
		if len(b)+len(chunk) > maxLineBytes {
			tooLong = true
		} else if !tooLong {
			b = append(b, chunk...)
		}
		if e != nil {
			return string(b), tooLong, e
		}
		if !isPrefix {
			return string(b), tooLong, nil
		}
	}
}

func parseRow(l string, fields []string, lineNo int, source, software string) (model.Event, bool) {
	cols := strings.Split(l, " ")
	if len(cols) != len(fields) {
		return model.Event{}, false
	}
	get := make(map[string]string, len(fields))
	for i, name := range fields {
		v := cols[i]
		if v == "-" {
			v = ""
		}
		get[name] = v
	}
	// Both date and time are needed. With either missing the request is
	// undated; the date is never borrowed from a header or a file name.
	var ts time.Time
	known := false
	if d, t := get["date"], get["time"]; d != "" && t != "" {
		parsed, err := time.Parse("2006-01-02 15:04:05", d+" "+t)
		if err != nil {
			return model.Event{}, false
		}
		ts, known = parsed.UTC(), true
	}

	stem, query := get["cs-uri-stem"], get["cs-uri-query"]
	uri := stem
	if query != "" {
		uri += "?" + query
	}
	extra := map[string]string{
		"method":          get["cs-method"],
		"uri":             clip(uri, 4096),
		"uri_stem":        clip(stem, 4096),
		"uri_query":       clip(query, 4096),
		"status":          get["sc-status"],
		"substatus":       get["sc-substatus"],
		"win32_status":    get["sc-win32-status"],
		"bytes":           get["sc-bytes"],
		"request_bytes":   get["cs-bytes"],
		"time_taken_ms":   get["time-taken"],
		"server_ip":       get["s-ip"],
		"server_port":     get["s-port"],
		"site":            get["s-sitename"],
		"server_name":     get["s-computername"],
		"host_header":     get["cs-host"],
		"protocol":        get["cs-version"],
		"user_agent":      clip(get["cs(User-Agent)"], 4096),
		"referrer":        clip(get["cs(Referer)"], 4096),
		"line_number":     strconv.Itoa(lineNo),
		"history_file":    source,
		"timezone":        "UTC (IIS W3C logs UTC, per Microsoft documentation)",
		"records_outcome": "false: the line records the status IIS returned, not what the request did",
	}
	for name, v := range get {
		if v != "" && strings.Contains(strings.ToLower(name), "forwarded-for") {
			extra["x_forwarded_for"] = clip(v, 512)
		}
	}
	if software != "" {
		extra["iis_software"] = clip(software, 128)
	}
	if !known {
		extra["timestamp_known"] = "false"
	}
	for k, v := range extra {
		if v == "" {
			delete(extra, k)
		}
	}
	return model.Event{
		Timestamp:       ts,
		EventType:       model.EventWebRequest,
		User:            get["cs-username"],
		NetworkSource:   get["c-ip"],
		ArtifactType:    model.ArtifactIISLog,
		Parser:          parserName,
		FilePath:        source,
		SourceReference: "line:" + strconv.Itoa(lineNo),
		Confidence:      0.95,
		Extra:           extra,
	}, true
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
