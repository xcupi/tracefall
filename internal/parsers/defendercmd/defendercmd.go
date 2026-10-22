// Package defendercmd reads MpCmdRun.log, the log of the Microsoft Defender
// command-line tool (MpCmdRun.exe).
//
// The log records each run of the tool with its command line and the start and
// end time it printed. That makes it execution evidence for MpCmdRun.exe, and
// MpCmdRun.exe -DownloadFile -url ... -path ... is a known way to fetch a file
// with a signed Microsoft binary.
//
// The times are the machine's LOCAL time and carry no zone, so a run is not
// given an instant. When the collection's own SYSTEM hive records the zone, a
// UTC reading is derived with that one fixed offset (daylight-saving changes are
// not applied) and the offset's source is named. The tool prints the day and
// month in the machine's language; only the English forms are read, and any
// other time is kept as written.
package defendercmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "defendercmd@1"

const (
	maxFileBytes = 64 << 20
	maxCmdBytes  = 4096
	maxRawBytes  = 8 << 10
	maxRuns      = 200000
)

var nameRe = regexp.MustCompile(`(?i)^mpcmdrun(?:-[0-9-]+)?\.log$`)

const cmdMarker = "MpCmdRun: Command Line:"

type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactDefenderCmdLog }

func (Parser) Detect(relPath string) bool {
	return nameRe.MatchString(filepath.Base(strings.ReplaceAll(relPath, `\`, "/")))
}

// DetectContent claims the UTF-16 form the tool writes when its own first line
// is in the header.
func (Parser) DetectContent(header []byte) bool {
	if len(header) < 4 || header[0] != 0xff || header[1] != 0xfe {
		return false
	}
	return strings.Contains(decode(header), "MpCmdRun:")
}

func (p Parser) ConfirmContent(header []byte) bool { return p.DetectContent(header) }

func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	return p.ParseWithContext(absPath, parsers.ParseContext{})
}

// decode reads UTF-16LE with a byte order mark, or UTF-8 otherwise. A trailing
// odd byte (a file cut mid-character) is dropped.
func decode(b []byte) string {
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		b = b[2:]
		u := make([]uint16, 0, len(b)/2)
		for i := 0; i+1 < len(b); i += 2 {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		}
		return string(utf16.Decode(u))
	}
	return strings.ToValidUTF8(string(b), "\uFFFD")
}

var (
	timeRe = regexp.MustCompile(`^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{4} \d{2}:\d{2}:\d{2}$`)
	errRe  = regexp.MustCompile(`(?i)\berror\b|\bfailed\b`)
)

// clean drops the left-to-right marks the tool puts before each token of a time.
func clean(s string) string {
	s = strings.NewReplacer("\u200e", "", "\u200f", "", "\ufeff", "").Replace(s)
	return strings.Join(strings.Fields(s), " ")
}

func (Parser) ParseWithContext(absPath string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
	st, err := os.Stat(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if st.Size() > maxFileBytes {
		return parsers.ParseResult{}, fmt.Errorf("defendercmd: file exceeds %d bytes", maxFileBytes)
	}
	raw, err := os.ReadFile(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	lines := strings.Split(decode(raw), "\n")

	var out parsers.ParseResult
	starts := []int{}
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), cmdMarker) {
			starts = append(starts, i)
		}
	}
	for n, s := range starts {
		if n >= maxRuns {
			break
		}
		end := len(lines)
		if n+1 < len(starts) {
			end = starts[n+1]
		}
		ev, rawText := run(lines[s:end], s+1, filepath.Base(absPath), ctx.TimeBasis)
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ev.SourceReference, Raw: rawText})
	}
	return out, nil
}

func run(block []string, lineNo int, source string, basis *parsers.TimeBasis) (model.Event, string) {
	cmd := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(block[0]), cmdMarker))
	cmd = strings.TrimRight(cmd, "\r")
	if len(cmd) > maxCmdBytes {
		cmd = cmd[:maxCmdBytes]
	}
	extra := map[string]string{
		"command_line": cmd,
		"line_number":  strconv.Itoa(lineNo),
		"history_file": source,
	}
	toks := tokens(cmd)
	if len(toks) > 0 {
		extra["executable"] = toks[0]
	}
	if len(toks) > 1 {
		extra["verb"] = toks[1]
	}
	for i := 1; i+1 < len(toks); i++ {
		switch strings.ToLower(toks[i]) {
		case "-url":
			extra["download_url"] = toks[i+1]
		case "-path":
			extra["download_path"] = toks[i+1]
		}
	}

	var errs []string
	var rawB strings.Builder
	for i, l := range block {
		l = strings.TrimRight(l, "\r")
		if rawB.Len() < maxRawBytes {
			rawB.WriteString(l + "\n")
		}
		t := clean(l)
		switch {
		case strings.HasPrefix(t, "Start Time:"):
			_, local := extra["timestamp_local"]
			_, text := extra["timestamp_text"]
			if !local && !text {
				timeFields(extra, strings.TrimSpace(strings.TrimPrefix(t, "Start Time:")), "timestamp_local", "timestamp_text")
			}
		case strings.HasPrefix(t, "MpCmdRun: End Time:"):
			timeFields(extra, strings.TrimSpace(strings.TrimPrefix(t, "MpCmdRun: End Time:")), "end_local", "end_text")
		case i > 0 && errRe.MatchString(t) && len(errs) < 3:
			if len(t) > 200 {
				t = t[:200]
			}
			errs = append(errs, t)
		}
	}
	if len(errs) > 0 {
		extra["error_lines"] = strings.Join(errs, " | ")
	}
	if loc, ok := extra["timestamp_local"]; ok {
		extra["timestamp_basis"] = "local time; offset not recorded"
		if basis != nil {
			if t, err := time.Parse("2006-01-02T15:04:05", loc); err == nil {
				extra["timestamp_utc"] = t.Add(time.Duration(basis.ActiveBiasMinutes) * time.Minute).Format("2006-01-02T15:04:05Z")
				extra["timestamp_utc_basis"] = basis.Source + "; one fixed offset, daylight-saving changes not applied"
			}
		}
	} else {
		extra["timestamp_basis"] = "no readable start time in the record"
	}
	raw := rawB.String()
	if len(raw) > maxRawBytes {
		raw = raw[:maxRawBytes]
	}
	return model.Event{
		EventType: model.EventDefenderCommand, ArtifactType: model.ArtifactDefenderCmdLog, Parser: parserName,
		FilePath: source, SourceReference: "line:" + strconv.Itoa(lineNo), Confidence: 0.95, Extra: extra,
	}, raw
}

// timeFields stores a time as ISO local text when it is in the English form the
// parser reads, and otherwise keeps it as written under textKey.
func timeFields(extra map[string]string, v, key, textKey string) {
	if timeRe.MatchString(v) {
		if t, err := time.Parse("Mon Jan 2 2006 15:04:05", v); err == nil {
			extra[key] = t.Format("2006-01-02T15:04:05")
			return
		}
	}
	if len(v) > 80 {
		v = v[:80]
	}
	extra[textKey] = v
}

// tokens splits a command line on spaces, keeping a double-quoted part whole and
// without its quotes.
func tokens(s string) []string {
	var out []string
	var cur strings.Builder
	inQ, has := false, false
	for _, r := range s {
		switch {
		case r == '"':
			inQ, has = !inQ, true
		case r == ' ' && !inQ:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if has {
		out = append(out, cur.String())
	}
	return out
}
