// Package defendermplog reads the Microsoft Defender antimalware support logs
// (MPLog-*.log, MPDetection-*.log).
//
// These are very large, free-form engine logs. Only two kinds of line are read
// because they state something an investigator can cite:
//
//   - "Process creation blocked: ProcessName: ..., ProcessId: ..., Parent Pid:
//     ..." from real-time protection. It states that creation was blocked. It is
//     NOT a process start and is never mapped to one. The process id, parent
//     PID and the two ProcessCreationTime tokens are kept as written (PIDs are
//     per host and are reused; do not join them across hosts). Each token is
//     also shown as a Windows FILETIME reading, labelled as derived.
//   - "DETECTIONEVENT <source> <threat label> <resource>": the engine's own
//     record of a detection. The label is the engine's name, not a computed
//     family; a CmdLine resource is a command-line string, not a file.
//
// Every other line (the vast majority) is skipped by design and counted. The
// time at the start of a line carries no zone, so it is kept as written and the
// event stays undated; it is never converted. The file is streamed in a bounded
// buffer, with caps on the bytes scanned, the length of one line and the number
// of events; anything past a cap is counted and reported in the parse coverage.
package defendermplog

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
	"unicode/utf16"

	"tracefall/internal/cmdsem"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/winevent"
)

const parserName = "defendermplog@1"

const (
	defaultMaxScanBytes = 1 << 30 // bytes of one file that are scanned
	defaultMaxEvents    = 100000
	maxLineUnits        = 32 << 10 // characters of one line that are kept
	maxResourceBytes    = 2048
	maxRawBytes         = 4 << 10
	maxNotes            = 6
)

var nameRe = regexp.MustCompile(`(?i)^mp(?:log|detection)-[0-9][0-9a-z-]*\.log$`)

var (
	prefixRe  = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)\s+(.*)$`)
	blockedRe = regexp.MustCompile(`^(?:\[[A-Za-z]+\]\s+)?Process creation blocked:\s*ProcessName:\s*(.*?),\s*ProcessId:\s*(\d+),\s*ProcessCreationTime:\s*(\d+),\s*Parent Pid:\s*(\d+),\s*ParentProcessCreationTime:\s*(\d+),\s*Reason:\s*(\d+)\s*$`)
	detectRe  = regexp.MustCompile(`^DETECTIONEVENT\s+(\S+)\s+(\S+)\s+(.+)$`)
)

// Parser reads Defender support logs. The zero value uses the default caps.
type Parser struct {
	maxScanBytes int64
	maxEvents    int
}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactDefenderMPLog }

func (Parser) Detect(relPath string) bool {
	return nameRe.MatchString(filepath.Base(strings.ReplaceAll(relPath, `\`, "/")))
}

// DetectContent never claims a file by content: the name decides.
func (Parser) DetectContent([]byte) bool { return false }

// ConfirmContent requires the first non-empty line of the header to start with
// the engine's timestamp prefix, so a renamed unrelated file is not claimed.
func (Parser) ConfirmContent(header []byte) bool {
	s := newScanner(strings.NewReader(string(header)), int64(len(header)))
	for {
		ln, ok := s.next()
		if !ok {
			return false
		}
		if t := strings.TrimSpace(ln.text); t != "" {
			return prefixRe.MatchString(t)
		}
	}
}

func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	maxScan, maxEvents := p.maxScanBytes, p.maxEvents
	if maxScan <= 0 {
		maxScan = defaultMaxScanBytes
	}
	if maxEvents <= 0 {
		maxEvents = defaultMaxEvents
	}
	f, err := os.Open(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return parsers.ParseResult{}, err
	}
	sc := newScanner(f, maxScan)

	var out parsers.ParseResult
	cov := &model.ParseCoverage{}
	out.Coverage = cov
	var notes []string
	note := func(s string) {
		if len(notes) < maxNotes {
			notes = append(notes, s)
		}
	}
	var prev struct {
		no   int
		text string
	}
	truncatedLines, firstTruncated := 0, 0
	skippedByCap := 0

	lineNo := 0
	for {
		ln, ok := sc.next()
		if !ok {
			break
		}
		lineNo++
		cov.RecordsRead++
		if ln.truncated {
			truncatedLines++
			if firstTruncated == 0 {
				firstTruncated = lineNo
			}
		}
		text := strings.TrimSpace(ln.text)
		m := prefixRe.FindStringSubmatch(text)
		if m == nil {
			prev.no, prev.text = lineNo, boundText(text)
			continue
		}
		stamp, rest := m[1], m[2]
		var ev model.Event
		var emit bool
		switch {
		case strings.Contains(rest, "Process creation blocked"):
			b := blockedRe.FindStringSubmatch(rest)
			if b == nil {
				cov.RecordsFailed++
				note(fmt.Sprintf("line %d names a blocked process creation but did not match the expected fields; not emitted", lineNo))
			} else {
				ev, emit = blockedEvent(b, stamp, lineNo, ln.offset, prev.no, prev.text), true
			}
		case strings.HasPrefix(rest, "DETECTIONEVENT"):
			d := detectRe.FindStringSubmatch(rest)
			if d == nil {
				cov.RecordsFailed++
				note(fmt.Sprintf("line %d is a detection event record that did not match the expected fields; not emitted", lineNo))
			} else {
				ev, emit = detectionEvent(d, stamp, lineNo, ln.offset), true
			}
		}
		if emit {
			if len(out.Events) >= maxEvents {
				cov.Unmapped++
				cov.LimitReached = true
				skippedByCap++
			} else {
				raw := boundText(text)
				if prev.no == lineNo-1 && strings.Contains(prev.text, "reported as threat") {
					raw = prev.text + "\n" + raw
				}
				out.Events = append(out.Events, ev)
				out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ev.SourceReference, Raw: raw})
				cov.Mapped++
			}
		}
		prev.no, prev.text = lineNo, boundText(text)
	}

	if sc.capped {
		cov.LimitReached = true
		note(fmt.Sprintf("scan cap of %d bytes reached; %d bytes of the file were not read", maxScan, st.Size()-sc.pos))
	}
	if skippedByCap > 0 {
		note(fmt.Sprintf("event cap of %d reached; %d further matching lines were counted but not emitted", maxEvents, skippedByCap))
	}
	if truncatedLines > 0 {
		note(fmt.Sprintf("%d line(s) longer than %d characters were truncated before matching (first at line %d)", truncatedLines, maxLineUnits, firstTruncated))
	}
	if sc.oddTail {
		note("the file ends in a partial UTF-16 character, which was dropped")
	}
	note("selective reader: only lines naming a detection or a blocked process creation are read; all other lines are skipped by design")
	cov.Notes = notes
	return out, nil
}

func boundText(s string) string {
	if len(s) > maxRawBytes {
		return s[:maxRawBytes]
	}
	return s
}

const timeNote = "MPLog prefix time; no zone is recorded, kept as written and not converted"

func commonExtra(stamp string, lineNo int, offset int64) map[string]string {
	return map[string]string{
		"timestamp_local": stamp,
		"timestamp_basis": timeNote,
		"line_number":     strconv.Itoa(lineNo),
		"byte_offset":     strconv.FormatInt(offset, 10),
	}
}

func blockedEvent(b []string, stamp string, lineNo int, offset int64, prevNo int, prevText string) model.Event {
	x := commonExtra(stamp, lineNo, offset)
	x["process_name"] = b[1]
	x["process_id"] = b[2]
	x["process_creation_time_raw"] = b[3]
	x["parent_pid"] = b[4]
	x["parent_process_creation_time_raw"] = b[5]
	x["reason_code"] = b[6]
	if t, ok := filetimeUTC(b[3]); ok {
		x["process_creation_utc_derived"] = t
	}
	if t, ok := filetimeUTC(b[5]); ok {
		x["parent_creation_utc_derived"] = t
	}
	x["derived_time_basis"] = "the two ProcessCreationTime tokens are read as Windows FILETIME (100 ns since 1601-01-01 UTC); this reading is derived here, the log does not label them as times, and it is separate from the zone-less line prefix"
	if prevNo == lineNo-1 && strings.Contains(prevText, "reported as threat") {
		x["preceding_threat_report_line"] = strconv.Itoa(prevNo)
	}
	x["evidence_meaning"] = "Defender real-time protection recorded that creation of this process was blocked."
	x["limitations"] = "States that creation was blocked: it is not a process start and not proof that any command ran or completed. The log does not name the parent image; process and parent ids are per host and are reused, so they are kept as written and are not joined across hosts. " +
		"A neighbouring engine line that reports a command-line threat is retained by line number, not merged into this record."
	return model.Event{
		EventType: model.EventAntimalwareBlock, ArtifactType: model.ArtifactDefenderMPLog, Parser: parserName,
		ProcessName: b[1], SourceReference: "line:" + strconv.Itoa(lineNo), Confidence: 0.95, Extra: x,
	}
}

func detectionEvent(d []string, stamp string, lineNo int, offset int64) model.Event {
	x := commonExtra(stamp, lineNo, offset)
	x["detection_source"] = d[1]
	x["threat_name"] = d[2]
	res := d[3]
	if i := strings.Index(res, ";internalCmdLine:"); i >= 0 {
		res = res[:i]
		x["internal_blob_omitted"] = "true"
	}
	res = cmdsem.Redact(strings.TrimSpace(res))
	if len(res) > maxResourceBytes {
		res = res[:maxResourceBytes]
		x["resource_truncated"] = "true"
	}
	x["resource"] = res
	kind, scheme := winevent.AntimalwareResourceKind(res)
	x["resource_kind"] = kind
	if scheme != "" {
		x["resource_scheme"] = scheme
	}
	x["evidence_meaning"] = "The Defender engine log recorded a detection of this resource under the engine's own label."
	note := "The label is the engine's recorded name, not an independently computed family."
	if kind == "command_line" {
		note = "The resource is a command-line string, not a file. " + note
	}
	x["limitations"] = note + " A detection does not show that the resource ran or that any command completed; the line carries no detection id, severity or action, which the Operational event log may record for the same detection."
	return model.Event{
		EventType: model.EventAntimalwareDetection, ArtifactType: model.ArtifactDefenderMPLog, Parser: parserName,
		SourceReference: "line:" + strconv.Itoa(lineNo), Confidence: 0.9, Extra: x,
	}
}

// filetimeUTC reads a decimal token as a Windows FILETIME. It reports false
// outside 1601..9999 so a stray number is never shown as a date.
func filetimeUTC(tok string) (string, bool) {
	v, err := strconv.ParseUint(tok, 10, 64)
	if err != nil || v == 0 || v >= 2650467743990000000 {
		return "", false
	}
	const unixEpoch = 11644473600 // seconds from 1601 to 1970
	sec := int64(v/10_000_000) - unixEpoch
	nsec := int64(v%10_000_000) * 100
	return time.Unix(sec, nsec).UTC().Format("2006-01-02T15:04:05.999999Z"), true
}

// ---- streaming line scanner ----

type encoding int

const (
	encUTF8 encoding = iota
	encUTF16LE
	encUTF16BE
)

type line struct {
	text      string
	offset    int64 // byte offset of the line's first byte in the file
	truncated bool
}

type scanner struct {
	r       *bufio.Reader
	enc     encoding
	pos     int64 // bytes consumed, BOM included
	limit   int64
	capped  bool
	oddTail bool
}

func newScanner(src io.Reader, limit int64) *scanner {
	r := bufio.NewReaderSize(src, 64<<10)
	head, _ := r.Peek(4)
	s := &scanner{r: r, limit: limit}
	switch {
	case len(head) >= 2 && head[0] == 0xff && head[1] == 0xfe:
		s.enc = encUTF16LE
		s.skip(2)
	case len(head) >= 2 && head[0] == 0xfe && head[1] == 0xff:
		s.enc = encUTF16BE
		s.skip(2)
	case len(head) >= 3 && head[0] == 0xef && head[1] == 0xbb && head[2] == 0xbf:
		s.skip(3)
	case len(head) >= 4 && head[0] != 0 && head[1] == 0 && head[3] == 0:
		s.enc = encUTF16LE
	case len(head) >= 4 && head[0] == 0 && head[2] == 0 && head[1] != 0:
		s.enc = encUTF16BE
	}
	return s
}

func (s *scanner) skip(n int) {
	_, _ = s.r.Discard(n)
	s.pos += int64(n)
}

// next returns the next line without its terminator. It reports false at the
// end of the input or at the scan cap.
func (s *scanner) next() (line, bool) {
	start := s.pos
	if s.enc == encUTF8 {
		return s.nextUTF8(start)
	}
	return s.nextUTF16(start)
}

func (s *scanner) atCap(unit int64) bool {
	if s.pos+unit <= s.limit {
		return false
	}
	if _, err := s.r.Peek(1); err == nil {
		s.capped = true
	}
	return true
}

func (s *scanner) nextUTF8(start int64) (line, bool) {
	var buf []byte
	n, trunc := 0, false
	for {
		if s.atCap(1) {
			return line{}, false
		}
		b, err := s.r.ReadByte()
		if err != nil {
			break
		}
		s.pos++
		n++
		if b == '\n' {
			return finish(buf, start, trunc), true
		}
		if len(buf) < maxLineUnits {
			buf = append(buf, b)
		} else {
			trunc = true
		}
	}
	if n == 0 {
		return line{}, false
	}
	return finish(buf, start, trunc), true
}

func finish(buf []byte, start int64, trunc bool) line {
	t := strings.TrimSuffix(strings.ToValidUTF8(string(buf), "\uFFFD"), "\r")
	return line{text: t, offset: start, truncated: trunc}
}

func (s *scanner) nextUTF16(start int64) (line, bool) {
	var units []uint16
	n, trunc := 0, false
	for {
		if s.atCap(2) {
			return line{}, false
		}
		b0, err := s.r.ReadByte()
		if err != nil {
			break
		}
		b1, err := s.r.ReadByte()
		if err != nil {
			s.pos++
			s.oddTail = true
			break
		}
		s.pos += 2
		n++
		var u uint16
		if s.enc == encUTF16LE {
			u = uint16(b0) | uint16(b1)<<8
		} else {
			u = uint16(b1) | uint16(b0)<<8
		}
		if u == '\n' {
			return finish16(units, start, trunc), true
		}
		if len(units) < maxLineUnits {
			units = append(units, u)
		} else {
			trunc = true
		}
	}
	if n == 0 {
		return line{}, false
	}
	return finish16(units, start, trunc), true
}

func finish16(units []uint16, start int64, trunc bool) line {
	t := strings.TrimSuffix(string(utf16.Decode(units)), "\r")
	return line{text: t, offset: start, truncated: trunc}
}
