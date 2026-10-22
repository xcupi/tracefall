// Package grafanalogfile parses a Grafana application log (grafana.log).
//
// Each line is read by grafanalog.ParseLine. A line that is not a Grafana
// record is counted and reported, never guessed at. A log line records what
// Grafana wrote; it does not show who caused the activity, and a missing line
// is not a missing request.
package grafanalogfile

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"tracefall/internal/grafanalog"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "grafanalogfile@1"

// ErrNoGrafanaRecords means no line of the file is a Grafana log record.
var ErrNoGrafanaRecords = errors.New("grafanalogfile: no Grafana log record found")

const maxLineBytes = 1 << 20

// maxEvents is a variable only so a test can lower it.
var maxEvents = 250000

var nameRE = regexp.MustCompile(`^(grafana\.log(\.\d+|\.\d{4}-\d{2}-\d{2}|-\d{4}-?\d{2}-?\d{2})?|grafana-\d{4}-\d{2}-\d{2}\.log)$`)

// Parser implements parsers.ArtifactParser, parsers.ContentDetector.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactGrafanaLog }

// Detect matches grafana.log, grafana.log.<n|date> and grafana-YYYY-MM-DD.log.
func (Parser) Detect(relPath string) bool {
	rel := strings.ReplaceAll(relPath, `\`, "/")
	return nameRE.MatchString(strings.ToLower(filepath.Base(rel)))
}

// DetectContent claims a file whose first line is a Grafana record, whatever
// the file is called.
func (Parser) DetectContent(header []byte) bool {
	line := header
	truncated := len(header) >= parsers.SniffLength
	if i := strings.IndexByte(string(header), '\n'); i >= 0 {
		line, truncated = header[:i], false
	}
	s := string(line)
	if _, ok := grafanalog.ParseLine(s); ok {
		return true
	}
	if !truncated {
		return false
	}
	// The window may end inside a value: retry with the cut moved back to
	// earlier spaces, a few times.
	for i := 0; i < 8; i++ {
		j := strings.LastIndexByte(s, ' ')
		if j < 0 {
			return false
		}
		s = s[:j]
		if _, ok := grafanalog.ParseLine(s); ok {
			return true
		}
	}
	return false
}

func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	f, err := os.Open(absPath) // read-only
	if err != nil {
		return parsers.ParseResult{}, err
	}
	defer f.Close()
	base := filepath.Base(absPath)
	br := bufio.NewReaderSize(f, 64<<10)

	var res parsers.ParseResult
	cov := &model.ParseCoverage{}
	var buf []byte
	lineNo, unparsed, oversized := 0, 0, 0
	capped := false
	for !capped {
		buf = buf[:0]
		tooLong := false
		var rerr error
		for {
			chunk, err := br.ReadSlice('\n')
			if !tooLong {
				if len(buf)+len(chunk) > maxLineBytes+2 {
					tooLong = true
				} else {
					buf = append(buf, chunk...)
				}
			}
			if err == bufio.ErrBufferFull {
				continue
			}
			rerr = err
			break
		}
		if rerr != nil && rerr != io.EOF {
			return parsers.ParseResult{}, rerr
		}
		if len(buf) == 0 && !tooLong && rerr == io.EOF {
			break
		}
		lineNo++
		if tooLong {
			oversized++
			unparsed++
			cov.RecordsRead++
		} else if line := strings.TrimRight(string(buf), "\r\n"); strings.TrimSpace(line) != "" {
			cov.RecordsRead++
			if len(res.Events) >= maxEvents {
				capped = true
				break
			}
			ev, ok := grafanalog.ParseLine(line)
			if !ok {
				unparsed++
			} else {
				ref := "line:" + strconv.Itoa(lineNo)
				ev.ArtifactType = model.ArtifactGrafanaLog
				ev.Parser = parserName
				ev.FilePath = base
				ev.SourceReference = ref
				ev.Confidence = 0.95
				ev.Extra["line_number"] = strconv.Itoa(lineNo)
				res.Events = append(res.Events, ev)
				res.Raw = append(res.Raw, model.RawEvidence{SourceReference: ref, Raw: line})
			}
		}
		if rerr == io.EOF {
			break
		}
	}
	if capped {
		// The record that hit the cap was read but not mapped.
		cov.LimitReached = true
		cov.Notes = append(cov.Notes, fmt.Sprintf("event limit of %d reached at line %d; the rest of the file was not read", maxEvents, lineNo))
	}
	if len(res.Events) == 0 {
		return parsers.ParseResult{}, ErrNoGrafanaRecords
	}
	cov.Mapped = len(res.Events)
	cov.Unmapped = unparsed
	if unparsed > 0 {
		res.Events[0].Extra["unparsed_lines"] = strconv.Itoa(unparsed)
		cov.Notes = append(cov.Notes, fmt.Sprintf("%d line(s) are not Grafana records and were counted, not parsed", unparsed))
	}
	if oversized > 0 {
		cov.Notes = append(cov.Notes, fmt.Sprintf("%d line(s) longer than %d bytes were counted, not parsed", oversized, maxLineBytes))
	}
	res.Coverage = cov
	return res, nil
}
