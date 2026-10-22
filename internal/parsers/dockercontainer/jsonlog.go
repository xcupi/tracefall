package dockercontainer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"tracefall/internal/cmdsem"
	"tracefall/internal/grafanalog"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const (
	maxLineBytes    = 1 << 20 // longest log line that is parsed
	maxRecords      = 250000  // log records parsed from one file
	maxMessageBytes = 1024
	maxRawBytes     = 16 << 10 // raw text kept per log record
)

type logRecord struct {
	Log    *string `json:"log"`
	Stream string  `json:"stream"`
	Time   string  `json:"time"`
}

// readLine reads one line without ever holding more than limit bytes. It
// returns the line (without the newline), whether it was longer than limit,
// and io.EOF after the last line.
func readLine(r *bufio.Reader, limit int) (line []byte, oversized bool, err error) {
	var buf []byte
	for {
		chunk, e := r.ReadSlice('\n')
		if !oversized {
			if len(buf)+len(chunk) > limit+1 { // +1: the newline itself
				oversized = true
				buf = nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		if e != nil && e != io.EOF {
			return nil, false, e
		}
		if e == io.EOF && len(chunk) == 0 && len(buf) == 0 && !oversized {
			return nil, false, io.EOF
		}
		if oversized {
			return nil, true, nil
		}
		return bytes.TrimSuffix(buf, []byte("\n")), false, nil
	}
}

func clipRunes(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n], true
}

func parseLog(absPath, id, fileName string) (parsers.ParseResult, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)

	var out parsers.ParseResult
	var lines, unparsed, oversized, undated, rawClipped int
	limitReached := false
	for {
		line, big, err := readLine(r, maxLineBytes)
		if err == io.EOF {
			break
		}
		if err != nil {
			return parsers.ParseResult{}, err
		}
		if len(out.Events) >= maxRecords {
			limitReached = true
			break
		}
		lines++
		if big {
			oversized++
			continue
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		var rec logRecord
		if len(bytes.TrimSpace(line)) == 0 || json.Unmarshal(line, &rec) != nil || rec.Log == nil {
			unparsed++
			continue
		}
		msg := *rec.Log
		partial := !strings.HasSuffix(msg, "\n")
		msg = strings.TrimSuffix(msg, "\n")
		msg = strings.TrimSuffix(msg, "\r")

		ref := "line:" + strconv.Itoa(lines)
		var ev model.Event
		if g, ok := grafanalog.ParseLine(msg); ok {
			ev = g
		} else {
			ev = model.Event{EventType: model.EventContainerLog, Extra: map[string]string{}}
			m, cut := clipRunes(cmdsem.Redact(msg), maxMessageBytes)
			ev.Extra["message"] = m
			if cut {
				ev.Extra["message_truncated"] = "true"
			}
		}
		appTime := !ev.Timestamp.IsZero()
		ts, perr := time.Parse(time.RFC3339Nano, rec.Time)
		switch {
		case appTime && perr == nil:
			ev.Extra["container_received"] = rec.Time
		case appTime:
			if rec.Time != "" {
				ev.Extra["container_received"] = rec.Time
			}
		case perr == nil:
			ev.Timestamp = ts.UTC()
		default:
			undated++
			if rec.Time != "" {
				ev.Extra["time_as_written"] = rec.Time
			}
		}
		ev.Extra["container_id"] = id
		ev.Extra["stream"] = rec.Stream
		if partial {
			ev.Extra["partial_line"] = "true"
		}
		ev.ArtifactType = model.ArtifactContainerLog
		ev.Parser = parserName
		// FilePath is part of the dedup identity and the engine time can tie,
		// so the line number goes with the name.
		ev.FilePath = fileName + ":" + strconv.Itoa(lines)
		ev.SourceReference = ref
		ev.Confidence = 0.95

		raw := string(line)
		if len(raw) > maxRawBytes {
			raw, _ = clipRunes(raw, maxRawBytes)
			rawClipped++
		}
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ref, Raw: raw})
	}
	if len(out.Events) == 0 {
		return parsers.ParseResult{}, fmt.Errorf("dockercontainer: no valid json-file record in %d line(s) (%d not JSON objects with a log field, %d longer than %d bytes)", lines, unparsed, oversized, maxLineBytes)
	}
	if unparsed > 0 {
		out.Events[0].Extra["unparsed_lines"] = strconv.Itoa(unparsed)
	}
	if oversized > 0 {
		out.Events[0].Extra["oversized_lines"] = strconv.Itoa(oversized)
	}
	cov := &model.ParseCoverage{RecordsRead: lines, Mapped: len(out.Events), RecordsFailed: unparsed + oversized, Undated: undated, LimitReached: limitReached}
	if unparsed > 0 {
		cov.Notes = append(cov.Notes, fmt.Sprintf("%d line(s) were not valid JSON objects with a log field and were not parsed", unparsed))
	}
	if oversized > 0 {
		cov.Notes = append(cov.Notes, fmt.Sprintf("%d line(s) were longer than %d bytes and were not parsed", oversized, maxLineBytes))
	}
	if undated > 0 {
		cov.Notes = append(cov.Notes, fmt.Sprintf("%d record(s) have no usable engine time and are undated", undated))
	}
	if rawClipped > 0 {
		cov.Notes = append(cov.Notes, fmt.Sprintf("raw text of %d record(s) was cut at %d bytes", rawClipped, maxRawBytes))
	}
	if limitReached {
		cov.Notes = append(cov.Notes, fmt.Sprintf("stopped after %d records; the rest of the file was not read", maxRecords))
	}
	out.Coverage = cov
	return out, nil
}
