package mssql

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

var errStreamRecordLimit = errors.New("mssql: record byte limit reached")

const streamRecordBytes = 1 << 20

// sqlLines reads encoded lines without retaining the file. A UTF-16 delimiter
// is a code unit, not an arbitrary 0x0a byte inside another character.
func sqlLines(ctx context.Context, f *os.File, visit func(int, string) error) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReaderSize(f, 64<<10)
	head, _ := r.Peek(2)
	wide := len(head) == 2 && head[0] == 255 && head[1] == 254
	if wide {
		_, _ = r.Discard(2)
	}
	n := 1
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var b []byte
		if wide {
			b = append(b, 255, 254)
		}
		eof := false
		for {
			if len(b) > streamRecordBytes {
				return fmt.Errorf("%w: encoded line exceeds %d bytes", errStreamRecordLimit, streamRecordBytes)
			}
			if len(b)&4095 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			c, err := r.ReadByte()
			if err == io.EOF {
				eof = true
				break
			}
			if err != nil {
				return err
			}
			b = append(b, c)
			if wide {
				d, err := r.ReadByte()
				if err != nil {
					if err == io.EOF {
						return fmt.Errorf("mssql: truncated UTF-16LE")
					}
					return err
				}
				b = append(b, d)
				if c == 10 && d == 0 {
					break
				}
			} else if c == 10 {
				break
			}
		}
		if len(b) > streamRecordBytes {
			return fmt.Errorf("%w: encoded line exceeds %d bytes", errStreamRecordLimit, streamRecordBytes)
		}
		var line string
		var err error
		if !wide && n > 1 {
			if !utf8.Valid(b) {
				return fmt.Errorf("mssql: invalid UTF-8")
			}
			line = string(b)
		} else {
			line, err = decode(b)
		}
		if err != nil {
			return err
		}
		if err = visit(n, line); err != nil {
			return err
		}
		n++
		if eof {
			return nil
		}
	}
}

// ParseStream makes two bounded passes: a source-wide server-name census, then
// record emission. This preserves legacy attribution even for a header at EOF
// or contradictory names. No file-size/record-count safety limit is increased;
// callers must supply a bounded job context. A single oversized record is an
// explicit partial-coverage failure, not silent truncation.
func (p Parser) ParseStream(ctx context.Context, path string, pc parsers.ParseContext, sink parsers.RecordSink) (*model.ParseCoverage, error) {
	cov := &model.ParseCoverage{}
	sinkFailed := false
	fail := func(err error) (*model.ParseCoverage, error) {
		cov.LimitReached = errors.Is(err, errStreamRecordLimit) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		if !cov.LimitReached && !sinkFailed {
			cov.RecordsFailed++
		}
		cov.Notes = append(cov.Notes, "SQL stream did not reach complete EOF; emitted batches are partial coverage.")
		return cov, err
	}
	f, err := os.Open(path)
	if err != nil {
		return cov, err
	}
	defer f.Close()
	recorded := ""
	ambiguous := false
	err = sqlLines(ctx, f, func(_ int, line string) error {
		entry := engineLine.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
		if entry == nil || !strings.EqualFold(entry[2], "Server") || !strings.HasPrefix(strings.ToLower(entry[3]), "server name is '") {
			return nil
		}
		m := serverName.FindStringSubmatch(entry[3])
		if m == nil {
			return nil
		}
		if recorded != "" && !strings.EqualFold(recorded, m[1]) {
			ambiguous = true
		}
		recorded = m[1]
		return nil
	})
	if err != nil {
		return fail(err)
	}
	var batch parsers.ParseResult
	batchBytes := 0
	flush := func() error {
		if len(batch.Events) == 0 {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		err := sink(batch)
		sinkFailed = err != nil
		batch = parsers.ParseResult{}
		batchBytes = 0
		return err
	}
	var event *model.Event
	var raw model.RawEvidence
	var record, message strings.Builder
	finish := func() error {
		if event == nil {
			return nil
		}
		raw.Raw = record.String()
		event.Extra["message"] = message.String()
		ApplyMessage(event, message.String())
		batch.Events = append(batch.Events, *event)
		batch.Raw = append(batch.Raw, raw)
		batchBytes += len(raw.Raw) + len(message.String())
		cov.Mapped++
		if event.Timestamp.IsZero() {
			cov.Undated++
		}
		event = nil
		if len(batch.Events) >= 128 || batchBytes >= streamRecordBytes {
			return flush()
		}
		return nil
	}
	err = sqlLines(ctx, f, func(n int, line string) error {
		m := engineLine.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
		agentID := ""
		if p.Agent {
			a := agentLine.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
			m = nil
			if a != nil {
				m = []string{a[0], a[1], a[2], a[4]}
				agentID = a[3]
			}
		}
		if m == nil {
			if event != nil {
				if record.Len()+len(line) > streamRecordBytes || message.Len()+len(line)+1 > streamRecordBytes {
					return fmt.Errorf("%w: logical record exceeds %d bytes", errStreamRecordLimit, streamRecordBytes)
				}
				record.WriteString(line)
				message.WriteString(strings.TrimRight(line, "\r\n") + "\n")
			}
			return nil
		}
		if err := finish(); err != nil {
			return err
		}
		cov.RecordsRead++
		record.Reset()
		message.Reset()
		record.WriteString(line)
		message.WriteString(m[3])
		ref := "line:" + strconv.Itoa(n)
		e := model.Event{FilePath: pc.EvidencePath, EventType: model.EventSQLMessage, ArtifactType: p.ArtifactType(), Parser: p.Name(), SourceReference: ref, Confidence: 0.95, Extra: map[string]string{"timestamp_local": m[1], "timestamp_basis": "local time; offset not recorded", "message": m[3], "sql_source": m[2]}}
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
		event = &e
		raw = model.RawEvidence{SourceReference: ref, Raw: line}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	if err = finish(); err == nil {
		err = flush()
	}
	if err != nil {
		return fail(err)
	}
	return cov, nil
}

var _ parsers.StreamingParser = (*Parser)(nil)
