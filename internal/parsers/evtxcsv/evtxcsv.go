// Package evtxcsv parses the CSV output of EvtxECmd (Eric Zimmerman's
// Windows Event Log parser, run by KAPE's !EZParser module against
// collected .evtx files). Tracefall consumes this CSV rather than raw
// binary .evtx directly: EvtxECmd already resolves each event's Maps
// definition into named PayloadData fields, which is exactly the
// structured extraction Tracefall needs, and re-implementing the .evtx
// binary format and Maps engine from scratch would spend Phase 1's budget
// on a solved problem instead of on detection/correlation. Raw .evtx
// parsing is a natural Phase 2 addition behind the same ArtifactParser
// interface.
//
// One parser instance covers three distinct KAPE-priority artifacts --
// Security 4624/4625/4688, PowerShell 4104, and (as a bonus, since it
// costs nothing extra) Sysmon Network Connect -- because they all arrive
// in the same EvtxECmd CSV shape. Extending coverage to another
// channel/EventID pair is a new case in the switch in toEvent, not a new
// parser.
package evtxcsv

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/normalize"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/winevent"
)

const parserName = "evtxcsv@1"

// Parser implements parsers.ArtifactParser for EvtxECmd CSV output.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactWindowsEventLog }

// Detect matches EvtxECmd's default output naming convention, e.g.
// "20240115143022_EvtxECmd_Output.csv", anywhere under the evidence root.
func (Parser) Detect(relPath string) bool {
	base := strings.ToLower(filepath.Base(relPath))
	return strings.Contains(base, "evtxecmd") && strings.HasSuffix(base, ".csv")
}

// row is one EvtxECmd CSV record, keyed by the real tool's column names.
type row struct {
	TimeCreated    string
	EventId        string
	Provider       string
	Channel        string
	ComputerName   string
	UserName       string
	RemoteHost     string
	MapDescription string
	PayloadData1   string
	PayloadData2   string
	PayloadData3   string
	PayloadData4   string
	PayloadData5   string
	PayloadData6   string
	RecordNumber   string
}

func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("evtxcsv: reading header: %w", err)
	}
	col := indexColumns(header)

	var out parsers.ParseResult
	rowNum := 1
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return parsers.ParseResult{}, fmt.Errorf("evtxcsv: row %d: %w", rowNum, err)
		}
		rowNum++

		rw := row{
			TimeCreated:    get(rec, col, "TimeCreated"),
			EventId:        get(rec, col, "EventId"),
			Provider:       get(rec, col, "Provider"),
			Channel:        get(rec, col, "Channel"),
			ComputerName:   get(rec, col, "ComputerName"),
			UserName:       get(rec, col, "UserName"),
			RemoteHost:     get(rec, col, "RemoteHost"),
			MapDescription: get(rec, col, "MapDescription"),
			PayloadData1:   get(rec, col, "PayloadData1"),
			PayloadData2:   get(rec, col, "PayloadData2"),
			PayloadData3:   get(rec, col, "PayloadData3"),
			PayloadData4:   get(rec, col, "PayloadData4"),
			PayloadData5:   get(rec, col, "PayloadData5"),
			PayloadData6:   get(rec, col, "PayloadData6"),
			RecordNumber:   get(rec, col, "RecordNumber"),
		}

		payload := parsePayload(strings.Join([]string{
			rw.PayloadData1, rw.PayloadData2, rw.PayloadData3,
			rw.PayloadData4, rw.PayloadData5, rw.PayloadData6,
		}, "; "))

		ts, ok := normalize.Timestamp(rw.TimeCreated)
		if !ok {
			// No usable timestamp -- this record can't be placed on the
			// timeline, so it's dropped rather than defaulting to a
			// fabricated time that would corrupt correlation.
			continue
		}

		ev := model.Event{
			Timestamp:       ts,
			Host:            normalize.Host(rw.ComputerName),
			User:            normalize.User(rw.UserName),
			Provider:        rw.Channel,
			EventID:         normalize.Int(rw.EventId),
			ArtifactType:    model.ArtifactWindowsEventLog,
			Parser:          parserName,
			Confidence:      1.0,
			SourceReference: "row:" + fmt.Sprint(rowNum-1),
			Extra:           map[string]string{},
		}
		// The channel/EventID mapping is shared with the raw .evtx parser
		// (internal/parsers/winevent) so the same Windows record read from
		// a CSV export and from the binary log normalizes identically and
		// deduplicates as one event rather than two.
		if !winevent.Normalize(&ev, winevent.Input{
			Channel:     rw.Channel,
			Provider:    rw.Provider,
			EventID:     normalize.Int(rw.EventId),
			Data:        payload,
			RemoteHost:  normalize.User(rw.RemoteHost),
			Description: rw.MapDescription,
		}) {
			// Channel/EventId combination we don't have a mapping for
			// yet -- skip rather than emit an under-specified event.
			continue
		}

		// RecordNumber is Windows' EventRecordID, not the CSV row position.
		// Missing/invalid values remain unknown; never substitute rowNum.
		if id, err := strconv.ParseUint(rw.RecordNumber, 10, 64); err == nil {
			ev.Extra["evtx_record_id"] = strconv.FormatUint(id, 10)
		}
		rawJSON, _ := json.Marshal(rec)
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, model.RawEvidence{
			SourceReference: ev.SourceReference,
			Raw:             string(rawJSON),
		})
	}
	return out, nil
}

func indexColumns(header []string) map[string]int {
	m := make(map[string]int, len(header))
	for i, h := range header {
		m[strings.TrimSpace(h)] = i
	}
	return m
}

func get(rec []string, col map[string]int, name string) string {
	i, ok := col[name]
	if !ok || i >= len(rec) {
		return ""
	}
	return strings.TrimSpace(rec[i])
}

// parsePayload parses EvtxECmd's Maps-derived "Key: Value; Key2: Value2"
// payload format into a lookup map.
func parsePayload(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return out
}
