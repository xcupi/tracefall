package mssqlxe

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

func (p Parser) exports(b []byte, path string, c parsers.ParseContext) (parsers.ParseResult, error) {
	r := parsers.ParseResult{Coverage: &model.ParseCoverage{}}
	if strings.HasSuffix(strings.ToLower(path), ".jsonl") {
		s := bufio.NewScanner(bytes.NewReader(b))
		s.Buffer(make([]byte, 4096), maxLine)
		for s.Scan() {
			if len(r.Events) >= maxRecords {
				return parsers.ParseResult{}, fmt.Errorf("record cap")
			}
			line := s.Text()
			var row struct {
				Name      string                     `json:"name"`
				Timestamp string                     `json:"timestamp"`
				Fields    map[string]json.RawMessage `json:"fields"`
				Actions   map[string]json.RawMessage `json:"actions"`
			}
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				return r, err
			}
			if row.Name == "" {
				return r, fmt.Errorf("mssqlxe: missing event name")
			}
			f := map[string]string{"event_name": row.Name}
			for _, m := range []map[string]json.RawMessage{row.Fields, row.Actions} {
				for k, v := range m {
					var text string
					if json.Unmarshal(v, &text) != nil {
						text = string(v)
					}
					f[k] = text
				}
			}
			p.append(&r, c, f, line, row.Timestamp)
		}
		return r, s.Err()
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	recognized := false
	for {
		start := d.InputOffset()
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return r, err
		}
		el, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		for _, a := range el.Attr {
			if a.Name.Local == "truncated" && (a.Value == "1" || a.Value == "true") {
				return r, fmt.Errorf("mssqlxe: truncated XML export")
			}
		}
		if el.Name.Local == "RingBufferTarget" || el.Name.Local == "Events" || el.Name.Local == "event" {
			recognized = true
		}
		if el.Name.Local != "event" {
			continue
		}
		var row struct {
			Name      string `xml:"name,attr"`
			Timestamp string `xml:"timestamp,attr"`
			Data      []struct {
				Name  string `xml:"name,attr"`
				Value string `xml:"value"`
			} `xml:"data"`
			Actions []struct {
				Name  string `xml:"name,attr"`
				Value string `xml:"value"`
			} `xml:"action"`
		}
		if err := d.DecodeElement(&row, &el); err != nil {
			return r, err
		}
		if row.Name == "" {
			return r, fmt.Errorf("mssqlxe: missing event name")
		}
		if d.InputOffset()-start > maxLine || len(r.Events) >= maxRecords {
			return parsers.ParseResult{}, fmt.Errorf("record/line cap")
		}
		f := map[string]string{"event_name": row.Name}
		for _, v := range row.Data {
			f[v.Name] = v.Value
		}
		for _, v := range row.Actions {
			f[v.Name] = v.Value
		}
		p.append(&r, c, f, string(b[start:d.InputOffset()]), row.Timestamp)
	}
	if !recognized {
		return r, fmt.Errorf("mssqlxe: not XE XML")
	}
	return r, nil
}
