// Package pecmd parses the CSV output of PECmd (Eric Zimmerman's Prefetch
// parser, run by KAPE's !EZParser module against collected .pf files).
// As with evtxcsv, Tracefall consumes PECmd's CSV rather than
// re-implementing raw Prefetch binary decompression/parsing -- see the
// evtxcsv package doc for the rationale, which applies identically here.
package pecmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/normalize"
	"tracefall/internal/parsers"
)

const parserName = "pecmd@1"

type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactPrefetch }

// Detect matches PECmd's default output naming convention, e.g.
// "20240115143022_PECmd_Output.csv".
func (Parser) Detect(relPath string) bool {
	base := strings.ToLower(filepath.Base(relPath))
	return strings.Contains(base, "pecmd") && strings.HasSuffix(base, ".csv")
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
		return parsers.ParseResult{}, fmt.Errorf("pecmd: reading header: %w", err)
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
			return parsers.ParseResult{}, fmt.Errorf("pecmd: row %d: %w", rowNum, err)
		}
		rowNum++

		exeName := get(rec, col, "ExecutableName")
		lastRun := get(rec, col, "LastRun")
		sourceFile := get(rec, col, "SourceFilename")
		runCount := get(rec, col, "RunCount")

		ts, ok := normalize.Timestamp(lastRun)
		if !ok || exeName == "" {
			continue
		}

		ev := model.Event{
			Timestamp:       ts,
			EventType:       model.EventPrefetchExecution,
			ProcessName:     strings.ToLower(strings.TrimSpace(exeName)),
			FilePath:        sourceFile,
			ArtifactType:    model.ArtifactPrefetch,
			Parser:          parserName,
			Confidence:      0.9, // prefetch LastRun approximates, doesn't guarantee, exact execution time
			SourceReference: "row:" + fmt.Sprint(rowNum-1),
			Extra: map[string]string{
				"run_count": runCount,
			},
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
