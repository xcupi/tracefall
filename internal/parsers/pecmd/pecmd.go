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
	"time"

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

		extra := map[string]string{
			"run_count": runCount,
		}
		if vol := get(rec, col, "Volume0Name"); vol != "" {
			extra["volume_name"] = vol
		}
		if serial := get(rec, col, "Volume0Serial"); serial != "" {
			extra["volume_serial"] = serial
		}
		// FilesLoaded is PECmd's semicolon-delimited list of every file
		// (DLLs and other referenced files) the executable touched during
		// the run(s) it tracked -- often hundreds of entries. Extra is
		// triage metadata, not a blob store, so only the count and a
		// bounded sample are kept; the full list remains available via
		// the raw evidence record for a deeper look.
		if filesLoaded := get(rec, col, "FilesLoaded"); filesLoaded != "" {
			files := strings.Split(filesLoaded, ";")
			extra["files_loaded_count"] = fmt.Sprint(len(files))
			extra["files_loaded_sample"] = truncateList(files, 500)
		}
		if earliest, ok := earliestPreviousRun(rec, col); ok {
			extra["earliest_recorded_run"] = earliest
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
			Extra:           extra,
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

// earliestPreviousRun finds the oldest timestamp among PECmd's
// PreviousRun0..PreviousRun6 columns (the up-to-7 execution times a
// Prefetch file retains in addition to LastRun), if the CSV has any of
// them populated. This is the closest thing to a "first execution"
// PECmd's output actually exposes -- not literally the first time the
// program ever ran, only the oldest run still retained in this .pf file's
// history, which is why it's labeled "earliest_recorded_run" rather than
// "first_run".
func earliestPreviousRun(rec []string, col map[string]int) (string, bool) {
	var earliest time.Time
	found := false
	for i := 0; i < 7; i++ {
		v := get(rec, col, fmt.Sprintf("PreviousRun%d", i))
		ts, ok := normalize.Timestamp(v)
		if !ok {
			continue
		}
		if !found || ts.Before(earliest) {
			earliest, found = ts, true
		}
	}
	if !found {
		return "", false
	}
	return earliest.Format(time.RFC3339), true
}

// truncateList joins vals with "; ", bounded to n characters, so a very
// long PECmd FilesLoaded list doesn't bloat Extra.
func truncateList(vals []string, n int) string {
	joined := strings.Join(vals, "; ")
	if len(joined) <= n {
		return joined
	}
	return joined[:n] + "..."
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
