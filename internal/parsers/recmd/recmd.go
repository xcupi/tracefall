// Package recmd parses the batch CSV output of RECmd (Eric Zimmerman's
// Registry Explorer command-line tool), run by KAPE's !EZParser module
// with a Run-Keys batch definition against collected registry hives. As
// with evtxcsv and pecmd, Tracefall consumes RECmd's CSV rather than
// parsing raw registry hive binary format -- see evtxcsv's package doc
// for the rationale.
package recmd

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

const parserName = "recmd@1"

type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactRegistryRunKey }

// Detect matches RECmd's batch-mode output naming convention, e.g.
// "20240115143022_RECmd_Batch_RunKeys_Output.csv".
func (Parser) Detect(relPath string) bool {
	base := strings.ToLower(filepath.Base(relPath))
	return strings.Contains(base, "recmd") && strings.HasSuffix(base, ".csv")
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
		return parsers.ParseResult{}, fmt.Errorf("recmd: reading header: %w", err)
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
			return parsers.ParseResult{}, fmt.Errorf("recmd: row %d: %w", rowNum, err)
		}
		rowNum++

		hivePath := get(rec, col, "HivePath")
		keyPath := get(rec, col, "KeyPath")
		valueName := get(rec, col, "ValueName")
		valueData := get(rec, col, "ValueData")
		lastWrite := get(rec, col, "LastWriteTimestamp")

		ts, ok := normalize.Timestamp(lastWrite)
		if !ok || keyPath == "" {
			continue
		}

		fullPath := keyPath
		if valueName != "" {
			fullPath = keyPath + "\\" + valueName
		}

		ev := model.Event{
			Timestamp: ts,
			// hivePath is typically "...\Users\<name>\NTUSER.DAT" for
			// HKCU hives -- the owning user, when available, isn't
			// carried anywhere else in RECmd's output.
			User:            userFromHivePath(hivePath),
			EventType:       model.EventRegistryRunKey,
			RegistryPath:    fullPath,
			FilePath:        valueData,
			ProcessName:     normalize.ExecutableFromCommandLine(valueData),
			ArtifactType:    model.ArtifactRegistryRunKey,
			Parser:          parserName,
			Confidence:      1.0,
			SourceReference: "row:" + fmt.Sprint(rowNum-1),
			Extra: map[string]string{
				"hive_path":  hivePath,
				"value_name": valueName,
				"value_data": valueData,
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

// userFromHivePath extracts the profile owner from a hive path like
// `C:\Users\jdoe\NTUSER.DAT`, returning "" for machine-wide hives
// (SOFTWARE, SYSTEM, etc.) that aren't under a user profile.
func userFromHivePath(hivePath string) string {
	parts := strings.Split(strings.ReplaceAll(hivePath, "/", `\`), `\`)
	for i, p := range parts {
		if strings.EqualFold(p, "Users") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
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
