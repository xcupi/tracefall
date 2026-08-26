// Package scheduledtasks parses raw Windows Task Scheduler XML files, as
// KAPE collects them directly from C:\Windows\System32\Tasks and
// ProgramData\Microsoft\Windows\Start Menu\Programs\Startup equivalents.
// Unlike evtxcsv/pecmd/recmd, no EZ Tools companion is needed here: task
// XML is a simple, well-documented, already-textual format, so Tracefall
// parses it natively with encoding/xml.
package scheduledtasks

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"tracefall/internal/model"
	"tracefall/internal/normalize"
	"tracefall/internal/parsers"
)

const parserName = "scheduledtasks@1"

type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactScheduledTask }

// Detect matches raw Task Scheduler XML files collected under a "Tasks"
// directory, mirroring KAPE's collection layout for
// C:\Windows\System32\Tasks.
func (Parser) Detect(relPath string) bool {
	lower := strings.ToLower(filepath.ToSlash(relPath))
	if !strings.HasSuffix(lower, ".xml") {
		return false
	}
	return strings.HasPrefix(lower, "tasks/") || strings.Contains(lower, "/tasks/")
}

// taskXML mirrors the subset of the Task Scheduler XML schema
// (http://schemas.microsoft.com/windows/2004/02/mit/task) Tracefall needs.
type taskXML struct {
	RegistrationInfo struct {
		Date   string `xml:"Date"`
		Author string `xml:"Author"`
	} `xml:"RegistrationInfo"`
	Principals struct {
		Principal []struct {
			UserId   string `xml:"UserId"`
			RunLevel string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}

	data = decodeUTF16(data)

	var t taskXML
	dec := xml.NewDecoder(bytes.NewReader(data))
	// Real Task Scheduler XML declares encoding="UTF-16"; decodeUTF16
	// above already converted the bytes to UTF-8, so this CharsetReader
	// just needs to not reject the (now-inaccurate) declared charset.
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) { return input, nil }
	if err := dec.Decode(&t); err != nil {
		return parsers.ParseResult{}, err
	}

	taskName := strings.TrimSuffix(filepath.Base(absPath), filepath.Ext(absPath))

	ts, ok := normalize.Timestamp(t.RegistrationInfo.Date)
	if !ok {
		return parsers.ParseResult{}, nil
	}

	// Prefer the human-readable Author (e.g. "CORP\jdoe"); Task Scheduler
	// XML's Principal/UserId is frequently a raw SID, which is only
	// useful as a fallback when no Author was recorded.
	principalUserId, runLevel := "", ""
	if len(t.Principals.Principal) > 0 {
		principalUserId = t.Principals.Principal[0].UserId
		runLevel = t.Principals.Principal[0].RunLevel
	}
	user := t.RegistrationInfo.Author
	if user == "" {
		user = principalUserId
	}

	var command, args string
	if len(t.Actions.Exec) > 0 {
		command = t.Actions.Exec[0].Command
		args = t.Actions.Exec[0].Arguments
	}
	commandLine := strings.TrimSpace(command + " " + args)

	extra := map[string]string{
		"task_name":         taskName,
		"author":            t.RegistrationInfo.Author,
		"principal_user_id": principalUserId,
		// RunLevel is "HighestAvailable" or "LeastPrivilege" per the Task
		// Scheduler XML schema -- "HighestAvailable" is a genuine
		// triage-relevant signal (the task runs elevated), so it's kept
		// distinct rather than folded into a generic field.
		"run_level": runLevel,
		"task_path": taskPathFrom(absPath, taskName),
	}

	ev := model.Event{
		Timestamp:       ts,
		User:            normalize.User(user),
		EventType:       model.EventScheduledTaskCreate,
		ProcessName:     normalize.ProcessName(command),
		ProcessPath:     command,
		CommandLine:     commandLine,
		ArtifactType:    model.ArtifactScheduledTask,
		Parser:          parserName,
		Confidence:      1.0,
		SourceReference: "task:" + taskName,
		Extra:           extra,
	}

	rawJSON, _ := json.Marshal(t)
	return parsers.ParseResult{
		Events: []model.Event{ev},
		Raw: []model.RawEvidence{{
			SourceReference: ev.SourceReference,
			Raw:             string(rawJSON),
		}},
	}, nil
}

// taskPathFrom reconstructs the task's Task Scheduler namespace path (e.g.
// `\Microsoft\Windows\UpdateOrchestrator\Schedule Scan`) from its absolute
// filesystem location, which KAPE preserves faithfully under a "Tasks"
// root (e.g. ".../Tasks/Microsoft/Windows/UpdateOrchestrator/Schedule
// Scan"). Falls back to just "\"+taskName if no "Tasks" segment is found,
// since Parse only receives an absolute path, not the evidence root or a
// relative path the way Detect does.
func taskPathFrom(absPath, taskName string) string {
	norm := filepath.ToSlash(absPath)
	segments := strings.Split(norm, "/")
	for i, seg := range segments {
		if strings.EqualFold(seg, "Tasks") && i+1 < len(segments) {
			rest := segments[i+1:]
			rest[len(rest)-1] = taskName // drop the .xml extension on the final segment
			return `\` + strings.Join(rest, `\`)
		}
	}
	return `\` + taskName
}

// decodeUTF16 converts UTF-16 (LE or BE, detected by BOM) bytes to UTF-8.
// Real Task Scheduler XML files, as KAPE collects them, are UTF-16LE with
// a BOM; data without a recognized UTF-16 BOM is returned unchanged
// (assumed already UTF-8/ASCII).
func decodeUTF16(data []byte) []byte {
	var little bool
	switch {
	case len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE:
		little = true
	case len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF:
		little = false
	default:
		return data
	}

	body := data[2:]
	units := make([]uint16, 0, len(body)/2)
	for i := 0; i+1 < len(body); i += 2 {
		if little {
			units = append(units, uint16(body[i])|uint16(body[i+1])<<8)
		} else {
			units = append(units, uint16(body[i])<<8|uint16(body[i+1]))
		}
	}
	return []byte(string(utf16.Decode(units)))
}
