// Package scheduledtasks parses raw Windows Task Scheduler XML files, as
// KAPE collects them directly from C:\Windows\System32\Tasks and
// ProgramData\Microsoft\Windows\Start Menu\Programs\Startup equivalents.
// Unlike evtxcsv/pecmd/recmd, no EZ Tools companion is needed here: task
// XML is a simple, well-documented, already-textual format, so Tracefall
// parses it natively with encoding/xml.
package scheduledtasks

import (
	"bytes"
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

// Detect matches XML exports and native extensionless task files under a "Tasks"
// directory, mirroring KAPE's collection layout for
// C:\Windows\System32\Tasks.
func (Parser) Detect(relPath string) bool {
	lower := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(relPath), `\`, "/"))
	// A task's name is its file name, so dots and spaces are part of the
	// name, not an extension (".30319" in a version number, ".exe task").
	// Only a short alphabetic suffix is a real file extension.
	if ext := filepath.Ext(lower); ext != "" && ext != ".xml" && isFileExtension(ext) {
		return false
	}
	return strings.HasPrefix(lower, "tasks/") || strings.Contains(lower, "/tasks/")
}

// taskXML mirrors the subset of the Task Scheduler XML schema
// (http://schemas.microsoft.com/windows/2004/02/mit/task) Tracefall needs.
type taskXML struct {
	XMLName          xml.Name `xml:"Task"`
	RegistrationInfo struct {
		Date   string `xml:"Date"`
		Author string `xml:"Author"`
	} `xml:"RegistrationInfo"`
	Principals struct {
		XML       string `xml:",innerxml"`
		Principal []struct {
			UserId   string `xml:"UserId"`
			RunLevel string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Actions struct {
		XML  string `xml:",innerxml"`
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	return p.ParseWithContext(absPath, parsers.ParseContext{})
}

// ParseWithContext takes the task's namespace path from the evidence-relative
// path in ctx. Without it only the task's own name is known: the server's
// absolute path says where the evidence was stored, not where the task lived.
func (p Parser) ParseWithContext(absPath string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
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

	taskName := filepath.Base(absPath)
	if strings.EqualFold(filepath.Ext(taskName), ".xml") {
		taskName = strings.TrimSuffix(taskName, filepath.Ext(taskName))
	}

	ts, local, dateOK := normalize.XMLTimestamp(t.RegistrationInfo.Date)

	// Prefer the human-readable Author (e.g. "CORP\jdoe"); Task Scheduler
	// XML's Principal/UserId is frequently a raw SID, which is only
	// useful as a fallback when no Author was recorded.
	principalUserId, runLevel := "", ""
	if len(t.Principals.Principal) > 0 {
		principalUserId = t.Principals.Principal[0].UserId
		runLevel = t.Principals.Principal[0].RunLevel
	}
	user := t.RegistrationInfo.Author
	// Built-in tasks store a localized-resource reference ("$(@%SystemRoot%\
	// system32\x.dll,-101)") instead of a name. It names no account, so it is
	// kept in the author extra and never used as the user.
	if strings.HasPrefix(strings.TrimSpace(user), "$(@") {
		user = ""
	}
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
		"task_name":           taskName,
		"task_actions_xml":    t.Actions.XML,
		"task_principals_xml": t.Principals.XML,
		"evidence_kind":       "task_configuration",
		"evidence_meaning":    "Task definition/configuration, not execution evidence. RegistrationInfo/Date is the author-supplied registration date, not a verified execution or creation time.",
		"author":              t.RegistrationInfo.Author,
		"principal_user_id":   principalUserId,
		// RunLevel is "HighestAvailable" or "LeastPrivilege" per the Task
		// Scheduler XML schema -- "HighestAvailable" is a genuine
		// configuration signal (requests elevation), so it's kept
		// distinct rather than folded into a generic field.
		"run_level": runLevel,
		"task_path": taskPathFrom(ctx.EvidencePath, taskName),
	}

	extra["timestamp_original"] = t.RegistrationInfo.Date
	switch {
	case local != "":
		extra["timestamp_local"] = local
		extra["timestamp_basis"] = "task_registration_local_zone_unknown"
	case dateOK:
		extra["timestamp_basis"] = "task_registration_explicit_zone"
	case strings.TrimSpace(t.RegistrationInfo.Date) == "":
		extra["timestamp_basis"] = "task_registration_date_absent"
	default:
		extra["timestamp_basis"] = "task_registration_date_invalid"
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

	return parsers.ParseResult{
		Events: []model.Event{ev},
		Raw: []model.RawEvidence{{
			SourceReference: ev.SourceReference,
			Raw:             string(data),
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
	if absPath == "" {
		return `\` + taskName
	}
	// Prefer the System32\Tasks root; fall back to the first Tasks segment.
	start := -1
	for i, seg := range segments {
		if strings.EqualFold(seg, "Tasks") && i+1 < len(segments) {
			if start < 0 {
				start = i
			}
			if i > 0 && (strings.EqualFold(segments[i-1], "System32") || strings.EqualFold(segments[i-1], "SysNative")) {
				start = i
				break
			}
		}
	}
	for i, seg := range segments {
		if i == start && strings.EqualFold(seg, "Tasks") && i+1 < len(segments) {
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

// isFileExtension reports whether ext (with its dot) looks like a real file
// extension: one to five letters.
func isFileExtension(ext string) bool {
	e := strings.TrimPrefix(ext, ".")
	if len(e) == 0 || len(e) > 5 {
		return false
	}
	for _, c := range e {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}
