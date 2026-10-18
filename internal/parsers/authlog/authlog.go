// Package authlog parses the syslog-style authentication log
// (/var/log/auth.log and its plain rotations auth.log.N).
//
// # Timestamps: partial on purpose
//
// Each line starts "Mon DD HH:MM:SS" with no year. The year is not in the
// file and cannot be recovered from the file's own content. So no event
// from this parser has a Timestamp. The month, day and time are kept
// verbatim in Extra["timestamp_partial"], so an examiner can filter by time
// of day (the usual question: "what happened at 11:26?") and read the
// order the lines were written in, without a year being invented.
//
// The file's modification time is never used to fill in the year: it is
// when the file was last written, not when a line was logged, and it can
// be changed.
//
// # What is emitted
//
//   - su: "Successful su for X by Y" and "FAILED su for X by Y" ->
//     privilege_switch, with the outcome in Extra.
//   - sudo: "<user> : ... COMMAND=<cmd>" -> sudo_command. sudo logs the
//     command it authorised; it does not prove the command ran.
//   - sshd: "Accepted <method> for U from IP port N" -> logon_success, and
//     "Failed <method> for [invalid user] U from IP port N" -> logon_failure.
//
// PAM session open/close lines and systemd or CRON noise are not emitted:
// they repeat the action lines above or describe nothing an examiner acts
// on. Lines of an unrecognised form produce no event, and their count is
// the difference between the file's lines and the events.
package authlog

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/normalize"
	"tracefall/internal/parsers"
)

const parserName = "authlog@1"

const maxFileBytes = 64 << 20 // a busy host's auth.log can be tens of MB

// header is the syslog prefix: "Mar 20 11:26:22 host proc[pid]: message".
// The timestamp is one group so it is kept exactly as written, including the
// padding of single-digit days ("Mar  5").
var header = regexp.MustCompile(`^([A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}) (\S+) ([^:\[ ]+)(?:\[[0-9]+\])?: (.*)$`)

var (
	suSuccess = regexp.MustCompile(`^Successful su for (\S+) by (\S+)$`)
	suFailed  = regexp.MustCompile(`^FAILED su for (\S+) by (\S+)$`)
	sudoCmd   = regexp.MustCompile(`^\s*(\S+) : .*?TTY=(\S+) ; PWD=(.*?) ; USER=(\S+) ; COMMAND=(.*)$`)
	sshAccept = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port ([0-9]+)`)
	sshFail   = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(\S+) from (\S+) port ([0-9]+)`)
)

// Parser implements parsers.ArtifactParser.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactAuthLog }

// Detect matches auth.log and its numbered plain rotations (auth.log.1).
// Compressed rotations (.gz) are not claimed: they are not readable as text
// and are reported as unsupported rather than guessed at.
func (Parser) Detect(relPath string) bool {
	base := filepath.Base(strings.ReplaceAll(relPath, `\`, "/"))
	if strings.EqualFold(base, "auth.log") {
		return true
	}
	return regexp.MustCompile(`(?i)^auth\.log\.[0-9]+$`).MatchString(base)
}

// DetectContent returns false: syslog text has no signature to sniff, and
// claiming any log that looks like one would misclassify other files.
func (Parser) DetectContent(header []byte) bool { return false }

// Parse reads an auth log with no evidence path.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	return p.ParseWithContext(absPath, parsers.ParseContext{})
}

// ParseWithContext reads the file in file order. The file's own line order is
// kept, since an auth log is written in the order things happened and carries
// no year to sort by.
func (p Parser) ParseWithContext(absPath string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if info.Size() > maxFileBytes {
		return parsers.ParseResult{}, fmt.Errorf("authlog: file exceeds %d bytes", maxFileBytes)
	}
	raw, err := os.ReadFile(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	text := strings.ToValidUTF8(string(raw), "\uFFFD")

	sourceName := filepath.Base(absPath)
	var out parsers.ParseResult
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		m := header.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		stamp, host, proc, msg := m[1], m[2], m[3], m[4]
		ref := "line:" + strconv.Itoa(i+1)

		var ev *model.Event
		switch proc {
		case "su":
			ev = suEvent(msg)
		case "sudo":
			ev = sudoEvent(msg)
		case "sshd":
			ev = sshEvent(msg)
		}
		if ev == nil {
			continue
		}

		ev.Host = normalize.Host(host)
		ev.ArtifactType = model.ArtifactAuthLog
		ev.Parser = parserName
		ev.FilePath = sourceName
		ev.SourceReference = ref
		// Zero time, always. The year is not in the file.
		ev.Extra["timestamp_known"] = "false"
		ev.Extra["timestamp_partial"] = stamp
		ev.Extra["timestamp_basis"] = "auth.log lines carry no year; month, day and time are kept as written, and the year is deliberately not inferred"
		ev.Extra["line_number"] = strconv.Itoa(i + 1)
		ev.Extra["history_file"] = sourceName

		out.Events = append(out.Events, *ev)
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ref, Raw: line})
	}
	return out, nil
}

func suEvent(msg string) *model.Event {
	if m := suSuccess.FindStringSubmatch(msg); m != nil {
		return &model.Event{
			EventType: model.EventPrivilegeSwitch, User: m[2], ProcessName: "su",
			Confidence: 0.9, Extra: map[string]string{"outcome": "success", "target_user": m[1]},
		}
	}
	if m := suFailed.FindStringSubmatch(msg); m != nil {
		return &model.Event{
			EventType: model.EventPrivilegeSwitch, User: m[2], ProcessName: "su",
			Confidence: 0.9, Extra: map[string]string{"outcome": "failed", "target_user": m[1]},
		}
	}
	return nil
}

func sudoEvent(msg string) *model.Event {
	m := sudoCmd.FindStringSubmatch(msg)
	if m == nil {
		return nil
	}
	cmd := strings.TrimSpace(m[5])
	proc := cmd
	if fields := strings.Fields(cmd); len(fields) > 0 {
		proc = filepath.Base(fields[0])
	}
	return &model.Event{
		EventType: model.EventSudoCommand, User: m[1], ProcessName: proc,
		CommandLine: cmd, Confidence: 0.8,
		Extra: map[string]string{
			"target_user":       m[4],
			"tty":               m[2],
			"working_dir":       m[3],
			"records_execution": "false: sudo records the authorisation of the command, not that it ran or succeeded",
		},
	}
}

func sshEvent(msg string) *model.Event {
	if m := sshAccept.FindStringSubmatch(msg); m != nil {
		return &model.Event{
			EventType: model.EventLogonSuccess, User: m[2], NetworkSource: m[3],
			ProcessName: "sshd", Confidence: 0.9,
			Extra: map[string]string{"auth_method": m[1], "source_port": m[4]},
		}
	}
	if m := sshFail.FindStringSubmatch(msg); m != nil {
		return &model.Event{
			EventType: model.EventLogonFailure, User: m[3], NetworkSource: m[4],
			ProcessName: "sshd", Confidence: 0.9,
			Extra: map[string]string{
				"auth_method":  m[1],
				"source_port":  m[5],
				"invalid_user": strconv.FormatBool(m[2] != ""),
			},
		}
	}
	return nil
}
