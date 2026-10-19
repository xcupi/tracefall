// Package syslog parses the general system log (/var/log/syslog) for the one
// thing it records that is unambiguous evidence: scheduled jobs.
//
// # What is emitted, and what is not
//
// cron logs each job it starts as
//
//	Mar 21 16:25:01 host CRON[1705]: (root) CMD (<command>)
//
// That line is the only kind this parser turns into an event
// (scheduled_job_run): the account, the command text, and the time cron
// started it. cron does not record the job's result, so the event does not
// claim the command succeeded.
//
// The rest of a system log is desktop, kernel, and daemon chatter. This
// parser does not interpret it. In particular it does not emit USB
// attachment events. A rule that matches the word "usb" cannot tell a
// removable drive from a virtual input device: both get the same "new USB
// device" kernel message, so until the parser can tell them apart it reports
// nothing rather than reporting the wrong thing.
//
// # Timestamps are partial
//
// Like auth.log, syslog lines carry "Mon DD HH:MM:SS" and no year. Events
// have a zero Timestamp; the month, day and time are kept as written in
// Extra["timestamp_partial"]. The year is not inferred, and the file's
// modification time is not used.
//
// Lines without a program name (for example "[1240]: gsd-media-keys: ...")
// are skipped; they cannot be attributed to a source.
package syslog

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

const parserName = "syslog@1"

const maxFileBytes = 256 << 20

// header is "Mon DD HH:MM:SS host program[pid]: message". The program is
// required; a line without one is not claimed.
var header = regexp.MustCompile(`^([A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}) (\S+) ([^:\[ ]+)(?:\[([0-9]+)\])?: (.*)$`)

// cronCmd matches "(user) CMD (command)". The command is everything between
// the outer parentheses, greedily, because commands contain parentheses.
var cronCmd = regexp.MustCompile(`^\(([^)]+)\) CMD \((.*)\)$`)

// Parser implements parsers.ArtifactParser.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactSyslog }

// Detect matches the plain system log and its numbered rotations. Compressed
// rotations (.gz) are not claimed.
func (Parser) Detect(relPath string) bool {
	base := filepath.Base(strings.ReplaceAll(relPath, `\`, "/"))
	if strings.EqualFold(base, "syslog") {
		return true
	}
	return syslogRotation.MatchString(base)
}

var syslogRotation = regexp.MustCompile(`(?i)^syslog\.[0-9]+$`)

// DetectContent returns false: syslog has no signature to sniff.
func (Parser) DetectContent(header []byte) bool { return false }

// Parse reads a system log with no evidence path.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	return p.ParseWithContext(absPath, parsers.ParseContext{})
}

// ParseWithContext reads the file in file order.
func (p Parser) ParseWithContext(absPath string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if info.Size() > maxFileBytes {
		return parsers.ParseResult{}, fmt.Errorf("syslog: file exceeds %d bytes", maxFileBytes)
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
		m := header.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		stamp, host, program, pid, msg := m[1], m[2], m[3], m[4], m[5]
		if program != "CRON" {
			continue
		}
		c := cronCmd.FindStringSubmatch(msg)
		if c == nil {
			continue
		}
		ref := "line:" + strconv.Itoa(i+1)
		extra := map[string]string{
			"timestamp_known":   "false",
			"timestamp_partial": stamp,
			"timestamp_basis":   "syslog lines carry no year; month, day and time are kept as written, and the year is deliberately not inferred",
			"line_number":       strconv.Itoa(i + 1),
			"cron_pid":          pid,
			"records_execution": "false: cron records that it started the job, not its result",
			"history_file":      sourceName,
		}
		ev := model.Event{
			EventType:       model.EventScheduledJobRun,
			Host:            normalize.Host(host),
			User:            c[1],
			CommandLine:     strings.TrimSpace(c[2]),
			FilePath:        sourceName,
			ArtifactType:    model.ArtifactSyslog,
			Parser:          parserName,
			Confidence:      0.9,
			SourceReference: ref,
			Extra:           extra,
		}
		if pidNum, err := strconv.ParseInt(pid, 10, 64); err == nil {
			ev.PID = pidNum
		}
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ref, Raw: line})
	}
	return out, nil
}
