// Package syslog parses the general system log (/var/log/syslog and its
// sibling daemon.log) for two things it records that are unambiguous
// evidence: scheduled jobs, and a short list of service messages that bear
// on security or integrity.
//
// # What is emitted, and what is not
//
// cron logs each job it starts as
//
//	Mar 21 16:25:01 host CRON[1705]: (root) CMD (<command>)
//
// That line becomes a scheduled_job_run: the account, the command text, and
// the time cron started it. cron does not record the job's result, so the
// event does not claim the command succeeded.
//
// A MySQL server and its helper scripts write service_message events for a
// fixed allow-list (see serviceRules): a passwordless administrator
// account, corrupt tables, an unclean shutdown and crash recovery, server
// errors, and start/stop. Each event keeps the line as written and says
// what the line does and does not show. The list is short on purpose: a
// log line that is not on it is not evidence that nothing happened.
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
//
// Each event also carries Extra["partial_ordinal"] and ["partial_calendar"],
// the position of the stamp relative to 1 January of an unspecified year, so
// lines of one file can be ordered and measured against each other. See
// package partialtime for the limits.
//
// mysqld stamps its own messages with a date ("100318 10:18:31", YYMMDD).
// That text is kept verbatim in Extra["embedded_stamp"]. It is the server's
// own clock and it is not used to date the syslog stamp, to fill in a
// year, or to date any other line.
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
	"tracefall/internal/partialtime"
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
	if strings.EqualFold(base, "syslog") || strings.EqualFold(base, "daemon.log") {
		return true
	}
	return syslogRotation.MatchString(base)
}

// daemon.log is the same format and is where Debian-family systems send
// service messages. "messages" is not claimed: the name is too common.
var syslogRotation = regexp.MustCompile(`(?i)^(?:syslog|daemon\.log)\.[0-9]+$`)

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
	var stamps []string
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		m := header.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		stamp, host, program, pid, msg := m[1], m[2], m[3], m[4], m[5]
		stamps = append(stamps, stamp)
		ref := "line:" + strconv.Itoa(i+1)
		extra := map[string]string{
			"timestamp_known":   "false",
			"timestamp_partial": stamp,
			"timestamp_basis":   "syslog lines carry no year; month, day and time are kept as written, and the year is deliberately not inferred",
			"line_number":       strconv.Itoa(i + 1),
			"history_file":      sourceName,
		}
		var ev model.Event
		if program == "CRON" {
			c := cronCmd.FindStringSubmatch(msg)
			if c == nil {
				continue
			}
			extra["cron_pid"] = pid
			extra["records_execution"] = "false: cron records that it started the job, not its result"
			ev = model.Event{
				EventType:   model.EventScheduledJobRun,
				User:        c[1],
				CommandLine: strings.TrimSpace(c[2]),
				Confidence:  0.9,
			}
		} else {
			rule, ok := matchServiceRule(program, msg)
			if !ok {
				continue
			}
			extra["category"] = rule.category
			extra["program"] = baseProgram(program)
			extra["message"] = clip(msg, 500)
			extra["meaning"] = rule.meaning
			if em := embeddedStamp.FindString(msg); em != "" {
				extra["embedded_stamp"] = em
			}
			ev = model.Event{
				EventType:   model.EventServiceMessage,
				ProcessName: baseProgram(program),
				Confidence:  0.9,
			}
		}
		ev.Host = normalize.Host(host)
		ev.FilePath = sourceName
		ev.ArtifactType = model.ArtifactSyslog
		ev.Parser = parserName
		ev.SourceReference = ref
		ev.Extra = extra
		if pidNum, err := strconv.ParseInt(pid, 10, 64); err == nil {
			ev.PID = pidNum
		}
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ref, Raw: line})
	}
	cal := partialtime.CalendarFor(stamps)
	for i := range out.Events {
		partialtime.Annotate(out.Events[i].Extra, out.Events[i].Extra["timestamp_partial"], cal)
	}
	return out, nil
}

// embeddedStamp is mysqld's own "YYMMDD HH:MM:SS" prefix, kept as text.
var embeddedStamp = regexp.MustCompile(`^[0-9]{6} +[0-9]{1,2}:[0-9]{2}:[0-9]{2}`)

// baseProgram turns "/etc/mysql/debian-start" into "debian-start".
func baseProgram(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// serviceRule is one allow-listed service message.
type serviceRule struct {
	category string
	programs []string // base names of the programs that write it
	pattern  *regexp.Regexp
	meaning  string
}

var mysqlPrograms = []string{"mysqld", "mysqld_safe", "mysqlcheck", "debian-start", "mysql"}

// serviceRules is the whole allow-list. Order matters only for readability:
// a message matches at most one rule, the first.
var serviceRules = []serviceRule{
	{
		category: "database_insecure_account", programs: mysqlPrograms,
		pattern: regexp.MustCompile(`root accounts without password`),
		meaning: "The MySQL start-up check found administrator accounts with no password. It shows the weakness existed at that moment; it does not show anyone used it.",
	},
	{
		category: "database_integrity", programs: mysqlPrograms,
		pattern: regexp.MustCompile(`(?i)found corrupt tables|marked as crashed|Database was not shut down normally|Starting crash recovery`),
		meaning: "The database reported damaged tables or an unclean shutdown. Power loss, a crash and tampering all produce it; the line does not say which.",
	},
	{
		category: "database_error", programs: mysqlPrograms,
		pattern: regexp.MustCompile(`\[ERROR\]|^ERROR:`),
		meaning: "The database or its start-up script logged an error. The line does not say what the cause was.",
	},
	{
		category: "database_lifecycle", programs: mysqlPrograms,
		pattern: regexp.MustCompile(`Starting mysqld daemon|mysqld .*ended|Shutdown complete|ready for connections`),
		meaning: "The database server started or stopped. It dates a restart; it does not say who requested it.",
	},
}

func matchServiceRule(program, msg string) (serviceRule, bool) {
	base := baseProgram(program)
	for _, r := range serviceRules {
		for _, p := range r.programs {
			if base == p && r.pattern.MatchString(msg) {
				return r, true
			}
		}
	}
	return serviceRule{}, false
}
