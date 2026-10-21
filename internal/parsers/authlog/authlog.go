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
//   - useradd, userdel, usermod, groupadd, groupdel, gpasswd, passwd and
//     chpasswd -> account_change. The log says the system applied the
//     change; it does not say who asked for it, so the event's User is
//     empty and the account or group changed is in Extra["object_name"].
//     The shadow-group twin of a group line is not emitted: it repeats
//     the line before it.
//
// # Relative time
//
// A year-less stamp still orders the lines of ONE file and measures the
// distance between them. Each event therefore also carries
// Extra["partial_ordinal"] (seconds from 1 January 00:00:00 of an
// unspecified year) and Extra["partial_calendar"]. See package partialtime
// for what that can and cannot support: it never yields a date, never
// compares two files, and gives no distance across a New Year.
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
	"tracefall/internal/partialtime"
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

// Account-management lines. shadow-utils quotes names with a backtick and an
// apostrophe in older releases and with two apostrophes in newer ones.
const q = "[`']"

var (
	acctNewUser    = regexp.MustCompile(`^new user: name=([^,]+), UID=([0-9]+), GID=([0-9]+), home=([^,]*), shell=(.*)$`)
	acctNewGroup   = regexp.MustCompile(`^new group: name=([^,]+), GID=([0-9]+)`)
	acctDelUser    = regexp.MustCompile("^delete user " + q + "([^'`]+)" + q)
	acctDelGroupA  = regexp.MustCompile("^removed group " + q + "([^'`]+)" + q)
	acctDelGroupB  = regexp.MustCompile("^group " + q + "([^'`]+)" + q + " removed")
	acctAddMember  = regexp.MustCompile("^add " + q + "([^'`]+)" + q + " to group " + q + "([^'`]+)" + q)
	acctDelMember  = regexp.MustCompile("^delete " + q + "([^'`]+)" + q + " from group " + q + "([^'`]+)" + q)
	acctPwChanged  = regexp.MustCompile(`^pam_unix\((?:passwd|chpasswd):chauthtok\): password changed for (\S+)`)
	acctModPw      = regexp.MustCompile("^change user " + q + "([^'`]+)" + q + " password")
	acctLockUnlock = regexp.MustCompile("^(lock|unlock) user " + q + "([^'`]+)" + q + " password")
	acctModOther   = regexp.MustCompile("^change user " + q + "([^'`]+)" + q + " (.+)$")
)

var accountProcs = map[string]bool{
	"useradd": true, "userdel": true, "usermod": true, "groupadd": true, "groupdel": true,
	"groupmod": true, "gpasswd": true, "passwd": true, "chpasswd": true,
}

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
	return authRotation.MatchString(base)
}

// authRotation matches the numbered plain rotations. Red Hat's "secure" is
// the same log, but its name is too common to claim by name alone.
var authRotation = regexp.MustCompile(`(?i)^auth\.log\.[0-9]+$`)

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
	var stamps []string // every stamp in the file, so the calendar is the file's
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
		stamps = append(stamps, stamp)
		ref := "line:" + strconv.Itoa(i+1)

		var ev *model.Event
		switch proc {
		case "su":
			ev = suEvent(msg)
		case "sudo":
			ev = sudoEvent(msg)
		case "sshd":
			ev = sshEvent(msg)
		default:
			if accountProcs[proc] {
				ev = accountEvent(proc, msg)
			}
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
	// The calendar needs the whole file: one "Feb 29" anywhere makes it a
	// leap-year log, and every event is read against the same calendar.
	cal := partialtime.CalendarFor(stamps)
	for i := range out.Events {
		partialtime.Annotate(out.Events[i].Extra, out.Events[i].Extra["timestamp_partial"], cal)
	}
	return out, nil
}

// accountEvent maps one shadow-utils or PAM account line to an
// account_change event, or nil for a line it does not recognise or one that
// only repeats the line before it (the shadow-group twin).
func accountEvent(proc, msg string) *model.Event {
	if strings.Contains(msg, "shadow group") {
		return nil
	}
	mk := func(action, objType, name string, extra map[string]string) *model.Event {
		if extra == nil {
			extra = map[string]string{}
		}
		extra["action"], extra["object_type"], extra["object_name"] = action, objType, name
		extra["actor_known"] = "false: the log records that the change was applied, not who requested it"
		return &model.Event{
			EventType: model.EventAccountChange, ProcessName: proc, Confidence: 0.9, Extra: extra,
		}
	}
	if m := acctNewUser.FindStringSubmatch(msg); m != nil {
		return mk("user_created", "user", m[1], map[string]string{"uid": m[2], "gid": m[3], "home": m[4], "shell": m[5]})
	}
	if m := acctNewGroup.FindStringSubmatch(msg); m != nil {
		return mk("group_created", "group", m[1], map[string]string{"gid": m[2]})
	}
	if m := acctDelUser.FindStringSubmatch(msg); m != nil {
		return mk("user_deleted", "user", m[1], nil)
	}
	if m := acctDelGroupA.FindStringSubmatch(msg); m != nil {
		return mk("group_deleted", "group", m[1], nil)
	}
	if m := acctDelGroupB.FindStringSubmatch(msg); m != nil {
		return mk("group_deleted", "group", m[1], nil)
	}
	if m := acctAddMember.FindStringSubmatch(msg); m != nil {
		return mk("group_member_added", "group", m[2], map[string]string{"member": m[1]})
	}
	if m := acctDelMember.FindStringSubmatch(msg); m != nil {
		return mk("group_member_removed", "group", m[2], map[string]string{"member": m[1]})
	}
	if m := acctPwChanged.FindStringSubmatch(msg); m != nil {
		return mk("password_changed", "user", m[1], nil)
	}
	if m := acctModPw.FindStringSubmatch(msg); m != nil {
		return mk("password_changed", "user", m[1], nil)
	}
	if m := acctLockUnlock.FindStringSubmatch(msg); m != nil {
		action := "password_locked"
		if m[1] == "unlock" {
			action = "password_unlocked"
		}
		return mk(action, "user", m[2], nil)
	}
	if m := acctModOther.FindStringSubmatch(msg); m != nil {
		return mk("user_modified", "user", m[1], map[string]string{"change": m[2]})
	}
	return nil
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
