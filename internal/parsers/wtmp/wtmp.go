// Package wtmp parses the utmp-format login record file (/var/log/wtmp).
//
// # What this artifact is
//
// wtmp is an append-only sequence of fixed 384-byte utmp records written
// by login(1), sshd and init. Each record carries a session type, a PID,
// a terminal line, a user name, a remote host or display, and an epoch
// timestamp. Unlike bash history, its times are real and per record.
//
// The layout used is glibc's x86-64 struct utmp, checked against a real
// Linux wtmp (see the real-sample test): type at 0, pid at 4, line at 8,
// user at 44, host at 76, and tv_sec at 340.
//
// Only the record types that describe a session are emitted: USER_PROCESS
// (a login), DEAD_PROCESS (a logout) and BOOT_TIME (a boot). RUN_LVL,
// INIT_PROCESS, LOGIN_PROCESS, NEW_TIME, OLD_TIME and ACCOUNTING records are
// bookkeeping: they are skipped and produce no event and no raw record.
//
// btmp (failed logins) has the same layout but different meaning for the
// same type codes, so it is deliberately not handled by this parser.
package wtmp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "wtmp@1"

const (
	recordSize = 384
	maxBytes   = 256 << 20 // a busy host's wtmp is tens of MB at most
)

// utmp ut_type values (glibc bits/utmp.h).
const (
	typeBootTime    = 2
	typeUserProcess = 7
	typeDeadProcess = 8
)

// ErrNotUtmp means the file cannot be a whole number of utmp records.
var ErrNotUtmp = errors.New("wtmp: size is not a multiple of the 384-byte utmp record")

// ErrTooLarge means the file exceeds the size ceiling.
var ErrTooLarge = errors.New("wtmp: file exceeds the maximum size")

// Parser implements parsers.ArtifactParser.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactWtmp }

// Detect matches the file name. Only "wtmp" is claimed; "btmp" is out of
// scope (see the package comment).
func (Parser) Detect(relPath string) bool {
	return filepath.Base(strings.ReplaceAll(relPath, `\`, "/")) == "wtmp"
}

// DetectContent returns false. utmp has no magic number, so any file whose
// size happens to divide by 384 would be claimed; name only is honest.
func (Parser) DetectContent(header []byte) bool { return false }

// Parse reads a wtmp file.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	return p.ParseWithContext(absPath, parsers.ParseContext{})
}

// ParseWithContext reads the records in file order. wtmp is not guaranteed
// to be time-sorted (rotations and clock changes break the order), so the
// file order is kept and each event carries its own timestamp.
func (p Parser) ParseWithContext(absPath string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if info.Size() > maxBytes {
		return parsers.ParseResult{}, fmt.Errorf("%w: %d bytes", ErrTooLarge, info.Size())
	}
	raw, err := os.ReadFile(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if len(raw)%recordSize != 0 {
		return parsers.ParseResult{}, fmt.Errorf("%w: %d bytes", ErrNotUtmp, len(raw))
	}

	sourceName := filepath.Base(absPath)
	var out parsers.ParseResult
	for i := 0; i+recordSize <= len(raw); i += recordSize {
		rec := raw[i : i+recordSize]
		ut := decode(rec)
		ref := "record:" + strconv.Itoa(i/recordSize+1)

		var eventType string
		switch ut.typ {
		case typeUserProcess:
			eventType = model.EventSessionStart
		case typeDeadProcess:
			eventType = model.EventSessionEnd
		case typeBootTime:
			eventType = model.EventSystemBoot
		default:
			continue // bookkeeping: no event and no raw record
		}

		ts := time.Time{}
		if ut.sec > 0 {
			ts = time.Unix(ut.sec, 0).UTC()
		}
		ev := model.Event{
			Timestamp:       ts,
			EventType:       eventType,
			User:            ut.user,
			PID:             int64(ut.pid),
			FilePath:        sourceName,
			ArtifactType:    model.ArtifactWtmp,
			Parser:          parserName,
			Confidence:      0.9, // a login record is written by the system, not typed
			SourceReference: ref,
			Extra: map[string]string{
				"utmp_type":       utmpTypeName(ut.typ),
				"terminal":        ut.line,
				"remote":          ut.host,
				"timestamp_known": strconv.FormatBool(!ts.IsZero()),
			},
		}
		if eventType == model.EventSystemBoot {
			ev.User = ""
			ev.CommandLine = strings.TrimSpace(ut.user) // "reboot" / kernel string
		}
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ref, Raw: fmt.Sprintf("type=%d user=%q line=%q host=%q", ut.typ, ut.user, ut.line, ut.host)})
	}
	return out, nil
}

type record struct {
	typ  int16
	pid  int32
	line string
	user string
	host string
	sec  int64
}

func decode(r []byte) record {
	return record{
		typ:  int16(binary.LittleEndian.Uint16(r[0:2])),
		pid:  int32(binary.LittleEndian.Uint32(r[4:8])),
		line: cstr(r[8:40]),
		user: cstr(r[44:76]),
		host: cstr(r[76:332]),
		sec:  int64(int32(binary.LittleEndian.Uint32(r[340:344]))),
	}
}

// cstr reads a NUL-terminated field; the bytes are kept as the file holds
// them, with invalid UTF-8 replaced rather than dropped.
func cstr(b []byte) string {
	if i := indexNUL(b); i >= 0 {
		b = b[:i]
	}
	return strings.ToValidUTF8(string(b), "\uFFFD")
}

func indexNUL(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

func utmpTypeName(t int16) string {
	switch t {
	case 0:
		return "EMPTY"
	case 1:
		return "RUN_LVL"
	case 2:
		return "BOOT_TIME"
	case 3:
		return "NEW_TIME"
	case 4:
		return "OLD_TIME"
	case 5:
		return "INIT_PROCESS"
	case 6:
		return "LOGIN_PROCESS"
	case 7:
		return "USER_PROCESS"
	case 8:
		return "DEAD_PROCESS"
	case 9:
		return "ACCOUNTING"
	}
	return "UNKNOWN(" + strconv.Itoa(int(t)) + ")"
}
