// Package partialtime compares log lines whose timestamps carry no year.
//
// Syslog-style logs write "Mon DD HH:MM:SS". The year is not in the file
// and Tracefall never invents it, so those events keep a zero Timestamp.
// That blocks every rule that asks "how long after" -- yet the question
// "were these two lines written within ten minutes of each other, in the
// same file?" does not need a year. The distance between two stamps in one
// file is the same in any year, as long as the calendar is the same.
//
// What this package provides is therefore RELATIVE time only:
//
//   - Ordinal turns a stamp into seconds since 1 January 00:00:00 of an
//     unspecified year. It is not a time of day on any date.
//   - Delta returns the distance between two events from the same file.
//
// What it deliberately does not do:
//
//   - It does not produce a calendar date. Nothing here knows the year.
//   - It does not compare lines from different files. Rotations such as
//     auth.log and auth.log.1 may cover different years, and nothing in
//     the files says which came first.
//   - It does not bridge a New Year. A stamp that is earlier than the one
//     before it in file order means the year changed (or the log is out of
//     order); either way the distance is unknown, so Delta reports false.
//   - It does not use the file's modification time or the acquisition date.
//
// Leap years: "Feb 29" exists only in a leap year, so a file that holds
// one is read against a leap calendar and every other file against a
// common-year calendar. The calendar is recorded on the event so the
// assumption is visible and two events are only compared when they agree.
package partialtime

import (
	"strconv"
	"strings"
	"time"
)

// Keys under which the parsers record the relative position on an event.
const (
	// KeyStamp is the stamp exactly as written in the log.
	KeyStamp = "timestamp_partial"
	// KeyOrdinal is seconds since 1 January 00:00:00 of an unspecified year.
	KeyOrdinal = "partial_ordinal"
	// KeyCalendar is CalendarLeap or CalendarCommon.
	KeyCalendar = "partial_calendar"
	// KeyLine is the 1-based line number in the source file.
	KeyLine = "line_number"
)

// Calendar values for KeyCalendar.
const (
	CalendarLeap   = "leap"
	CalendarCommon = "common"
)

var months = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March, "Apr": time.April,
	"May": time.May, "Jun": time.June, "Jul": time.July, "Aug": time.August,
	"Sep": time.September, "Oct": time.October, "Nov": time.November, "Dec": time.December,
}

// Reference years used only to count seconds; no output ever names them.
const (
	commonYear = 2001
	leapYear   = 2000
)

// IsLeapDay reports whether stamp is "Feb 29".
func IsLeapDay(stamp string) bool {
	f := strings.Fields(stamp)
	return len(f) >= 2 && f[0] == "Feb" && f[1] == "29"
}

// CalendarFor returns CalendarLeap when any stamp is a leap day.
func CalendarFor(stamps []string) string {
	for _, s := range stamps {
		if IsLeapDay(s) {
			return CalendarLeap
		}
	}
	return CalendarCommon
}

// Ordinal converts "Mon DD HH:MM:SS" to seconds since 1 January 00:00:00 of
// an unspecified year of the given calendar. It returns false for a stamp
// that is not in that form or names a date the calendar does not have.
func Ordinal(stamp, calendar string) (int64, bool) {
	f := strings.Fields(stamp)
	if len(f) != 3 {
		return 0, false
	}
	mon, ok := months[f[0]]
	if !ok {
		return 0, false
	}
	day, err := strconv.Atoi(f[1])
	if err != nil || day < 1 || day > 31 {
		return 0, false
	}
	clock := strings.Split(f[2], ":")
	if len(clock) != 3 {
		return 0, false
	}
	var hms [3]int
	for i, c := range clock {
		n, err := strconv.Atoi(c)
		if err != nil || n < 0 {
			return 0, false
		}
		hms[i] = n
	}
	if hms[0] > 23 || hms[1] > 59 || hms[2] > 60 { // 60: leap second
		return 0, false
	}
	year := commonYear
	if calendar == CalendarLeap {
		year = leapYear
	}
	t := time.Date(year, mon, day, hms[0], hms[1], hms[2], 0, time.UTC)
	// time.Date rolls an impossible date (Feb 30, Apr 31) into the next
	// month. Such a stamp is corrupt, not a date to be repaired.
	if t.Month() != mon || t.Day() != day {
		return 0, false
	}
	start := time.Date(year, time.January, 1, 0, 0, 0, 0, time.UTC)
	return int64(t.Sub(start) / time.Second), true
}

// Position is where one event sits in its source file.
type Position struct {
	File     string // SourceFileID: only events from one file are comparable
	Line     int
	Ordinal  int64
	Calendar string
}

// PositionOf reads the position the parsers recorded. It returns false for
// an event that has none (any event with a real timestamp, for one).
func PositionOf(sourceFileID string, extra map[string]string) (Position, bool) {
	if sourceFileID == "" {
		return Position{}, false
	}
	ord, err := strconv.ParseInt(extra[KeyOrdinal], 10, 64)
	if err != nil {
		return Position{}, false
	}
	line, err := strconv.Atoi(extra[KeyLine])
	if err != nil || line < 1 {
		return Position{}, false
	}
	cal := extra[KeyCalendar]
	if cal != CalendarLeap && cal != CalendarCommon {
		return Position{}, false
	}
	return Position{File: sourceFileID, Line: line, Ordinal: ord, Calendar: cal}, true
}

// Before reports whether a was written before b in the same file.
func (a Position) Before(b Position) bool {
	if a.File != b.File {
		return a.File < b.File
	}
	return a.Line < b.Line
}

// Delta is the time from a to b, for a at or before b in one file under one
// calendar. It returns false when the two are not comparable or when b is
// earlier on the calendar than a (a year change or an out-of-order log).
func Delta(a, b Position) (time.Duration, bool) {
	if a.File != b.File || a.Calendar != b.Calendar || a.Line > b.Line {
		return 0, false
	}
	d := b.Ordinal - a.Ordinal
	if d < 0 {
		return 0, false
	}
	return time.Duration(d) * time.Second, true
}

// Annotate records the relative position of stamp on an event's Extra. A
// stamp that cannot be placed on the calendar leaves the event without a
// position, so no rule will order it.
func Annotate(extra map[string]string, stamp, calendar string) {
	if ord, ok := Ordinal(stamp, calendar); ok {
		extra[KeyOrdinal] = strconv.FormatInt(ord, 10)
		extra[KeyCalendar] = calendar
	}
}

// Item is one failure or success in file order.
type Item struct {
	Pos     Position
	Success bool
}

// Burst is a run of failures and the success that ended it. Failures holds
// indexes into the items slice, in file order; Success is the index of the
// success.
type Burst struct {
	Failures []int
	Success  int
}

// BurstsBeforeSuccess finds every run of at least minFailures failures, each
// within gap of the one before it, that a success follows within window of
// the last failure. items must be in file order and belong to one account
// and one source.
//
// A success ends the run it follows. A password-guessing source keeps
// guessing after it gets in, and later failures start a new run, so the
// success must be tied to the failures that precede it, not to the end of the
// whole attack. A pair that is not comparable (another file, a year change)
// also ends a run.
func BurstsBeforeSuccess(items []Item, minFailures int, gap, window time.Duration) []Burst {
	var out []Burst
	var run []int
	for i, it := range items {
		if !it.Success {
			if len(run) > 0 {
				if d, ok := Delta(items[run[len(run)-1]].Pos, it.Pos); !ok || d > gap {
					run = nil
				}
			}
			run = append(run, i)
			continue
		}
		if len(run) >= minFailures {
			if d, ok := Delta(items[run[len(run)-1]].Pos, it.Pos); ok && d <= window {
				out = append(out, Burst{Failures: append([]int{}, run...), Success: i})
			}
		}
		run = nil
	}
	return out
}
