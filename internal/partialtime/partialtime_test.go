package partialtime

import (
	"testing"
	"time"
)

func TestOrdinal_RejectsWhatIsNotAStamp(t *testing.T) {
	for _, s := range []string{"", "Mar 5", "Xyz 05 10:00:00", "Mar 05 25:00:00", "Mar 05 10:61:00",
		"Feb 30 10:00:00", "Apr 31 10:00:00", "Mar aa 10:00:00", "Mar 05 10:00"} {
		if _, ok := Ordinal(s, CalendarCommon); ok {
			t.Errorf("%q must not parse", s)
		}
	}
}

func TestOrdinal_LeapDayExistsOnlyOnALeapCalendar(t *testing.T) {
	if _, ok := Ordinal("Feb 29 10:00:00", CalendarCommon); ok {
		t.Error("Feb 29 does not exist on a common calendar")
	}
	if _, ok := Ordinal("Feb 29 10:00:00", CalendarLeap); !ok {
		t.Error("Feb 29 exists on a leap calendar")
	}
	if CalendarFor([]string{"Mar  1 00:00:00", "Feb 29 12:00:00"}) != CalendarLeap {
		t.Error("a file holding Feb 29 is read as leap")
	}
	if CalendarFor([]string{"Mar  1 00:00:00"}) != CalendarCommon {
		t.Error("otherwise common")
	}
}

func pos(file string, line int, stamp, cal string) Position {
	o, ok := Ordinal(stamp, cal)
	if !ok {
		panic(stamp)
	}
	return Position{File: file, Line: line, Ordinal: o, Calendar: cal}
}

func TestDelta_PaddedDayAndMonthBoundary(t *testing.T) {
	a := pos("f", 1, "Mar  5 23:59:50", CalendarCommon) // single-digit day, as syslog pads it
	b := pos("f", 2, "Mar  6 00:00:20", CalendarCommon)
	if d, ok := Delta(a, b); !ok || d != 30*time.Second {
		t.Fatalf("got %v %v, want 30s", d, ok)
	}
	c := pos("f", 1, "Jan 31 23:59:00", CalendarCommon)
	e := pos("f", 2, "Feb  1 00:01:00", CalendarCommon)
	if d, ok := Delta(c, e); !ok || d != 2*time.Minute {
		t.Fatalf("month rollover: got %v %v", d, ok)
	}
}

func TestDelta_RefusesWhatItCannotKnow(t *testing.T) {
	a := pos("f1", 1, "Mar  5 10:00:00", CalendarCommon)
	if _, ok := Delta(a, pos("f2", 2, "Mar  5 10:01:00", CalendarCommon)); ok {
		t.Error("two files may be different years")
	}
	if _, ok := Delta(a, pos("f1", 2, "Mar  5 10:01:00", CalendarLeap)); ok {
		t.Error("different calendars are not comparable")
	}
	// A year change: the stamp goes backwards while the line goes forward.
	nye := pos("f", 1, "Dec 31 23:59:00", CalendarCommon)
	ny := pos("f", 2, "Jan  1 00:01:00", CalendarCommon)
	if _, ok := Delta(nye, ny); ok {
		t.Error("distance across a New Year is unknown and must not be guessed")
	}
	// Reversed lines.
	if _, ok := Delta(pos("f", 5, "Mar  5 10:00:00", CalendarCommon), pos("f", 4, "Mar  5 10:01:00", CalendarCommon)); ok {
		t.Error("b before a in the file")
	}
}

func TestPositionOf_NeedsEverythingOrNothing(t *testing.T) {
	extra := map[string]string{KeyLine: "7"}
	Annotate(extra, "Mar  5 10:00:00", CalendarCommon)
	if _, ok := PositionOf("file-1", extra); !ok {
		t.Fatal("annotated event should have a position")
	}
	if _, ok := PositionOf("", extra); ok {
		t.Error("no source file, no position")
	}
	bad := map[string]string{KeyLine: "7"}
	Annotate(bad, "garbage", CalendarCommon)
	if _, ok := PositionOf("file-1", bad); ok {
		t.Error("an unplaceable stamp must leave the event without a position")
	}
}

func items(spec ...interface{}) []Item {
	var out []Item
	for i := 0; i < len(spec); i += 3 {
		out = append(out, Item{Pos: pos("f", spec[i].(int), spec[i+1].(string), CalendarCommon), Success: spec[i+2].(bool)})
	}
	return out
}

func TestBursts_SuccessEndsTheRunItFollows(t *testing.T) {
	// A source guesses, gets in, and keeps guessing: each success is tied to
	// the failures just before it, not to the end of the whole attack.
	its := items(
		1, "Mar  5 10:00:00", false, 2, "Mar  5 10:00:02", false, 3, "Mar  5 10:00:04", false,
		4, "Mar  5 10:00:05", true,
		5, "Mar  5 10:00:06", false, 6, "Mar  5 10:00:07", false, 7, "Mar  5 10:00:08", false, 8, "Mar  5 10:00:09", false,
		9, "Mar  5 10:00:10", true,
		10, "Mar  5 10:00:11", false, 11, "Mar  5 10:00:12", false,
	)
	got := BurstsBeforeSuccess(its, 3, 10*time.Minute, 30*time.Minute)
	if len(got) != 2 {
		t.Fatalf("got %d bursts, want 2: %+v", len(got), got)
	}
	if len(got[0].Failures) != 3 || got[0].Success != 3 || len(got[1].Failures) != 4 || got[1].Success != 8 {
		t.Fatalf("wrong split: %+v", got)
	}
}

func TestBursts_Refusals(t *testing.T) {
	win := 30 * time.Minute
	gap := 10 * time.Minute
	cases := map[string][]Item{
		"too few failures": items(1, "Mar  5 10:00:00", false, 2, "Mar  5 10:00:01", false, 3, "Mar  5 10:00:02", true),
		"gap too large": items(1, "Mar  5 10:00:00", false, 2, "Mar  5 10:20:00", false, 3, "Mar  5 10:40:00", false,
			4, "Mar  5 10:41:00", true),
		"success too late": items(1, "Mar  5 10:00:00", false, 2, "Mar  5 10:00:01", false, 3, "Mar  5 10:00:02", false,
			4, "Mar  5 11:00:00", true),
		"success first": items(1, "Mar  5 09:59:00", true, 2, "Mar  5 10:00:00", false, 3, "Mar  5 10:00:01", false, 4, "Mar  5 10:00:02", false),
		"year change": items(1, "Dec 31 23:58:00", false, 2, "Dec 31 23:58:30", false, 3, "Dec 31 23:59:00", false,
			4, "Jan  1 00:00:20", true),
	}
	for name, its := range cases {
		if got := BurstsBeforeSuccess(its, 3, gap, win); len(got) != 0 {
			t.Errorf("%s: got %+v", name, got)
		}
	}
}

func TestBursts_AnotherFileEndsTheRun(t *testing.T) {
	its := []Item{
		{Pos: pos("f1", 1, "Mar  5 10:00:00", CalendarCommon)},
		{Pos: pos("f1", 2, "Mar  5 10:00:01", CalendarCommon)},
		{Pos: pos("f1", 3, "Mar  5 10:00:02", CalendarCommon)},
		{Pos: pos("f2", 4, "Mar  5 10:00:03", CalendarCommon), Success: true},
	}
	if got := BurstsBeforeSuccess(its, 3, 10*time.Minute, 30*time.Minute); len(got) != 0 {
		t.Fatalf("two files: %+v", got)
	}
}
