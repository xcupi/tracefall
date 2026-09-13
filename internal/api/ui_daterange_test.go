package api

import (
	"strings"
	"testing"
)

// UI regression tests for precise date-range filtering (Phase 17).
//
// These read app.js and assert the behaviour that only exists in the
// frontend -- the same approach ui_phase14_test.go takes.

// The date popover must accept a custom start AND end date-time, with
// seconds. A time input without step="1" hides the seconds field in
// every major browser, which would make second-level filtering
// unreachable however correct the backend is.
func TestUIDateRange_InputsAcceptSecondPrecision(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function renderDatePopover(")

	for _, id := range []string{"-f-from-d", "-f-from-t", "-f-to-d", "-f-to-t"} {
		if !strings.Contains(body, id) {
			t.Errorf("the date popover has no %s input; a custom start and end are both required", id)
		}
	}
	// Both TIME inputs must offer seconds.
	timeInputs := strings.Count(body, `class="filter-time-input"`)
	if timeInputs != 2 {
		t.Errorf("found %d time inputs, want 2 (a start and an end)", timeInputs)
	}
	if got := strings.Count(body, `step="1"`); got != 2 {
		t.Errorf(`found %d time inputs with step="1", want 2; without it browsers hide the seconds field`, got)
	}
	if !strings.Contains(body, `type="date"`) || !strings.Contains(body, `type="time"`) {
		t.Error("the popover must use native date and time inputs")
	}
}

// readDateTime is the single place a bound becomes an instant. It must
// extend an END bound to the end of the unit the analyst named, or a
// one-second range cannot contain an event with sub-second precision.
func TestUIDateRange_EndBoundExtendsToTheUnitNamed(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function readDateTime(")

	if !strings.Contains(body, `which === "to"`) {
		t.Error("readDateTime does not distinguish the start bound from the end bound")
	}
	if !strings.Contains(body, "endOfUnit(") {
		t.Error("readDateTime does not extend an end bound to the end of its unit")
	}
	// It must decide on the PRECISION actually typed, not assume one.
	if !strings.Contains(body, "hasSeconds") {
		t.Error("readDateTime does not detect whether seconds were entered")
	}
	// The three widths the rule requires.
	for _, want := range []string{"24 * 3600 * 1000", "60 * 1000", "1000"} {
		if !strings.Contains(body, want) {
			t.Errorf("readDateTime is missing the %s unit width", want)
		}
	}
	// And it must still resolve in the DISPLAY timezone, not the
	// browser's -- the Phase 14 rule this must not regress.
	if !strings.Contains(body, "wallTimeToInstant(") {
		t.Error("readDateTime no longer resolves bounds in the display timezone")
	}
	if strings.Contains(body, "new Date(`${d}T${time}`)") {
		t.Error("readDateTime parses in the browser's timezone again")
	}

	helper := functionBody(t, src, "function endOfUnit(")
	if !strings.Contains(helper, "widthMs - 1") {
		t.Error("endOfUnit does not return the last instant of the unit")
	}
}

// The Timeline sends its bounds to the SERVER as absolute instants, so
// the filtering happens against the stored timestamp rather than a
// rendered string.
func TestUIDateRange_TimelineSendsAbsoluteInstantsToTheServer(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function timelineQuery(")

	if !strings.Contains(body, `q.set("from", f.from.toISOString())`) ||
		!strings.Contains(body, `q.set("to", f.to.toISOString())`) {
		t.Error("the timeline does not send its date bounds as absolute instants")
	}
}

// Clearing the filter must reset BOTH date inputs and BOTH time inputs,
// on the popover's own Clear and on the bar's Clear all -- a leftover
// time with no date, or a stale second, silently narrows every later
// query.
func TestUIDateRange_ClearingResetsEveryDateAndTimeInput(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function wireFilterBar(")

	// Every reset path must touch all four inputs.
	if got := strings.Count(body, `["from-d", "from-t", "to-d", "to-t"]`); got < 3 {
		t.Errorf("only %d reset paths clear all four date/time inputs; the popover Clear, the chip and Clear all each need one", got)
	}
	// And each must drop the resolved instants too, not just the inputs.
	if strings.Count(body, "state.from = null") < 2 || strings.Count(body, "state.to = null") < 2 {
		t.Error("a reset path clears the inputs but leaves the resolved bounds set")
	}
	// The date chip must be removable on its own.
	if !strings.Contains(body, `chip.dataset.field === "__date"`) {
		t.Error("the active-filter chip cannot clear the date range by itself")
	}
}

// The popover must state which zone the bounds are read in. A range
// entered in one zone and displayed in another is the mistake this
// whole area exists to prevent.
func TestUIDateRange_PopoverStatesItsTimezone(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function renderDatePopover(")

	if !strings.Contains(body, "displayTimezone") {
		t.Error("the date popover does not name the timezone its inputs are read in")
	}
	if !strings.Contains(body, "tzLabel()") {
		t.Error("the popover does not show the zone's label")
	}
	// The chip must carry the zone as well, so a collapsed popover still
	// says what the range means.
	label := functionBody(t, src, "function dateRangeLabel(")
	if !strings.Contains(label, "tzLabel()") {
		t.Error("the date chip does not state its timezone")
	}
}

// Findings filter on the same bounds, through the same state, so the two
// tabs cannot drift apart.
func TestUIDateRange_FindingsUseTheSameBounds(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function findingMatchesFilters(")

	if !strings.Contains(body, "filters.from") || !strings.Contains(body, "filters.to") {
		t.Error("the findings filter does not apply the date bounds")
	}
	// Compared against the finding's own window, not a rendered string.
	if !strings.Contains(body, "last_seen") || !strings.Contains(body, "first_seen") {
		t.Error("the findings filter does not compare against first_seen/last_seen")
	}
	if strings.Contains(body, "fmtTime(") || strings.Contains(body, "fmtDate(") {
		t.Error("the findings filter compares against a rendered timestamp string")
	}
}

// The timeline's own predicate (reused by the investigation detail view)
// must also compare instants, never rendered text.
func TestUIDateRange_EventPredicateComparesInstants(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function eventMatchesFilters(")

	if !strings.Contains(body, "new Date(e.timestamp)") {
		t.Error("the event predicate does not compare against the normalized timestamp")
	}
	if strings.Contains(body, "fmtTime(") {
		t.Error("the event predicate compares against a rendered timestamp string")
	}
}

// A date-looking search term must be labelled as a TEXT search, and must
// point at the control that does filter by time.
//
// This is the confusion that made the filter look broken: "2021" in the
// search box returned 43 results on a real case -- all coincidental
// matches on the string "2021" inside paths, URLs and titles -- which
// reads as time filtering, while the more precise "2021-04" returned
// nothing and read as a bug.
func TestUIDateRange_PartialDateSearchIsLabelledAsText(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function partialDateTerm(")

	// Complete forms are resolved as moments and must NOT be warned about.
	if !strings.Contains(body, `\d{4}-\d{2}-\d{2}`) {
		t.Error("partialDateTerm does not exempt a complete date from the note")
	}
	// The partial forms that must be.
	for _, want := range []string{`^\d{4}$`, `^\d{4}-\d{1,2}$`} {
		if !strings.Contains(body, want) {
			t.Errorf("partialDateTerm does not recognize %s", want)
		}
	}

	note := functionBody(t, src, "function renderSearchScopeNote(")
	for _, want := range []string{"searched as", "text", "Date range"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note does not mention %q", want)
		}
	}
	if !strings.Contains(note, "esc(") {
		t.Error("the note interpolates the analyst's term without escaping it")
	}

	// It must be rendered with the results, including the empty case --
	// the empty result is exactly when it is most needed.
	page := functionBody(t, src, "function renderTimelinePage(")
	if strings.Count(page, "scopeNote") < 3 {
		t.Error("the scope note is not rendered on both the populated and empty result paths")
	}
}
