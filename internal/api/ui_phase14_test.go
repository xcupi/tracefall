package api

import (
	"os"
	"strings"
	"testing"
)

// UI regression tests for this pass. These read app.js and assert the
// behaviour that is only expressible in the frontend -- the same
// approach the existing lifecycle_ui_test.go takes, and the reason
// functionBody exists.

func appJS(t *testing.T) []byte {
	t.Helper()
	src, err := os.ReadFile("../web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// Issue 1: browser coverage must be shown as a boundary, and must never
// imply the whole family is unsupported.
func TestUI_BrowserCoverageShowsBothSides(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function renderCapabilityBoundary(")

	for _, want := range []string{"Not currently supported", "Supported in this family"} {
		if !strings.Contains(body, want) {
			t.Errorf("capability boundary does not render %q", want)
		}
	}
	if !strings.Contains(body, "not_parsed") || !strings.Contains(body, "parsed_instead") {
		t.Error("the boundary does not read the server's parsed_instead / not_parsed lists")
	}
	// The detail panel must call it.
	details := functionBody(t, src, "function evidenceDetails(")
	if !strings.Contains(details, "renderCapabilityBoundary(") {
		t.Error("evidence details no longer renders the capability boundary")
	}
}

// Issue 5: the UI must distinguish known-but-unparsed from unrecognized.
func TestUI_DistinguishesKnownUnsupportedFromUnrecognized(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function capabilityClassification(")

	if !strings.Contains(body, "Known artifact, parser unavailable") {
		t.Error("no wording for a recognized-but-unsupported artifact")
	}
	if !strings.Contains(body, "Unrecognized") {
		t.Error("no wording for a genuinely unidentified artifact")
	}
	if !strings.Contains(body, "f.recognized") {
		t.Error("the classification does not consult the server's recognized flag")
	}
	// It must be surfaced in the detail grid.
	details := functionBody(t, src, "function evidenceDetails(")
	if !strings.Contains(details, "capabilityClassification(") {
		t.Error("evidence details does not show the classification")
	}
}

// Issue 2: the import UI must offer cancellation and treat a cancelled
// import as a normal outcome rather than a failure.
func TestUI_ImportOffersCancellation(t *testing.T) {
	src := appJS(t)
	text := string(src)

	runner := functionBody(t, src, "async function runImportWithProgress(")
	if !strings.Contains(runner, "/cancel") {
		t.Error("the import runner never calls the cancel endpoint")
	}
	if !strings.Contains(runner, "cancelled") {
		t.Error("the import runner does not handle the cancelled terminal state")
	}

	progress := functionBody(t, src, "function renderImportProgress(")
	if !strings.Contains(progress, "import-cancel-btn") {
		t.Error("no Cancel import button in the progress panel")
	}
	if !strings.Contains(progress, "Cancel import") {
		t.Error("the cancel control is not labelled 'Cancel import'")
	}
	if !strings.Contains(progress, "Cancelling...") {
		t.Error("no in-flight state; a clicked Cancel button would look inert")
	}
	if !strings.Contains(progress, "p.done") {
		t.Error("the Cancel button is not hidden once the import is done")
	}

	results := functionBody(t, src, "function renderImportResults(")
	if !strings.Contains(results, "Import cancelled") {
		t.Error("a cancelled import is not labelled as cancelled")
	}
	if !strings.Contains(results, "not a parse failure") {
		t.Error("unprocessed files are not distinguished from parse failures in the summary")
	}
	// The summary must not claim files were "never processed": some of
	// them were parsed and then discarded unwritten, which is a
	// different thing and the analyst can tell.
	if strings.Contains(results, "never processed") {
		t.Error("the cancelled summary claims files were never processed; some were parsed but not written")
	}
	if !strings.Contains(results, "unprocessed") {
		t.Error("the cancelled summary does not report unprocessed files")
	}
	// The phase label table must know the state.
	if !strings.Contains(text, `cancelled: "Cancelled"`) {
		t.Error("the phase label table has no entry for cancelled")
	}
}

// Issue 3: correlations and activity chains must expose their events.
func TestUI_CorrelationEventsAreInspectable(t *testing.T) {
	src := appJS(t)

	card := functionBody(t, src, "function renderCorrelationCard(")
	if !strings.Contains(card, "mountCorrelationEventDetail(") {
		t.Error("a correlation card offers no way to inspect its events")
	}
	if !strings.Contains(card, "underlying event") {
		t.Error("the event count does not say the events are the correlation's underlying events")
	}

	chain := functionBody(t, src, "function renderActivityChain(")
	if !strings.Contains(chain, "mountCorrelationEventDetail(") {
		t.Error("an activity chain offers no event drill-down")
	}
	if !strings.Contains(chain, "CHAIN_INLINE_STEPS") {
		t.Error("a long chain still renders every step inline")
	}

	detail := functionBody(t, src, "function mountCorrelationEventDetail(")
	if !strings.Contains(detail, "paginate(") || !strings.Contains(detail, "wirePager(") {
		t.Error("the drill-down does not paginate; a 60-event chain would render as one wall")
	}
	if !strings.Contains(detail, "rowForEvent(") {
		t.Error("the drill-down does not reuse the existing event row renderer")
	}
	if !strings.Contains(detail, "hidden") {
		t.Error("the drill-down is not collapsed by default")
	}
}

// Ordering must be deterministic, and an activity chain's recorded
// narrative order must never be re-sorted.
func TestUI_CorrelationEventOrderingIsDeterministic(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function correlationEventsFor(")

	if !strings.Contains(body, "isChainCorrelationType(") {
		t.Error("chain ordering is not distinguished from other correlations")
	}
	if !strings.Contains(body, "return { events: resolved, missing, ordering: \"narrative\" }") {
		t.Error("an activity chain's recorded event order is not preserved verbatim")
	}
	// Non-chain correlations sort chronologically with a stable tiebreak.
	if !strings.Contains(body, "localeCompare") {
		t.Error("no stable tiebreak: events sharing a timestamp could order differently between renders")
	}
	if !strings.Contains(body, "new Date(a.timestamp)") {
		t.Error("non-chain correlations are not ordered by event timestamp")
	}
	// Unresolvable events must be reported, never silently dropped.
	if !strings.Contains(body, "missing") {
		t.Error("unresolved events are not counted")
	}
	detail := functionBody(t, src, "function mountCorrelationEventDetail(")
	if !strings.Contains(detail, "could not be resolved") {
		t.Error("unresolved events are not surfaced to the analyst")
	}
}

// Issue 4: case state must be visible at a glance in the header.
func TestUI_CaseHeaderShowsStatePriorityAndFreshness(t *testing.T) {
	src := appJS(t)

	header := functionBody(t, src, "function renderCaseHeader(")
	if !strings.Contains(header, "renderCaseStateBadges(") {
		t.Error("the case header does not render the state badges")
	}

	badges := functionBody(t, src, "function renderCaseStateBadges(")
	for _, fn := range []string{"caseWorkflowBadge(", "casePriorityBadge(", "analysisStateBadge("} {
		if !strings.Contains(badges, fn) {
			t.Errorf("state badges do not include %s", fn)
		}
	}

	// The workflow badge must show the ANALYST status, never the engine
	// status -- conflating the two is a standing hazard in this codebase.
	wf := functionBody(t, src, "function caseWorkflowBadge(")
	if strings.Contains(wf, "c.status") {
		t.Error("the workflow badge reads the engine status instead of case_status")
	}

	// Analysis freshness must have three distinct states.
	an := functionBody(t, src, "function analysisStateBadge(")
	for _, want := range []string{"ANALYSIS STALE", "ANALYZED", "NEVER ANALYZED"} {
		if !strings.Contains(an, want) {
			t.Errorf("analysis badge is missing the %q state", want)
		}
	}

	// Editing must still exist, in exactly one place.
	if !strings.Contains(header, "case-status-select") || !strings.Contains(header, "case-priority-select") {
		t.Error("the editable selects were removed from the header")
	}
	if strings.Count(header, `id="case-status-select"`) != 1 {
		t.Error("more than one control edits case status")
	}
	if strings.Count(header, `id="case-priority-select"`) != 1 {
		t.Error("more than one control edits priority")
	}
}

// Issue 6: timestamp conversion must be centralized and DST-correct.
func TestUI_TimezoneConversionIsCentralizedAndDSTCorrect(t *testing.T) {
	src := appJS(t)
	text := string(src)

	fmtTime := functionBody(t, src, "function fmtTime(")
	fmtDate := functionBody(t, src, "function fmtDate(")

	for name, body := range map[string]string{"fmtTime": fmtTime, "fmtDate": fmtDate} {
		if !strings.Contains(body, "tzParts(") {
			t.Errorf("%s does not convert through the shared timezone formatter", name)
		}
		if !strings.Contains(body, "tzLabel()") {
			t.Errorf("%s does not label which zone it rendered in", name)
		}
		if strings.Contains(body, "toISOString") {
			t.Errorf("%s still formats via toISOString, which is always UTC", name)
		}
	}

	// Conversion must go through the IANA database, never offset maths.
	if !strings.Contains(text, "Intl.DateTimeFormat") {
		t.Error("no Intl.DateTimeFormat: conversion is not using the timezone database")
	}
	if !strings.Contains(functionBody(t, src, "function tzFormatter("), "timeZone: zone") {
		t.Error("the formatter does not pass an IANA timeZone")
	}
	// Hand-rolled offset arithmetic is exactly what the requirement
	// forbids: it cannot express DST.
	for _, bad := range []string{"3600 * 7", "* 7 * 60", "setHours(d.getHours() + "} {
		if strings.Contains(text, bad) {
			t.Errorf("hand-rolled offset arithmetic found: %q", bad)
		}
	}

	// Settings must load before the first render.
	if !strings.Contains(text, "await loadDisplaySettings()") {
		t.Error("display settings are not awaited before the first route render")
	}
	// Hardcoded UTC column headers would now be wrong.
	if strings.Contains(text, "Time (UTC)") {
		t.Error("a column header still hardcodes UTC instead of naming the display zone")
	}
}

// Issue 7: the setting must be reachable and persist the IANA id.
func TestUI_TimezoneControlPersistsIANAIdentifier(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function renderTimezoneControl(")

	if !strings.Contains(body, `api("/settings"`) {
		t.Error("the control does not persist through the settings endpoint")
	}
	if !strings.Contains(body, `method: "PUT"`) {
		t.Error("the control does not PUT its change")
	}
	if !strings.Contains(body, "timezone: chosen") {
		t.Error("the control does not send the canonical identifier")
	}
	if !strings.Contains(body, "applyDisplaySettings(") {
		t.Error("the control does not apply the server's confirmed setting")
	}
	if !strings.Contains(body, "route()") {
		t.Error("changing the zone does not re-render the current view")
	}
	// It must NOT trigger re-analysis or a data refetch.
	for _, bad := range []string{"/analyze", "location.reload"} {
		if strings.Contains(body, bad) {
			t.Errorf("changing the display timezone triggers %q", bad)
		}
	}
	// The control must live in the persistent chrome, not one page.
	html, err := os.ReadFile("../web/static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), `id="timezone-control"`) {
		t.Error("no timezone control host in the app shell")
	}
}

// Changing the timezone must re-render the CASE HEADER too.
//
// route() has a fast path that swaps only the tab body when the same
// case is already on screen. Taking it after a timezone change left the
// header's Created / Last analyzed timestamps in the previous zone while
// every other timestamp on the page had converted -- two zones on one
// screen, unlabelled as such. Proven by browser verification before this
// guard existed.
func TestUI_TimezoneChangeRebuildsTheCaseHeader(t *testing.T) {
	src := appJS(t)
	body := functionBody(t, src, "function renderTimezoneControl(")

	if !strings.Contains(body, "renderedCaseId = null") {
		t.Error("the timezone handler does not reset renderedCaseId, so route() will take the " +
			"switchTab fast path and leave the case header in the previous zone")
	}
	if !strings.Contains(body, "renderedTab = null") {
		t.Error("the timezone handler does not reset renderedTab")
	}
	// The reset must come before the route() CALL, or it does nothing.
	// Anchored on "route();" -- the word "route()" also appears in the
	// comment explaining why the reset is there, and matching that
	// instead would compare against the wrong position.
	reset := strings.Index(body, "renderedCaseId = null")
	call := strings.Index(body, "route();")
	if reset < 0 || call < 0 {
		t.Fatalf("could not locate the reset (%d) or the route() call (%d)", reset, call)
	}
	if reset > call {
		t.Error("renderedCaseId is reset after route(), which is too late to matter")
	}
	// And the header must actually format through the shared formatter.
	header := functionBody(t, src, "function renderCaseHeader(")
	if !strings.Contains(header, "fmtTime(c.created_at)") {
		t.Error("the case header does not format Created through the shared formatter")
	}
	if !strings.Contains(header, "fmtTime(c.analyzed_at)") {
		t.Error("the case header does not format Last analyzed through the shared formatter")
	}
}

// The case header's right-hand controls must be ONE coherent row.
//
// Regression: .case-state-badges was a COLUMN flex nested inside the row
// that holds Export and Delete Case. The three badges stacked vertically
// into a single tall flex item, and the two buttons centred against the
// full height of that stack -- so the status badges and the action
// buttons appeared to sit on different rows, and the badges overlapped
// the header's intended structure.
//
// A geometric check in a real browser is what actually proves the fix
// (all five controls share one centre line at desktop width); this
// guards the CSS declarations that make it true, because the failure
// mode is a single property flipping back.
func TestUI_CaseHeaderActionsAreOneRow(t *testing.T) {
	css, err := os.ReadFile("../web/static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)

	rule := func(selector string) string {
		i := strings.Index(text, "\n"+selector+" {")
		if i < 0 {
			t.Fatalf("no %s rule", selector)
		}
		end := strings.Index(text[i:], "}")
		if end < 0 {
			t.Fatalf("unterminated %s rule", selector)
		}
		return text[i : i+end]
	}

	badges := rule(".case-state-badges")
	if strings.Contains(badges, "flex-direction: column") {
		t.Error("the state badges are a column again: they will stack vertically and the " +
			"action buttons will centre against the whole stack")
	}
	if !strings.Contains(badges, "flex-direction: row") {
		t.Error("the state badges do not declare a row direction")
	}
	if !strings.Contains(badges, "align-items: center") {
		t.Error("the state badges are not vertically centred")
	}

	actions := rule(".case-header-actions")
	for _, want := range []string{"display: flex", "align-items: center", "flex-wrap: wrap"} {
		if !strings.Contains(actions, want) {
			t.Errorf("the action group is missing %q", want)
		}
	}
	// Wrapping must keep the group together on the right, not scatter it.
	if !strings.Contains(actions, "justify-content: flex-end") {
		t.Error("the action group does not stay right-aligned when it wraps")
	}

	// Absolute positioning is explicitly ruled out for these elements.
	for _, sel := range []string{".case-header-actions", ".case-state-badges"} {
		if strings.Contains(rule(sel), "position: absolute") {
			t.Errorf("%s uses absolute positioning", sel)
		}
	}

	// Analysis state must be visually distinct from status/priority and
	// must not dominate: outlined rather than filled.
	i := strings.Index(text, "\n.badge.analysis-state {")
	if i < 0 {
		t.Fatal("no .badge.analysis-state rule")
	}
	analysis := text[i : i+strings.Index(text[i:], "}")]
	if !strings.Contains(analysis, "background: transparent") {
		t.Error("the analysis badge is filled, so it competes with the status and priority badges")
	}
	if !strings.Contains(analysis, "border") {
		t.Error("the analysis badge has no outline to distinguish it")
	}
}

// The top bar must not force a horizontal scrollbar on a narrow
// viewport. Adding the timezone control widened its right-hand group
// past a phone width, which put a horizontal scrollbar on every screen
// in the app.
func TestUI_TopBarWrapsInsteadOfOverflowing(t *testing.T) {
	css, err := os.ReadFile("../web/static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)
	for _, sel := range []string{".topbar", ".topbar-right"} {
		i := strings.Index(text, "\n"+sel+" {")
		if i < 0 {
			t.Fatalf("no %s rule", sel)
		}
		rule := text[i : i+strings.Index(text[i:], "}")]
		if !strings.Contains(rule, "flex-wrap: wrap") {
			t.Errorf("%s does not wrap; its contents will push the page wider than the viewport", sel)
		}
	}
}

// Case-status badges must use the palette, and OPEN must look active.
//
// Regression: OPEN was styled `background: var(--bg-muted, #e8eaed)`.
// --bg-muted is not defined in this theme, so the fallback applied and
// an ACTIVE case rendered as a near-white chip on a dark panel -- it
// read as disabled. The other three statuses were Material light-theme
// hexes that belong to no palette here.
//
// This pins the fix at its cause: status colours come from the theme
// tokens, and every var() used must actually be defined.
func TestUI_CaseStatusBadgesUseThePalette(t *testing.T) {
	css, err := os.ReadFile("../web/static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)

	rule := func(selector string) string {
		i := strings.Index(text, "\n"+selector+" {")
		if i < 0 {
			t.Fatalf("no %s rule", selector)
		}
		return text[i : i+strings.Index(text[i:], "}")]
	}

	// Every var() referenced by the status badges must be a real token.
	defined := map[string]bool{}
	for _, tok := range []string{"--accent", "--ok", "--high", "--medium", "--low", "--critical", "--text", "--text-dim", "--border"} {
		if strings.Contains(text, tok+":") {
			defined[tok] = true
		}
	}
	if defined["--bg-muted"] {
		t.Error("--bg-muted is defined now; this test's premise needs revisiting")
	}

	statuses := map[string]string{
		".badge.case-state-open":          "--accent", // blue: an active state
		".badge.case-state-investigating": "--high",   // amber/orange
		".badge.case-state-contained":     "--ok",     // green
	}
	for sel, wantToken := range statuses {
		r := rule(sel)
		if !strings.Contains(r, "var("+wantToken+")") {
			t.Errorf("%s does not take its colour from var(%s): %s", sel, wantToken, r)
		}
		if strings.Contains(r, "var(--bg-muted") {
			t.Errorf("%s still references the undefined --bg-muted token", sel)
		}
		// A tinted fill is what separates a status badge from the
		// outline-only priority badges beside it.
		if !strings.Contains(r, "background: rgba(") {
			t.Errorf("%s has no tinted background, so it will not read as a state", sel)
		}
	}

	// CLOSED is the deliberate exception: neutral grey, and the one
	// status allowed to recede.
	closed := rule(".badge.case-state-closed")
	if !strings.Contains(closed, "rgba(136, 146, 171") {
		t.Errorf("CLOSED is not a neutral grey: %s", closed)
	}
	for _, hot := range []string{"var(--ok)", "var(--accent)", "var(--critical)", "var(--high)"} {
		if strings.Contains(closed, hot) {
			t.Errorf("CLOSED uses an active colour %s", hot)
		}
	}

	// Analysis state stays separate from case status, and stale is a
	// warning rather than a critical.
	stale := rule(".badge.analysis-stale")
	if !strings.Contains(stale, "var(--high)") {
		t.Errorf("stale analysis is not the warning colour: %s", stale)
	}
	if strings.Contains(stale, "var(--critical)") {
		t.Error("stale analysis uses the critical colour, which is reserved for priority and severity")
	}
	if !strings.Contains(rule(".badge.analysis-current"), "var(--ok)") {
		t.Error("ANALYZED is not green")
	}

	// Priority colours must be untouched by all of this.
	for sel, want := range map[string]string{
		".badge.prio-critical": "var(--critical)",
		".badge.prio-high":     "var(--high)",
		".badge.prio-medium":   "var(--medium)",
		".badge.prio-low":      "var(--low)",
	} {
		i := strings.Index(text, "\n"+sel+" ")
		if i < 0 {
			t.Fatalf("no %s rule", sel)
		}
		line := text[i : i+strings.Index(text[i:], "\n}")+1]
		if !strings.Contains(line, want) {
			t.Errorf("%s no longer uses %s", sel, want)
		}
	}
	// Priority stays outline-only, so it can never be confused with a
	// status badge.
	if !strings.Contains(rule(".badge.prio"), "background: transparent") {
		t.Error("priority badges gained a fill; they would then look like status badges")
	}
}
