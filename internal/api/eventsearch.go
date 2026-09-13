package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/store"
)

// The forensic timeline: analyst-facing search over normalized events
// (Phase 14).
//
// # What layer this is
//
// Tracefall keeps five things apart, and this file serves exactly one of
// them:
//
//	raw evidence -> artifact -> EVENT -> finding -> investigation
//
// An event is an observation a parser normalized out of an artifact. It
// is NOT a detection. Most events in a real case will never be cited by
// a finding, and that is the normal, expected state -- a browser visit
// to a research forum is a fact about the machine whether or not any
// rule cares about it. This view exists precisely so those events are
// findable, because before it the only events an analyst could reach
// through the UI were the ones a detection had already selected.
//
// So: this endpoint never creates a finding, never promotes an event,
// and never implies that an event without a finding is uninteresting.
// Where a relationship to a finding or investigation does exist it is
// exposed as a LINK, so the analyst can cross the boundary deliberately
// and always knows which side they are on.
//
// # Where the timezone rule is enforced
//
// Stored timestamps are UTC instants and are never rewritten (see
// api/settings.go). A calendar date, though, is not an instant -- "29
// April 2021" names a different 24 hours in Jakarta than it does in
// UTC. resolveDateRange is the single place that turns the analyst's
// local calendar date into the pair of instants that bracket it, using
// the configured display timezone. Everything below that point deals in
// instants only.

// eventSearchDateLayout is the calendar-date form the timeline's date
// inputs submit: an unambiguous ISO date, deliberately not a
// locale-formatted one. A date filter must mean the same thing to every
// analyst who types it.
const eventSearchDateLayout = "2006-01-02"

// eventSearchDateTimeLayouts are the fuller forms accepted alongside a
// bare date, for an analyst narrowing to part of a day. Minutes and
// seconds are both accepted because "18:17" and "18:17:38" are equally
// natural to type off a report.
//
// Each carries the PRECISION it expresses, which decides how far a `to`
// bound reaches -- see parseBound. A layout with no sub-second field
// names a whole second, and a range ending "at 18:17:38" must therefore
// include every instant within that second.
var eventSearchDateTimeLayouts = []struct {
	form  string
	width time.Duration
}{
	{"2006-01-02T15:04:05", time.Second},
	{"2006-01-02 15:04:05", time.Second},
	{"2006-01-02T15:04", time.Minute},
	{"2006-01-02 15:04", time.Minute},
}

// ResolvedRange reports exactly which instants a date filter became.
//
// It is returned to the client rather than kept private because a
// timezone conversion the analyst cannot see is a timezone conversion
// they cannot check. Showing "2021-04-29 in Asia/Jakarta = 2021-04-28
// 17:00:00Z to 2021-04-29 16:59:59Z" turns an invisible assumption into
// a stated one, which is the difference between a tool an examiner can
// testify about and one they cannot.
type ResolvedRange struct {
	// From/To are the inclusive UTC bounds actually queried, empty when
	// that end is unbounded.
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	// Timezone is the IANA zone the analyst's input was interpreted in.
	Timezone string `json:"timezone"`
	// Input echoes what was asked for, so the two can be compared.
	Input string `json:"input,omitempty"`
}

// resolveDateRange turns the request's date inputs into UTC instants,
// interpreted in loc.
//
// Three forms are supported, and all three are calendar-local:
//
//	date=2021-04-29              the whole of that local day
//	from=2021-04-29              from the start of that local day
//	to=2021-04-29                to the end of that local day
//	from=2021-04-29T18:00 &c.    a precise local instant
//
// A bare `to` date extends to the END of that day (23:59:59.999999999
// local), because an analyst who types the same date in both boxes means
// "that day", not "an empty instant at midnight". This mirrors the
// inclusive-both-ends rule the rest of Tracefall's filtering uses.
//
// An unparseable value is reported as an error rather than ignored.
// Silently dropping a date filter would show the analyst the whole case
// while they believed they were looking at one day, which is a far worse
// failure than a message saying the date could not be read.
func resolveDateRange(q map[string][]string, loc *time.Location) (from, to time.Time, input string, err error) {
	get := func(k string) string {
		if v, ok := q[k]; ok && len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}

	if d := get("date"); d != "" {
		day, perr := time.ParseInLocation(eventSearchDateLayout, d, loc)
		if perr != nil {
			return time.Time{}, time.Time{}, d, fmt.Errorf("date %q is not a valid YYYY-MM-DD date", d)
		}
		// AddDate then step back one nanosecond, rather than adding 24
		// hours: a local day is not always 24 hours long. On a DST
		// transition it is 23 or 25, and adding a fixed duration would
		// silently clip an hour of evidence off one day a year, or spill
		// an hour of the next day into it.
		return day, day.AddDate(0, 0, 1).Add(-time.Nanosecond), d, nil
	}

	// parseBound resolves one end of the range.
	//
	// isEnd matters because a bound is written at some PRECISION, and
	// the two ends of a range treat that precision differently. "From
	// 18:17:38" means the instant that second begins; "to 18:17:38"
	// means the instant it ends. Applying the start of the second to
	// both makes the range [18:17:38.000, 18:17:38.000] -- a window one
	// nanosecond wide, which excludes an event recorded at
	// 18:17:38.900891 and makes a one-second range unable to isolate the
	// event inside it. That is the bug this function exists to not have.
	//
	// So an end bound is extended to the last instant of whatever unit
	// was named: end of day for a bare date, end of minute for
	// HH:MM, end of second for HH:MM:SS.
	parseBound := func(raw string, isEnd bool) (time.Time, error) {
		endOf := func(t time.Time, width time.Duration) time.Time {
			if !isEnd {
				return t
			}
			return t.Add(width).Add(-time.Nanosecond)
		}
		if t, perr := time.ParseInLocation(eventSearchDateLayout, raw, loc); perr == nil {
			if isEnd {
				// Calendar arithmetic, not +24h: a local day is 23 or 25
				// hours long across a daylight-saving transition.
				return t.AddDate(0, 0, 1).Add(-time.Nanosecond), nil
			}
			return t, nil
		}
		for _, layout := range eventSearchDateTimeLayouts {
			if t, perr := time.ParseInLocation(layout.form, raw, loc); perr == nil {
				return endOf(t, layout.width), nil
			}
		}
		// An RFC3339 value carries its own offset and is therefore
		// already an INSTANT, not a wall-clock reading at some
		// precision. It is used exactly as given -- a caller who wrote
		// the offset was being explicit, and silently widening their
		// bound would be answering a different question. This is also
		// the form the dashboard sends, which has already resolved its
		// own precision.
		if t, perr := time.Parse(time.RFC3339, raw); perr == nil {
			return t, nil
		}
		return time.Time{}, fmt.Errorf("%q is not a valid date or date-time", raw)
	}

	var parts []string
	if raw := get("from"); raw != "" {
		from, err = parseBound(raw, false)
		if err != nil {
			return time.Time{}, time.Time{}, raw, err
		}
		parts = append(parts, "from "+raw)
	}
	if raw := get("to"); raw != "" {
		to, err = parseBound(raw, true)
		if err != nil {
			return time.Time{}, time.Time{}, raw, err
		}
		parts = append(parts, "to "+raw)
	}
	return from, to, strings.Join(parts, " "), nil
}

// searchTermMoment recognizes a free-text term that names a MOMENT, and
// returns the window it covers.
//
// The window's width is the PRECISION the analyst typed, which is the
// whole point: someone who types a bare date is asking about that day,
// and someone who pastes a full timestamp out of a report is asking
// about that second. Widening a full timestamp to its whole day would
// bury the one event they came for; narrowing a bare date to midnight
// would find nothing.
//
//	2021-04-29                 that local day
//	2021-04-29 18:17           that local minute
//	2021-04-29 18:17:38        that local second
//	2021-04-29T18:17:38Z       that second, at the offset given
//
// Interpreted in loc, the display timezone, for the same reason the date
// filter is: every timestamp on screen is rendered in that zone, so a
// time typed into the search box means that zone's wall clock.
//
// ok is false for an ordinary term, which is the overwhelmingly common
// case and costs one failed parse.
func searchTermMoment(term string, loc *time.Location) (from, to time.Time, ok bool) {
	term = strings.TrimSpace(term)
	if term == "" {
		return time.Time{}, time.Time{}, false
	}
	// Most terms are not moments and most are not even close, so the
	// cheapest possible rejection comes first: a moment must start with
	// four digits and a separator.
	if len(term) < 8 || !isAllDigits(term[:4]) {
		return time.Time{}, time.Time{}, false
	}

	type layout struct {
		form  string
		width time.Duration
	}
	// Ordered longest-first, so "2021-04-29 18:17:38" is read as a
	// second rather than matching the date form on its prefix.
	layouts := []layout{
		{"2006-01-02T15:04:05", time.Second},
		{"2006-01-02 15:04:05", time.Second},
		{"2006-01-02T15:04", time.Minute},
		{"2006-01-02 15:04", time.Minute},
		{"2006-01-02", 0}, // 0 means "a calendar day", handled below
	}
	for _, l := range layouts {
		t, err := time.ParseInLocation(l.form, term, loc)
		if err != nil {
			continue
		}
		if l.width == 0 {
			// Calendar arithmetic, not +24h: a local day is 23 or 25
			// hours long across a daylight-saving transition.
			return t, t.AddDate(0, 0, 1).Add(-time.Nanosecond), true
		}
		return t, t.Add(l.width).Add(-time.Nanosecond), true
	}
	// An RFC3339 value carries its own offset and is already an instant.
	if t, err := time.Parse(time.RFC3339, term); err == nil {
		return t, t.Add(time.Second).Add(-time.Nanosecond), true
	}
	return time.Time{}, time.Time{}, false
}

// isAllDigits reports whether every byte is a decimal digit.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// EventSearchRequest is one parsed timeline query.
type EventSearchRequest struct {
	Query store.EventQuery
	Page  PageRequest
	Range ResolvedRange
}

// eventSearchSortFromQuery maps the request's sort parameter onto the
// store's allow-list. Anything unrecognized becomes newest-first rather
// than an error: a bad sort is a navigation mistake, and the analyst is
// better served by results in a defined order than by a 400.
func eventSearchSortFromQuery(v string) store.EventSort {
	if strings.EqualFold(strings.TrimSpace(v), "asc") || v == string(store.EventSortTimeAsc) {
		return store.EventSortTimeAsc
	}
	return store.EventSortTimeDesc
}

// parseEventSearch reads a timeline query off the request.
//
// loc is the display timezone, and is the ONLY thing that makes a
// calendar date mean a particular pair of instants.
func parseEventSearch(r *http.Request, caseID string, loc *time.Location) (EventSearchRequest, error) {
	q := r.URL.Query()

	from, to, input, err := resolveDateRange(q, loc)
	if err != nil {
		return EventSearchRequest{}, err
	}

	page := parsePageRequest(r, timelinePageSizes, defaultTimelinePageSize)

	// A free-text term that names a moment also searches that moment.
	// See searchTermMoment.
	textFrom, textTo, _ := searchTermMoment(q.Get("q"), loc)

	req := EventSearchRequest{
		Query: store.EventQuery{
			CaseID:            caseID,
			CollectionIDs:     nonEmpty(q["collection"]),
			ArtifactTypes:     nonEmpty(q["artifact_type"]),
			EventTypes:        nonEmpty(q["event_type"]),
			Hosts:             nonEmpty(q["host"]),
			Users:             nonEmpty(q["user"]),
			Processes:         nonEmpty(q["process"]),
			From:              from,
			To:                to,
			Filename:          strings.TrimSpace(q.Get("filename")),
			Path:              strings.TrimSpace(q.Get("path")),
			URL:               strings.TrimSpace(q.Get("url")),
			Domain:            strings.TrimSpace(q.Get("domain")),
			IP:                strings.TrimSpace(q.Get("ip")),
			CommandLine:       strings.TrimSpace(q.Get("command_line")),
			OriginalPath:      strings.TrimSpace(q.Get("original_path")),
			Text:              strings.TrimSpace(q.Get("q")),
			TextTimeFrom:      textFrom,
			TextTimeTo:        textTo,
			FindingSeverities: nonEmpty(q["severity"]),
			FindingTechniques: nonEmpty(q["technique"]),
			Sort:              eventSearchSortFromQuery(q.Get("sort")),
			Limit:             page.PageSize,
			Offset:            (page.Page - 1) * page.PageSize,
		},
		Page: page,
		Range: ResolvedRange{
			Timezone: loc.String(),
			Input:    input,
		},
	}
	if !from.IsZero() {
		req.Range.From = from.UTC().Format(time.RFC3339Nano)
	}
	if !to.IsZero() {
		req.Range.To = to.UTC().Format(time.RFC3339Nano)
	}
	return req, nil
}

// FindingRef is a POINTER from an event to a finding that cites it.
//
// Deliberately not the finding itself. Embedding findings in timeline
// rows would blur the boundary this whole phase exists to keep sharp:
// the row would start to look like a detection result, and an analyst
// scanning the timeline would lose track of which layer they were
// reading. A reference carries enough to label and link, and no more.
type FindingRef struct {
	FindingID  string `json:"finding_id"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	RuleID     string `json:"detection_rule"`
	// Techniques are the finding's ATT&CK ids. Carried on the reference
	// because they are how a timeline row shows technique chips at all:
	// a technique reaches an event only through the findings that cite
	// it, and it belongs to the finding, not to the event.
	Techniques []string `json:"attack_techniques,omitempty"`
}

// CorrelationRef points from an event to a correlation that includes it.
type CorrelationRef struct {
	CorrelationID string `json:"correlation_id"`
	Type          string `json:"correlation_type"`
	Title         string `json:"title"`
}

// InvestigationRef is the same idea one layer further out.
type InvestigationRef struct {
	InvestigationID string `json:"investigation_id"`
	Title           string `json:"title"`
	Category        string `json:"category"`
	Severity        string `json:"severity"`
	Score           int    `json:"risk_score"`
}

// TimelineEvent is one row of the forensic timeline.
//
// It embeds the stored event unchanged -- same fields, same names, same
// UTC timestamp -- and adds only what the row needs in order to be
// READ: a human label for the artifact, an explicit statement of
// whether a timestamp exists, and links out to the layers above.
//
// Nothing here reinterprets the event. In particular Findings may be
// empty, and an empty Findings list is a statement about Tracefall's
// current detections, never about the event.
type TimelineEvent struct {
	model.Event

	// ArtifactLabel is the human-readable name of the artifact class,
	// taken from the SAME capability registry the evidence triage view
	// uses. Not a second naming scheme invented for this view -- the
	// timeline and the evidence table call an artifact the same thing.
	ArtifactLabel string `json:"artifact_label"`

	// TimestampKnown states whether the artifact recorded a time.
	// Derivable from a zero Timestamp, but a forensic answer should not
	// require the reader to know Tracefall's encoding for "unknown".
	TimestampKnown bool `json:"timestamp_known"`

	// Findings are the current detections citing this event; empty when
	// none do. Investigations are the analytical groupings those
	// findings belong to. Both are references -- see FindingRef.
	Findings       []FindingRef       `json:"findings"`
	Investigations []InvestigationRef `json:"investigations"`

	// Correlations are the reconstructed activity chains and entity
	// linkages this event participates in. Like Findings, a reference
	// and routinely empty.
	Correlations []CorrelationRef `json:"correlations"`
}

// EventSearchResponse is one page of the forensic timeline.
type EventSearchResponse struct {
	Page[TimelineEvent]

	// Range states which instants a date filter resolved to, and in
	// which zone -- see ResolvedRange.
	Range ResolvedRange `json:"range"`

	// TotalInCase is how many events the case holds in total, so the UI
	// can distinguish "no events match your filters" (a filter problem)
	// from "this case has no events at all" (an evidence problem). Those
	// need different words in front of an analyst, and guessing between
	// them from a zero page is not possible.
	TotalInCase int `json:"total_in_case"`

	// Filtered reports whether any constraint was applied.
	Filtered bool `json:"filtered"`
}

// SearchEvents runs one forensic timeline query and returns a page.
func (s *Service) SearchEvents(req EventSearchRequest) (EventSearchResponse, error) {
	var out EventSearchResponse

	events, total, err := s.store.SearchEvents(req.Query)
	if err != nil {
		return out, err
	}

	totalInCase, err := s.store.CountEvents(req.Query.CaseID)
	if err != nil {
		return out, err
	}

	rows, err := s.decorateEvents(req.Query.CaseID, events)
	if err != nil {
		return out, err
	}

	out.Page = Page[TimelineEvent]{
		Items:      rows,
		Number:     req.Page.Page,
		PageSize:   req.Page.PageSize,
		Total:      total,
		TotalPages: totalPages(total, req.Page.PageSize),
	}
	out.Range = req.Range
	out.TotalInCase = totalInCase
	out.Filtered = eventQueryConstrains(req.Query)
	return out, nil
}

// totalPages is the page count for a total, matching paginate's
// arithmetic so the two can never disagree.
func totalPages(total, pageSize int) int {
	if pageSize <= 0 {
		return 0
	}
	return (total + pageSize - 1) / pageSize
}

// eventQueryConstrains reports whether a query narrows anything at all.
func eventQueryConstrains(q store.EventQuery) bool {
	return len(q.CollectionIDs) > 0 || len(q.ArtifactTypes) > 0 || len(q.EventTypes) > 0 ||
		len(q.Hosts) > 0 || len(q.Users) > 0 || len(q.Processes) > 0 ||
		!q.From.IsZero() || !q.To.IsZero() ||
		q.Filename != "" || q.Path != "" || q.URL != "" || q.Domain != "" || q.IP != "" ||
		q.CommandLine != "" || q.OriginalPath != "" || q.Text != "" ||
		len(q.FindingSeverities) > 0 || len(q.FindingTechniques) > 0
}

// decorateEvents turns stored events into timeline rows, resolving each
// row's links to the findings and investigations that cite it.
//
// The finding lookup is scoped to the page's own event ids, so
// annotating ten rows reads the findings relevant to ten rows rather
// than every finding in the case (see store.FindingsForEvents).
//
// Investigations are resolved only when the page actually has findings
// on it. An investigation is a grouping OF findings, so a page whose
// events are cited by nothing cannot belong to one, and computing the
// case's investigations to discover that would be pure waste -- which
// matters, because the common case for a forensic timeline is a page of
// perfectly ordinary events that no detection has ever looked at.
func (s *Service) decorateEvents(caseID string, events []model.Event) ([]TimelineEvent, error) {
	ids := make([]string, 0, len(events))
	for _, e := range events {
		ids = append(ids, e.ID)
	}

	findingsByEvent, err := s.store.FindingsForEvents(caseID, ids)
	if err != nil {
		return nil, err
	}
	correlationsByEvent, err := s.store.CorrelationsForEvents(caseID, ids)
	if err != nil {
		return nil, err
	}

	investigationsByFinding := map[string][]InvestigationRef{}
	if len(findingsByEvent) > 0 {
		investigations, err := s.Investigations(caseID)
		if err != nil {
			return nil, err
		}
		for _, inv := range investigations {
			ref := InvestigationRef{
				InvestigationID: inv.ID, Title: inv.Title, Category: inv.Category,
				Severity: inv.Severity, Score: inv.Score,
			}
			for _, fid := range inv.FindingIDs {
				investigationsByFinding[fid] = append(investigationsByFinding[fid], ref)
			}
		}
	}

	rows := make([]TimelineEvent, 0, len(events))
	for _, e := range events {
		row := TimelineEvent{
			Event:          e,
			ArtifactLabel:  eventArtifactLabel(e.ArtifactType),
			TimestampKnown: !e.Timestamp.IsZero(),
			// Non-nil so the JSON is [] rather than null: the dashboard
			// maps over these directly, and a null would make "no related
			// finding" an error condition instead of a normal answer.
			Findings:       []FindingRef{},
			Investigations: []InvestigationRef{},
			Correlations:   []CorrelationRef{},
		}
		for _, c := range correlationsByEvent[e.ID] {
			row.Correlations = append(row.Correlations, CorrelationRef{
				CorrelationID: c.ID, Type: c.Type, Title: c.Title,
			})
		}
		seenInv := map[string]bool{}
		for _, f := range findingsByEvent[e.ID] {
			row.Findings = append(row.Findings, FindingRef{
				FindingID: f.ID, Title: f.Title, Severity: f.Severity,
				Confidence: f.Confidence, RuleID: f.RuleID, Techniques: f.Techniques,
			})
			for _, inv := range investigationsByFinding[f.ID] {
				if seenInv[inv.InvestigationID] {
					continue
				}
				seenInv[inv.InvestigationID] = true
				row.Investigations = append(row.Investigations, inv)
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// EventFacetsResponse is the filter vocabulary for one case's timeline.
//
// Every list is derived from the events the case actually holds, so the
// dropdowns offer only choices that can return something. Labels come
// from the capability registry; values are the model constants, so the
// UI never invents a name and never has to translate one back.
type EventFacetsResponse struct {
	ArtifactTypes []FacetOption `json:"artifact_types"`
	EventTypes    []FacetOption `json:"event_types"`
	Hosts         []string      `json:"hosts"`
	Users         []string      `json:"users"`
	Processes     []string      `json:"processes"`
	Collections   []string      `json:"collections"`

	// Earliest/Latest bracket the case's timestamped evidence, in UTC.
	// Empty when nothing in the case carries a time.
	Earliest string `json:"earliest,omitempty"`
	Latest   string `json:"latest,omitempty"`

	// Timezone is the display zone these will be rendered in, so the
	// timeline can label its own date controls without a second request.
	Timezone DisplaySettings `json:"timezone"`

	// TotalEvents is the case's event count.
	TotalEvents int `json:"total_events"`
}

// FacetOption is one filter choice: the stored value, plus the label an
// analyst reads.
type FacetOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// EventFacets returns the timeline's filter vocabulary for one case.
func (s *Service) EventFacets(caseID string) (EventFacetsResponse, error) {
	var out EventFacetsResponse

	facets, err := s.store.EventFacets(caseID)
	if err != nil {
		return out, err
	}
	total, err := s.store.CountEvents(caseID)
	if err != nil {
		return out, err
	}
	tz, err := s.DisplaySettings()
	if err != nil {
		return out, err
	}

	out.ArtifactTypes = make([]FacetOption, 0, len(facets.ArtifactTypes))
	for _, at := range facets.ArtifactTypes {
		out.ArtifactTypes = append(out.ArtifactTypes, FacetOption{Value: at, Label: eventArtifactLabel(at)})
	}
	out.EventTypes = make([]FacetOption, 0, len(facets.EventTypes))
	for _, et := range facets.EventTypes {
		out.EventTypes = append(out.EventTypes, FacetOption{Value: et, Label: eventTypeLabel(et)})
	}
	out.Hosts = orEmpty(facets.Hosts)
	out.Users = orEmpty(facets.Users)
	out.Processes = orEmpty(facets.Processes)
	out.Collections = orEmpty(facets.Collections)
	if !facets.Earliest.IsZero() {
		out.Earliest = facets.Earliest.UTC().Format(time.RFC3339Nano)
	}
	if !facets.Latest.IsZero() {
		out.Latest = facets.Latest.UTC().Format(time.RFC3339Nano)
	}
	out.Timezone = tz
	out.TotalEvents = total
	return out, nil
}

func orEmpty(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// eventArtifactLabel names an artifact class for the timeline, reusing
// the capability registry's label (see explain.go's artifactTypeLabel)
// so the timeline, the evidence table and a severity explanation all
// call an artifact the same thing.
//
// The only thing added here is the empty case: an event with no artifact
// type at all should render as blank, not as the registry's
// "Unrecognized", which is a classification and would read as one.
func eventArtifactLabel(artifactType string) string {
	if artifactType == "" {
		return ""
	}
	return artifactTypeLabel(artifactType)
}

// eventTypeLabel renders an event-type constant as a readable phrase.
//
// This is a presentation of the SAME value, not a rename: the constant
// is what filters carry and what the API returns, and the label is only
// ever shown next to it. "usnjrnl_rename" reads as "Usnjrnl rename"
// rather than being mapped to some invented friendlier name, so an
// analyst can always tell which constant a label came from -- and no
// table has to be kept in step as parsers add event types.
func eventTypeLabel(eventType string) string {
	if eventType == "" {
		return ""
	}
	s := strings.ReplaceAll(eventType, "_", " ")
	s = strings.ToUpper(s[:1]) + s[1:]
	// Acronyms keep their casing. Sentence-casing alone turns
	// "sam_local_account" into "Sam local account", which reads as a
	// name rather than as the Windows SAM -- and an analyst hunting for
	// SAM evidence scans for the capitals. The list is small and is
	// applied word-by-word so it can never rewrite part of a word.
	words := strings.Split(s, " ")
	for i, w := range words {
		if up, ok := eventTypeAcronyms[strings.ToLower(w)]; ok {
			words[i] = up
		}
	}
	return strings.Join(words, " ")
}

// eventTypeAcronyms are the words whose conventional spelling is not
// sentence case. Presentation only -- the constant is unchanged.
var eventTypeAcronyms = map[string]string{
	"sam": "SAM", "ntlm": "NTLM", "dns": "DNS", "usnjrnl": "USN journal",
	"lnk": "LNK", "mft": "MFT", "url": "URL", "tgt": "TGT",
}

// displayLocation loads the configured display timezone, falling back to
// UTC. A zone that cannot be loaded must never make the timeline
// unusable -- the analyst gets UTC and correct results, rather than an
// error page.
func (s *Service) displayLocation() (*time.Location, error) {
	settings, err := s.DisplaySettings()
	if err != nil {
		return time.UTC, err
	}
	loc, lerr := time.LoadLocation(settings.Timezone)
	if lerr != nil {
		return time.UTC, nil
	}
	return loc, nil
}
