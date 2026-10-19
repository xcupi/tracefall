package api

import (
	"io"
	"sort"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/report"
)

// timelineAgg is everything the report says about a case's timeline, built in
// one pass over the events as they stream past. The report never needs the
// events themselves for this: only counts, the first and last dated instants,
// and per-period counts at both granularities (the granularity is chosen at
// the end, once the span is known).
type timelineAgg struct {
	total, dated int
	byArtifact   map[string]int
	first, last  time.Time
	haveDated    bool
	byDay        map[string]int
	byMonth      map[string]int
}

func newTimelineAgg() *timelineAgg {
	return &timelineAgg{byArtifact: map[string]int{}, byDay: map[string]int{}, byMonth: map[string]int{}}
}

func (a *timelineAgg) add(e model.Event) {
	a.total++
	a.byArtifact[artifactTypeLabel(e.ArtifactType)]++
	if !isDatedEvent(e) {
		return
	}
	a.dated++
	ts := e.Timestamp.UTC()
	if !a.haveDated || ts.Before(a.first) {
		a.first = ts
	}
	if !a.haveDated || ts.After(a.last) {
		a.last = ts
	}
	a.haveDated = true
	a.byDay[ts.Format("2006-01-02")]++
	a.byMonth[ts.Format("2006-01")]++
}

// streamTimeline writes the case's timeline CSV to w and returns the aggregate
// of the same events, in one streamed pass. The CSV is byte-identical to the
// one ExportTimelineCSV writes, because both use timelineCSVWriter.
func (s *Service) streamTimeline(caseID string, w io.Writer) (*timelineAgg, error) {
	tw, err := newTimelineCSVWriter(w)
	if err != nil {
		return nil, err
	}
	agg := newTimelineAgg()
	err = s.store.ForEachEvent(caseID, func(e model.Event) error {
		agg.add(e)
		return tw.add(e)
	})
	if err != nil {
		return nil, err
	}
	if err := tw.close(); err != nil {
		return nil, err
	}
	return agg, nil
}

// wantedEventIDs lists the events the report must resolve by id: those a
// finding cites (its evidence and the timeline's key events) and those a
// correlation links (the investigation narratives). Nothing else is loaded.
func wantedEventIDs(findings []model.Finding, correlations []model.Correlation) []string {
	seen := map[string]bool{}
	var ids []string
	add := func(list []string) {
		for _, id := range list {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	for _, f := range findings {
		add(f.SupportingEvents)
	}
	for _, c := range correlations {
		add(c.EventIDs)
	}
	sort.Strings(ids)
	return ids
}

// timelineFromAgg turns the streamed aggregate into the report's timeline
// section. key holds the events a finding cites; they are the only events the
// section names.
func timelineFromAgg(a *timelineAgg, key []model.Event, srcByID map[string]model.SourceFile) report.Timeline {
	tl := report.Timeline{Total: a.total, Dated: a.dated, Undated: a.total - a.dated}
	for name, n := range a.byArtifact {
		tl.ByArtifact = append(tl.ByArtifact, report.Count{Name: name, N: n})
	}
	sort.Slice(tl.ByArtifact, func(i, j int) bool {
		if tl.ByArtifact[i].N != tl.ByArtifact[j].N {
			return tl.ByArtifact[i].N > tl.ByArtifact[j].N
		}
		return tl.ByArtifact[i].Name < tl.ByArtifact[j].Name
	})

	if a.haveDated {
		tl.Earliest, tl.Latest = reportTime(a.first), reportTime(a.last)
		unit, periods := "day", a.byDay
		if a.last.Sub(a.first) > 62*24*time.Hour {
			unit, periods = "month", a.byMonth
		}
		tl.PeriodUnit = unit
		for p, n := range periods {
			tl.ByPeriod = append(tl.ByPeriod, report.Count{Name: p, N: n})
		}
		sort.Slice(tl.ByPeriod, func(i, j int) bool { return tl.ByPeriod[i].Name < tl.ByPeriod[j].Name })
	}

	sortEvents(key)
	if len(key) > maxKeyEvents {
		tl.KeyOmitted = len(key) - maxKeyEvents
		key = key[:maxKeyEvents]
	}
	for _, e := range key {
		tl.Key = append(tl.Key, eventRef(e, srcByID))
	}
	return tl
}
