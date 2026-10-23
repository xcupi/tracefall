package api

import (
	"fmt"
	"sort"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/report"
)

// maxExternalListed bounds Appendix D; the cut is disclosed in the report.
const maxExternalListed = 200

// maxExternalEventRefs is how many source events are named per hash.
const maxExternalEventRefs = 3

// reportExternal assembles Appendix D from what is stored. It sends nothing:
// a report never causes a request to an outside service.
func (s *Service) reportExternal(caseID string) (report.External, error) {
	lvl, err := s.EgressLevel(caseID)
	if err != nil {
		return report.External{}, err
	}
	ext := report.External{EgressLevel: string(lvl), EgressDescription: lvl.Describe()}
	rows, err := s.VirusTotalResults(caseID)
	if err != nil {
		return report.External{}, err
	}
	ext.VirusTotal = buildVTSection(rows)
	return ext, nil
}

func buildVTSection(rows []VTResult) report.ExternalProvider {
	p := report.ExternalProvider{}
	type item struct {
		row   report.ExternalRow
		score int // engines that flagged it; -1 not known, -2 no answer
	}
	var items []item
	for _, r := range rows {
		it := item{row: report.ExternalRow{
			Indicator: r.Indicator, IndicatorType: r.IndicatorType, CheckedAt: r.FetchedAt, Events: eventRefs(r.EventIDs),
		}}
		switch {
		case r.Status == model.EnrichmentError:
			p.Errors++
			it.score = -2
			it.row.Verdict = "no answer (" + oneLine(r.Error) + ")"
		case r.Result == nil:
			// a stored answer that cannot be read is an error, not "not known"
			p.Errors++
			it.score = -2
			it.row.Verdict = "no answer (stored answer unreadable)"
		case !r.Result.Found:
			p.Answered++
			p.Unknown++
			it.score = -1
			it.row.Verdict = "not known to VirusTotal"
			it.row.Link = r.Result.Link
		default:
			p.Answered++
			p.Known++
			res := r.Result
			flagged := res.Malicious + res.Suspicious
			it.score = flagged
			it.row.Verdict = fmt.Sprintf("%d of %d engines flagged it (%d malicious, %d suspicious)", flagged, res.Engines(), res.Malicious, res.Suspicious)
			it.row.Label, it.row.FileType, it.row.ReportedName = oneLine(res.ThreatLabel), oneLine(res.TypeDescription), oneLine(res.MeaningfulName)
			it.row.LastAnalysis, it.row.Link = res.LastAnalysis, res.Link
		}
		items = append(items, it)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].score != items[j].score {
			return items[i].score > items[j].score
		}
		return items[i].row.Indicator < items[j].row.Indicator
	})
	for i, it := range items {
		if i >= maxExternalListed {
			p.Omitted = len(items) - maxExternalListed
			break
		}
		p.Rows = append(p.Rows, it.row)
	}
	return p
}

func eventRefs(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	shown := ids
	if len(shown) > maxExternalEventRefs {
		shown = shown[:maxExternalEventRefs]
	}
	out := strings.Join(shown, ", ")
	if len(ids) > len(shown) {
		out += fmt.Sprintf(" (+%d more)", len(ids)-len(shown))
	}
	return out
}

// oneLine shortens text that came from an outside service: it is shown in a
// table cell, so it is bounded and flattened to one line.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 120 {
		s = string(r[:120]) + "..."
	}
	return s
}
