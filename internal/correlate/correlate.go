// Package correlate is Tracefall's deterministic correlation engine. It
// builds explicit relationships between normalized events -- it never
// invents an event or a link that isn't backed by the evidence actually
// present in the case. Three kinds of correlation are implemented:
//
//   - process_chain:   a child process's recorded parent-process name
//     matches an actual parent process-create event on the same host.
//   - temporal:        events on the same host clustered into bursts of
//     activity separated by quiet gaps.
//   - activity_chain:  a narrative sequence (e.g. logon -> Office ->
//     PowerShell -> payload -> persistence -> network) stitched together
//     from process_chain and entity (same host/user/executable) links,
//     stopping wherever the evidence stops -- a missing step is simply
//     absent, never fabricated.
//
// Correlation is independent of internal/detect: it runs over the same
// normalized events and does not require or depend on findings, so it
// stays useful even for investigators who want to explore relationships
// the fixed rule set didn't happen to flag.
package correlate

import (
	"sort"

	"github.com/google/uuid"

	"tracefall/internal/model"
)

// Run builds every correlation type for a case's events and returns them
// with IDs assigned, ordered by first-seen time for stable output.
func Run(caseID string, events []model.Event) []model.Correlation {
	var out []model.Correlation
	out = append(out, BuildProcessChains(caseID, events)...)
	out = append(out, BuildEntityCorrelations(caseID, events)...)
	out = append(out, BuildTemporalClusters(caseID, events)...)
	out = append(out, BuildActivityChains(caseID, events)...)

	for i := range out {
		out[i].ID = uuid.NewString()
		out[i].CaseID = caseID
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
			return out[i].FirstSeen.Before(out[j].FirstSeen)
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func byType(events []model.Event, t string) []model.Event {
	var res []model.Event
	for _, e := range events {
		if e.EventType == t {
			res = append(res, e)
		}
	}
	return res
}

func chainRange(events ...model.Event) (first, last model.Event) {
	for i, e := range events {
		if i == 0 || e.Timestamp.Before(first.Timestamp) {
			first = e
		}
		if i == 0 || e.Timestamp.After(last.Timestamp) {
			last = e
		}
	}
	return
}
