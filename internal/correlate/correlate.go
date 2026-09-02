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
//     PowerShell/script host -> payload -> persistence -> network)
//     stitched together from process_chain and entity (same
//     host/user/executable) links, stopping wherever the evidence stops
//     -- a missing step is simply absent, never fabricated.
//   - credential_chain (Phase 4): a burst of failed logons into a
//     success (brute force), or explicit-credential use into the
//     activity that followed it (credential abuse). See
//     credential_chain.go.
//   - service_chain (Phase 4): a service installation into the service's
//     process actually starting, into any network connection that
//     process made. See service_chain.go.
//   - web_resource (Phase 14): the same web host observed in two
//     independent browser artifacts -- a recorded visit in browser
//     history and a stored response in the browser cache. See
//     web_resource.go, which is explicit that the two make different
//     claims and that cache is not evidence of navigation.
//
// Correlation is independent of internal/detect: it runs over the same
// normalized events and does not require or depend on findings, so it
// stays useful even for investigators who want to explore relationships
// the fixed rule set didn't happen to flag.
package correlate

import (
	"sort"

	"tracefall/internal/model"
)

// Run builds every correlation type for a case's events and returns them
// with IDs assigned, ordered by first-seen time for stable output.
//
// Correlation IDs are content-derived (model.StableID), not random --
// see internal/detect.Run's identical rationale for Finding IDs: the
// same correlation, across two separate /analyze calls on unchanged
// evidence, must produce the SAME ID both times so any state keyed by it
// (e.g. an investigation's stable ID, which is itself derived from its
// member finding/correlation IDs) survives a no-op re-analysis.
func Run(caseID string, events []model.Event) []model.Correlation {
	var out []model.Correlation
	out = append(out, BuildProcessChains(caseID, events)...)
	out = append(out, BuildEntityCorrelations(caseID, events)...)
	out = append(out, BuildTemporalClusters(caseID, events)...)
	out = append(out, BuildActivityChains(caseID, events)...)
	out = append(out, BuildCredentialChains(caseID, events)...)
	out = append(out, BuildServiceChains(caseID, events)...)
	out = append(out, BuildWebResourceCorrelations(caseID, events)...)

	for i := range out {
		out[i].CaseID = caseID
		idParts := append([]string{caseID, out[i].Type}, out[i].EventIDs...)
		out[i].ID = model.StableID("corr", idParts...)
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

// chainKey builds a composite (host, secondary) map key -- the same
// (host, process name) index shape process_chain.go's BuildProcessChains
// already uses for its parent lookup, generalized so the other chain
// builders (activity/credential/service) can index by host alone, by
// (host, process), (host, parent process), or (host, user) as each
// lookup needs.
func chainKey(host, secondary string) string { return host + "\x00" + secondary }

// indexEvents groups events by keyFn(e) for O(1) candidate-set lookup.
// Every find*/latest*/earliest* helper in this package re-checks its own
// match conditions against whatever slice it's handed, so indexing here
// only narrows the candidate set before that scan -- it cannot change
// which event is picked, only how many events must be looked at to pick
// it. This is what keeps chain-building from degrading to an
// every-pivot-scans-every-event-of-that-type-in-the-case pattern, which
// on a large case (many hosts, many events per host) is the difference
// between a sub-second and a minutes-long /analyze call.
func indexEvents(events []model.Event, keyFn func(model.Event) string) map[string][]model.Event {
	idx := make(map[string][]model.Event, len(events))
	for _, e := range events {
		k := keyFn(e)
		idx[k] = append(idx[k], e)
	}
	return idx
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
