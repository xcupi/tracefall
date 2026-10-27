// Package correlate is Tracefall's deterministic correlation engine. It
// builds explicit relationships between normalized events -- it never
// invents an event or a link that isn't backed by the evidence actually
// present in the case. Three kinds of correlation are implemented:
//
//   - process_chain: a recorded parent PID/GUID with compatible lifetime
//     and acquisition identifies a parent instance. A unique name/time-only
//     relationship is explicitly hypothetical and never identifies a PID.
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
	"fmt"
	"sort"

	"tracefall/internal/hostid"
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
	out, _ := RunFrom(caseID, model.SliceSource(events))
	return out
}

// typedInputTypes are the event types the typed chain builders read. Each
// builder indexes only these (logons, process creates, persistence, service
// installs, network connections, explicit-credential logons), so loading this
// set gives them exactly the events they would see from a full load.
var typedInputTypes = []string{
	model.EventProcessCreate,
	model.EventLogonSuccess,
	model.EventLogonFailure,
	model.EventLogonExplicitCreds,
	model.EventRegistryRunKey,
	model.EventScheduledTaskCreate,
	model.EventRegistryPersistence,
	model.EventServiceInstall,
	model.EventNetworkConnection,
	// Read by the clock-offset model and the machine-identity table: clock
	// readings from a capture, and the registry events that name a machine
	// (its hostname, addresses and operating system).
	model.EventClockObservation,
	model.EventDNSQuery,
	model.EventRegistryKeyLastWrite,
	sqlXEEvent,
	sqlAuditEvent,
	sqlClientDiagnostic,
}

// RunFrom builds every correlation from src. The typed builders get only the
// events they read; the two that look at every event (temporal bursts and
// entity footprints) get a reference per event instead of the full event.
func RunFrom(caseID string, src model.EventSource) ([]model.Correlation, error) {
	typed, err := src.Load(model.EventFilter{Types: typedInputTypes, Artifacts: webArtifactNames()})
	if err != nil {
		return nil, fmt.Errorf("loading correlation inputs: %w", err)
	}
	refs, err := src.Refs()
	if err != nil {
		return nil, fmt.Errorf("loading event references: %w", err)
	}
	// Supply host-only projections for the untyped records too: a filtered
	// load must not hide an incompatible host spelling from identity checks.
	// These are projections of real referenced events, not new observations.
	seenNames := map[string]bool{}
	nameKey := func(coll, host string) string { return coll + "\x00" + host }
	for _, e := range typed {
		seenNames[nameKey(e.CollectionID, e.Host)] = true
	}
	for _, r := range refs {
		k := nameKey(r.CollectionID, r.Host)
		if r.Host != "" && !seenNames[k] {
			seenNames[k] = true
			typed = append(typed, model.Event{ID: r.ID, CaseID: caseID, CollectionID: r.CollectionID, Host: r.Host})
		}
	}
	// Reference-only consumers must use the same case-wide identity decision
	// as typed chains, not reintroduce a contradicted raw host attribution.
	names := hostid.AcquisitionNames(typed)
	byName := map[string]string{}
	for _, e := range typed {
		byName[nameKey(e.CollectionID, e.Host)] = names[e.ID]
	}
	validatedRefs := make([]model.EventRef, 0, len(refs))
	for _, r := range refs {
		if r.Host != "" {
			h := byName[nameKey(r.CollectionID, r.Host)]
			if h == "" {
				continue
			}
			r.Host = h
		}
		validatedRefs = append(validatedRefs, r)
	}
	var out []model.Correlation
	out = append(out, BuildProcessChains(caseID, typed)...)
	out = append(out, BuildEntityCorrelations(caseID, validatedRefs)...)
	out = append(out, BuildTemporalClusters(caseID, validatedRefs)...)
	out = append(out, BuildActivityChains(caseID, typed)...)
	out = append(out, BuildCredentialChains(caseID, typed)...)
	out = append(out, BuildServiceChains(caseID, typed)...)
	out = append(out, buildSQLWindows(caseID, typed)...)
	out = append(out, BuildWebResourceCorrelations(caseID, typed)...)
	reg := hostid.Build(typed)
	out = append(out, BuildClockSkew(caseID, typed, reg)...)
	out = append(out, BuildHostRelations(caseID, typed, reg)...)

	// Web objects seen in a capture, and the host events that later name the
	// same file. Both loads are narrow: only capture requests, and only host
	// events carrying one of the delivered names.
	capReqs, err := src.Load(model.EventFilter{Types: []string{model.EventWebRequest}, Within: []string{model.ArtifactNetworkCapture}})
	if err != nil {
		return nil, fmt.Errorf("loading capture requests: %w", err)
	}
	if names := webObjectNames(capReqs); len(names) > 0 {
		hostEvs, err := src.Load(model.EventFilter{
			Types: []string{model.EventFilesystemCreated, model.EventFilesystemModified, model.EventFilesystemChanged, model.EventFileCreate,
				model.EventUsnCreate, model.EventUsnRename, model.EventProcessCreate, model.EventPrefetchExecution,
				model.EventAmcacheApplication, model.EventBrowserDownload, model.EventMemoryFile, model.EventMemoryFileContent},
			Names: names,
		})
		if err != nil {
			return nil, fmt.Errorf("loading host events for delivered files: %w", err)
		}
		out = append(out, BuildWebToHost(caseID, capReqs, hostEvs, reg, ClockEstimates(typed, reg))...)
	}

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
	return out, nil
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
