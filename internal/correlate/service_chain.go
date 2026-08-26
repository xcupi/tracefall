package correlate

import (
	"time"

	"tracefall/internal/model"
)

// serviceChainWindow bounds how far apart a service installation, the
// service's process actually starting, and any network connection that
// process made can be while still being considered one narrative -- see
// activityLookWindow's identical rationale in activity_chain.go.
const serviceChainWindow = activityLookWindow

// BuildServiceChains links a service installation (Phase 4's
// EventServiceInstall, from System Event ID 7045) to the service's
// process actually starting -- a process-create for the same executable
// on the same host shortly after installation -- and onward to any
// network connection that process made. A chain is only emitted for the
// steps the evidence actually supports; a service install with no
// corresponding process-create (e.g. a service that was installed but
// never started) is left to the service-persistence finding alone
// (internal/detect's servicePersistence rule), not fabricated into a
// longer chain.
func BuildServiceChains(caseID string, events []model.Event) []model.Correlation {
	installs := byType(events, model.EventServiceInstall)
	creates := byType(events, model.EventProcessCreate)
	netConns := byType(events, model.EventNetworkConnection)

	// See activity_chain.go's identical indexing for why.
	createsByHostProc := indexEvents(creates, func(e model.Event) string { return chainKey(e.Host, e.ProcessName) })
	netConnsByHostProc := indexEvents(netConns, func(e model.Event) string { return chainKey(e.Host, e.ProcessName) })

	var out []model.Correlation
	for _, install := range installs {
		target := install.ProcessName
		if target == "" {
			continue
		}
		proc, ok := findProcessAfter(createsByHostProc[chainKey(install.Host, target)], install.Host, target, install.Timestamp, serviceChainWindow)
		if !ok {
			continue
		}
		chain := []model.Event{install, proc}
		if n, ok := findNetwork(netConnsByHostProc[chainKey(proc.Host, proc.ProcessName)], proc.Host, proc.ProcessName, proc.Timestamp, serviceChainWindow); ok {
			chain = append(chain, n)
		}
		out = append(out, buildTypedChainCorrelation(caseID, model.CorrelationServiceChain, "Service chain", chain))
	}
	return out
}

// findProcessAfter finds the process-create event for (host, processName)
// nearest at-or-after at, within window -- the service actually starting
// following its installation.
func findProcessAfter(events []model.Event, host, processName string, at time.Time, window time.Duration) (model.Event, bool) {
	var best model.Event
	found := false
	for _, e := range events {
		if e.Host != host || e.ProcessName != processName {
			continue
		}
		if e.Timestamp.Before(at) || e.Timestamp.Sub(at) > window {
			continue
		}
		if !found || e.Timestamp.Before(best.Timestamp) {
			best, found = e, true
		}
	}
	return best, found
}
