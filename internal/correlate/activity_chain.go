package correlate

import (
	"fmt"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/procclass"
)

// activityLookWindow bounds how far apart consecutive steps of a chain
// (logon -> Office -> PowerShell -> payload -> persistence -> network)
// can be while still being considered one narrative. Chosen generously
// (a couple of hours) because a real investigation timeline can be
// slower-moving than a lab reproduction; it is deliberately not so wide
// that it starts linking unrelated sessions.
const activityLookWindow = 2 * time.Hour

// BuildActivityChains stitches together the attack-pattern narrative --
// logon -> Office document execution -> PowerShell -> payload -> persistence
// -> outbound network connection -- wherever the evidence in the case
// actually supports each step. A chain is only emitted for the steps that
// are evidenced; Tracefall never fabricates a missing link (e.g. Phase 1
// has no browser/download artifact parser, so chains never claim one).
func BuildActivityChains(caseID string, events []model.Event) []model.Correlation {
	creates := byType(events, model.EventProcessCreate)
	logons := byType(events, model.EventLogonSuccess)
	registryRuns := byType(events, model.EventRegistryRunKey)
	scheduledTasks := byType(events, model.EventScheduledTaskCreate)
	netConns := byType(events, model.EventNetworkConnection)

	var out []model.Correlation
	for _, ps := range creates {
		if !procclass.IsOffice(ps.ParentProcessName) || !procclass.IsPowerShell(ps.ProcessName) {
			continue
		}
		chain := []model.Event{}

		// Step 1: prior successful logon by the same user on the same host.
		if logon, ok := latestBefore(logons, ps.Host, ps.User, ps.Timestamp, activityLookWindow); ok {
			chain = append(chain, logon)
		}

		// Step 2: the Office process-create event itself (the parent).
		if officeEv, ok := findProcessCreate(creates, ps.Host, ps.ParentProcessName, ps.Timestamp, activityLookWindow); ok {
			chain = append(chain, officeEv)
		}

		// Step 3: the PowerShell process-create event (the pivot itself).
		chain = append(chain, ps)

		// Step 4: a payload process spawned by this PowerShell instance.
		payload, hasPayload := findChild(creates, ps)
		if hasPayload {
			chain = append(chain, payload)
		}

		// Step 5: persistence referencing either the payload or PowerShell.
		persistTarget := ps.ProcessName
		if hasPayload {
			persistTarget = payload.ProcessName
		}
		if p, ok := findPersistence(registryRuns, scheduledTasks, ps.Host, persistTarget, ps.Timestamp, activityLookWindow); ok {
			chain = append(chain, p)
		}

		// Step 6: outbound network connection from the payload (or PowerShell).
		if n, ok := findNetwork(netConns, ps.Host, persistTarget, ps.Timestamp, activityLookWindow); ok {
			chain = append(chain, n)
		}

		if len(chain) < 3 {
			// Just the Office->PowerShell pivot with no corroborating
			// steps isn't a "chain" -- the office-spawns-powershell
			// detection rule already covers that case on its own.
			continue
		}

		out = append(out, buildChainCorrelation(caseID, chain))
	}
	return out
}

func buildChainCorrelation(caseID string, chain []model.Event) model.Correlation {
	ids := make([]string, len(chain))
	steps := make([]string, len(chain))
	for i, e := range chain {
		ids[i] = e.ID
		steps[i] = stepLabel(e)
	}
	first, last := chain[0], chain[len(chain)-1]
	for _, e := range chain {
		if e.Timestamp.Before(first.Timestamp) {
			first = e
		}
		if e.Timestamp.After(last.Timestamp) {
			last = e
		}
	}
	title := fmt.Sprintf("Activity chain: %s", joinArrow(steps))
	desc := fmt.Sprintf(
		"A %d-step evidenced activity sequence was reconstructed on host %s between %s and %s: %s.",
		len(chain), first.Host, first.Timestamp.Format(time.RFC3339), last.Timestamp.Format(time.RFC3339), joinArrow(steps))
	return model.Correlation{
		CaseID:      caseID,
		Type:        model.CorrelationActivityChain,
		Title:       title,
		Description: desc,
		EventIDs:    ids,
		FirstSeen:   first.Timestamp,
		LastSeen:    last.Timestamp,
	}
}

func stepLabel(e model.Event) string {
	switch e.EventType {
	case model.EventLogonSuccess:
		return "logon(" + orDash(e.User) + ")"
	case model.EventProcessCreate:
		return "exec(" + e.ProcessName + ")"
	case model.EventRegistryRunKey:
		return "persist(registry)"
	case model.EventScheduledTaskCreate:
		return "persist(scheduled task)"
	case model.EventNetworkConnection:
		return "network(" + orDash(e.NetworkDest) + ")"
	default:
		return e.EventType
	}
}

func joinArrow(steps []string) string {
	out := ""
	for i, s := range steps {
		if i > 0 {
			out += " -> "
		}
		out += s
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// latestBefore returns the most recent event in events for (host, user)
// with Timestamp <= at and within window of it.
func latestBefore(events []model.Event, host, user string, at time.Time, window time.Duration) (model.Event, bool) {
	var best model.Event
	found := false
	for _, e := range events {
		if e.Host != host || (user != "" && e.User != user) {
			continue
		}
		if e.Timestamp.After(at) || at.Sub(e.Timestamp) > window {
			continue
		}
		if !found || e.Timestamp.After(best.Timestamp) {
			best, found = e, true
		}
	}
	return best, found
}

// findProcessCreate finds the process-create event for (host, processName)
// nearest before at, within window.
func findProcessCreate(events []model.Event, host, processName string, at time.Time, window time.Duration) (model.Event, bool) {
	var best model.Event
	found := false
	for _, e := range events {
		if e.Host != host || e.ProcessName != processName {
			continue
		}
		if e.Timestamp.After(at) || at.Sub(e.Timestamp) > window {
			continue
		}
		if !found || e.Timestamp.After(best.Timestamp) {
			best, found = e, true
		}
	}
	return best, found
}

// findChild finds a process-create event whose ParentProcessName matches
// parent's ProcessName, on the same host, at or after parent's timestamp.
func findChild(events []model.Event, parent model.Event) (model.Event, bool) {
	var best model.Event
	found := false
	for _, e := range events {
		if e.Host != parent.Host || e.ParentProcessName != parent.ProcessName {
			continue
		}
		if e.Timestamp.Before(parent.Timestamp) {
			continue
		}
		if !found || e.Timestamp.Before(best.Timestamp) {
			best, found = e, true
		}
	}
	return best, found
}

// findPersistence finds a registry-run-key or scheduled-task event on
// host whose target executable matches processName, at or after at and
// within window.
func findPersistence(registryRuns, scheduledTasks []model.Event, host, processName string, at time.Time, window time.Duration) (model.Event, bool) {
	all := append(append([]model.Event{}, registryRuns...), scheduledTasks...)
	var best model.Event
	found := false
	for _, e := range all {
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

// findNetwork finds a network-connection event on host from processName,
// at or after at and within window.
func findNetwork(events []model.Event, host, processName string, at time.Time, window time.Duration) (model.Event, bool) {
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
