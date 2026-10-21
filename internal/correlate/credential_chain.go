package correlate

import (
	"sort"
	"time"

	"tracefall/internal/model"
)

// Windowing constants for credential-related chains. Deliberately not
// shared with internal/detect's bruteForceThenSuccess rule -- see
// correlate.go's package doc: correlation is independent of detection, so
// it doesn't import detect's internals, even for a constant. The values
// themselves are the same because they describe the same real-world
// pattern (a burst of failures followed by a success), not because the
// packages are coupled.
const (
	credBruteForceThreshold     = 3
	credBruteForceGapWindow     = 10 * time.Minute
	credBruteForceSuccessWindow = 30 * time.Minute
	credAbuseLookWindow         = 2 * time.Hour
)

// BuildCredentialChains links credential-related event sequences into
// evidence-backed narratives:
//
//   - brute force: a burst of failed logons (Security 4625) for the same
//     (host, user) followed by a successful logon (4624).
//   - credential abuse: explicit-credential use (4648) followed by a
//     process actually running as that target account, followed by
//     whatever that process did next -- stopping wherever the evidence
//     stops, exactly like BuildActivityChains.
func BuildCredentialChains(caseID string, events []model.Event) []model.Correlation {
	var out []model.Correlation
	out = append(out, buildBruteForceChains(caseID, events)...)
	out = append(out, buildSequenceBruteForceChains(caseID, events)...)
	out = append(out, buildCredentialAbuseChains(caseID, events)...)
	return out
}

func buildBruteForceChains(caseID string, events []model.Event) []model.Correlation {
	type key struct{ host, user string }
	failuresByKey := map[key][]model.Event{}
	successesByKey := map[key][]model.Event{}
	for _, e := range byType(events, model.EventLogonFailure) {
		k := key{e.Host, e.User}
		failuresByKey[k] = append(failuresByKey[k], e)
	}
	for _, e := range byType(events, model.EventLogonSuccess) {
		k := key{e.Host, e.User}
		successesByKey[k] = append(successesByKey[k], e)
	}

	keys := make([]key, 0, len(failuresByKey))
	for k := range failuresByKey {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].host != keys[j].host {
			return keys[i].host < keys[j].host
		}
		return keys[i].user < keys[j].user
	})

	var out []model.Correlation
	for _, k := range keys {
		failures := append([]model.Event{}, failuresByKey[k]...)
		sort.Slice(failures, func(i, j int) bool { return failures[i].Timestamp.Before(failures[j].Timestamp) })

		var burst []model.Event
		flush := func() {
			if len(burst) < credBruteForceThreshold {
				burst = nil
				return
			}
			last := burst[len(burst)-1]
			for _, s := range successesByKey[k] {
				if s.Timestamp.After(last.Timestamp) && withinWindow(last.Timestamp, s.Timestamp, credBruteForceSuccessWindow) {
					chain := append(append([]model.Event{}, burst...), s)
					out = append(out, buildTypedChainCorrelation(caseID, model.CorrelationCredentialChain, "Brute-force chain", chain))
					break
				}
			}
			burst = nil
		}
		for i, f := range failures {
			if i > 0 && !withinWindow(failures[i-1].Timestamp, f.Timestamp, credBruteForceGapWindow) {
				flush()
			}
			burst = append(burst, f)
		}
		flush()
	}
	return out
}

func buildCredentialAbuseChains(caseID string, events []model.Event) []model.Correlation {
	explicitCreds := byType(events, model.EventLogonExplicitCreds)
	creates := byType(events, model.EventProcessCreate)
	netConns := byType(events, model.EventNetworkConnection)
	registryRuns := byType(events, model.EventRegistryRunKey)
	scheduledTasks := byType(events, model.EventScheduledTaskCreate)

	// See activity_chain.go's identical indexing for why: without this,
	// every explicit-credential event rescans every process-create in the
	// case looking for the account it ran as.
	createsByHostUser := indexEvents(creates, func(e model.Event) string { return chainKey(e.Host, e.User) })
	createsByHostParent := indexEvents(creates, func(e model.Event) string { return chainKey(e.Host, e.ParentProcessName) })
	registryRunsByHostProc := indexEvents(registryRuns, func(e model.Event) string { return chainKey(e.Host, e.ProcessName) })
	scheduledTasksByHostProc := indexEvents(scheduledTasks, func(e model.Event) string { return chainKey(e.Host, e.ProcessName) })
	netConnsByHostProc := indexEvents(netConns, func(e model.Event) string { return chainKey(e.Host, e.ProcessName) })

	var out []model.Correlation
	for _, cred := range explicitCreds {
		targetUser := cred.Extra["target_user_name"]
		if targetUser == "" {
			continue
		}
		proc, ok := earliestAfter(createsByHostUser[chainKey(cred.Host, targetUser)], cred.Host, targetUser, cred.Timestamp, credAbuseLookWindow)
		if !ok {
			continue
		}
		chain := []model.Event{cred, proc}

		if child, ok := findChild(createsByHostParent[chainKey(proc.Host, proc.ProcessName)], proc); ok {
			chain = append(chain, child)
		}
		last := chain[len(chain)-1]
		lk := chainKey(last.Host, last.ProcessName)
		if p, ok := findPersistence(last.Host, last.ProcessName, last.Timestamp, activityLookWindow, registryRunsByHostProc[lk], scheduledTasksByHostProc[lk]); ok {
			chain = append(chain, p)
		} else if n, ok := findNetwork(netConnsByHostProc[lk], last.Host, last.ProcessName, last.Timestamp, activityLookWindow); ok {
			chain = append(chain, n)
		}

		if len(chain) < 3 {
			// Explicit creds with no corroborating follow-on activity
			// isn't a chain worth surfacing on its own -- detect's
			// explicitCredentialUse rule already reports the bare
			// observation.
			continue
		}
		out = append(out, buildTypedChainCorrelation(caseID, model.CorrelationCredentialChain, "Credential abuse chain", chain))
	}
	return out
}

// withinWindow reports whether a and b are within window of each other,
// regardless of order.
func withinWindow(a, b time.Time, window time.Duration) bool {
	d := b.Sub(a)
	if d < 0 {
		d = -d
	}
	return d <= window
}

// earliestAfter returns the earliest event in events for (host, user)
// with Timestamp >= at and within window of it -- the process that first
// ran as the target account after the explicit-credential logon.
func earliestAfter(events []model.Event, host, user string, at time.Time, window time.Duration) (model.Event, bool) {
	var best model.Event
	found := false
	for _, e := range events {
		if e.Host != host || e.User != user {
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
