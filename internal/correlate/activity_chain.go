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

// BuildActivityChains requires recorded parent/process identity for the
// Office-to-interpreter pivot. Session and network context require identity;
// full-path persistence references are explicitly labelled configuration
// associations, never attributed to the target PID as its writer.
func BuildActivityChains(caseID string, events []model.Event) []model.Correlation {
	events = chainHostKeys(events)
	creates := sortedChainEvents(byType(events, model.EventProcessCreate))
	parents := lineageParents(caseID, creates)
	children := map[string][]model.Event{}
	for _, child := range creates {
		if p, ok := parents[child.ID]; ok {
			children[p.ID] = append(children[p.ID], child)
		}
	}
	networks := byType(events, model.EventNetworkConnection)
	var out []model.Correlation
	for _, ps := range creates {
		if !procclass.IsOffice(ps.ParentProcessName) || !(procclass.IsPowerShell(ps.ProcessName) || procclass.IsScriptHost(ps.ProcessName)) {
			continue
		}
		office, ok := parents[ps.ID]
		if !ok {
			continue
		}
		chain := []model.Event{office, ps}
		target := ps
		if cs := children[ps.ID]; len(cs) == 1 {
			target = cs[0]
			chain = append(chain, target)
		}
		// A recorded session is useful context; a nearby same-user logon is not
		// evidence that this process belonged to that session.
		var logons []model.Event
		for _, l := range byType(events, model.EventLogonSuccess) {
			if sameEvidenceScope(office, l) && processTime(l) && l.Timestamp.Before(office.Timestamp) && office.Timestamp.Sub(l.Timestamp) <= activityLookWindow && l.User != "" && l.User == office.User && l.Extra["logon_id"] != "" && l.Extra["logon_id"] == office.Extra["logon_id"] {
				logons = append(logons, l)
			}
		}
		if len(logons) == 1 {
			chain = append(chain, logons[0])
		}
		configs := configurationFor(target, events)
		contextual := len(configs) > 0
		chain = append(chain, configs...)
		if n, ok := networkFor(target, networks, creates); ok {
			tied := false
			for _, e := range chain {
				if e.Timestamp.Equal(n.Timestamp) {
					tied = true
				}
			}
			if !tied {
				chain = append(chain, n)
			}
		}
		if len(chain) < 3 {
			continue
		}
		chain = sortedChainEvents(chain)
		c := buildChainCorrelation(caseID, chain)
		c.Description = "Recorded parent/process identity and strictly ordered timestamps link process, session and network observations within one host acquisition. This is not proof of intent or causation. Unrecorded exits leave process lifetime and unobserved PID reuse uncertain."
		if contextual {
			c.Title = "Contextual " + c.Title
			c.Description += " Persistence configuration references the same full executable path on the same established machine, possibly in a different acquisition; it does not establish that the target process wrote the configuration or that the configured mechanism executed. A configuration PID identifies its writer, not the configured target. Configuration timestamps are recorded artifact times; a task author-recorded registration date is not proven creation time."
		}
		out = append(out, c)
	}
	return out
}

func buildChainCorrelation(caseID string, chain []model.Event) model.Correlation {
	return buildTypedChainCorrelation(caseID, model.CorrelationActivityChain, "Activity chain", chain)
}

// buildTypedChainCorrelation is buildChainCorrelation generalized to any
// chain-shaped correlation type (activity/credential/service chains all
// share the same "ordered narrative of evidenced steps" shape) -- see
// credential_chain.go and service_chain.go, which reuse it rather than
// duplicating this construction.
func buildTypedChainCorrelation(caseID, corrType, titlePrefix string, chain []model.Event) model.Correlation {
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
	title := fmt.Sprintf("%s: %s", titlePrefix, joinArrow(steps))
	desc := fmt.Sprintf(
		"A %d-step evidenced sequence was reconstructed on host %s between %s and %s: %s.",
		len(chain), first.Host, first.Timestamp.Format(time.RFC3339), last.Timestamp.Format(time.RFC3339), joinArrow(steps))
	return model.Correlation{
		CaseID:      caseID,
		Type:        corrType,
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
	case model.EventLogonFailure:
		return "failed_logon(" + orDash(e.User) + ")"
	case model.EventLogonExplicitCreds:
		return "explicit_creds(" + orDash(e.Extra["target_user_name"]) + ")"
	case model.EventProcessCreate:
		return "exec(" + e.ProcessName + ")"
	case model.EventRegistryRunKey, model.EventRegistryPersistence:
		return "persist(registry)"
	case model.EventScheduledTaskCreate:
		return "persist(scheduled task)"
	case model.EventServiceInstall:
		return "persist(service)"
	case model.EventFileCreate:
		return "drop(" + orDash(e.FilePath) + ")"
	case model.EventDNSQuery:
		return "dns(" + orDash(e.NetworkDest) + ")"
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
