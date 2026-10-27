package correlate

import (
	"sort"
	"strings"
	"time"
	"tracefall/internal/hostid"
	"tracefall/internal/model"
)

// lineageParents reuses the process-chain identity/lifetime checks, but never
// promotes its explicitly hypothetical name-only relationships into activity.
// The narrative window remains bounded even for a long-lived identified parent.
func lineageParents(caseID string, creates []model.Event) map[string]model.Event {
	byID := map[string]model.Event{}
	for _, e := range creates {
		byID[e.ID] = e
	}
	out := map[string]model.Event{}
	for _, c := range BuildProcessChains(caseID, creates) {
		if strings.HasPrefix(c.Title, "Hypothetical:") {
			continue
		}
		p, ch := byID[c.EventIDs[0]], byID[c.EventIDs[1]]
		if ch.Timestamp.Sub(p.Timestamp) > activityLookWindow {
			continue
		}
		out[ch.ID] = p
	}
	return out
}

func sortedChainEvents(events []model.Event) []model.Event {
	out := append([]model.Event(nil), events...)
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Timestamp.Equal(out[j].Timestamp) {
			return out[i].Timestamp.Before(out[j].Timestamp)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func sameEvidenceScope(a, b model.Event) bool {
	return a.CaseID != "" && a.CaseID == b.CaseID && a.CollectionID != "" && a.CollectionID == b.CollectionID && a.Host != "" && a.Host == b.Host
}

// processObservation requires an identified creation, strict recorded order,
// and compatibility with all observed starts/exits, not just matching names.
// Missing exit records remain an explicit uncertainty in the rendered chain.
func processObservation(proc, observation model.Event, creates []model.Event) bool {
	if !sameEvidenceScope(proc, observation) || !processTime(proc) || !processTime(observation) || !observation.Timestamp.After(proc.Timestamp) || observation.Timestamp.Sub(proc.Timestamp) > activityLookWindow {
		return false
	}
	if proc.ProcessName == "" || proc.ProcessName != observation.ProcessName {
		return false
	}
	if proc.ProcessPath != "" && observation.ProcessPath != "" && !sameExecutablePath(proc.ProcessPath, observation.ProcessPath) {
		return false
	}
	pg, og := proc.Extra["process_guid"], observation.Extra["process_guid"]
	if pg != "" && og != "" && pg != og {
		return false
	}
	if proc.PID > 0 && observation.PID > 0 && proc.PID != observation.PID {
		return false
	}
	if !(pg != "" && pg == og) && !(proc.PID > 0 && proc.PID == observation.PID) {
		return false
	}
	if og != "" && pg != og {
		return false
	}
	if exit := proc.Extra["exit_time"]; exit != "" {
		end, err := time.Parse(time.RFC3339Nano, exit)
		if err != nil || !observation.Timestamp.Before(end) {
			return false
		}
	}
	for _, other := range creates {
		if other.ID == proc.ID || !sameEvidenceScope(proc, other) {
			continue
		}
		if !(proc.PID > 0 && other.PID == proc.PID) && !(pg != "" && other.Extra["process_guid"] == pg) {
			continue
		}
		if !processTime(other) || (!other.Timestamp.Before(proc.Timestamp) && !other.Timestamp.After(observation.Timestamp)) {
			return false
		}
	}
	return true
}

func networkFor(proc model.Event, networks, creates []model.Event) (model.Event, bool) {
	for _, n := range sortedChainEvents(networks) {
		if processObservation(proc, n, creates) {
			return n, true
		}
	}
	return model.Event{}, false
}

func configurationFor(proc model.Event, events []model.Event) (model.Event, bool) {
	var candidates []model.Event
	for _, e := range events {
		switch e.EventType {
		case model.EventRegistryRunKey, model.EventRegistryPersistence, model.EventScheduledTaskCreate, model.EventServiceInstall:
		default:
			continue
		}
		if !sameEvidenceScope(proc, e) || !processTime(e) || !e.Timestamp.After(proc.Timestamp) || e.Timestamp.Sub(proc.Timestamp) > activityLookWindow || e.ProcessName != proc.ProcessName {
			continue
		}
		target := e.Extra["value_data"]
		if target == "" {
			target = e.ProcessPath
		}
		if target == "" {
			target = e.FilePath
		}
		if sameExecutablePath(target, proc.ProcessPath) {
			candidates = append(candidates, e)
		}
	}
	if len(candidates) == 1 {
		return candidates[0], true
	}
	return model.Event{}, false
}

func chainHostKeys(events []model.Event) []model.Event {
	names := hostid.AcquisitionNames(events)
	out := append([]model.Event(nil), events...)
	for i := range out {
		out[i].Host = names[out[i].ID]
	}
	return out
}
