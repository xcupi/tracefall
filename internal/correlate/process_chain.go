package correlate

import (
	"fmt"
	"time"

	"tracefall/internal/model"
)

// parentLookupWindow bounds how far back a parent process-create event
// can be from its child's and still be considered the same process
// lineage -- without a bound, a stale process name reused hours later on
// a busy host could be matched incorrectly.
const parentLookupWindow = 2 * time.Hour

// BuildProcessChains links each process-create event to the process-create
// event of its recorded parent (Security 4688 carries the parent's image
// name directly, so this is a lookup, not a PID-tree walk). Each link
// becomes one process_chain correlation.
func BuildProcessChains(caseID string, events []model.Event) []model.Correlation {
	creates := byType(events, model.EventProcessCreate)

	// Index process-create events by (host, process name) for parent
	// lookup, kept time-sorted so we can find the nearest preceding
	// instance deterministically.
	byHostProcess := map[string][]model.Event{}
	key := func(host, proc string) string { return host + "\x00" + proc }
	for _, e := range creates {
		k := key(e.Host, e.ProcessName)
		byHostProcess[k] = append(byHostProcess[k], e)
	}

	var out []model.Correlation
	for _, child := range creates {
		if child.ParentProcessName == "" {
			continue
		}
		parent, ok := nearestPreceding(byHostProcess[key(child.Host, child.ParentProcessName)], child.Timestamp)
		if !ok {
			continue
		}
		title := fmt.Sprintf("%s -> %s", parent.ProcessName, child.ProcessName)
		desc := fmt.Sprintf("%s (PID %d) created %s (PID %d) on host %s.",
			parent.ProcessName, parent.PID, child.ProcessName, child.PID, child.Host)
		first, last := chainRange(parent, child)
		out = append(out, model.Correlation{
			CaseID:      caseID,
			Type:        model.CorrelationProcessChain,
			Title:       title,
			Description: desc,
			EventIDs:    []string{parent.ID, child.ID},
			FirstSeen:   first.Timestamp,
			LastSeen:    last.Timestamp,
		})
	}
	return out
}

// nearestPreceding returns the event in candidates with the latest
// timestamp that is still <= at and within parentLookupWindow of it.
func nearestPreceding(candidates []model.Event, at time.Time) (model.Event, bool) {
	var best model.Event
	found := false
	for _, c := range candidates {
		if c.Timestamp.After(at) {
			continue
		}
		if at.Sub(c.Timestamp) > parentLookupWindow {
			continue
		}
		if !found || c.Timestamp.After(best.Timestamp) {
			best = c
			found = true
		}
	}
	return best, found
}
