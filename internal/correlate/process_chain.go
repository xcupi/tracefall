package correlate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"tracefall/internal/model"
)

// Only name-only hypotheses have a proximity limit. An identified parent
// can legitimately have been running for days before creating its child.
const parentLookupWindow = 2 * time.Hour

func processScope(e model.Event) string {
	return strings.Join([]string{e.CaseID, e.Host, e.CollectionID}, "\x00")
}
func processTime(e model.Event) bool {
	return !e.Timestamp.IsZero() && e.Extra["timestamp_basis"] != "memory_snapshot"
}

// BuildProcessChains uses recorded identity and observed lifetimes. Missing
// identity permits at most an explicitly hypothetical name relationship, never
// attribution to a particular PID. Contradictory identity is not a fallback.
func BuildProcessChains(caseID string, events []model.Event) []model.Correlation {
	creates := byType(events, model.EventProcessCreate)
	sort.Slice(creates, func(i, j int) bool {
		if !creates[i].Timestamp.Equal(creates[j].Timestamp) {
			return creates[i].Timestamp.Before(creates[j].Timestamp)
		}
		return creates[i].ID < creates[j].ID
	})
	byPID := map[string][]model.Event{}
	byGUID := map[string][]model.Event{}
	byName := map[string][]model.Event{}
	for _, e := range creates {
		scope := processScope(e)
		if e.PID > 0 {
			k := fmt.Sprintf("%s\x00%d", scope, e.PID)
			byPID[k] = append(byPID[k], e)
		}
		if g := e.Extra["process_guid"]; g != "" {
			k := scope + "\x00" + g
			byGUID[k] = append(byGUID[k], e)
		}
		k := scope + "\x00" + e.ProcessName
		byName[k] = append(byName[k], e)
	}
	var out []model.Correlation
	for _, child := range creates {
		if child.Host == "" || !processTime(child) || (child.PID > 0 && child.PID == child.PPID) || (child.CaseID != "" && child.CaseID != caseID) {
			continue
		}
		scope := processScope(child)
		pg := child.Extra["parent_process_guid"]
		identified := pg != "" || child.PPID > 0
		var candidates []model.Event
		switch {
		case child.PPID > 0:
			candidates = byPID[fmt.Sprintf("%s\x00%d", scope, child.PPID)]
		case pg != "":
			candidates = byGUID[scope+"\x00"+pg]
		default:
			if child.ParentProcessName == "" || child.ArtifactType == model.ArtifactMemoryAnalysis {
				continue
			}
			candidates = byName[scope+"\x00"+child.ParentProcessName]
		}
		var parent model.Event
		count := 0
		ambiguous := false
		for _, p := range candidates {
			if p.ID == child.ID {
				continue
			}
			if !processTime(p) {
				if identified {
					ambiguous = true
				}
				continue
			}
			if !p.Timestamp.Before(child.Timestamp) {
				if identified && p.Timestamp.Equal(child.Timestamp) {
					ambiguous = true
				}
				continue
			}
			if !identified && (child.Timestamp.Sub(p.Timestamp) > parentLookupWindow || p.ArtifactType == model.ArtifactMemoryAnalysis) {
				continue
			}
			if identified {
				if count == 0 || p.Timestamp.After(parent.Timestamp) {
					parent = p
					count = 1
				} else if p.Timestamp.Equal(parent.Timestamp) {
					count++
				}
			} else {
				parent = p
				count++
			}
		}
		if ambiguous || count != 1 {
			continue
		}
		if pg != "" && parent.Extra["process_guid"] != pg {
			continue
		}
		if child.PPID > 0 && parent.PID != child.PPID {
			continue
		}
		if child.ParentProcessName != "" && parent.ProcessName != child.ParentProcessName {
			continue
		}
		if exit := parent.Extra["exit_time"]; exit != "" {
			end, err := time.Parse(time.RFC3339Nano, exit)
			if err != nil || !child.Timestamp.Before(end) {
				continue
			}
		}
		strong := identified && child.CaseID != "" && child.CollectionID != ""
		if !strong && (child.ArtifactType == model.ArtifactMemoryAnalysis || parent.ArtifactType == model.ArtifactMemoryAnalysis) {
			continue
		}
		title := fmt.Sprintf("%s -> %s", parent.ProcessName, child.ProcessName)
		label := func(e model.Event) string {
			s := e.ProcessName
			if e.PID > 0 {
				s += fmt.Sprintf(" (PID %d)", e.PID)
			}
			if g := e.Extra["process_guid"]; g != "" {
				s += " (GUID " + g + ")"
			}
			return s
		}
		desc := fmt.Sprintf("Recorded parent identity links %s to %s on host %s; the parent creation precedes the child and is compatible with available lifetime records. This is a recorded lineage, not proof of intent.", label(parent), label(child), child.Host)
		if !strong {
			title = "Hypothetical: " + title
			desc = fmt.Sprintf("Hypothetical parent-name relationship: %s and %s on host %s have compatible names and ordered timestamps. Missing process or acquisition identity prevents attribution to a particular parent instance; causation is not established.", parent.ProcessName, child.ProcessName, child.Host)
		}
		out = append(out, model.Correlation{CaseID: caseID, Type: model.CorrelationProcessChain, Title: title, Description: desc, EventIDs: []string{parent.ID, child.ID}, FirstSeen: parent.Timestamp, LastSeen: child.Timestamp})
	}
	return out
}
