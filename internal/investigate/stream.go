package investigate

import (
	"sort"
	"time"

	"tracefall/internal/model"
)

// EachEvent calls fn for every event of a case, in any order. RunStreamed does
// not depend on the order it receives events in.
type EachEvent func(fn func(model.Event) error) error

// narrativeTypes are the event types the narrative writes a clause for. Those
// events are kept whole; every other event of a group is kept as its type and
// time only, which is all the narrative needs of it (for the logon-failure
// burst rule, which depends on what sits between two failures).
var narrativeTypes = map[string]bool{
	model.EventLogonFailure:        true,
	model.EventLogonSuccess:        true,
	model.EventProcessCreate:       true,
	model.EventRegistryRunKey:      true,
	model.EventRegistryPersistence: true,
	model.EventScheduledTaskCreate: true,
	model.EventServiceInstall:      true,
	model.EventNetworkConnection:   true,
	model.EventDNSQuery:            true,
	model.EventLogonExplicitCreds:  true,
	model.EventPrivilegedLogon:     true,
}

// NeedsExtra reports whether an event of this type needs its Extra map to
// be narrated. Every other type is read without it.
func NeedsExtra(eventType string) bool { return narrativeTypes[eventType] }

// member is one event of a group, kept for ordering, bounds and the narrative.
type member struct {
	ts   time.Time
	id   string
	host string
	typ  string
	ev   *model.Event // set for narrative types only
}

// seqItem is one step of a group's chronological sequence, as the narrative
// reads it.
type seqItem struct {
	typ string
	ts  time.Time
	ev  *model.Event
}

// groupAcc accumulates one group's events as they stream past, so that no
// group needs its whole event set in memory. Its results are the same values
// the previous per-event code computed from a sorted slice.
type groupAcc struct {
	members                             []member
	hosts, users, colls, sfs, artifacts map[string]bool
	processNames                        []string
	seq                                 []seqItem
}

func newGroupAcc() *groupAcc {
	return &groupAcc{
		hosts: map[string]bool{}, users: map[string]bool{}, colls: map[string]bool{},
		sfs: map[string]bool{}, artifacts: map[string]bool{},
	}
}

func (a *groupAcc) add(e model.Event) {
	m := member{ts: e.Timestamp, id: e.ID, host: e.Host, typ: e.EventType}
	if narrativeTypes[e.EventType] {
		ev := e
		m.ev = &ev
	}
	a.members = append(a.members, m)
	a.hosts[e.Host] = true
	a.users[e.User] = true
	a.colls[e.CollectionID] = true
	a.sfs[e.SourceFileID] = true
	a.artifacts[e.ArtifactType] = true
}

// finish orders the members by timestamp, then id, and derives the sequence,
// the process names and the bounds. It must run once, after every event.
func (a *groupAcc) finish() {
	sort.SliceStable(a.members, func(i, j int) bool {
		if !a.members[i].ts.Equal(a.members[j].ts) {
			return a.members[i].ts.Before(a.members[j].ts)
		}
		return a.members[i].id < a.members[j].id
	})
	lastProcess := ""
	for _, m := range a.members {
		if m.typ == model.EventProcessCreate && m.ev.ProcessName != "" && m.ev.ProcessName != lastProcess {
			a.processNames = append(a.processNames, m.ev.ProcessName)
			lastProcess = m.ev.ProcessName
		}
	}
	if len(a.processNames) > 3 {
		a.processNames = a.processNames[:3]
	}
	a.seq = make([]seqItem, len(a.members))
	for i, m := range a.members {
		a.seq[i] = seqItem{typ: m.typ, ts: m.ts, ev: m.ev}
	}
}

// bounds returns the first and last timestamps, zero for an empty group.
func (a *groupAcc) bounds() (time.Time, time.Time) {
	if len(a.members) == 0 {
		return time.Time{}, time.Time{}
	}
	return a.members[0].ts, a.members[len(a.members)-1].ts
}

// primaryHost is the host of the group's first event, empty for no events.
func (a *groupAcc) primaryHost() string {
	if len(a.members) == 0 {
		return ""
	}
	return a.members[0].host
}

func setKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// RunStreamed groups a case's findings and correlations into Investigations,
// reading the case's events once through each. Only the events a group
// references are kept, and of those only the narrative's types are kept whole.
// The result is the same as Run gives for the same events.
func RunStreamed(caseID string, each EachEvent, findings []model.Finding, correlations []model.Correlation) ([]model.Investigation, error) {
	findingsByID := make(map[string]model.Finding, len(findings))
	for _, f := range findings {
		findingsByID[f.ID] = f
	}
	correlationsByID := make(map[string]model.Correlation, len(correlations))
	for _, c := range correlations {
		correlationsByID[c.ID] = c
	}

	groups := buildGroups(findings, correlations)
	memberOf := map[string][]int{}
	for gi, g := range groups {
		for id := range g.eventIDs {
			memberOf[id] = append(memberOf[id], gi)
		}
	}
	accs := make([]*groupAcc, len(groups))
	for i := range accs {
		accs[i] = newGroupAcc()
	}
	err := each(func(e model.Event) error {
		for _, gi := range memberOf[e.ID] {
			accs[gi].add(e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	out := make([]model.Investigation, 0, len(groups))
	for gi, g := range groups {
		accs[gi].finish()
		out = append(out, buildInvestigation(caseID, g, accs[gi], findingsByID, correlationsByID))
	}
	sortInvestigations(out)
	return out, nil
}

// sortInvestigations orders investigations by start time, then title.
func sortInvestigations(out []model.Investigation) {
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].StartTime.Equal(out[j].StartTime) {
			return out[i].StartTime.Before(out[j].StartTime)
		}
		return out[i].Title < out[j].Title
	})
}
