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

// NeedsExtra includes identity metadata as well as narrative fields. The
// metadata may accompany any event type, including unreferenced observations;
// it is decoded one event at a time, then retained only as compact projections.
func NeedsExtra(eventType string) bool { return true }

// member is one event of a group, kept for ordering, bounds and the narrative.
type member struct {
	ts                               time.Time
	id, host, typ, caseID            string
	user, coll, sourceFile, artifact string
	ev                               *model.Event // set for narrative types only
}

func newMember(e model.Event) member {
	m := member{ts: e.Timestamp, id: e.ID, host: e.Host, typ: e.EventType, caseID: e.CaseID,
		user: e.User, coll: e.CollectionID, sourceFile: e.SourceFileID, artifact: e.ArtifactType}
	if narrativeTypes[e.EventType] {
		ev := e
		m.ev = &ev
	}
	return m
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

func (a *groupAcc) add(m member) {
	a.members = append(a.members, m)
	a.hosts[m.host] = true
	a.users[m.user] = true
	a.colls[m.coll] = true
	a.sfs[m.sourceFile] = true
	a.artifacts[m.artifact] = true
}

// finish orders the members -- dated ones by timestamp, then id, followed by
// the undated ones by id -- and derives the sequence, the process names and
// the bounds. It must run once, after every event.
func (a *groupAcc) finish() {
	sort.SliceStable(a.members, func(i, j int) bool {
		di, dj := isDated(a.members[i].ts), isDated(a.members[j].ts)
		if di != dj {
			return di
		}
		if di && !a.members[i].ts.Equal(a.members[j].ts) {
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

// bounds returns the first and last recorded timestamps. Events with no
// recorded time are not part of a window; a group with none dated has the
// zero time for both.
func (a *groupAcc) bounds() (time.Time, time.Time) {
	var first, last time.Time
	for _, m := range a.members {
		if !isDated(m.ts) {
			continue
		}
		if first.IsZero() {
			first = m.ts
		}
		last = m.ts
	}
	return first, last
}

// primaryHost is the host of the group's first event that records one, empty
// when none does.
func (a *groupAcc) primaryHost() string {
	for _, m := range a.members {
		if m.host != "" {
			return m.host
		}
	}
	return ""
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

	// Events are read once, keeping only those a finding or correlation names.
	// Their host and acquisition decide which events a correlation may join.
	referenced := map[string]bool{}
	for _, f := range findings {
		for _, id := range f.SupportingEvents {
			referenced[id] = true
		}
	}
	for _, c := range correlations {
		for _, id := range c.EventIDs {
			referenced[id] = true
		}
	}
	members := make(map[string]member, len(referenced))
	// Keep one compact projection per distinct identity observation, not full
	// unreferenced events or a per-event case inventory.
	inventory := map[[7]string]model.Event{}
	err := each(func(e model.Event) error {
		if e.Host != "" {
			k := [7]string{e.CaseID, e.CollectionID, e.Host, e.Extra["domain"], e.Extra["host_role"], e.Extra["os_product_name"], e.Extra["os_current_build"]}
			if _, ok := inventory[k]; !ok {
				inventory[k] = model.Event{ID: model.StableID("identity", k[:]...), CaseID: e.CaseID, CollectionID: e.CollectionID, Host: e.Host, Extra: map[string]string{"domain": k[3], "host_role": k[4], "os_product_name": k[5], "os_current_build": k[6]}}
			}
		}
		if referenced[e.ID] {
			members[e.ID] = newMember(e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	projections := make([]model.Event, 0, len(inventory))
	for _, e := range inventory {
		projections = append(projections, e)
	}
	groups := buildGroups(findings, correlations, newIdentities(members, projections))
	accs := make([]*groupAcc, len(groups))
	for gi, g := range groups {
		accs[gi] = newGroupAcc()
		for _, id := range sortedKeys(g.eventIDs) {
			if m, ok := members[id]; ok {
				accs[gi].add(m)
			}
		}
	}

	out := make([]model.Investigation, 0, len(groups))
	for gi, g := range groups {
		accs[gi].finish()
		out = append(out, buildInvestigation(caseID, g, accs[gi], findingsByID, correlationsByID))
	}
	sortInvestigations(out)
	return out, nil
}

// sortInvestigations orders investigations by start time, then title; those
// with no recorded time come last, ordered by title and id.
func sortInvestigations(out []model.Investigation) {
	sort.SliceStable(out, func(i, j int) bool {
		di, dj := isDated(out[i].StartTime), isDated(out[j].StartTime)
		if di != dj {
			return di
		}
		if di && !out[i].StartTime.Equal(out[j].StartTime) {
			return out[i].StartTime.Before(out[j].StartTime)
		}
		if out[i].Title != out[j].Title {
			return out[i].Title < out[j].Title
		}
		return out[i].ID < out[j].ID
	})
}
