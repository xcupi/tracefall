package investigate

import (
	"tracefall/internal/hostid"
	"tracefall/internal/model"
)

// identities says which machine each referenced event belongs to, so that a
// correlation never joins events of machines the evidence does not show to be
// one. A case is not a machine, and neither is an unnamed acquisition shared
// with another.
//
//   - An event with a recorded host is that host. Within one acquisition the
//     short and the fully qualified form of a name are one machine when
//     hostid.Resolve says so; across acquisitions only identical names are.
//   - An event with no host is unknown, scoped to its acquisition: two such
//     events of one acquisition are the same unknown, those of different
//     acquisitions are not, and an event with neither host nor acquisition
//     (or one no longer in the case) is unknown on its own.
type identities struct {
	byID map[string]identity
}

type identity struct {
	key   string
	known bool
}

func newIdentities(members map[string]member, inventory ...[]model.Event) identities {
	// Resolve member comparison keys against the case-wide compact inventory,
	// including metadata from records that no finding or correlation references.
	var projections []model.Event
	representative := map[string]string{}
	nameKey := func(coll, host string) string { return coll + "\x00" + host }
	for id, m := range members {
		k := nameKey(m.coll, m.host)
		if _, ok := representative[k]; !ok {
			representative[k] = id
			projections = append(projections, model.Event{ID: id, CaseID: m.caseID, Host: m.host, CollectionID: m.coll})
		}
	}
	if len(inventory) > 0 {
		projections = append(projections, inventory[0]...)
	}
	names := hostid.AcquisitionNames(projections)
	idn := identities{byID: make(map[string]identity, len(members))}
	for id, m := range members {
		switch h := names[representative[nameKey(m.coll, m.host)]]; {
		case h == "" && m.coll != "":
			idn.byID[id] = identity{key: "unknown\x00" + m.coll}
		case h == "":
			idn.byID[id] = identity{key: "unknown-event\x00" + id}
		default:
			idn.byID[id] = identity{key: "host\x00" + h, known: true}
		}
	}
	return idn
}

func (i identities) of(id string) identity {
	if v, ok := i.byID[id]; ok {
		return v
	}
	return identity{key: "unknown-event\x00" + id}
}

// sameMachineOnly reports whether a correlation type describes one machine by
// construction. Credential, host-relation and web-to-host correlations relate
// machines to each other and may join two known hosts.
func sameMachineOnly(correlationType string) bool {
	switch correlationType {
	case model.CorrelationEntity, model.CorrelationProcessChain,
		model.CorrelationActivityChain, model.CorrelationServiceChain, model.CorrelationTemporal:
		return true
	}
	return false
}

// buckets splits a correlation's event ids into the sets it may join, in the
// order each set first appears. Every id lands in exactly one bucket.
func (i identities) buckets(correlationType string, ids []string) [][]string {
	var order []string
	by := map[string][]string{}
	for _, id := range ids {
		v := i.of(id)
		key := v.key
		if v.known && !sameMachineOnly(correlationType) {
			key = "known-hosts"
		}
		if _, ok := by[key]; !ok {
			order = append(order, key)
		}
		by[key] = append(by[key], id)
	}
	out := make([][]string, 0, len(order))
	for _, k := range order {
		out = append(out, by[k])
	}
	return out
}
