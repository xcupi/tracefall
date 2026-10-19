package investigate

import "tracefall/internal/model"

// group is one connected component of findings/correlations/events that
// belong to the same investigative story, before it's turned into a full
// model.Investigation.
type group struct {
	eventIDs       map[string]bool
	findingIDs     map[string]bool
	correlationIDs map[string]bool
}

// buildGroups clusters findings and correlations into connected
// components based on shared events: two findings land in the same
// group if they share a supporting event directly, or if a correlation's
// EventIDs bridge an event from each of them (e.g. an activity_chain
// correlation whose steps include both an execution finding's event and
// a persistence finding's event pulls those two findings into one
// group).
//
// This is deliberately the ONLY grouping signal. "Same host" and "same
// user" are NOT used to merge groups -- two unrelated findings on the
// same host that share no event and no correlation stay separate
// investigations. Every edge in the underlying graph is real evidence
// (an existing Finding.SupportingEvents list or an existing
// Correlation.EventIDs list, both already computed by internal/detect
// and internal/correlate), so grouping can never invent a relationship
// those engines didn't already establish.
//
// A connected component with events but zero findings (e.g. a temporal
// cluster or entity correlation with no finding attached to any of its
// events) is dropped -- it's correlation context, not something worth
// promoting to a risk-assessed investigation on its own.
//
// temporal correlations specifically are never used to merge groups
// (see mergeworthy) -- internal/correlate's own doc comment describes
// temporal as "the weakest, most general correlation type: it asserts
// these events happened close together, nothing about causation", which
// is exactly the "same host, same time window" signal this package's
// grouping is required NOT to use. Without this exclusion, a burst of
// entirely unrelated low-severity findings that merely occurred within
// the same 10-minute window on one host (ordinary, benign administrative
// activity is a real example of this) would get merged into one
// artificially inflated "multi-stage" investigation -- exactly the
// false-positive failure mode this package must avoid.
func buildGroups(findings []model.Finding, correlations []model.Correlation) []group {
	uf := newUnionFind()

	for _, f := range findings {
		uf.unionAll(f.SupportingEvents)
	}
	for _, c := range correlations {
		if !mergeworthy(c.Type) {
			continue
		}
		uf.unionAll(c.EventIDs)
	}

	byRoot := map[string]*group{}
	groupFor := func(eventID string) *group {
		root := uf.find(eventID)
		g, ok := byRoot[root]
		if !ok {
			g = &group{eventIDs: map[string]bool{}, findingIDs: map[string]bool{}, correlationIDs: map[string]bool{}}
			byRoot[root] = g
		}
		return g
	}

	for _, f := range findings {
		if len(f.SupportingEvents) == 0 {
			continue
		}
		g := groupFor(f.SupportingEvents[0])
		g.findingIDs[f.ID] = true
		for _, e := range f.SupportingEvents {
			g.eventIDs[e] = true
		}
	}
	for _, c := range correlations {
		if !mergeworthy(c.Type) || len(c.EventIDs) == 0 {
			continue
		}
		g := groupFor(c.EventIDs[0])
		g.correlationIDs[c.ID] = true
		for _, e := range c.EventIDs {
			g.eventIDs[e] = true
		}
	}

	var out []group
	// Walked in key order: map order would make the investigation order, and
	// so the report, differ from run to run.
	for _, root := range sortedKeys(byRoot) {
		g := byRoot[root]
		if len(g.findingIDs) == 0 {
			continue
		}
		out = append(out, *g)
	}
	return out
}

// mergeworthy reports whether a correlation type is strong enough
// evidence of genuine relatedness to merge two findings' groups
// together. process_chain (an actual recorded parent/child link),
// entity (the same executable independently corroborated across 2+
// artifact types), and the three narrative chain types are all backed
// by a specific, named heuristic beyond mere timing -- temporal is not
// (see buildGroups' doc comment).
func mergeworthy(correlationType string) bool {
	return correlationType != model.CorrelationTemporal
}

// unionFind is a minimal disjoint-set structure over event IDs, used
// only to compute connected components -- no path is meaningful outside
// buildGroups.
type unionFind struct {
	parent map[string]string
}

func newUnionFind() *unionFind { return &unionFind{parent: map[string]string{}} }

func (u *unionFind) add(x string) {
	if _, ok := u.parent[x]; !ok {
		u.parent[x] = x
	}
}

func (u *unionFind) find(x string) string {
	u.add(x)
	if u.parent[x] != x {
		u.parent[x] = u.find(u.parent[x])
	}
	return u.parent[x]
}

func (u *unionFind) union(a, b string) {
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		u.parent[ra] = rb
	}
}

// unionAll registers every id in ids and merges them into one component.
func (u *unionFind) unionAll(ids []string) {
	for _, id := range ids {
		u.add(id)
	}
	for i := 1; i < len(ids); i++ {
		u.union(ids[0], ids[i])
	}
}
