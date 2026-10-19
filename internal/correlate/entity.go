package correlate

import (
	"fmt"
	"sort"

	"tracefall/internal/model"
)

// entityMinArtifactTypes is the minimum number of distinct artifact types
// an executable must appear in before it's surfaced as an entity
// correlation -- a name appearing in only one artifact (e.g. just a
// single process-create event) isn't a cross-artifact linkage, it's just
// an event, and is already visible on the timeline.
const entityMinArtifactTypes = 2

// BuildEntityCorrelations groups events that reference the same
// executable (by normalized process name) on the same host across two or
// more distinct artifact types -- e.g. a binary that shows up in a
// process-create event, a Prefetch execution record, and a registry Run
// key. This traces one entity's footprint across independent evidence
// sources, which is exactly the kind of cross-artifact corroboration that
// turns a single weak indicator into a well-supported one.
func BuildEntityCorrelations(caseID string, refs []model.EventRef) []model.Correlation {
	type key struct{ host, entity string }
	groups := map[key][]model.EventRef{}

	for _, e := range refs {
		entity := e.ProcessName
		if entity == "" {
			continue
		}
		k := key{e.Host, entity}
		groups[k] = append(groups[k], e)
	}

	// Deterministic iteration order.
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].host != keys[j].host {
			return keys[i].host < keys[j].host
		}
		return keys[i].entity < keys[j].entity
	})

	var out []model.Correlation
	for _, k := range keys {
		group := groups[k]
		artifacts := map[string]bool{}
		for _, e := range group {
			artifacts[e.ArtifactType] = true
		}
		if len(artifacts) < entityMinArtifactTypes {
			continue
		}
		sort.Slice(group, func(i, j int) bool { return group[i].Timestamp.Before(group[j].Timestamp) })

		ids := make([]string, len(group))
		for i, e := range group {
			ids[i] = e.ID
		}
		first, last := group[0], group[len(group)-1]
		out = append(out, model.Correlation{
			CaseID: caseID,
			Type:   model.CorrelationEntity,
			Title:  fmt.Sprintf("%s observed across %d artifact types", k.entity, len(artifacts)),
			Description: fmt.Sprintf(
				"%q was referenced by %d events spanning %d distinct artifact types on host %s, between %s and %s. "+
					"Corroboration across independent artifact sources raises confidence beyond any single event.",
				k.entity, len(group), len(artifacts), k.host, first.Timestamp.Format(rfc3339), last.Timestamp.Format(rfc3339)),
			EventIDs:  ids,
			FirstSeen: first.Timestamp,
			LastSeen:  last.Timestamp,
		})
	}
	return out
}

const rfc3339 = "2006-01-02T15:04:05Z07:00"
