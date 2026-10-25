package correlate

import (
	"fmt"
	"sort"
	"time"

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
	// An event without a host belongs to no known machine, so it is scoped to
	// its acquisition: two acquisitions that both lack a host are not one
	// machine. Without a host and without an acquisition nothing scopes it,
	// and it is not correlated.
	type key struct{ host, unknownIn, entity string }
	groups := map[key][]model.EventRef{}

	for _, e := range refs {
		entity := e.ProcessName
		if entity == "" {
			continue
		}
		k := key{host: e.Host, entity: entity}
		if e.Host == "" {
			if e.CollectionID == "" {
				continue
			}
			k.unknownIn = e.CollectionID
		}
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
		if keys[i].unknownIn != keys[j].unknownIn {
			return keys[i].unknownIn < keys[j].unknownIn
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
		// Dated events first in time order; undated ones last, in id order.
		sort.Slice(group, func(i, j int) bool {
			di, dj := !group[i].Timestamp.IsZero(), !group[j].Timestamp.IsZero()
			switch {
			case di != dj:
				return di
			case di && !group[i].Timestamp.Equal(group[j].Timestamp):
				return group[i].Timestamp.Before(group[j].Timestamp)
			}
			return group[i].ID < group[j].ID
		})

		ids := make([]string, len(group))
		for i, e := range group {
			ids[i] = e.ID
		}
		var first, last time.Time
		undated := 0
		for _, e := range group {
			if e.Timestamp.IsZero() {
				undated++
				continue
			}
			if first.IsZero() {
				first = e.Timestamp
			}
			last = e.Timestamp
		}
		window := "time not recorded"
		if !first.IsZero() {
			window = "between " + first.Format(rfc3339) + " and " + last.Format(rfc3339)
			if undated > 0 {
				window += fmt.Sprintf(" (%d event(s) with no recorded time)", undated)
			}
		}
		where := "host " + k.host
		if k.host == "" {
			where = "a host not recorded (one acquisition)"
		}
		out = append(out, model.Correlation{
			CaseID: caseID,
			Type:   model.CorrelationEntity,
			Title:  fmt.Sprintf("%s observed across %d artifact types", k.entity, len(artifacts)),
			Description: fmt.Sprintf(
				"%q was referenced by %d events spanning %d distinct artifact types on %s, %s. "+
					"Corroboration across independent artifact sources raises confidence beyond any single event.",
				k.entity, len(group), len(artifacts), where, window),
			EventIDs:  ids,
			FirstSeen: first,
			LastSeen:  last,
		})
	}
	return out
}

const rfc3339 = "2006-01-02T15:04:05Z07:00"
