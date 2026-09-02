package correlate

import (
	"fmt"
	"sort"

	"tracefall/internal/model"
)

// webArtifactTypes are the independent browser artifacts a web host can
// be observed in. Each makes a DIFFERENT claim about that host, which is
// the entire point of correlating them:
//
//   - browser history: a navigation was recorded.
//   - browser cache:   a response was received and stored.
//
// A host present in both is corroborated by two independent sources. A
// host present only in the cache is not evidence of navigation, and this
// correlation is careful never to imply otherwise.
var webArtifactTypes = map[string]string{
	model.ArtifactBrowserHistory: "browser history (a recorded navigation)",
	model.ArtifactBrowserCache:   "browser cache (a stored response)",
}

// BuildWebResourceCorrelations groups events that reference the same web
// host across two or more distinct browser artifact types.
//
// # What this correlation asserts
//
// Only that the same host appears in more than one browser artifact. It
// is deliberately NOT a finding, carries no severity, and applies no
// reputation or keyword judgement to the host -- a cached advertising
// domain and a cached payload host produce exactly the same correlation.
// Deciding what a host means is the analyst's job; this only makes sure
// the two independent observations of it are visible side by side.
//
// # Why the threshold is two ARTIFACT TYPES, not two events
//
// A host seen ten times in one cache is still a single source saying one
// thing, and each of those events is already on the timeline. Requiring
// two distinct artifact types is what makes this cross-artifact
// corroboration rather than a restatement of the timeline -- the same
// rule BuildEntityCorrelations uses for executables.
func BuildWebResourceCorrelations(caseID string, events []model.Event) []model.Correlation {
	groups := map[string][]model.Event{}
	for _, e := range events {
		if _, ok := webArtifactTypes[e.ArtifactType]; !ok {
			continue
		}
		// NetworkDest carries the host for both artifacts. An event
		// without one cannot be grouped, and is left alone rather than
		// guessed at from a URL fragment.
		if e.NetworkDest == "" {
			continue
		}
		groups[e.NetworkDest] = append(groups[e.NetworkDest], e)
	}

	hosts := make([]string, 0, len(groups))
	for h := range groups {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	var out []model.Correlation
	for _, host := range hosts {
		group := groups[host]
		kinds := map[string]bool{}
		for _, e := range group {
			kinds[e.ArtifactType] = true
		}
		if len(kinds) < 2 {
			continue
		}
		sort.SliceStable(group, func(i, j int) bool { return group[i].Timestamp.Before(group[j].Timestamp) })

		ids := make([]string, len(group))
		for i, e := range group {
			ids[i] = e.ID
		}
		// Named in a fixed order so the description is deterministic.
		var sources []string
		for _, t := range []string{model.ArtifactBrowserHistory, model.ArtifactBrowserCache} {
			if kinds[t] {
				sources = append(sources, webArtifactTypes[t])
			}
		}
		first, last := group[0], group[len(group)-1]
		out = append(out, model.Correlation{
			CaseID: caseID,
			Type:   model.CorrelationWebResource,
			Title:  fmt.Sprintf("%s observed in %d browser artifacts", host, len(kinds)),
			Description: fmt.Sprintf(
				"%q was referenced by %d events across %d independent browser artifacts -- %s -- between %s and %s. "+
					"History records that a navigation happened; cache records only that a response was received and stored, "+
					"which can occur without the user visiting, viewing, clicking, downloading or running anything. "+
					"This correlation reports that both sources mention the host; it makes no judgement about the host itself.",
				host, len(group), len(kinds), joinWithAnd(sources),
				first.Timestamp.Format(rfc3339), last.Timestamp.Format(rfc3339)),
			EventIDs:  ids,
			FirstSeen: first.Timestamp,
			LastSeen:  last.Timestamp,
		})
	}
	return out
}

func joinWithAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	default:
		return fmt.Sprintf("%s and %s", parts[0], parts[len(parts)-1])
	}
}
