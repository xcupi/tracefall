package correlate

import (
	"fmt"
	"sort"
	"time"

	"tracefall/internal/model"
)

// temporalGap is the quiet period that ends one activity burst and starts
// the next. temporalMinEvents/temporalMinArtifacts are the minimum size
// for a burst to be worth surfacing as a correlation -- a single event or
// a run of identical routine events isn't a meaningful cluster.
const (
	temporalGap          = 10 * time.Minute
	temporalMinEvents    = 3
	temporalMinArtifacts = 2
)

// BuildTemporalClusters groups each host's events into bursts of activity
// separated by gaps of at least temporalGap, and emits one correlation
// per burst that spans multiple artifact types -- a simple, explainable
// heuristic for "these events likely belong to the same episode of
// activity" without asserting any causal relationship between them.
func BuildTemporalClusters(caseID string, refs []model.EventRef) []model.Correlation {
	byHost := map[string][]model.EventRef{}
	for _, e := range refs {
		byHost[e.Host] = append(byHost[e.Host], e)
	}

	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	var out []model.Correlation
	for _, host := range hosts {
		hostEvents := byHost[host]
		sort.Slice(hostEvents, func(i, j int) bool { return hostEvents[i].Timestamp.Before(hostEvents[j].Timestamp) })

		var cluster []model.EventRef
		flush := func() {
			if len(cluster) < temporalMinEvents {
				cluster = nil
				return
			}
			artifacts := map[string]bool{}
			for _, e := range cluster {
				artifacts[e.ArtifactType] = true
			}
			if len(artifacts) < temporalMinArtifacts {
				cluster = nil
				return
			}
			first, last := cluster[0], cluster[len(cluster)-1]
			ids := make([]string, len(cluster))
			for i, e := range cluster {
				ids[i] = e.ID
			}
			out = append(out, model.Correlation{
				CaseID: caseID,
				Type:   model.CorrelationTemporal,
				Title:  fmt.Sprintf("Activity burst on %s (%d events)", host, len(cluster)),
				Description: fmt.Sprintf(
					"%d events across %d artifact type(s) occurred on host %s within a %s window, between %s and %s.",
					len(cluster), len(artifacts), host, temporalGap, first.Timestamp.Format(time.RFC3339), last.Timestamp.Format(time.RFC3339)),
				EventIDs:  ids,
				FirstSeen: first.Timestamp,
				LastSeen:  last.Timestamp,
			})
			cluster = nil
		}

		for i, e := range hostEvents {
			if i > 0 && e.Timestamp.Sub(hostEvents[i-1].Timestamp) > temporalGap {
				flush()
			}
			cluster = append(cluster, e)
		}
		flush()
	}
	return out
}
