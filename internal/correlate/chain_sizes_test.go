package correlate_test

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"tracefall/internal/correlate"
	"tracefall/internal/model"
)

// Correlation event references at every size (issue 3).
//
// The UI drill-down resolves c.EventIDs against the timeline. That is
// only sound if EventIDs is complete, ordered deterministically, and
// carries no duplicates -- at 1 event, at 60, and at every size between.

func burstEvents(host string, n int) []model.Event {
	base := time.Date(2026, 5, 4, 8, 0, 0, 0, time.UTC)
	out := make([]model.Event, 0, n)
	for i := 0; i < n; i++ {
		// Two artifact types, so the burst clears temporalMinArtifacts.
		at := model.ArtifactPrefetch
		if i%2 == 1 {
			at = model.ArtifactWindowsEventLog
		}
		out = append(out, model.Event{
			ID:           fmt.Sprintf("evt-%s-%04d", host, i),
			CaseID:       "case-1",
			Host:         host,
			Timestamp:    base.Add(time.Duration(i) * time.Second),
			ArtifactType: at,
			EventType:    "process_create",
			ProcessName:  fmt.Sprintf("P%03d.EXE", i),
		})
	}
	return out
}

// A correlation must reference exactly the events in its cluster, with
// no duplicates and no omissions, at every size.
func TestCorrelationEventIDs_AtEverySize(t *testing.T) {
	// temporalMinEvents is 3: a burst of fewer events is deliberately not
	// surfaced, because two events do not evidence an episode of
	// activity. 0/1/2 therefore assert that NO correlation is produced,
	// which is itself part of the contract the drill-down relies on.
	const minBurst = 3
	for _, n := range []int{0, 1, 2, 3, 5, 60, 250} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			events := burstEvents("DESKTOP-0J3S8C2", n)
			corrs := correlate.BuildTemporalClusters("case-1", refsOfEvents(events))

			if n < minBurst {
				// Too small to be a burst worth surfacing; emitting one
				// would assert an episode from one or two events.
				if len(corrs) != 0 {
					t.Errorf("a %d-event input produced %d correlation(s); want none", n, len(corrs))
				}
				return
			}
			if len(corrs) == 0 {
				t.Fatalf("no correlation for a %d-event burst", n)
			}
			c := corrs[0]

			// Complete.
			if len(c.EventIDs) != n {
				t.Errorf("EventIDs has %d entries, want %d", len(c.EventIDs), n)
			}
			// The title must report the same number it references.
			if want := fmt.Sprintf("(%d events)", len(c.EventIDs)); !contains(c.Title, want) {
				t.Errorf("title %q does not report %q", c.Title, want)
			}
			// No duplicates -- a duplicated reference would double-count
			// an event in the drill-down.
			seen := map[string]bool{}
			for _, id := range c.EventIDs {
				if seen[id] {
					t.Errorf("duplicate event reference %q", id)
				}
				seen[id] = true
			}
			// Every reference must resolve to a real event.
			byID := map[string]model.Event{}
			for _, e := range events {
				byID[e.ID] = e
			}
			for _, id := range c.EventIDs {
				if _, ok := byID[id]; !ok {
					t.Errorf("event reference %q resolves to nothing", id)
				}
			}
			// Chronological and deterministic.
			var times []time.Time
			for _, id := range c.EventIDs {
				times = append(times, byID[id].Timestamp)
			}
			if !sort.SliceIsSorted(times, func(i, j int) bool { return times[i].Before(times[j]) }) {
				t.Error("event references are not in chronological order")
			}
			// FirstSeen/LastSeen must bound the referenced events.
			if !c.FirstSeen.Equal(times[0]) {
				t.Errorf("FirstSeen = %s, want %s", c.FirstSeen, times[0])
			}
			if !c.LastSeen.Equal(times[len(times)-1]) {
				t.Errorf("LastSeen = %s, want %s", c.LastSeen, times[len(times)-1])
			}
		})
	}
}

// The same input must produce the same references in the same order on
// every run -- the drill-down's ordering guarantee depends on it.
func TestCorrelationEventIDs_AreDeterministic(t *testing.T) {
	events := burstEvents("DESKTOP-0J3S8C2", 60)
	first := correlate.BuildTemporalClusters("case-1", refsOfEvents(events))
	for i := 0; i < 25; i++ {
		again := correlate.BuildTemporalClusters("case-1", refsOfEvents(events))
		if len(again) != len(first) {
			t.Fatalf("run %d produced %d correlations, want %d", i, len(again), len(first))
		}
		for j := range first {
			if again[j].ID != first[j].ID {
				t.Fatalf("run %d: correlation %d id changed", i, j)
			}
			if len(again[j].EventIDs) != len(first[j].EventIDs) {
				t.Fatalf("run %d: correlation %d event count changed", i, j)
			}
			for k := range first[j].EventIDs {
				if again[j].EventIDs[k] != first[j].EventIDs[k] {
					t.Fatalf("run %d: correlation %d event %d order changed", i, j, k)
				}
			}
		}
	}
}

// A 60-event burst is the case that prompted the drill-down. It must
// produce exactly one correlation carrying all 60 references.
func TestCorrelationEventIDs_SixtyEventBurst(t *testing.T) {
	events := burstEvents("DESKTOP-0J3S8C2", 60)
	corrs := correlate.BuildTemporalClusters("case-1", refsOfEvents(events))
	if len(corrs) != 1 {
		t.Fatalf("got %d correlations, want 1", len(corrs))
	}
	c := corrs[0]
	if len(c.EventIDs) != 60 {
		t.Fatalf("EventIDs has %d entries, want 60", len(c.EventIDs))
	}
	if !contains(c.Title, "Activity burst on DESKTOP-0J3S8C2 (60 events)") {
		t.Errorf("title = %q", c.Title)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// refsOfEvents projects test events to the references the temporal correlator reads.
func refsOfEvents(events []model.Event) []model.EventRef {
	out := make([]model.EventRef, len(events))
	for i, e := range events {
		out[i] = model.RefOf(e)
	}
	return out
}
