package correlate

import (
	"reflect"
	"strings"
	"testing"
	"time"
	"tracefall/internal/model"
)

func TestTemporalClustersTiesUseID(t *testing.T) {
	base := time.Date(2026, 2, 3, 4, 0, 0, 0, time.UTC)
	events := []model.Event{{ID: "c", Host: "host01", ArtifactType: "a", Timestamp: base}, {ID: "b", Host: "host01", ArtifactType: "b", Timestamp: base}, {ID: "a", Host: "host01", ArtifactType: "a", Timestamp: base}}
	got := BuildTemporalClusters("case01", refsOf(events))
	if len(got) != 1 || !reflect.DeepEqual(got[0].EventIDs, []string{"a", "b", "c"}) {
		t.Fatalf("ties not sorted by ID: %+v", got)
	}
}

func TestTemporalClustersQuietPeriodDescription(t *testing.T) {
	base := time.Date(2026, 2, 3, 4, 0, 0, 0, time.UTC)
	events := []model.Event{}
	for i, minute := range []int{0, 10, 20, 31, 41, 51} {
		events = append(events, model.Event{ID: string(rune('a' + i)), Host: "host01", ArtifactType: string(rune('a' + i%2)), Timestamp: base.Add(time.Duration(minute) * time.Minute)})
	}
	got := BuildTemporalClusters("case01", refsOf(events))
	if len(got) != 2 {
		t.Fatalf("quiet-period grouping: %+v", got)
	}
	for _, c := range got {
		if strings.Contains(c.Description, "within a 10m0s window") || !strings.Contains(c.Description, "20m0s") || !strings.Contains(c.Description, "consecutive") {
			t.Fatalf("misleading burst duration: %s", c.Description)
		}
	}
}

func TestTemporalClustersExcludeUndated(t *testing.T) {
	base := time.Date(2026, 2, 3, 4, 0, 0, 0, time.UTC)
	for _, dated := range []int{0, 2, 3} {
		events := []model.Event{{ID: "u1", Host: "host01", ArtifactType: "a"}, {ID: "u2", Host: "host01", ArtifactType: "b"}, {ID: "u3", Host: "host01", ArtifactType: "a"}}
		for i := 0; i < dated; i++ {
			events = append(events, model.Event{ID: string(rune('a' + i)), Host: "host01", ArtifactType: string(rune('a' + i)), Timestamp: base})
		}
		before := append([]model.Event(nil), events...)
		got := BuildTemporalClusters("case01", refsOf(events))
		want := 0
		if dated == 3 {
			want = 1
		}
		if len(got) != want {
			t.Fatalf("%d dated: got %d clusters, want %d", dated, len(got), want)
		}
		if dated == 3 && !reflect.DeepEqual(got[0].EventIDs, []string{"a", "b", "c"}) {
			t.Fatalf("undated members or unstable ties: %v", got[0].EventIDs)
		}
		if !reflect.DeepEqual(events, before) {
			t.Fatal("timeline input changed")
		}
	}
}
