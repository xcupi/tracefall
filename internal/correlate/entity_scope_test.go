package correlate

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

func entityRef(id, coll, host, artifact string) model.EventRef {
	return model.EventRef{ID: id, CollectionID: coll, Host: host, ProcessName: "agent.exe", ArtifactType: artifact, Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

func TestEntity_UnknownHostIsScopedToItsCollection(t *testing.T) {
	refs := []model.EventRef{
		entityRef("e1", "collection01", "", "srum_db"),
		entityRef("e2", "collection02", "", "scheduled_task"),
	}
	if got := BuildEntityCorrelations("case01", refs); len(got) != 0 {
		t.Fatalf("unknown-host events of two collections were correlated: %+v", got)
	}
}

func TestEntity_UnknownHostWithoutAcquisitionIsNotCorrelated(t *testing.T) {
	refs := []model.EventRef{entityRef("e1", "", "", "srum_db"), entityRef("e2", "", "", "scheduled_task")}
	if got := BuildEntityCorrelations("case01", refs); len(got) != 0 {
		t.Fatalf("events with neither host nor acquisition were correlated: %+v", got)
	}
}

func TestEntity_UnknownHostInOneCollectionStaysCorrelatedWithoutAHostClaim(t *testing.T) {
	refs := []model.EventRef{
		entityRef("e1", "collection01", "", "srum_db"),
		entityRef("e2", "collection01", "", "scheduled_task"),
		entityRef("e3", "collection02", "", "scheduled_task"),
	}
	got := BuildEntityCorrelations("case01", refs)
	if len(got) != 1 || len(got[0].EventIDs) != 2 {
		t.Fatalf("want one correlation of the two events of collection01, got %+v", got)
	}
	if strings.Contains(got[0].Description, "on host ") || !strings.Contains(got[0].Description, "host not recorded") {
		t.Fatalf("description claims a host: %q", got[0].Description)
	}
}

func TestEntity_KnownHostStillCorrelatesAcrossCollections(t *testing.T) {
	refs := []model.EventRef{
		entityRef("e1", "collection01", "host01", "srum_db"),
		entityRef("e2", "collection02", "host01", "scheduled_task"),
	}
	if got := BuildEntityCorrelations("case01", refs); len(got) != 1 {
		t.Fatalf("recorded same host across collections: %+v", got)
	}
}

func TestEntity_UndatedEventsAreNotGivenATimeWindow(t *testing.T) {
	undated := entityRef("e1", "collection01", "host01", "scheduled_task")
	undated.Timestamp = time.Time{}
	dated := entityRef("e2", "collection01", "host01", "srum_db")
	got := BuildEntityCorrelations("case01", []model.EventRef{undated, dated})
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if strings.Contains(got[0].Description, "0001-01-01") {
		t.Fatalf("undated event given year 1: %q", got[0].Description)
	}
	if !got[0].FirstSeen.Equal(dated.Timestamp) || !got[0].LastSeen.Equal(dated.Timestamp) {
		t.Fatalf("bounds must come from dated events only: %v %v", got[0].FirstSeen, got[0].LastSeen)
	}
	if !strings.Contains(got[0].Description, "1 event(s) with no recorded time") {
		t.Fatalf("undated count missing: %q", got[0].Description)
	}
	all := BuildEntityCorrelations("case01", []model.EventRef{undated, {ID: "e3", CollectionID: "collection01", Host: "host01", ProcessName: "agent.exe", ArtifactType: "srum_db"}})
	if len(all) != 1 || !all[0].FirstSeen.IsZero() || !strings.Contains(all[0].Description, "time not recorded") {
		t.Fatalf("all-undated: %+v", all)
	}
}
