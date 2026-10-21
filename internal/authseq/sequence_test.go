package authseq

import (
	"testing"
	"time"
	"tracefall/internal/model"
)

func TestSuccessRetainsEligibleEarlierBurstAcrossQuietGap(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var es []model.Event
	for i, minute := range []int{0, 1, 2, 20, 21} {
		typ := model.EventLogonFailure
		if i == 4 {
			typ = model.EventLogonSuccess
		}
		es = append(es, model.Event{ID: string(rune('a' + i)), Host: "host01", User: "alice", Timestamp: base.Add(time.Duration(minute) * time.Minute), EventType: typ})
	}
	got := BeforeSuccess(es, 3, 10*time.Minute, 30*time.Minute)
	if len(got) != 1 || len(got[0]) != 4 || got[0][2].ID != "c" || got[0][3].ID != "e" {
		t.Fatalf("lost qualifying burst before success: %+v", got)
	}
}
