package hostid

import (
	"testing"
	"tracefall/internal/model"
)

func TestReviewAmbiguousOwnerRemainsIPBlocker(t *testing.T) {
	fact := func(id, host, ip string) model.Event {
		return model.Event{ID: id, CaseID: "case", CollectionID: id, Host: host, EventType: model.EventRegistryKeyLastWrite, Extra: map[string]string{"registry_value_name": "ComputerName", "ip_origin": ip + "=static"}}
	}
	events := []model.Event{fact("a", "host01", "10.0.0.5"), fact("b", "host02", "10.0.0.5"), fact("c", "host01.a.example", "10.0.0.6"), fact("d", "host01.b.example", "10.0.0.7")}
	for i := 0; i < 2; i++ {
		r := Build(events).ByIP("10.0.0.5")
		if !r.Ambiguous || r.Identity != nil {
			t.Fatalf("unresolved strongest owner disappeared: %+v", r)
		}
		events[0], events[3] = events[3], events[0]
	}
	events = []model.Event{fact("short", "host01", "10.0.0.5"), fact("full", "host01.corp.example", "10.0.0.5")}
	events[1].CollectionID = "short"
	if r := Build(events).ByIP("10.0.0.5"); r.Identity == nil || r.Ambiguous {
		t.Fatalf("compatible aliases must retain ownership: %+v", r)
	}
}
