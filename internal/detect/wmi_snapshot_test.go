package detect

import (
	"testing"
	"tracefall/internal/model"
)

func TestWMISnapshotConfigurationAloneHasNoMaliciousVerdict(t *testing.T) {
	events := []model.Event{}
	for _, class := range []string{"__EventFilter", "CommandLineEventConsumer", "__FilterToConsumerBinding"} {
		events = append(events, model.Event{ID: class, CaseID: "case01", CollectionID: "collection01", Host: "host01", ArtifactType: model.ArtifactWMIRepository, EventType: model.EventWMISnapshot, Extra: map[string]string{"wmi_class": class, "wmi_semantics": "configuration only"}})
	}
	if findings := Run("case01", events); len(findings) != 0 {
		t.Fatal("configuration snapshot became firing/execution, actor or malicious verdict")
	}
}
