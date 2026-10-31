package correlate

import (
	"reflect"
	"strings"
	"testing"
	"tracefall/internal/model"
)

func wmiContextEvents() []model.Event {
	base := model.Event{CaseID: "case01", CollectionID: "collection01", Host: "host01", ArtifactType: model.ArtifactWMIRepository, EventType: model.EventWMISnapshot}
	f := base
	f.ID = "filter"
	f.Extra = map[string]string{"wmi_class": "__EventFilter", "wmi_repository_sha256": strings.Repeat("a", 64), "wmi_native_key": "filter-native"}
	c := base
	c.ID = "consumer"
	c.Extra = map[string]string{"wmi_class": "CommandLineEventConsumer", "wmi_repository_sha256": strings.Repeat("a", 64), "wmi_native_key": "consumer-native"}
	b := base
	b.ID = "binding"
	b.Extra = map[string]string{"wmi_class": "__FilterToConsumerBinding", "wmi_repository_sha256": strings.Repeat("a", 64), "wmi_native_key": "binding-native", "filter_reference_status": "resolved", "consumer_reference_status": "resolved", "filter_native_key": "filter-native", "consumer_native_key": "consumer-native"}
	return []model.Event{f, c, b}
}
func TestWMIContextConsumerGenericAndUndated(t *testing.T) {
	es := wmiContextEvents()
	for _, got := range [][]model.Correlation{BuildWMIContexts("case01", es), Run("case01", es)} {
		if len(got) != 1 || got[0].Type != model.CorrelationWMIConfigurationContext || !reflect.DeepEqual(got[0].EventIDs, []string{"binding", "consumer", "filter"}) || !got[0].FirstSeen.IsZero() || !got[0].LastSeen.IsZero() {
			t.Fatalf("configured relationship not consumed: %+v", got)
		}
		for _, word := range []string{"configuration", "not", "execution", "same", "time not recorded"} {
			if !strings.Contains(got[0].Description, word) {
				t.Fatalf("missing evidence limitation %q", word)
			}
		}
	}
	reversed := []model.Event{es[2], es[1], es[0]}
	if !reflect.DeepEqual(BuildWMIContexts("case01", es), BuildWMIContexts("case01", reversed)) {
		t.Fatal("input order changes context")
	}
}
func TestWMIContextRequiresAcquisitionAndExactClass(t *testing.T) {
	for _, mode := range []string{"case", "collection", "host", "repository", "class", "ambiguous", "unresolved"} {
		t.Run(mode, func(t *testing.T) {
			es := wmiContextEvents()
			switch mode {
			case "case":
				es[0].CaseID = "case02"
			case "collection":
				es[0].CollectionID = "collection02"
			case "host":
				es[0].Host = "host02"
			case "repository":
				es[0].Extra["wmi_repository_sha256"] = strings.Repeat("b", 64)
			case "class":
				es[0].Extra["wmi_class"] = "CommandLineEventConsumer"
			case "ambiguous":
				x := es[0]
				x.ID = "filter-duplicate"
				es = append(es, x)
			case "unresolved":
				es[2].Extra["filter_reference_status"] = "unresolved"
			}
			got := BuildWMIContexts("case01", es)
			if len(got) != 1 || !reflect.DeepEqual(got[0].EventIDs, []string{"binding", "consumer"}) {
				t.Fatalf("foreign/ambiguous target joined: %+v", got)
			}
		})
	}
}
