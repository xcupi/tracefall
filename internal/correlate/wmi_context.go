package correlate

import (
	"fmt"
	"sort"
	"strings"
	"tracefall/internal/model"
)

// BuildWMIContexts consumes the parser's structural, exact-reference results.
// It rechecks persisted acquisition/repository/native target identities. This
// same-producer association never links configuration to process execution.
func BuildWMIContexts(caseID string, events []model.Event) []model.Correlation {
	type key struct{ caseID, collection, host, repository, native string }
	index := map[key][]model.Event{}
	ids := map[string]int{}
	scope := func(e model.Event, native string) key {
		return key{e.CaseID, e.CollectionID, strings.ToUpper(e.Host), e.Extra["wmi_repository_sha256"], native}
	}
	valid := func(e model.Event) bool {
		return e.CaseID == caseID && e.CollectionID != "" && e.ID != "" && e.ArtifactType == model.ArtifactWMIRepository && e.EventType == model.EventWMISnapshot && e.Extra["wmi_repository_sha256"] != "" && e.Extra["wmi_native_key"] != ""
	}
	for _, e := range events {
		ids[e.ID]++
		if valid(e) {
			k := scope(e, e.Extra["wmi_native_key"])
			index[k] = append(index[k], e)
		}
	}
	out := []model.Correlation{}
	for _, binding := range events {
		if !valid(binding) || ids[binding.ID] != 1 || binding.Extra["wmi_class"] != "__FilterToConsumerBinding" {
			continue
		}
		members := map[string]bool{binding.ID: true}
		resolved := 0
		for _, role := range []string{"filter", "consumer"} {
			if binding.Extra[role+"_reference_status"] != "resolved" {
				continue
			}
			candidates := index[scope(binding, binding.Extra[role+"_native_key"])]
			if len(candidates) != 1 {
				continue
			}
			target := candidates[0]
			if ids[target.ID] != 1 {
				continue
			}
			class := target.Extra["wmi_class"]
			if role == "filter" && class != "__EventFilter" {
				continue
			}
			if role == "consumer" {
				switch class {
				case "CommandLineEventConsumer", "ActiveScriptEventConsumer", "NTEventLogEventConsumer", "LogFileEventConsumer", "SMTPEventConsumer":
				default:
					continue
				}
			}
			members[target.ID] = true
			resolved++
		}
		c := model.Correlation{CaseID: caseID, Type: model.CorrelationWMIConfigurationContext, Title: "WMI configuration context", Description: fmt.Sprintf("WMI binding configuration snapshot: %d of 2 exact reference endpoints present in the same case, collection, host and repository. Unresolved or ambiguous endpoints remain visible on the binding observation. This is same-producer configuration context, not firing, OS execution, actor attribution, maliciousness, authorization or independent corroboration; time not recorded.", resolved)}
		for id := range members {
			c.EventIDs = append(c.EventIDs, id)
		}
		sort.Strings(c.EventIDs)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.Join(out[i].EventIDs, "\x00") < strings.Join(out[j].EventIDs, "\x00")
	})
	return out
}
