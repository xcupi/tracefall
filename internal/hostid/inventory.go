package hostid

import (
	"sort"
	"tracefall/internal/model"
)

// Inventory retains one compact projection per distinct recorded identity tuple.
// It does not retain whole unreferenced events; cardinality is not hard-capped.
// Values remain literal. Normalization belongs to the identity decision.
type Inventory map[[7]string]model.Event

func (i Inventory) Add(e model.Event) {
	if e.Host == "" {
		return
	}
	k := [7]string{e.CaseID, e.CollectionID, e.Host, e.Extra["domain"], e.Extra["host_role"], e.Extra["os_product_name"], e.Extra["os_current_build"]}
	if _, ok := i[k]; !ok {
		i[k] = model.Event{ID: model.StableID("identity", k[:]...), CaseID: e.CaseID, CollectionID: e.CollectionID, Host: e.Host, Extra: map[string]string{"domain": k[3], "host_role": k[4], "os_product_name": k[5], "os_current_build": k[6]}}
	}
}

func (i Inventory) Events() []model.Event {
	out := make([]model.Event, 0, len(i))
	for _, e := range i {
		out = append(out, e)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out
}
