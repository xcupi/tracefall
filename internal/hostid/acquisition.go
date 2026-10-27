package hostid

import (
	"strings"
	"tracefall/internal/model"
)

// AcquisitionNames supplies transient comparison keys, never changes evidence.
// Alias proof requires co-occurrence in one nonempty acquisition. Once proven,
// the same case-wide identity uses one key across reacquisitions. Unknown names
// are not inherited, and conflicting FQDNs or recorded metadata remain blockers.
func AcquisitionNames(events []model.Event) map[string]string {
	groups := map[string][]string{}
	labels := map[string]map[string]bool{}
	domains := map[string]map[string]bool{}
	for _, e := range events {
		h := key(e.Host)
		if h == "" {
			continue
		}
		if e.CollectionID != "" {
			s := e.CaseID + "\x00" + e.CollectionID
			groups[s] = append(groups[s], h)
		}
		if isDNSName(h) && strings.Contains(h, ".") {
			k := e.CaseID + "\x00" + strings.SplitN(h, ".", 2)[0]
			if labels[k] == nil {
				labels[k] = map[string]bool{}
			}
			labels[k][h] = true
		}
		if d := key(e.Extra["domain"]); d != "" {
			k := e.CaseID + "\x00" + h
			if domains[k] == nil {
				domains[k] = map[string]bool{}
			}
			domains[k][d] = true
		}
	}
	canonical := map[string]string{}
	for scope, names := range groups {
		if h, ok := Resolve(names); ok {
			valid := true
			for _, n := range names {
				if n != key(h) && !aliasDomainCompatible(n, key(h), domains[strings.SplitN(scope, "\x00", 2)[0]+"\x00"+n]) {
					valid = false
				}
			}
			if valid {
				canonical[scope] = key(h)
			}
		}
	}
	// Only an acquisition that actually contains both spellings proves an
	// alias. A unique case-wide FQDN alone must not invent that relationship.
	aliases := map[string]string{}
	for scope, names := range groups {
		full := canonical[scope]
		if !isDNSName(full) || !strings.Contains(full, ".") {
			continue
		}
		caseID := strings.SplitN(scope, "\x00", 2)[0]
		short := strings.SplitN(full, ".", 2)[0]
		if len(labels[caseID+"\x00"+short]) != 1 {
			continue
		}
		for _, n := range names {
			if n == short {
				aliases[caseID+"\x00"+short] = full
			}
		}
	}
	out := map[string]string{}
	for _, e := range events {
		h := key(e.Host)
		if h == "" {
			out[e.ID] = ""
			continue
		}
		if len(domains[e.CaseID+"\x00"+h]) > 1 || (!strings.Contains(h, ".") && len(labels[e.CaseID+"\x00"+h]) > 1) {
			out[e.ID] = ""
			continue
		}
		if !strings.Contains(h, ".") {
			for full := range labels[e.CaseID+"\x00"+h] {
				if !aliasDomainCompatible(h, full, domains[e.CaseID+"\x00"+h]) {
					h = ""
					break
				}
			}
		}
		if h == "" {
			out[e.ID] = ""
			continue
		}
		if e.CollectionID != "" {
			if c := canonical[e.CaseID+"\x00"+e.CollectionID]; c != "" {
				h = c
			}
		}
		if c := aliases[e.CaseID+"\x00"+h]; c != "" {
			h = c
		}
		out[e.ID] = h
	}
	conflicts := metadataConflicts(events, func(e model.Event) string {
		if out[e.ID] == "" {
			return ""
		}
		return e.CaseID + "\x00" + out[e.ID]
	})
	for _, e := range events {
		if conflicts[e.CaseID+"\x00"+out[e.ID]] {
			out[e.ID] = ""
		}
	}
	return out
}

// aliasDomainCompatible applies the same recorded-domain contradiction rule
// to both registry aliases and acquisition comparison keys. Missing domain
// does not prove an alias; other acquisition evidence must still establish it.
func aliasDomainCompatible(short, full string, domains map[string]bool) bool {
	return len(domains) == 0 || (len(domains) == 1 && domains[strings.TrimPrefix(full, short+".")])
}

// Conflicting recorded machine metadata cannot be repaired by alias preference
// or by the order in which evidence arrived. Missing metadata is not conflict.
func metadataConflicts(events []model.Event, identity func(model.Event) string) map[string]bool {
	facts := map[string]map[string]string{}
	conflicts := map[string]bool{}
	for _, e := range events {
		k := identity(e)
		if k == "" {
			continue
		}
		if facts[k] == nil {
			facts[k] = map[string]string{}
		}
		for _, field := range []string{"domain", "host_role", "os_product_name", "os_current_build"} {
			v := key(e.Extra[field])
			if v == "" {
				continue
			}
			if old := facts[k][field]; old != "" && old != v {
				conflicts[k] = true
			}
			facts[k][field] = v
		}
	}
	return conflicts
}
