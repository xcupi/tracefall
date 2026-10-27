package correlate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"tracefall/internal/hostid"
	"tracefall/internal/model"
)

const maxHostRelations = 500

// logonKinds names the Windows logon types a relation between machines is
// built from. Interactive, service and batch logons carry the machine's own
// address or none, so they say nothing about a second machine.
var logonKinds = map[string]string{
	"3": "network logon", "10": "Remote Desktop logon", "7": "unlock from a remote session", "9": "logon with explicit credentials",
}

type relationKey struct{ from, to, kind string }

type relation struct {
	events      []model.Event
	first, last time.Time
	basis       hostid.Basis
}

// BuildHostRelations finds the places where the evidence shows one machine of
// the case reaching another, and says how it knows which machine an address
// is.
//
// Two sources: a logon recorded on a machine whose source address belongs to a
// different machine of the case, and conversations in a packet capture between
// two addresses that each belong to a machine of the case. A relation exists
// only when BOTH ends resolve; an address nothing explains stays out. An
// address two machines claim equally is ambiguous and also stays out.
//
// The weakest basis any end rests on is reported, because a relation is only
// as sound as its weakest identification.
func BuildHostRelations(caseID string, events []model.Event, reg *hostid.Registry) []model.Correlation {
	rels := map[relationKey]*relation{}
	names := hostid.AcquisitionNames(events)
	add := func(k relationKey, e model.Event, basis hostid.Basis) {
		r := rels[k]
		if r == nil {
			r = &relation{basis: basis}
			rels[k] = r
		} else if basis.Rank() < r.basis.Rank() {
			r.basis = basis
		}
		r.events = append(r.events, e)
		if r.first.IsZero() || e.Timestamp.Before(r.first) {
			r.first = e.Timestamp
		}
		if e.Timestamp.After(r.last) {
			r.last = e.Timestamp
		}
	}
	for _, e := range events {
		switch {
		case e.EventType == model.EventLogonSuccess && e.Host != "" && e.NetworkSource != "" && e.ArtifactType != model.ArtifactNetworkCapture:
			kind, ok := logonKinds[e.Extra["logon_type"]]
			if !ok {
				continue
			}
			target := names[e.ID]
			if target == "" || reg.AmbiguousName(target) {
				continue
			}
			if h := reg.ByName(target); h != nil {
				target = h.Name
			}
			src := reg.ByIP(e.NetworkSource)
			if src.Identity == nil || strings.EqualFold(src.Identity.Name, target) {
				continue
			}
			// A name the client reported in this very logon is the only thing
			// tying the address to the machine; it is a claim, not a finding.
			add(relationKey{src.Identity.Name, target, kind}, e, src.Basis)
		case e.EventType == model.EventNetworkConnection && e.ArtifactType == model.ArtifactNetworkCapture &&
			e.Extra["session"] != "true" && e.Extra["application"] != "":
			src, dst := reg.ByIP(e.NetworkSource), reg.ByIP(e.NetworkDest)
			if src.Identity == nil || dst.Identity == nil || strings.EqualFold(src.Identity.Name, dst.Identity.Name) {
				continue
			}
			b := src.Basis
			if dst.Basis.Rank() < b.Rank() {
				b = dst.Basis
			}
			add(relationKey{src.Identity.Name, dst.Identity.Name, "captured " + strings.ToUpper(e.Extra["application"]) + " traffic"}, e, b)
		}
	}
	keys := make([]relationKey, 0, len(rels))
	for k := range rels {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.from != b.from {
			return a.from < b.from
		}
		if a.to != b.to {
			return a.to < b.to
		}
		return a.kind < b.kind
	})
	var out []model.Correlation
	for _, k := range keys {
		if len(out) >= maxHostRelations {
			break
		}
		r := rels[k]
		sort.SliceStable(r.events, func(i, j int) bool { return r.events[i].Timestamp.Before(r.events[j].Timestamp) })
		ids := make([]string, 0, 12)
		for i, e := range r.events {
			if i >= 12 {
				break
			}
			ids = append(ids, e.ID)
		}
		scale := "the clock of the machine that recorded it"
		if strings.HasPrefix(k.kind, "captured") {
			scale = "the capturing machine's clock"
		}
		weak := ""
		if r.basis.Rank() <= hostid.BasisClaimed.Rank() {
			weak = " The address was tied to its machine only by what a client said about itself or by a name lookup, so treat the direction as a lead."
		}
		out = append(out, model.Correlation{
			CaseID: caseID, Type: model.CorrelationHostRelation,
			Title: fmt.Sprintf("%s reached %s: %s (%d event(s))", k.from, k.to, k.kind, len(r.events)),
			Description: fmt.Sprintf(
				"%d event(s) show %s reaching %s by %s, between %s and %s on %s. The weakest identification of an address in this relation: %s.%s "+
					"A logon shows the account was accepted on the destination, from that address; traffic in a capture shows the machines exchanged packets, not what was done.",
				len(r.events), k.from, k.to, k.kind, r.first.UTC().Format("2006-01-02 15:04:05 UTC"), r.last.UTC().Format("2006-01-02 15:04:05 UTC"),
				scale, r.basis.Describe(), weak),
			EventIDs: ids, FirstSeen: r.first, LastSeen: r.last,
		})
	}
	return out
}
