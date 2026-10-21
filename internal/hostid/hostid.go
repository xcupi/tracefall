// Package hostid answers "which machine is this address?" from the evidence
// itself, and says how it knows.
//
// Evidence from several machines arrives as events that name an address, a
// name, or neither. To say that a logon on one machine came from another
// machine in the case, an address has to be tied to a machine. This package
// builds that table from facts the evidence states and keeps the strength of
// each, because they are not equally reliable:
//
//	static      the machine's own configuration lists the address (SYSTEM hive)
//	memory      a socket in the machine's memory image has it as its local address
//	dhcp lease  the last lease the machine recorded: it held that address at
//	            some time, not necessarily on the day that matters
//	claimed     a logon record says the client was named X when it connected
//	            from this address; the client chose that name
//	dns         a name server answered with this address for a name
//
// An address whose strongest facts name two different machines is reported as
// ambiguous and resolved to neither: a wrong machine silently corrupts every
// relation drawn from it.
//
// The package never invents a machine. An address nothing explains stays
// unresolved.
package hostid

import (
	"net/netip"
	"sort"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/normalize"
)

// Basis is how an address came to be tied to a machine.
type Basis string

const (
	BasisStatic  Basis = "static"
	BasisMemory  Basis = "memory"
	BasisDHCP    Basis = "dhcp lease"
	BasisClaimed Basis = "claimed"
	BasisDNS     Basis = "dns"
)

// Rank orders bases by how much they can be trusted: higher is stronger.
func (b Basis) Rank() int { return b.rank() }

func (b Basis) rank() int {
	switch b {
	case BasisStatic, BasisMemory:
		return 4
	case BasisDHCP:
		return 3
	case BasisClaimed:
		return 2
	case BasisDNS:
		return 1
	}
	return 0
}

// Describe is a sentence fragment saying what the basis means.
func (b Basis) Describe() string {
	switch b {
	case BasisStatic:
		return "the machine's own network configuration lists this address"
	case BasisMemory:
		return "a socket in the machine's memory image uses this address locally"
	case BasisDHCP:
		return "the machine's configuration records this address as its last DHCP lease"
	case BasisClaimed:
		return "a logon record names the client this way; the client chose the name"
	case BasisDNS:
		return "a name server answered with this address for the name"
	}
	return string(b)
}

// Identity is one machine as the evidence describes it.
type Identity struct {
	Name     string // normalised machine name
	Domain   string
	Role     string // domain_controller, server, workstation
	OS       string
	OSBuild  string
	IPs      map[string]Basis
	Evidence []string // event ids, capped
	// Collected is true when the case holds this machine's own artifacts (its
	// hives or memory), as opposed to a name only another machine mentioned.
	Collected bool
}

const evidenceCap = 8

func (i *Identity) cite(id string) {
	if id != "" && len(i.Evidence) < evidenceCap {
		i.Evidence = append(i.Evidence, id)
	}
}

type claim struct {
	id    *Identity
	basis Basis
}

// Registry is the address-to-machine table.
type Registry struct {
	hosts map[string]*Identity
	byIP  map[string][]claim
}

func key(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if i := strings.IndexByte(n, '.'); i > 0 {
		n = n[:i] // a fully qualified name and its short name are one machine
	}
	return n
}

func (r *Registry) get(name string, collected bool) *Identity {
	k := key(name)
	if k == "" {
		return nil
	}
	h := r.hosts[k]
	if h == nil {
		h = &Identity{Name: normalize.Host(name), IPs: map[string]Basis{}}
		r.hosts[k] = h
	}
	if collected {
		h.Collected = true
	}
	return h
}

func (r *Registry) learn(h *Identity, ip string, b Basis, evID string) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
		return
	}
	s := addr.String()
	h.cite(evID)
	if old, ok := h.IPs[s]; !ok || b.rank() > old.rank() {
		h.IPs[s] = b
	}
	for _, c := range r.byIP[s] {
		if c.id == h {
			if b.rank() > c.basis.rank() {
				// replace in place
				for i := range r.byIP[s] {
					if r.byIP[s][i].id == h {
						r.byIP[s][i].basis = b
					}
				}
			}
			return
		}
	}
	r.byIP[s] = append(r.byIP[s], claim{h, b})
}

// Build reads the facts out of events. Events may be in any order.
func Build(events []model.Event) *Registry {
	r := &Registry{hosts: map[string]*Identity{}, byIP: map[string][]claim{}}
	// Machine-owned facts first, so that weaker facts can attach to them.
	for _, e := range events {
		switch {
		case e.EventType == model.EventRegistryKeyLastWrite && e.Extra["registry_value_name"] == "ComputerName" && e.Host != "":
			h := r.get(e.Host, true)
			h.cite(e.ID)
			if d := e.Extra["domain"]; d != "" {
				h.Domain = d
			}
			if role := e.Extra["host_role"]; role != "" {
				h.Role = role
			}
			for _, part := range strings.Split(e.Extra["ip_origin"], ";") {
				ip, origin, ok := strings.Cut(part, "=")
				if !ok {
					continue
				}
				b := BasisStatic
				if origin == string(BasisDHCP) {
					b = BasisDHCP
				}
				r.learn(h, ip, b, e.ID)
			}
		case e.EventType == model.EventRegistryKeyLastWrite && e.Extra["os_product_name"] != "" && e.Host != "":
			h := r.get(e.Host, true)
			h.OS, h.OSBuild = e.Extra["os_product_name"], e.Extra["os_current_build"]
			h.cite(e.ID)
		}
	}
	for _, e := range events {
		switch e.EventType {
		case model.EventNetworkConnection:
			// A socket's local address in a memory image is the machine's own.
			if e.ArtifactType == model.ArtifactMemoryAnalysis && e.Host != "" && e.NetworkSource != "" {
				r.learn(r.get(e.Host, true), e.NetworkSource, BasisMemory, e.ID)
			}
		case model.EventLogonSuccess:
			ws := strings.TrimSpace(e.Extra["workstation_name"])
			if ws != "" && ws != "-" && e.NetworkSource != "" && e.NetworkSource != "-" {
				r.learn(r.get(ws, false), e.NetworkSource, BasisClaimed, e.ID)
			}
		case model.EventDNSQuery:
			if e.NetworkDest == "" {
				continue
			}
			for _, a := range strings.Split(e.Extra["answers"], ",") {
				if _, err := netip.ParseAddr(a); err != nil {
					continue
				}
				// A name only becomes a machine here if the case already knows
				// that machine; DNS alone does not create one.
				if h := r.hosts[key(e.NetworkDest)]; h != nil {
					r.learn(h, a, BasisDNS, e.ID)
				}
			}
		}
	}
	return r
}

// Resolution is the answer to "which machine is this address?".
type Resolution struct {
	Identity  *Identity
	Basis     Basis
	Ambiguous bool // the strongest facts name more than one machine
}

// ByIP resolves an address. Identity is nil when nothing explains it or when
// the strongest facts disagree (Ambiguous is then true).
func (r *Registry) ByIP(ip string) Resolution {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return Resolution{}
	}
	claims := r.byIP[addr.String()]
	if len(claims) == 0 {
		return Resolution{}
	}
	best := 0
	for _, c := range claims {
		if c.basis.rank() > best {
			best = c.basis.rank()
		}
	}
	var top []claim
	for _, c := range claims {
		if c.basis.rank() == best {
			top = append(top, c)
		}
	}
	if len(top) > 1 {
		return Resolution{Ambiguous: true}
	}
	return Resolution{Identity: top[0].id, Basis: top[0].basis}
}

// ByName finds a machine by name, fully qualified or not.
func (r *Registry) ByName(name string) *Identity { return r.hosts[key(name)] }

// Hosts lists every machine, collected ones first, then by name.
func (r *Registry) Hosts() []*Identity {
	out := make([]*Identity, 0, len(r.hosts))
	for _, h := range r.hosts {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Collected != out[j].Collected {
			return out[i].Collected
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// SortedIPs lists a machine's addresses in order.
func (i *Identity) SortedIPs() []string {
	out := make([]string, 0, len(i.IPs))
	for ip := range i.IPs {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}
