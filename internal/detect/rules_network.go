package detect

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"tracefall/internal/model"
)

// Rules over what a packet capture shows. A capture shows traffic between
// addresses; it never shows what happened on either machine, and the rules say
// so in their findings.

// rdpBurstMin is how many separate connections to one Remote Desktop server
// from one client make a burst worth a lead. A handful is ordinary reconnection;
// guessing a password takes many.
const rdpBurstMin = 50

// rdpSessionMin is how many packets a Remote Desktop connection must exchange
// to be called a session. A handshake plus negotiation is a few dozen.
const rdpSessionMin = 200

// ---------- Many Remote Desktop connections, then a session ----------

type rdpConnectionBurst struct{}

func (rdpConnectionBurst) ID() string { return "rdp-connection-burst" }

func (rdpConnectionBurst) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventNetworkConnection}, Within: []string{model.ArtifactNetworkCapture}}
}

func (r rdpConnectionBurst) Evaluate(events []model.Event) []model.Finding {
	type pair struct{ client, server string }
	convs := map[pair]model.Event{}
	sessions := map[pair][]model.Event{}
	for _, e := range byType(events, model.EventNetworkConnection) {
		if e.ArtifactType != model.ArtifactNetworkCapture || e.Extra["application"] != "rdp" {
			continue
		}
		k := pair{e.NetworkSource, e.NetworkDest}
		if e.Extra["session"] == "true" {
			sessions[k] = append(sessions[k], e)
			continue
		}
		convs[k] = e
	}
	keys := make([]pair, 0, len(convs))
	for k := range convs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].client != keys[j].client {
			return keys[i].client < keys[j].client
		}
		return keys[i].server < keys[j].server
	})
	var out []model.Finding
	for _, k := range keys {
		c := convs[k]
		n, _ := strconv.Atoi(c.Extra["connections"])
		if n < rdpBurstMin {
			continue
		}
		// A connection of a few dozen packets is a handshake with a little
		// negotiation, which probes produce too. Only a connection that went
		// on for a while is a session worth pointing at.
		var long []model.Event
		var largest model.Event
		var largestPkts int
		for _, s := range sessions[k] {
			p, _ := strconv.Atoi(s.Extra["packets"])
			if p > largestPkts {
				largest, largestPkts = s, p
			}
			if p >= rdpSessionMin {
				long = append(long, s)
			}
		}
		sort.SliceStable(long, func(i, j int) bool { return long[i].Timestamp.Before(long[j].Timestamp) })
		sev, conf := model.SeverityMedium, model.ConfidenceLow
		tail := "No connection from this client went beyond a handshake and a little negotiation."
		if largestPkts > 0 {
			tail = fmt.Sprintf("The longest connection from this client was only %d packets, which is a handshake with some negotiation, not a working session.", largestPkts)
		}
		supporting := []model.Event{c}
		if len(long) > 0 {
			sev, conf = model.SeverityHigh, model.ConfidenceMedium
			first := long[0]
			tail = fmt.Sprintf("%d connection(s) from this client then went on for %d packets or more, the first starting %s from client port %s (%s packets). "+
				"That is a session that got past the handshake. Whether a logon succeeded cannot be read from encrypted Remote Desktop traffic: "+
				"match the client port against the server's logon events (Windows event 4624 records the source port).",
				len(long), rdpSessionMin, first.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC"), first.Extra["client_port"], first.Extra["packets"])
			supporting = append(supporting, long...)
		} else if largestPkts > 0 {
			supporting = append(supporting, largest)
		}
		cookie := ""
		if u := c.Extra["rdp_cookie_user"]; u != "" {
			cookie = fmt.Sprintf(" The clients' connection requests named the user %q; that is text the client sent, not an authenticated identity.", u)
		}
		title := fmt.Sprintf("%d Remote Desktop connections from %s to %s", n, c.NetworkSource, c.NetworkDest)
		desc := fmt.Sprintf(
			"The capture shows %d separate TCP connections from %s to the Remote Desktop port of %s, starting %s. "+
				"A burst like this is what password guessing against Remote Desktop looks like on the wire, and it is also what a scanner, "+
				"a load balancer's health check or a client with a broken saved credential looks like. %s%s "+
				"Times are the capturing machine's clock.",
			n, c.NetworkSource, c.NetworkDest, c.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC"), tail, cookie)
		out = append(out, newFinding(c.CaseID, r.ID(), title, sev, conf, desc, []string{"T1110.001", "T1021.001"}, capEvents(supporting)))
	}
	return out
}

// ---------- An executable delivered over HTTP from a bare address ----------

type executableFromBareAddress struct{}

func (executableFromBareAddress) ID() string { return "executable-over-http-from-address" }

func (executableFromBareAddress) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventWebRequest}, Within: []string{model.ArtifactNetworkCapture}}
}

func runnableSignature(sig string) bool {
	s := strings.ToLower(sig)
	return strings.Contains(s, "executable") || strings.Contains(s, "elf") || strings.Contains(s, "msi") || strings.Contains(s, "java")
}

// ipLiteral reports whether an HTTP Host (or, failing that, the destination)
// is an IP address rather than a name.
func ipLiteral(host string) bool {
	if i := strings.LastIndexByte(host, ':'); i > 0 && strings.Count(host, ":") == 1 {
		host = host[:i]
	}
	_, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil
}

func (r executableFromBareAddress) Evaluate(events []model.Event) []model.Finding {
	type key struct{ client, server, sha string }
	groups := map[key][]model.Event{}
	for _, e := range byType(events, model.EventWebRequest) {
		if e.ArtifactType != model.ArtifactNetworkCapture || e.Extra["status"] != "200" || e.Extra["reassembly"] != "complete" {
			continue
		}
		if !runnableSignature(e.Extra["file_signature"]) {
			continue
		}
		host := e.Extra["http_host"]
		if host == "" {
			host = e.NetworkDest
		}
		if !ipLiteral(host) {
			continue
		}
		k := key{e.NetworkSource, e.NetworkDest, e.Extra["response_sha256"]}
		groups[k] = append(groups[k], e)
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.client != b.client {
			return a.client < b.client
		}
		if a.server != b.server {
			return a.server < b.server
		}
		return a.sha < b.sha
	})
	var out []model.Finding
	for _, k := range keys {
		g := groups[k]
		sort.SliceStable(g, func(i, j int) bool { return g[i].Timestamp.Before(g[j].Timestamp) })
		e := g[0]
		name := e.Extra["filename"]
		if name == "" {
			name = "(no file name)"
		}
		title := fmt.Sprintf("%s fetched over HTTP from the address %s", name, k.server)
		desc := fmt.Sprintf(
			"The capture shows %s requesting %s%s over unencrypted HTTP at %s and receiving a %s of %s bytes (SHA-256 %s), %d time(s). "+
				"Legitimate software is normally fetched from a named site; a program served from a bare address is a common way for malware to be staged, "+
				"and a common way for internal tooling to be distributed. "+
				"The capture shows the bytes reached the client. It does not show they were saved, run, or what the program does: that needs the file or the client's own records. "+
				"Times are the capturing machine's clock.",
			k.client, e.Extra["http_host"], e.Extra["uri"], e.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC"),
			e.Extra["file_signature"], e.Extra["response_size"], k.sha, len(g))
		out = append(out, newFinding(e.CaseID, r.ID(), title, model.SeverityMedium, model.ConfidenceMedium, desc, []string{"T1105"}, capEvents(g)))
	}
	return out
}
