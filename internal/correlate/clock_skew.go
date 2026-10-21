package correlate

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"tracefall/internal/clockskew"
	"tracefall/internal/hostid"
	"tracefall/internal/model"
)

// Allowances for the physical delays the clock model cannot see. They widen an
// observation's interval; they never narrow it.
const (
	// A packet is captured some moment after the sender wrote the clock value
	// into it. On a LAN with the capture at either end this is milliseconds;
	// two seconds is a deliberately generous bound.
	captureDelayMax = 2 * time.Second
	// HTTP Date and NTP seconds are whole seconds; the true instant lies in
	// the second that follows the value.
	oneSecond = time.Second
)

const internetServers = "internet web servers (HTTP Date)"

func captureClock(e model.Event) string { return "capture:" + e.SourceFileID }

func parseUTC(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

// subjectFor names the clock an address stands for: the machine, when the case
// knows whose address it is, otherwise the address. Public addresses that were
// seen only through HTTP Date headers are pooled, so that a capture clock that
// is itself wrong shows up as one finding instead of one per web server.
func subjectFor(reg *hostid.Registry, ip string, httpDate bool) string {
	if reg != nil {
		if r := reg.ByIP(ip); r.Identity != nil {
			return "host:" + strings.ToLower(r.Identity.Name)
		}
	}
	if a, err := netip.ParseAddr(ip); err == nil {
		if httpDate && !a.IsPrivate() && !a.IsLinkLocalUnicast() && !a.IsLoopback() {
			return internetServers
		}
	}
	return "ip:" + ip
}

// clockObservations turns the clock readings in a capture into intervals.
func clockObservations(events []model.Event, reg *hostid.Registry) []clockskew.Observation {
	var out []clockskew.Observation
	for _, e := range events {
		if e.EventType != model.EventClockObservation {
			continue
		}
		observed, ok1 := parseUTC(e.Extra["observed_utc"])
		capture, ok2 := parseUTC(e.Extra["capture_utc"])
		if !ok1 || !ok2 {
			continue
		}
		ref := captureClock(e)
		ip := e.Extra["subject_ip"]
		switch {
		case e.Extra["source"] == "ntp" && e.Extra["role"] == "client":
			// The client wrote its clock into the packet, then the packet
			// reached the capture. observed is in [truth, truth+1s) and the
			// capture is up to captureDelayMax after the send.
			s := observed.Truncate(oneSecond)
			out = append(out, clockskew.Observation{
				Subject: subjectFor(reg, ip, false), Reference: ref, Method: "ntp client clock",
				Lo: s.Sub(capture), Hi: s.Add(oneSecond).Sub(capture) + captureDelayMax, EventIDs: []string{e.ID},
			})
		case e.Extra["source"] == "ntp" && e.Extra["role"] == "server":
			rcv, okR := parseUTC(e.Extra["receive_utc"])
			xmit, okX := parseUTC(e.Extra["transmit_utc"])
			req, okQ := parseUTC(e.Extra["request_capture_utc"])
			if okR && okX && okQ {
				// The server received the request after the capture saw it left
				// and sent the reply before the capture saw it arrive, so its
				// receive time lies between those two capture times less the
				// time it held the request.
				hold := xmit.Sub(rcv)
				if hold < 0 || hold > capture.Sub(req) {
					continue
				}
				out = append(out, clockskew.Observation{
					Subject: subjectFor(reg, ip, false), Reference: ref, Method: "ntp exchange",
					Lo: rcv.Sub(capture.Add(-hold)), Hi: rcv.Sub(req), EventIDs: []string{e.ID},
				})
			} else {
				s := observed.Truncate(oneSecond)
				out = append(out, clockskew.Observation{
					Subject: subjectFor(reg, ip, false), Reference: ref, Method: "ntp server clock",
					Lo: s.Sub(capture), Hi: s.Add(oneSecond).Sub(capture) + captureDelayMax, EventIDs: []string{e.ID},
				})
			}
		case e.Extra["source"] == "http_date":
			s := observed.Truncate(oneSecond)
			out = append(out, clockskew.Observation{
				Subject: subjectFor(reg, ip, true), Reference: ref, Method: "http date header",
				Lo: s.Sub(capture), Hi: s.Add(oneSecond).Sub(capture) + captureDelayMax, EventIDs: []string{e.ID},
			})
		}
	}
	return out
}

// logonObservations pairs a logon the host recorded with the capture's own
// record of the connection that carried it. The logon happened while the
// connection was open, which bounds the offset between the host's clock and
// the capture's.
func logonObservations(events []model.Event, reg *hostid.Registry) []clockskew.Observation {
	type key struct{ ip, port string }
	sessions := map[key][]model.Event{}
	for _, e := range events {
		if e.EventType == model.EventNetworkConnection && e.ArtifactType == model.ArtifactNetworkCapture && e.Extra["session"] == "true" {
			sessions[key{e.NetworkSource, e.Extra["client_port"]}] = append(sessions[key{e.NetworkSource, e.Extra["client_port"]}], e)
		}
	}
	if len(sessions) == 0 {
		return nil
	}
	var out []clockskew.Observation
	for _, l := range events {
		if l.EventType != model.EventLogonSuccess || l.Host == "" || l.Timestamp.IsZero() || l.ArtifactType == model.ArtifactNetworkCapture {
			continue
		}
		port := l.Extra["source_port"]
		if port == "" || l.NetworkSource == "" {
			continue
		}
		for _, s := range sessions[key{l.NetworkSource, port}] {
			// The session's server must be this host, when the case can say
			// whose address that is; a reused client port on another server is
			// not this logon.
			if r := reg.ByIP(s.NetworkDest); r.Identity != nil && !strings.EqualFold(r.Identity.Name, l.Host) {
				continue
			}
			first, ok1 := parseUTC(s.Extra["first_seen_utc"])
			if !ok1 {
				first = s.Timestamp
			}
			last, ok2 := parseUTC(s.Extra["last_seen_utc"])
			if !ok2 {
				continue
			}
			out = append(out, clockskew.Observation{
				Subject: "host:" + strings.ToLower(l.Host), Reference: captureClock(s), Method: "logon inside a captured connection",
				Lo: l.Timestamp.Sub(last), Hi: l.Timestamp.Sub(first), EventIDs: []string{l.ID, s.ID},
			})
		}
	}
	return out
}

// BuildClockSkew estimates, for each clock the evidence lets it compare, how
// far that clock is from the capture's, and reports the ones that are not
// consistent with zero or not consistent with themselves.
//
// It changes no timestamp. An estimate is a separate statement the reader can
// apply or not.
func BuildClockSkew(caseID string, events []model.Event, reg *hostid.Registry) []model.Correlation {
	var out []model.Correlation
	for _, est := range ClockEstimates(events, reg) {
		if est.Steady() && !est.Significant() {
			continue // consistent with no offset: nothing to report
		}
		out = append(out, skewCorrelation(caseID, est, events))
	}
	return out
}

// ClockEstimates is every (clock, capture) comparison the events allow, whether
// or not it is worth reporting. The web-to-host correlation reads them to put
// host times on the capture's scale.
func ClockEstimates(events []model.Event, reg *hostid.Registry) []clockskew.Estimate {
	obs := clockObservations(events, reg)
	obs = append(obs, logonObservations(events, reg)...)
	if len(obs) == 0 {
		return nil
	}
	// Public web servers are many independent clocks, some of them wrong.
	// They are pooled and only the offset most of them agree on is kept.
	var pooled, own []clockskew.Observation
	for _, o := range obs {
		if o.Subject == internetServers {
			pooled = append(pooled, o)
		} else {
			own = append(own, o)
		}
	}
	out := clockskew.Estimates(own)
	byRef := map[string][]clockskew.Observation{}
	for _, o := range pooled {
		byRef[o.Reference] = append(byRef[o.Reference], o)
	}
	refs := make([]string, 0, len(byRef))
	for r := range byRef {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	for _, r := range refs {
		if est, ok := clockskew.Majority(byRef[r], majorityShare); ok {
			out = append(out, est)
		}
	}
	return out
}

// majorityShare is how much of the pooled web servers must agree before the
// capture's own clock is blamed.
const majorityShare = 0.8

func skewCorrelation(caseID string, est clockskew.Estimate, events []model.Event) model.Correlation {
	var title, how string
	off, unc := est.Offset(), est.Uncertainty()
	subject := strings.TrimPrefix(strings.TrimPrefix(est.Subject, "host:"), "ip:")
	reference := strings.TrimPrefix(est.Reference, "capture:")
	switch {
	case est.Consistent:
		title = fmt.Sprintf("Clock offset: %s is %s from the capture clock (±%s, %d observation(s))",
			subject, clockskew.Format(off), unc.Round(time.Second), est.Count)
		how = fmt.Sprintf("Every observation agrees: together they place the offset between %s and %s (subject minus capture).",
			clockskew.Format(est.Lo), clockskew.Format(est.Hi))
	case est.Steady():
		title = fmt.Sprintf("Clock offset: %s is between %s and %s from the capture clock (%d observation(s))",
			subject, clockskew.Format(est.SpanLo), clockskew.Format(est.SpanHi), est.Count)
		how = fmt.Sprintf("The observations do not quite overlap but their midpoints differ by only %s, which is the size of timing noise and slow drift, so they are read as one steady offset.",
			(est.MidHi - est.MidLo).Round(time.Second))
	default:
		title = fmt.Sprintf("Clock offset is not constant: %s against the capture clock spans %s to %s (%d observation(s))",
			subject, clockskew.Format(est.MidLo), clockskew.Format(est.MidHi), est.Count)
		how = fmt.Sprintf("The observations disagree, so no single offset fits them. Either the clock was changed or drifted "+
			"during the evidence (median %s), or some observations pair unrelated events.", clockskew.Format(est.Median))
	}
	if est.Of > 0 {
		how += fmt.Sprintf(" %d of the %d clocks seen agree on this offset; the rest are not counted, because some web servers' clocks are simply wrong.", est.Count, est.Of)
		title += fmt.Sprintf(" — %d of %d agree", est.Count, est.Of)
	}
	sign := "ahead of"
	if off < 0 {
		sign = "behind"
	}
	desc := fmt.Sprintf(
		"Clock %q, compared with the clock of capture %q, reads about %s %s it. %s Method(s): %s. "+
			"Each observation is an interval, not a point: a value written to the wire is seen a moment later, and a "+
			"logon happens somewhere inside the connection that carried it. No timestamp has been changed. To read the "+
			"subject's events on the capture's time scale, subtract this offset.",
		subject, reference, absDur(off).Round(time.Second), sign, how, strings.Join(est.Methods, ", "))
	if est.Quarter != "" {
		desc += " The offset " + est.Quarter + ". That is a hypothesis about the cause (a wrong time-zone setting, for example); the evidence shows the offset, not why."
	}
	first, last := observationSpan(est.EventIDs, events)
	return model.Correlation{
		CaseID: caseID, Type: model.CorrelationClockSkew, Title: title, Description: desc,
		EventIDs: est.EventIDs, FirstSeen: first, LastSeen: last,
	}
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// observationSpan is the capture-time span of the events that support an
// estimate; their timestamps are all on one scale only when they come from the
// capture, so events stamped by a host are left out.
func observationSpan(ids []string, events []model.Event) (first, last time.Time) {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var ts []time.Time
	for _, e := range events {
		if want[e.ID] && e.ArtifactType == model.ArtifactNetworkCapture && !e.Timestamp.IsZero() {
			ts = append(ts, e.Timestamp)
		}
	}
	if len(ts) == 0 {
		return time.Time{}, time.Time{}
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	return ts[0], ts[len(ts)-1]
}
