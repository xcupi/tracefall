// Package authseq identifies ordered authentication observations, not causal access.
package authseq

import (
	"net/netip"
	"sort"
	"strings"
	"time"

	"tracefall/internal/model"
)

// BeforeSuccess ends a failure run at each success, including successes in a
// continuing stream of failures. A sequence contains only failures before it.
//
// Failures and successes are tied by case, host and account. The logon type,
// authentication package, logon process and workstation are NOT part of the
// tie: a guessing attempt over NTLM followed by an RDP or Kerberos logon is
// the usual shape of a successful guess, and splitting on them hides it. The
// source address and account domain narrow the tie only when BOTH sides record
// one and they differ (a different address or domain is a different actor or
// account); an unrecorded value never separates. Failures that record their
// subject session stay in separate streams. The collection is not part of the
// tie either: one host is often acquired more than once.
func BeforeSuccess(events []model.Event, threshold int, gap, window time.Duration) [][]model.Event {
	groups := map[string][]model.Event{}
	for _, e := range events {
		if e.EventType != model.EventLogonFailure && e.EventType != model.EventLogonSuccess {
			continue
		}
		if e.Timestamp.IsZero() || e.Host == "" || e.User == "" || e.ArtifactType == model.ArtifactMemoryAnalysis || e.Extra["timestamp_basis"] == "memory_snapshot" {
			continue
		}
		k := strings.Join([]string{e.CaseID, strings.ToLower(e.Host), strings.ToLower(e.User)}, "\x00")
		groups[k] = append(groups[k], e)
	}
	subject := func(e model.Event) string {
		s := e.Extra["subject_logon_id"]
		if s == "0x0" || s == "0" || s == "-" {
			return ""
		}
		return s
	}
	domain := func(e model.Event) string { return strings.ToLower(e.Extra["target_domain"]) }
	compatible := func(f, s model.Event) bool {
		if f.NetworkSource != "" && s.NetworkSource != "" && sourceKey(f.NetworkSource) != sourceKey(s.NetworkSource) {
			return false
		}
		if domain(f) != "" && domain(s) != "" && domain(f) != domain(s) {
			return false
		}
		if subject(f) != "" && subject(s) != "" && subject(f) != subject(s) {
			return false
		}
		return true
	}

	type stream struct {
		burst   []model.Event
		pending [][]model.Event
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out [][]model.Event
	for _, k := range keys {
		es := groups[k]
		sort.Slice(es, func(i, j int) bool {
			if !es[i].Timestamp.Equal(es[j].Timestamp) {
				return es[i].Timestamp.Before(es[j].Timestamp)
			}
			return es[i].ID < es[j].ID
		})
		// One stream per failure context (source, domain, subject session).
		streams := map[string]*stream{}
		ctxOf := func(e model.Event) string {
			return strings.Join([]string{sourceKey(e.NetworkSource), domain(e), subject(e)}, "\x00")
		}
		for _, e := range es {
			if e.EventType == model.EventLogonFailure {
				st := streams[ctxOf(e)]
				if st == nil {
					st = &stream{}
					streams[ctxOf(e)] = st
				}
				if len(st.burst) > 0 && e.Timestamp.Sub(st.burst[len(st.burst)-1].Timestamp) > gap {
					if len(st.burst) >= threshold {
						st.pending = append(st.pending, st.burst)
					}
					st.burst = nil
				}
				st.burst = append(st.burst, e)
				continue
			}
			// A success: tie it to every compatible stream's eligible runs.
			ctxs := make([]string, 0, len(streams))
			for c := range streams {
				ctxs = append(ctxs, c)
			}
			sort.Strings(ctxs)
			for _, c := range ctxs {
				st := streams[c]
				var probe model.Event
				switch {
				case len(st.burst) > 0:
					probe = st.burst[0]
				case len(st.pending) > 0:
					probe = st.pending[0][0]
				default:
					continue
				}
				if !compatible(probe, e) {
					continue
				}
				runs := st.pending
				if len(st.burst) >= threshold {
					runs = append(runs, st.burst)
				}
				for _, run := range runs {
					last := run[len(run)-1]
					if e.Timestamp.After(last.Timestamp) && e.Timestamp.Sub(last.Timestamp) <= window {
						out = append(out, append(append([]model.Event{}, run...), e))
					}
				}
				st.burst, st.pending = nil, nil
			}
		}
	}
	return out
}

// sourceKey canonicalizes valid literal addresses for comparison only. Unmap
// merges IPv4-mapped IPv6 with IPv4, but not IPv4-compatible IPv6. Zones remain
// part of identity. Invalid strings are exact recorded literals (no trimming,
// hostname case folding, port stripping, DNS lookup or address inference).
func sourceKey(raw string) string {
	if addr, err := netip.ParseAddr(raw); err == nil {
		return "ip\x00" + addr.WithZone("").Unmap().String() + "\x00" + addr.Zone()
	}
	return "literal\x00" + raw
}
