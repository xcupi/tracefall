// Package authseq identifies ordered authentication observations, not causal access.
package authseq

import (
	"sort"
	"strings"
	"time"

	"tracefall/internal/model"
)

// BeforeSuccess ends a failure run at each success, including successes in a
// continuing stream of failures. A sequence contains only failures before it.
func BeforeSuccess(events []model.Event, threshold int, gap, window time.Duration) [][]model.Event {
	groups := map[string][]model.Event{}
	for _, e := range events {
		if e.EventType != model.EventLogonFailure && e.EventType != model.EventLogonSuccess {
			continue
		}
		if e.Timestamp.IsZero() || e.Host == "" || e.User == "" || e.ArtifactType == model.ArtifactMemoryAnalysis || e.Extra["timestamp_basis"] == "memory_snapshot" {
			continue
		}
		// Target logon_id is deliberately NOT a grouping field: a 4625
		// does not open a session. Source ports are also per-attempt, not identity.
		k := strings.Join([]string{e.CaseID, e.CollectionID, e.Host, e.User, e.NetworkSource, e.Extra["target_domain"], e.Extra["logon_type"], e.Extra["workstation_name"], e.Extra["auth_package"], e.Extra["logon_process"]}, "\x00")
		groups[k] = append(groups[k], e)
	}
	// Some Windows failure sources omit SubjectLogonId entirely. In that
	// case the success's subject session cannot be used as a target-session
	// binding. Where failures DO record subjects, keep those streams apart;
	// missing subjects never bridge two known sessions.
	subject := func(e model.Event) string {
		s := e.Extra["subject_logon_id"]
		if s == "0x0" || s == "0" || s == "-" {
			return ""
		}
		return s
	}
	streams := map[string][]model.Event{}
	for k, es := range groups {
		known := false
		for _, e := range es {
			if e.EventType == model.EventLogonFailure && subject(e) != "" {
				known = true
				break
			}
		}
		for _, e := range es {
			key := k
			if known {
				key += "\x00" + subject(e)
			}
			streams[key] = append(streams[key], e)
		}
	}
	groups = streams
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
		var burst []model.Event
		var pending [][]model.Event
		for _, e := range es {
			// Retain only completed bursts still eligible for a future success.
			kept := pending[:0]
			for _, run := range pending {
				if e.Timestamp.Sub(run[len(run)-1].Timestamp) <= window {
					kept = append(kept, run)
				}
			}
			for i := len(kept); i < len(pending); i++ {
				pending[i] = nil
			}
			pending = kept
			if e.EventType == model.EventLogonFailure {
				if len(burst) > 0 && e.Timestamp.Sub(burst[len(burst)-1].Timestamp) > gap {
					if len(burst) >= threshold {
						pending = append(pending, burst)
					}
					burst = nil
				}
				burst = append(burst, e)
				continue
			}
			runs := pending
			if len(burst) >= threshold {
				runs = append(runs, burst)
			}
			for _, run := range runs {
				last := run[len(run)-1]
				if e.Timestamp.After(last.Timestamp) && e.Timestamp.Sub(last.Timestamp) <= window {
					out = append(out, append(append([]model.Event{}, run...), e))
				}
			}
			burst = nil
			pending = nil
		}
	}
	return out
}
