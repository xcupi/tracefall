package correlate

import (
	"fmt"
	"sort"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/partialtime"
)

// Windowing for the sequence chain. Like the other credential chains these
// are not shared with the detection package; see credential_chain.go.
const (
	seqChainCap = 24 // events listed per chain; the true count is in the title
)

// buildSequenceBruteForceChains is the credential chain for logs whose lines
// carry no year (auth.log and the like). It links a run of failed logons to
// the successful logon that follows, using only the order of lines in one
// file and the distance between their stamps.
//
// The account AND the source address must match, so failures from one
// address are never joined to a success from another. Lines from different
// files are never joined, and nothing is joined across a New Year: see
// package partialtime.
func buildSequenceBruteForceChains(caseID string, events []model.Event) []model.Correlation {
	type key struct{ host, user, src, file string }
	type placed struct {
		ev  model.Event
		pos partialtime.Position
	}
	byKey := map[key][]placed{}
	hasFailures := map[key]bool{}
	for _, e := range events {
		if !e.Timestamp.IsZero() || e.NetworkSource == "" {
			continue
		}
		if e.EventType != model.EventLogonFailure && e.EventType != model.EventLogonSuccess {
			continue
		}
		pos, ok := partialtime.PositionOf(e.SourceFileID, e.Extra)
		if !ok {
			continue
		}
		k := key{e.Host, e.User, e.NetworkSource, e.SourceFileID}
		byKey[k] = append(byKey[k], placed{e, pos})
		if e.EventType == model.EventLogonFailure {
			hasFailures[k] = true
		}
	}
	keys := make([]key, 0, len(byKey))
	for k := range byKey {
		if hasFailures[k] {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.host != b.host {
			return a.host < b.host
		}
		if a.user != b.user {
			return a.user < b.user
		}
		if a.src != b.src {
			return a.src < b.src
		}
		return a.file < b.file
	})
	var out []model.Correlation
	for _, k := range keys {
		list := byKey[k]
		sort.SliceStable(list, func(i, j int) bool { return list[i].pos.Line < list[j].pos.Line })
		its := make([]partialtime.Item, len(list))
		for i, p := range list {
			its[i] = partialtime.Item{Pos: p.pos, Success: p.ev.EventType == model.EventLogonSuccess}
		}
		for _, b := range partialtime.BurstsBeforeSuccess(its, credBruteForceThreshold, credBruteForceGapWindow, credBruteForceSuccessWindow) {
			first, last := list[b.Failures[0]], list[b.Failures[len(b.Failures)-1]]
			succ := list[b.Success]
			listed := b.Failures
			if len(listed) > seqChainCap {
				half := seqChainCap / 2
				listed = append(append([]int{}, b.Failures[:half]...), b.Failures[len(b.Failures)-half:]...)
			}
			ids := make([]string, 0, len(listed)+1)
			for _, idx := range listed {
				ids = append(ids, list[idx].ev.ID)
			}
			ids = append(ids, succ.ev.ID)
			span, _ := partialtime.Delta(first.pos, last.pos)
			out = append(out, model.Correlation{
				CaseID: caseID,
				Type:   model.CorrelationCredentialChain,
				Title: fmt.Sprintf("Brute-force chain (order within one log): %d failed_logon(%s) from %s -> logon(%s)",
					len(b.Failures), orDash(k.user), k.src, orDash(succ.ev.User)),
				Description: fmt.Sprintf(
					"On host %s, %d failed logons for %q from %s span %s of log time (%q to %q as written) and are followed on line %d "+
						"(%q) by a successful logon for the same account from the same address. The log carries no year, so the order "+
						"and distances are established within this one file and the calendar date is not known.",
					orDash(k.host), len(b.Failures), k.user, k.src, span.Round(time.Second),
					first.ev.Extra[partialtime.KeyStamp], last.ev.Extra[partialtime.KeyStamp], succ.pos.Line, succ.ev.Extra[partialtime.KeyStamp]),
				EventIDs: ids,
				// FirstSeen and LastSeen stay zero: no date is known.
			})
		}
	}
	return out
}
