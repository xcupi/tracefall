package investigate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"tracefall/internal/model"
)

// clause is one fragment of the generated narrative. A continuation
// clause is appended onto the current sentence with ", " (used for a
// process-create that's the direct child of the previous step, e.g.
// "...launched winword.exe, which spawned powershell.exe"); a
// non-continuation clause starts a new sentence.
type clause struct {
	text         string
	continuation bool
}

// buildNarrative composes a deterministic, template-generated,
// evidence-only prose summary of a group's events, in chronological
// order. It never speculates about intent -- no "the attacker", only
// "the activity"/"the process"/"the observed execution" -- and every
// clause is derived directly from a real event's fields, never invented.
//
// seq is the group's events in timestamp order. Only narrative types carry
// their full event (ev); the others carry their type and time, which is all
// the logon-failure burst rule needs of the events between two failures.
//
// Plain timestamp order is used rather than a chain correlation's own step
// order: an earlier version preferred the chain's order and narrated a chain
// event as "subsequently" after a non-chain event that actually occurred
// earlier. Chain steps are already chronological, so timestamp order gives the
// same narrative for them.
func buildNarrative(seq []seqItem) string {
	ordered := append([]seqItem{}, seq...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ts.Before(ordered[j].ts) })
	if len(ordered) == 0 {
		return ""
	}

	var clauses []clause
	var lastProcess string
	narratedAny := false

	i := 0
	for i < len(ordered) {
		it := ordered[i]
		e := it.ev

		switch it.typ {
		case model.EventLogonFailure:
			j := i
			for j < len(ordered) && ordered[j].typ == model.EventLogonFailure {
				j++
			}
			burst := ordered[i:j]
			clauses = append(clauses, clause{
				text: fmt.Sprintf("On %s, %d failed logon attempt(s) for user %s were observed between %s and %s",
					orDash(e.Host), len(burst), orDash(burst[0].ev.User), fmtT(burst[0].ts), fmtT(burst[len(burst)-1].ts)),
			})
			i = j
			narratedAny = true
			lastProcess = ""
			continue

		case model.EventLogonSuccess:
			text := fmt.Sprintf("A successful logon for user %s on host %s was observed at %s%s",
				orDash(e.User), orDash(e.Host), fmtT(e.Timestamp), logonTypeSuffix(e))
			if narratedAny {
				text = fmt.Sprintf("This was followed by a successful logon for user %s at %s%s",
					orDash(e.User), fmtT(e.Timestamp), logonTypeSuffix(e))
			}
			clauses = append(clauses, clause{text: text})
			// A logon didn't "spawn" anything -- the next process-create
			// must not be phrased as a continuation of it.
			lastProcess = ""

		case model.EventProcessCreate:
			switch {
			case lastProcess != "" && e.ParentProcessName == lastProcess:
				clauses = append(clauses, clause{text: fmt.Sprintf("which spawned %s", orDash(e.ProcessName)), continuation: true})
			case !narratedAny:
				clauses = append(clauses, clause{text: fmt.Sprintf("On host %s, the observed execution began with %s", orDash(e.Host), orDash(e.ProcessName))})
			default:
				clauses = append(clauses, clause{text: fmt.Sprintf("the process %s was subsequently observed executing", orDash(e.ProcessName))})
			}
			lastProcess = e.ProcessName

		case model.EventRegistryRunKey, model.EventRegistryPersistence:
			clauses = append(clauses, clause{text: fmt.Sprintf(
				"A registry persistence entry referencing %s was established at %s",
				orDash(e.FilePath), fmtT(e.Timestamp))})
			lastProcess = ""

		case model.EventScheduledTaskCreate:
			clauses = append(clauses, clause{text: fmt.Sprintf(
				"A scheduled task (%s) was registered at %s", orDash(e.Extra["task_name"]), fmtT(e.Timestamp))})
			lastProcess = ""

		case model.EventServiceInstall:
			clauses = append(clauses, clause{text: fmt.Sprintf(
				"A service (%s) was installed at %s, image path %s",
				orDash(e.Extra["service_name"]), fmtT(e.Timestamp), orDash(e.FilePath))})
			lastProcess = ""

		case model.EventNetworkConnection:
			clauses = append(clauses, clause{text: fmt.Sprintf(
				"A network connection to %s was subsequently observed at %s",
				orDash(e.NetworkDest), fmtT(e.Timestamp))})
			lastProcess = ""

		case model.EventDNSQuery:
			clauses = append(clauses, clause{text: fmt.Sprintf(
				"A DNS query for %s was observed at %s", orDash(e.NetworkDest), fmtT(e.Timestamp))})
			lastProcess = ""

		case model.EventLogonExplicitCreds:
			clauses = append(clauses, clause{text: fmt.Sprintf(
				"Explicit credentials for account %s were used at %s",
				orDash(e.Extra["target_user_name"]), fmtT(e.Timestamp))})
			lastProcess = ""

		case model.EventPrivilegedLogon:
			clauses = append(clauses, clause{text: fmt.Sprintf(
				"Privileged/administrative rights were assigned to a logon at %s", fmtT(e.Timestamp))})
			lastProcess = ""

		default:
			// Event types without a dedicated clause remain part of the
			// investigation's evidence (still in EventIDs) without being
			// narrated individually -- keeps the narrative focused on
			// the notable steps rather than a transcript of every event.
			i++
			continue
		}
		narratedAny = true
		i++
	}

	if len(clauses) == 0 {
		return ""
	}
	return joinClauses(clauses)
}

func joinClauses(clauses []clause) string {
	var sentences []string
	var current string
	for _, c := range clauses {
		if c.continuation && current != "" {
			current += ", " + c.text
			continue
		}
		if current != "" {
			sentences = append(sentences, current)
		}
		current = c.text
	}
	if current != "" {
		sentences = append(sentences, current)
	}
	for i, s := range sentences {
		sentences[i] = strings.TrimSuffix(s, ".") + "."
	}
	return strings.Join(sentences, " ")
}

func logonTypeSuffix(e *model.Event) string {
	switch e.Extra["logon_type"] {
	case "10":
		return " (remote interactive/RDP)"
	case "3":
		return " (network)"
	default:
		return ""
	}
}

func orDash(s string) string {
	if s == "" {
		return "an unknown host/process"
	}
	return s
}

func fmtT(t time.Time) string {
	return t.Format("15:04:05 UTC")
}
