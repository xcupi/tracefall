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
	// Dated steps first, in time order; steps with no recorded time follow, in
	// the order given. An undated step has no place in the time order, so it
	// is never narrated as before, after or subsequent to anything.
	ordered := append([]seqItem{}, seq...)
	sort.SliceStable(ordered, func(i, j int) bool {
		di, dj := isDated(ordered[i].ts), isDated(ordered[j].ts)
		if di != dj {
			return di
		}
		return di && ordered[i].ts.Before(ordered[j].ts)
	})
	if len(ordered) == 0 {
		return ""
	}

	var clauses []clause
	var lastProcess string
	narratedAny := false
	// prevDated is true when the clause just written states a recorded time,
	// the only case in which a later dated clause may be called "followed by"
	// or "subsequent".
	prevDated := false

	i := 0
	for i < len(ordered) {
		it := ordered[i]
		e := it.ev
		dated := isDated(it.ts)
		seqOK := dated && prevDated

		switch it.typ {
		case model.EventLogonFailure:
			j := i
			for j < len(ordered) && ordered[j].typ == model.EventLogonFailure && isDated(ordered[j].ts) == dated {
				j++
			}
			burst := ordered[i:j]
			window := "(time not recorded)"
			if dated {
				window = fmt.Sprintf("between %s and %s", fmtT(burst[0].ts), fmtT(burst[len(burst)-1].ts))
			}
			clauses = append(clauses, clause{
				text: fmt.Sprintf("%s, %d failed logon attempt(s) for user %s were observed %s",
					onHost(e.Host), len(burst), orDash(burst[0].ev.User), window),
			})
			i = j
			narratedAny = true
			prevDated = dated
			lastProcess = ""
			continue

		case model.EventLogonSuccess:
			text := fmt.Sprintf("A successful logon for user %s on %s was observed%s%s",
				orDash(e.User), hostPhrase(e.Host), atT(it.ts), logonTypeSuffix(e))
			if narratedAny && seqOK {
				text = fmt.Sprintf("This was followed by a successful logon for user %s%s%s",
					orDash(e.User), atT(it.ts), logonTypeSuffix(e))
			}
			clauses = append(clauses, clause{text: text})
			// A logon didn't "spawn" anything -- the next process-create
			// must not be phrased as a continuation of it.
			lastProcess = ""

		case model.EventProcessCreate:
			switch {
			case lastProcess != "" && e.ParentProcessName == lastProcess && seqOK:
				clauses = append(clauses, clause{text: fmt.Sprintf("which spawned %s", orDash(e.ProcessName)), continuation: true})
			case !dated:
				clauses = append(clauses, clause{text: fmt.Sprintf("%s, execution of %s was observed (time not recorded)", onHost(e.Host), orDash(e.ProcessName))})
			case !narratedAny:
				clauses = append(clauses, clause{text: fmt.Sprintf("%s, the observed execution began with %s", onHost(e.Host), orDash(e.ProcessName))})
			case !prevDated:
				clauses = append(clauses, clause{text: fmt.Sprintf("the process %s was observed executing%s", orDash(e.ProcessName), atT(it.ts))})
			default:
				clauses = append(clauses, clause{text: fmt.Sprintf("the process %s was subsequently observed executing", orDash(e.ProcessName))})
			}
			lastProcess = e.ProcessName

		case model.EventRegistryRunKey, model.EventRegistryPersistence:
			if dated {
				clauses = append(clauses, clause{text: fmt.Sprintf(
					"A registry persistence entry referencing %s was established at %s", orDash(e.FilePath), fmtT(it.ts))})
			} else {
				clauses = append(clauses, clause{text: fmt.Sprintf(
					"A registry persistence entry referencing %s was recorded (time not recorded)", orDash(e.FilePath))})
			}
			lastProcess = ""

		case model.EventScheduledTaskCreate:
			if dated {
				clauses = append(clauses, clause{text: fmt.Sprintf(
					"A scheduled task (%s) was registered at %s", orDash(e.Extra["task_name"]), fmtT(it.ts))})
			} else {
				clauses = append(clauses, clause{text: fmt.Sprintf(
					"A scheduled task (%s) definition was recorded (time not recorded)", orDash(e.Extra["task_name"]))})
			}
			lastProcess = ""

		case model.EventServiceInstall:
			if dated {
				clauses = append(clauses, clause{text: fmt.Sprintf(
					"A service (%s) was installed at %s, image path %s",
					orDash(e.Extra["service_name"]), fmtT(it.ts), orDash(e.FilePath))})
			} else {
				clauses = append(clauses, clause{text: fmt.Sprintf(
					"A service (%s) with image path %s was recorded (time not recorded)",
					orDash(e.Extra["service_name"]), orDash(e.FilePath))})
			}
			lastProcess = ""

		case model.EventNetworkConnection:
			word := "observed"
			if seqOK {
				word = "subsequently observed"
			}
			clauses = append(clauses, clause{text: fmt.Sprintf(
				"A network connection to %s was %s%s", orDash(e.NetworkDest), word, atT(it.ts))})
			lastProcess = ""

		case model.EventDNSQuery:
			clauses = append(clauses, clause{text: fmt.Sprintf(
				"A DNS query for %s was observed%s", orDash(e.NetworkDest), atT(it.ts))})
			lastProcess = ""

		case model.EventLogonExplicitCreds:
			clauses = append(clauses, clause{text: fmt.Sprintf(
				"Explicit credentials for account %s were used%s",
				orDash(e.Extra["target_user_name"]), atT(it.ts))})
			lastProcess = ""

		case model.EventPrivilegedLogon:
			clauses = append(clauses, clause{text: fmt.Sprintf(
				"Privileged/administrative rights were assigned to a logon%s", atT(it.ts))})
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
		prevDated = dated
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

// hostPhrase names a host, or says that none is recorded.
func hostPhrase(h string) string {
	if h == "" {
		return "a host that is not recorded"
	}
	return "host " + h
}

// onHost opens a sentence with the host, or says that none is recorded.
func onHost(h string) string {
	if h == "" {
		return "On a host that is not recorded"
	}
	return "On host " + h
}

// isDated reports whether t is a recorded time. The zero time and year 1 are
// how an undated observation is carried; neither is an instant.
func isDated(t time.Time) bool { return !t.IsZero() && t.UTC().Year() > 1 }

// atT is " at HH:MM:SS UTC" for a recorded time and " (time not recorded)"
// otherwise, so no clause shows a time the evidence does not have.
func atT(t time.Time) string {
	if !isDated(t) {
		return " (time not recorded)"
	}
	return " at " + fmtT(t)
}

func fmtT(t time.Time) string {
	if !isDated(t) {
		return "time not recorded"
	}
	return t.UTC().Format("15:04:05 UTC")
}
