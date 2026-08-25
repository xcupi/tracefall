// Package detect is Tracefall's deterministic detection engine. Every
// Rule here is a pure function of the case's normalized events -- no
// network calls, no LLM, no randomness -- so running Analyze twice on the
// same evidence always produces the same set of findings. That's the
// non-negotiable property the whole product design (see ARCHITECTURE.md)
// depends on.
//
// A rule must never assert a verdict ("this is malware") from a single
// weak indicator. Where a rule's signal is inherently weak on its own
// (e.g. one registry Run key), its finding is worded as an observation
// ("persistence mechanism observed") at low/medium confidence, not an
// accusation -- stronger claims require corroborating evidence, which is
// what the correlation engine (internal/correlate) builds out of multiple
// findings/events.
package detect

import (
	"time"

	"tracefall/internal/model"
)

// Rule evaluates one detection over a case's full, timestamp-sorted event
// set and returns zero or more findings. A rule may fire more than once
// (e.g. once per suspicious process) or not at all.
type Rule interface {
	ID() string
	Evaluate(events []model.Event) []model.Finding
}

// newFinding is a small constructor shared by every rule to keep Finding
// construction consistent (UTC timestamps, sorted supporting events).
func newFinding(caseID, ruleID, title, severity, confidence, description string, techniques []string, supporting []model.Event) model.Finding {
	first, last := timeRange(supporting)
	ids := make([]string, len(supporting))
	for i, e := range supporting {
		ids[i] = e.ID
	}
	return model.Finding{
		CaseID:           caseID,
		RuleID:           ruleID,
		Title:            title,
		Severity:         severity,
		Confidence:       confidence,
		Description:      description,
		SupportingEvents: ids,
		Techniques:       techniques,
		FirstSeen:        first,
		LastSeen:         last,
		CreatedAt:        time.Now().UTC(),
	}
}

func timeRange(events []model.Event) (first, last time.Time) {
	for i, e := range events {
		if i == 0 || e.Timestamp.Before(first) {
			first = e.Timestamp
		}
		if i == 0 || e.Timestamp.After(last) {
			last = e.Timestamp
		}
	}
	return first, last
}

func byType(events []model.Event, t string) []model.Event {
	var out []model.Event
	for _, e := range events {
		if e.EventType == t {
			out = append(out, e)
		}
	}
	return out
}

func withinWindow(a, b time.Time, window time.Duration) bool {
	d := b.Sub(a)
	if d < 0 {
		d = -d
	}
	return d <= window
}
