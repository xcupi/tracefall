// Package egress decides what may leave the server for an outside service.
//
// Tracefall's analysis needs nothing from outside. Anything that is sent out
// (a file hash to a reputation service, case facts to a language model) is an
// enrichment, and every enrichment is gated by the egress level of the case.
// The level is chosen per case by an analyst, defaults to none, and is
// recorded in the case's audit trail whenever it changes or something is sent.
//
// The levels are ordered; a higher level allows everything a lower one does:
//
//	none           nothing leaves the server.
//	hashes         file hashes (MD5, SHA-1, SHA-256) of files that were in the
//	               evidence, and nothing else: no file name, path, host, user,
//	               case name or event. A hash says "this exact content"; it
//	               reveals to the service that someone holds that content.
//	pseudonymized  structured facts about findings and the events they cite
//	               (titles, rules, times, process names, command lines, paths,
//	               addresses) with every name, address, identifier and hash
//	               replaced by a token that only this server can reverse, and
//	               secrets removed. Sent to a language model to draft a summary.
//	               Includes everything "hashes" allows.
//	full           case content as it is. Reserved: no feature uses it yet.
package egress

import (
	"fmt"
	"strings"
)

// Level is how much of a case may leave the server.
type Level string

const (
	None          Level = "none"
	Hashes        Level = "hashes"
	Pseudonymized Level = "pseudonymized"
	Full          Level = "full"
)

var order = []Level{None, Hashes, Pseudonymized, Full}

// Available lists the levels some feature of this build uses. A level that is
// reserved is understood but cannot be selected, so a setting never promises
// protection or exposure that no code implements.
var Available = []Level{None, Hashes, Pseudonymized}

// Parse accepts a level name, case-insensitively.
func Parse(s string) (Level, error) {
	l := Level(strings.ToLower(strings.TrimSpace(s)))
	for _, o := range order {
		if o == l {
			return l, nil
		}
	}
	return None, fmt.Errorf("egress: unknown level %q (expected one of none, hashes, pseudonymized, full)", s)
}

// Selectable reports whether a level may be chosen in this build.
func (l Level) Selectable() bool {
	for _, a := range Available {
		if a == l {
			return true
		}
	}
	return false
}

func (l Level) rank() int {
	for i, o := range order {
		if o == l {
			return i
		}
	}
	return 0 // an unknown value allows nothing
}

// AtLeast reports whether l allows everything min allows.
func (l Level) AtLeast(min Level) bool { return l.rank() >= min.rank() }

// Describe is what an analyst is told a level lets out.
func (l Level) Describe() string {
	switch l {
	case None:
		return "Nothing leaves the server. Analysis, findings and the report are unaffected."
	case Hashes:
		return "File hashes (MD5, SHA-1, SHA-256) of files found in the evidence may be sent to a reputation service. No file name, path, host, user, case name or event is sent."
	case Pseudonymized:
		return "Findings and the events they cite may be sent to a language model with every name, address, identifier and hash replaced by a token only this server can reverse, and secrets removed. Timestamps, process names and the shape of the activity are sent as they are. Includes file hashes."
	case Full:
		return "Reserved: case content as it is. No feature uses it yet."
	}
	return ""
}
