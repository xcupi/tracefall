package winevent_test

import (
	"strings"
	"testing"
)

// Added after independent review: mutations that survived the first test set.

// A WMI client-failure operation text can carry a command line; it must pass
// through the same redaction as the 5860 query.
func TestWMI5858_OperationIsRedacted(t *testing.T) {
	d := fail5858()
	d["Operation"] = "Start IWbemServices::ExecQuery - SELECT * FROM X /* --password=hunter2 */"
	e, ok := g02Direct(wmiIn(5858, d))
	if !ok {
		t.Fatal("5858 not mapped")
	}
	if strings.Contains(e.Extra["operation"], "hunter2") {
		t.Errorf("secret kept in operation: %q", e.Extra["operation"])
	}
}

// The limitation text is part of the contract: a configuration or registration
// record must never be worded as proof of intent or persistence.
func TestG02LimitationsDoNotOverclaim(t *testing.T) {
	h := map[string]string{"Timestamp": "2026-03-04T05:06:07.000Z", "Domain": "LAB", "User": "alice", "SID": "S-1-5-21-1001"}
	e, ok := g02Direct(cfgInput(1013, h))
	if !ok {
		t.Fatal("1013 not mapped")
	}
	l := strings.ToLower(e.Extra["limitations"])
	if !strings.Contains(l, "does not establish a deliberate attempt") || !strings.Contains(l, "does not establish an actor") {
		t.Errorf("1013 limitations must deny deliberate intent and actor: %q", e.Extra["limitations"])
	}
	e, ok = g02Direct(wmiIn(5860, ess5860()))
	if !ok {
		t.Fatal("5860 not mapped")
	}
	l = strings.ToLower(e.Extra["limitations"])
	for _, want := range []string{"does not establish that any event matched", "malicious intent", "is not the persistent subscription"} {
		if !strings.Contains(l, want) {
			t.Errorf("5860 limitations lack %q: %q", want, e.Extra["limitations"])
		}
	}
	if strings.Contains(l, "persistence is established") || strings.Contains(l, "persistence established") {
		t.Errorf("5860 must not claim persistence: %q", e.Extra["limitations"])
	}
}
