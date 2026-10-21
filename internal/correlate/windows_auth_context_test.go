package correlate

import (
	"testing"
	"time"

	"tracefall/internal/model"
)

// A guessed password is usually used through a different logon type or
// authentication package than the guesses (NTLM network guesses, then an RDP
// or Kerberos logon), and a host acquired twice stores the same account's
// events under two collections. Neither may hide the sequence.
func TestWindowsAuth_SuccessThroughADifferentLogonContextStillChains(t *testing.T) {
	for _, dimension := range []string{"logon_type", "auth_package", "logon_process", "workstation", "collection", "domain_unrecorded", "source_unrecorded"} {
		t.Run(dimension, func(t *testing.T) {
			base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			var events []model.Event
			for i := 0; i < 4; i++ {
				typ := model.EventLogonFailure
				if i == 3 {
					typ = model.EventLogonSuccess
				}
				events = append(events, model.Event{ID: string(rune('a' + i)), CaseID: "case01", CollectionID: "collection01", Host: "host01", User: "alice",
					NetworkSource: "203.0.113.1", EventType: typ, Timestamp: base.Add(time.Duration(i) * time.Minute),
					Extra: map[string]string{"target_domain": "domain01", "logon_type": "3", "auth_package": "NTLM", "logon_process": "NtLmSsp", "workstation_name": "ws01"}})
			}
			s := &events[3]
			switch dimension {
			case "logon_type":
				s.Extra["logon_type"] = "10"
			case "auth_package":
				s.Extra["auth_package"] = "Kerberos"
			case "logon_process":
				s.Extra["logon_process"] = "User32"
			case "workstation":
				s.Extra["workstation_name"] = "ws02"
			case "collection":
				s.CollectionID = "collection02"
			case "domain_unrecorded":
				delete(s.Extra, "target_domain")
			case "source_unrecorded":
				s.NetworkSource = ""
			}
			if got := buildBruteForceChains("case01", events); len(got) != 1 {
				t.Fatalf("sequence lost across %s: %+v", dimension, got)
			}
		})
	}
}
