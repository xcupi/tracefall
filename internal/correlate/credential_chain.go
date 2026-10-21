package correlate

import (
	"fmt"
	"sort"
	"time"

	"tracefall/internal/authseq"
	"tracefall/internal/model"
)

// Windowing constants are local policy; the neutral authseq helper is shared
// by detection and correlation without either engine depending on the other.
const (
	credBruteForceThreshold     = 3
	credBruteForceGapWindow     = 10 * time.Minute
	credBruteForceSuccessWindow = 30 * time.Minute
	credAbuseLookWindow         = 2 * time.Hour
)

// BuildCredentialChains links compatible authentication observations. Failures
// are partitioned by acquisition, account/domain, source and logon context;
// each success closes its run even while other failures continue. Explicit
// credential attempts produce qualified hypotheses, never causal execution or
// credential-abuse claims from account/process names and time alone.
func BuildCredentialChains(caseID string, events []model.Event) []model.Correlation {
	var out []model.Correlation
	out = append(out, buildBruteForceChains(caseID, events)...)
	out = append(out, buildSequenceBruteForceChains(caseID, events)...)
	out = append(out, buildCredentialAbuseChains(caseID, events)...)
	return out
}

func buildBruteForceChains(caseID string, events []model.Event) []model.Correlation {
	var out []model.Correlation
	for _, chain := range authseq.BeforeSuccess(events, credBruteForceThreshold, credBruteForceGapWindow, credBruteForceSuccessWindow) {
		if chain[0].CaseID != "" && chain[0].CaseID != caseID {
			continue
		}
		out = append(out, buildTypedChainCorrelation(caseID, model.CorrelationCredentialChain, "Brute-force chain", chain))
	}
	return out
}

func buildCredentialAbuseChains(caseID string, events []model.Event) []model.Correlation {
	// Name/time alone is useful triage, not an execution or abuse finding.
	// 4648's subject session belongs to the caller, NOT to the target account.
	domain := func(e model.Event) string {
		if d := e.Extra["subject_domain"]; d != "" {
			return d
		}
		return e.Extra["target_domain"]
	}
	usable := func(e model.Event) bool { return processTime(e) && e.ArtifactType != model.ArtifactMemoryAnalysis }
	ordered := func(a, b model.Event) bool {
		return usable(a) && usable(b) && b.Timestamp.After(a.Timestamp) && b.Timestamp.Sub(a.Timestamp) <= credAbuseLookWindow
	}
	same := func(a, b model.Event) bool { return a.Host != "" && processScope(a) == processScope(b) }
	creates := byType(events, model.EventProcessCreate)
	byPID := indexEvents(creates, func(e model.Event) string { return fmt.Sprintf("%s\x00%d", processScope(e), e.PID) })
	byAccount := indexEvents(creates, func(e model.Event) string { return processScope(e) + "\x00" + e.User })
	follows := indexEvents(events, func(e model.Event) string { return processScope(e) + "\x00" + e.User })
	creds := byType(events, model.EventLogonExplicitCreds)
	sort.Slice(creds, func(i, j int) bool {
		if !creds[i].Timestamp.Equal(creds[j].Timestamp) {
			return creds[i].Timestamp.Before(creds[j].Timestamp)
		}
		return creds[i].ID < creds[j].ID
	})
	var out []model.Correlation
	for _, cred := range creds {
		target := cred.Extra["target_user_name"]
		if target == "" || !usable(cred) || (cred.CaseID != "" && cred.CaseID != caseID) {
			continue
		}
		if server := cred.Extra["target_server_name"]; server != "" && server != "-" && server != "localhost" && server != cred.Host {
			continue
		}
		var proc model.Event
		candidateDomains := map[string]bool{}
		count := 0
		for _, p := range byAccount[processScope(cred)+"\x00"+target] {
			if !same(cred, p) || !ordered(cred, p) || (cred.Extra["target_domain"] != "" && domain(p) != cred.Extra["target_domain"]) {
				continue
			}
			if id := cred.Extra["target_logon_id"]; id != "" && (id == "0x0" || id != p.Extra["logon_id"]) {
				continue
			}
			if guid := cred.Extra["target_logon_guid"]; guid != "" && guid != p.Extra["logon_guid"] {
				continue
			}
			candidateDomains[domain(p)] = true
			if count == 0 || p.Timestamp.Before(proc.Timestamp) {
				proc = p
				count = 1
			} else if p.Timestamp.Equal(proc.Timestamp) {
				count++
			}
		}
		if count != 1 || (cred.Extra["target_domain"] == "" && len(candidateDomains) > 1) {
			continue
		}
		var next model.Event
		count = 0
		for _, e := range follows[processScope(proc)+"\x00"+proc.User] {
			if !same(proc, e) || !ordered(proc, e) || domain(e) != domain(proc) {
				continue
			}
			if a, c := proc.Extra["logon_id"], e.Extra["logon_id"]; a != "" && c != "" && a != c {
				continue
			}
			if a, c := proc.Extra["process_guid"], e.Extra["process_guid"]; e.EventType != model.EventProcessCreate && a != "" && c != "" && a != c {
				continue
			}
			match := false
			switch e.EventType {
			case model.EventProcessCreate:
				match = e.ParentProcessName == proc.ProcessName && (e.PPID == 0 || proc.PID == 0 || e.PPID == proc.PID)
			case model.EventNetworkConnection, model.EventRegistryRunKey, model.EventScheduledTaskCreate:
				match = e.ProcessName == proc.ProcessName && (e.PID == 0 || proc.PID == 0 || e.PID == proc.PID)
			}
			if e.EventType == model.EventProcessCreate {
				if g := e.Extra["parent_process_guid"]; g != "" && g != proc.Extra["process_guid"] {
					match = false
				}
			}
			if exit := proc.Extra["exit_time"]; exit != "" {
				end, err := time.Parse(time.RFC3339Nano, exit)
				if err != nil || !e.Timestamp.Before(end) {
					match = false
				}
			}
			if proc.PID > 0 {
				for _, p := range byPID[fmt.Sprintf("%s\x00%d", processScope(proc), proc.PID)] {
					if p.ID == proc.ID {
						continue
					}
					if !processTime(p) || (!p.Timestamp.Before(proc.Timestamp) && !p.Timestamp.After(e.Timestamp)) {
						match = false
						break
					}
				}
			}
			if !match {
				continue
			}
			if count == 0 || e.Timestamp.Before(next.Timestamp) {
				next = e
				count = 1
			} else if e.Timestamp.Equal(next.Timestamp) {
				count++
			}
		}
		if count != 1 {
			continue
		}
		c := buildTypedChainCorrelation(caseID, model.CorrelationCredentialChain, "Hypothetical explicit-credential relationship", []model.Event{cred, proc, next})
		c.Description = "Hypothetical temporal relationship between an explicit-credential attempt and account-name/process-name observations in compatible acquisition, domain and available session context. These observations do not establish successful credential use or causal execution; absent target-session binding, they do not identify execution caused by this attempt."
		if cred.Extra["target_domain"] == "" {
			c.Description += " Unknown target domain: only an account-name hypothesis is available, not an identified target account."
		}
		out = append(out, c)
	}
	return out
}

// withinWindow reports whether a and b are within window of each other,
// regardless of order.
func withinWindow(a, b time.Time, window time.Duration) bool {
	d := b.Sub(a)
	if d < 0 {
		d = -d
	}
	return d <= window
}
