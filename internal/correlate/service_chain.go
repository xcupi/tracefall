package correlate

import (
	"strings"

	"tracefall/internal/model"
)

// serviceChainWindow bounds how far apart a service installation, the
// service's process actually starting, and any network connection that
// process made can be while still being considered one narrative -- see
// activityLookWindow's identical rationale in activity_chain.go.
const serviceChainWindow = activityLookWindow

// BuildServiceChains retains a labelled contextual association between a
// service configuration and one subsequent creation of the same full-path
// executable in the same acquisition. Configuration is not proof of a service
// launch. Network observations additionally require recorded process identity.
func BuildServiceChains(caseID string, events []model.Event) []model.Correlation {
	events = chainHostKeys(events)
	creates := sortedChainEvents(byType(events, model.EventProcessCreate))
	var out []model.Correlation
	for _, install := range sortedChainEvents(byType(events, model.EventServiceInstall)) {
		var candidates []model.Event
		for _, proc := range creates {
			if install.ProcessName != "" && proc.ProcessName == install.ProcessName && sameExecutablePath(install.ProcessPath, proc.ProcessPath) && install.CaseID == caseID && sameEvidenceScope(install, proc) && processTime(install) && processTime(proc) && proc.Timestamp.After(install.Timestamp) && proc.Timestamp.Sub(install.Timestamp) <= serviceChainWindow {
				candidates = append(candidates, proc)
			}
		}
		if len(candidates) != 1 {
			continue
		}
		proc := candidates[0]
		chain := []model.Event{install, proc}
		if n, ok := networkFor(proc, byType(events, model.EventNetworkConnection), creates); ok {
			chain = append(chain, n)
		}
		c := buildTypedChainCorrelation(caseID, model.CorrelationServiceChain, "Contextual service chain", chain)
		c.Description = "Service configuration and a subsequent process creation reference the same full executable path. This contextual association does not establish that the service launched that process. Network attribution, when present, uses recorded process identity compatible with observed starts and exits; unrecorded exits and unobserved PID reuse remain uncertain."
		out = append(out, c)
	}
	return out
}

// Configuration paths containing arguments are intentionally not guessed into
// executable identities. Keep the raw configuration; abstain when uncertain.
func sameExecutablePath(a, b string) bool {
	clean := func(s string) string {
		return strings.ToLower(strings.ReplaceAll(strings.Trim(strings.TrimSpace(s), "\""), "\\", "/"))
	}
	a, b = clean(a), clean(b)
	return a != "" && (strings.HasPrefix(a, "/") || (len(a) > 2 && a[1:3] == ":/")) && a == b
}
