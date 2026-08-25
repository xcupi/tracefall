package detect

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/procclass"
)

// All returns every registered detection rule, in a fixed order so
// Analyze output ordering is stable across runs.
func All() []Rule {
	return []Rule{
		officeSpawnsPowerShell{},
		powershellEncodedCommand{},
		newRegistryRunKey{},
		newScheduledTask{},
		suspiciousProcessChain{},
		bruteForceThenSuccess{},
		executionThenPersistence{},
	}
}

// ---------- Rule 1: Office application spawning PowerShell ----------

type officeSpawnsPowerShell struct{}

func (officeSpawnsPowerShell) ID() string { return "office-spawns-powershell" }

func (r officeSpawnsPowerShell) Evaluate(events []model.Event) []model.Finding {
	var findings []model.Finding
	for _, e := range byType(events, model.EventProcessCreate) {
		if !procclass.IsOffice(e.ParentProcessName) || !procclass.IsPowerShell(e.ProcessName) {
			continue
		}
		title := fmt.Sprintf("Office application %s spawned %s", e.ParentProcessName, e.ProcessName)
		desc := fmt.Sprintf(
			"%s launched %s (PID %d) at %s on host %s, user %s. Office applications spawning a scripting "+
				"interpreter is a common initial-execution pattern for malicious document macros/payloads.",
			e.ParentProcessName, e.ProcessName, e.PID, e.Timestamp.Format(time.RFC3339), e.Host, orDash(e.User))
		findings = append(findings, newFinding(e.CaseID, r.ID(), title, model.SeverityHigh, model.ConfidenceMedium,
			desc, []string{"T1059.001", "T1204.002"}, []model.Event{e}))
	}
	return findings
}

// ---------- Rule 2: PowerShell with suspicious encoded command indicators ----------

type powershellEncodedCommand struct{}

func (powershellEncodedCommand) ID() string { return "powershell-encoded-command" }

var scriptSuspiciousIndicators = []struct {
	pattern *regexp.Regexp
	label   string
}{
	{regexp.MustCompile(`(?i)-enc\b|-encodedcommand\b`), "encoded command flag"},
	{regexp.MustCompile(`(?i)frombase64string`), "Base64 decode (FromBase64String)"},
	{regexp.MustCompile(`(?i)-w(indowstyle)?\s+hidden`), "hidden window style"},
	{regexp.MustCompile(`(?i)-nop\b|-noprofile\b`), "no-profile execution"},
	{regexp.MustCompile(`(?i)downloadstring|downloadfile|net\.webclient`), "network download cmdlet"},
	{regexp.MustCompile(`(?i)iex\b|invoke-expression`), "dynamic code execution (IEX)"},
	{regexp.MustCompile(`(?i)-bypass\b`), "execution policy bypass"},
}

// indicatorsIn returns the labels of every suspicious pattern found in s.
func indicatorsIn(s string) []string {
	var found []string
	for _, ind := range scriptSuspiciousIndicators {
		if ind.pattern.MatchString(s) {
			found = append(found, ind.label)
		}
	}
	return found
}

func (r powershellEncodedCommand) Evaluate(events []model.Event) []model.Finding {
	var findings []model.Finding

	for _, e := range byType(events, model.EventProcessCreate) {
		if !procclass.IsPowerShell(e.ProcessName) {
			continue
		}
		indicators := indicatorsIn(e.CommandLine)
		if len(indicators) == 0 {
			continue
		}
		findings = append(findings, r.finding(e, e.CommandLine, indicators))
	}

	for _, e := range byType(events, model.EventPowerShellScript) {
		indicators := indicatorsIn(e.CommandLine)
		if len(indicators) == 0 {
			continue
		}
		findings = append(findings, r.finding(e, e.CommandLine, indicators))
	}

	return findings
}

func (r powershellEncodedCommand) finding(e model.Event, cmd string, indicators []string) model.Finding {
	title := "PowerShell execution with suspicious command indicators"
	desc := fmt.Sprintf(
		"PowerShell activity on host %s (user %s) at %s matched %d suspicious indicator(s): %s. Command/script: %s",
		e.Host, orDash(e.User), e.Timestamp.Format(time.RFC3339), len(indicators), strings.Join(indicators, ", "), truncate(cmd, 300))
	severity := model.SeverityMedium
	confidence := model.ConfidenceMedium
	if len(indicators) >= 2 {
		severity = model.SeverityHigh
	}
	return newFinding(e.CaseID, r.ID(), title, severity, confidence, desc,
		[]string{"T1059.001", "T1027"}, []model.Event{e})
}

// ---------- Rule 3: New Registry Run Key persistence ----------

type newRegistryRunKey struct{}

func (newRegistryRunKey) ID() string { return "new-registry-run-key" }

func (r newRegistryRunKey) Evaluate(events []model.Event) []model.Finding {
	var findings []model.Finding
	for _, e := range byType(events, model.EventRegistryRunKey) {
		suspicious := procclass.HasSuspiciousPath(e.FilePath)
		severity, confidence := model.SeverityLow, model.ConfidenceLow
		if suspicious {
			severity, confidence = model.SeverityHigh, model.ConfidenceMedium
		}
		title := fmt.Sprintf("Registry Run Key persistence: %s", orDash(e.Extra["value_name"]))
		desc := fmt.Sprintf(
			"A Run key entry %q pointing to %q was observed under %s on host %s at %s. A single Run key "+
				"is a weak indicator on its own -- this is reported as an observed persistence mechanism, "+
				"not a malware verdict; see correlated findings for corroborating execution evidence.",
			orDash(e.Extra["value_name"]), orDash(e.FilePath), e.RegistryPath, e.Host, e.Timestamp.Format(time.RFC3339))
		if suspicious {
			desc += " The target path is located in a user-writable/non-standard directory, which raises confidence."
		}
		findings = append(findings, newFinding(e.CaseID, r.ID(), title, severity, confidence, desc,
			[]string{"T1547.001"}, []model.Event{e}))
	}
	return findings
}

// ---------- Rule 4: New Scheduled Task persistence ----------

type newScheduledTask struct{}

func (newScheduledTask) ID() string { return "new-scheduled-task" }

func (r newScheduledTask) Evaluate(events []model.Event) []model.Finding {
	var findings []model.Finding
	for _, e := range byType(events, model.EventScheduledTaskCreate) {
		lolbin := procclass.IsScriptHost(e.ProcessName) || procclass.IsPowerShell(e.ProcessName)
		suspiciousPath := procclass.HasSuspiciousPath(e.ProcessPath) || procclass.HasSuspiciousPath(e.CommandLine)
		severity, confidence := model.SeverityLow, model.ConfidenceLow
		if lolbin || suspiciousPath {
			severity, confidence = model.SeverityHigh, model.ConfidenceMedium
		}
		title := fmt.Sprintf("Scheduled Task persistence: %s", orDash(e.Extra["task_name"]))
		desc := fmt.Sprintf(
			"Scheduled Task %q was registered by %s at %s on host %s, action: %q. A single scheduled task "+
				"is a weak indicator on its own -- reported as an observed persistence mechanism.",
			orDash(e.Extra["task_name"]), orDash(e.User), e.Timestamp.Format(time.RFC3339), e.Host, truncate(e.CommandLine, 200))
		if lolbin {
			desc += fmt.Sprintf(" The task action invokes %s, a common execution/persistence living-off-the-land binary.", e.ProcessName)
		}
		if suspiciousPath {
			desc += " The task action references a user-writable/non-standard directory."
		}
		findings = append(findings, newFinding(e.CaseID, r.ID(), title, severity, confidence, desc,
			[]string{"T1053.005"}, []model.Event{e}))
	}
	return findings
}

// ---------- Rule 5: Suspicious process execution chain ----------

type suspiciousProcessChain struct{}

func (suspiciousProcessChain) ID() string { return "suspicious-process-chain" }

func (r suspiciousProcessChain) Evaluate(events []model.Event) []model.Finding {
	var findings []model.Finding
	for _, e := range byType(events, model.EventProcessCreate) {
		parentIsInterpreter := procclass.IsPowerShell(e.ParentProcessName) || e.ParentProcessName == "cmd.exe"
		if !parentIsInterpreter {
			continue
		}
		childSuspicious := procclass.HasSuspiciousPath(e.ProcessPath) || procclass.IsScriptHost(e.ProcessName)
		if !childSuspicious {
			continue
		}
		title := fmt.Sprintf("Suspicious execution chain: %s -> %s", e.ParentProcessName, e.ProcessName)
		desc := fmt.Sprintf(
			"%s spawned %s (PID %d, path %q) at %s on host %s. A scripting interpreter launching a process "+
				"from a non-standard location or invoking another living-off-the-land binary is consistent "+
				"with payload staging/execution.",
			e.ParentProcessName, e.ProcessName, e.PID, orDash(e.ProcessPath), e.Timestamp.Format(time.RFC3339), e.Host)
		findings = append(findings, newFinding(e.CaseID, r.ID(), title, model.SeverityHigh, model.ConfidenceMedium,
			desc, []string{"T1059", "T1059.001"}, []model.Event{e}))
	}
	return findings
}

// ---------- Rule 6: Multiple failed logons followed by successful logon ----------

type bruteForceThenSuccess struct{}

func (bruteForceThenSuccess) ID() string { return "brute-force-then-success" }

const (
	bruteForceThreshold     = 3
	bruteForceGapWindow     = 10 * time.Minute // max gap between consecutive failures counted as one burst
	bruteForceSuccessWindow = 30 * time.Minute // max time from last failure to the success that follows
)

func (r bruteForceThenSuccess) Evaluate(events []model.Event) []model.Finding {
	type key struct{ host, user string }
	failuresByKey := map[key][]model.Event{}
	successesByKey := map[key][]model.Event{}

	for _, e := range byType(events, model.EventLogonFailure) {
		k := key{e.Host, e.User}
		failuresByKey[k] = append(failuresByKey[k], e)
	}
	for _, e := range byType(events, model.EventLogonSuccess) {
		k := key{e.Host, e.User}
		successesByKey[k] = append(successesByKey[k], e)
	}

	var findings []model.Finding
	for k, failures := range failuresByKey {
		sort.Slice(failures, func(i, j int) bool { return failures[i].Timestamp.Before(failures[j].Timestamp) })

		// Build contiguous bursts of failures where consecutive gaps stay within bruteForceGapWindow.
		var burst []model.Event
		flush := func() {
			if len(burst) < bruteForceThreshold {
				burst = nil
				return
			}
			last := burst[len(burst)-1]
			for _, s := range successesByKey[k] {
				if s.Timestamp.After(last.Timestamp) && withinWindow(last.Timestamp, s.Timestamp, bruteForceSuccessWindow) {
					supporting := append(append([]model.Event{}, burst...), s)
					title := fmt.Sprintf("%d failed logons followed by success for %s", len(burst), orDash(k.user))
					desc := fmt.Sprintf(
						"User %q on host %s had %d failed logon attempts between %s and %s, followed by a "+
							"successful logon at %s. This pattern is consistent with brute-force or password-"+
							"spray credential access followed by successful authentication.",
						orDash(k.user), k.host, len(burst), burst[0].Timestamp.Format(time.RFC3339),
						last.Timestamp.Format(time.RFC3339), s.Timestamp.Format(time.RFC3339))
					findings = append(findings, newFinding(s.CaseID, r.ID(), title, model.SeverityHigh, model.ConfidenceHigh,
						desc, []string{"T1110", "T1078"}, supporting))
					break // one finding per burst is enough
				}
			}
			burst = nil
		}

		for i, f := range failures {
			if i > 0 && !withinWindow(failures[i-1].Timestamp, f.Timestamp, bruteForceGapWindow) {
				flush()
			}
			burst = append(burst, f)
		}
		flush()
	}
	return findings
}

// ---------- Rule 7: Execution -> persistence temporal correlation ----------

type executionThenPersistence struct{}

func (executionThenPersistence) ID() string { return "execution-persistence-temporal" }

const persistenceWindow = 15 * time.Minute

func (r executionThenPersistence) Evaluate(events []model.Event) []model.Finding {
	execs := append(append([]model.Event{}, byType(events, model.EventProcessCreate)...), byType(events, model.EventPrefetchExecution)...)

	var persistence []model.Event
	persistence = append(persistence, byType(events, model.EventRegistryRunKey)...)
	persistence = append(persistence, byType(events, model.EventScheduledTaskCreate)...)

	var findings []model.Finding
	for _, p := range persistence {
		target := persistenceTarget(p)
		if target == "" {
			continue
		}
		// One finding per persistence event, backed by the single best
		// matching execution -- not one per (exec, persistence) pair.
		// Process-create (4688) is authoritative evidence of execution;
		// Prefetch only approximates it (see pecmd's confidence note), so
		// it's used only when no process-create match exists.
		ex, ok := bestExecutionMatch(execs, p, target)
		if !ok {
			continue
		}
		mechanism := "registry Run key"
		techniques := []string{"T1547.001"}
		if p.EventType == model.EventScheduledTaskCreate {
			mechanism = "scheduled task"
			techniques = []string{"T1053.005"}
		}
		if procclass.IsPowerShell(ex.ProcessName) {
			techniques = append(techniques, "T1059.001")
		}
		title := fmt.Sprintf("%s executed then established persistence via %s", target, mechanism)
		desc := fmt.Sprintf(
			"%q executed at %s on host %s, then a %s referencing the same executable was established at "+
				"%s (%s later). Execution immediately followed by persistence for the same "+
				"binary is a strong indicator of an intentional persistence step, not incidental activity.",
			target, ex.Timestamp.Format(time.RFC3339), p.Host, mechanism,
			p.Timestamp.Format(time.RFC3339), humanizeDuration(p.Timestamp.Sub(ex.Timestamp)))
		findings = append(findings, newFinding(p.CaseID, r.ID(), title, model.SeverityCritical, model.ConfidenceHigh,
			desc, techniques, []model.Event{ex, p}))
	}
	return findings
}

// bestExecutionMatch returns the execution event that best explains
// persistence event p establishing itself for target: the process-create
// event nearest before p if one exists within window, otherwise the
// nearest Prefetch execution record.
func bestExecutionMatch(execs []model.Event, p model.Event, target string) (model.Event, bool) {
	var bestCreate, bestPrefetch model.Event
	foundCreate, foundPrefetch := false, false

	for _, ex := range execs {
		if ex.Host != p.Host || execTarget(ex) != target {
			continue
		}
		if !p.Timestamp.After(ex.Timestamp) || !withinWindow(ex.Timestamp, p.Timestamp, persistenceWindow) {
			continue
		}
		switch ex.EventType {
		case model.EventProcessCreate:
			if !foundCreate || ex.Timestamp.After(bestCreate.Timestamp) {
				bestCreate, foundCreate = ex, true
			}
		case model.EventPrefetchExecution:
			if !foundPrefetch || ex.Timestamp.After(bestPrefetch.Timestamp) {
				bestPrefetch, foundPrefetch = ex, true
			}
		}
	}
	if foundCreate {
		return bestCreate, true
	}
	return bestPrefetch, foundPrefetch
}

// persistenceTarget extracts the executable basename a persistence event
// points at, for matching against prior execution events.
func persistenceTarget(e model.Event) string {
	if e.ProcessName != "" {
		return e.ProcessName
	}
	return ""
}

func execTarget(e model.Event) string {
	return e.ProcessName
}

// humanizeDuration renders a short elapsed-time phrase for finding
// descriptions, avoiding a misleading "0 minute(s) later" for gaps under
// a minute.
func humanizeDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d second(s)", int(d.Seconds()))
	}
	return fmt.Sprintf("%d minute(s)", int(d.Minutes()))
}

func orDash(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
