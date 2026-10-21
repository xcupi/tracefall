package detect

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"tracefall/internal/authseq"
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
		// Phase 4 additions -- see docs/detection-engine.md.
		officeSpawnsScriptInterpreter{},
		suspiciousParentChildLineage{},
		servicePersistence{},
		registryPersistenceExtended{},
		explicitCredentialUse{},
		privilegedLogonObserved{},
		networkAfterExecution{},
		remoteLogonObserved{},
		memoryProcessSignals{},
		// Linux and server logs. See rules_hostlogs.go.
		bruteForceSequence{},
		webAttackIndicators{},
		accountChangeObserved{},
		databaseInsecureAccount{},
		systemChangeCommand{},
		// Packet captures. See rules_network.go.
		rdpConnectionBurst{},
		executableFromBareAddress{},
	}
}

// ---------- Rule 1: Office application spawning PowerShell ----------

type officeSpawnsPowerShell struct{}

func (officeSpawnsPowerShell) ID() string { return "office-spawns-powershell" }

// Inputs names the event types this rule reads. Every event it can
// match is among them; the engine loads only these, so a rule's memory is
// bounded by what it reads, not by the case.
func (r officeSpawnsPowerShell) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventProcessCreate}}
}

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

// Inputs names the event types this rule reads. Every event it can
// match is among them; the engine loads only these, so a rule's memory is
// bounded by what it reads, not by the case.
func (r powershellEncodedCommand) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventProcessCreate, model.EventPowerShellScript}}
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

// Inputs names the event types this rule reads. Every event it can
// match is among them; the engine loads only these, so a rule's memory is
// bounded by what it reads, not by the case.
func (r newRegistryRunKey) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventRegistryRunKey}}
}

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

// Inputs names the event types this rule reads. Every event it can
// match is among them; the engine loads only these, so a rule's memory is
// bounded by what it reads, not by the case.
func (r newScheduledTask) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventScheduledTaskCreate}}
}

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

// Inputs names the event types this rule reads. Every event it can
// match is among them; the engine loads only these, so a rule's memory is
// bounded by what it reads, not by the case.
func (r suspiciousProcessChain) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventProcessCreate}}
}

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

// Inputs names the event types this rule reads. Every event it can
// match is among them; the engine loads only these, so a rule's memory is
// bounded by what it reads, not by the case.
func (r bruteForceThenSuccess) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventLogonFailure, model.EventLogonSuccess}}
}

func (r bruteForceThenSuccess) Evaluate(events []model.Event) []model.Finding {
	var findings []model.Finding
	for _, chain := range authseq.BeforeSuccess(events, bruteForceThreshold, bruteForceGapWindow, bruteForceSuccessWindow) {
		s := chain[len(chain)-1]
		title := fmt.Sprintf("%d failed logons followed by success for %s", len(chain)-1, orDash(s.User))
		desc := fmt.Sprintf("User %q on host %s had %d failed logon attempts followed by a successful authentication. This temporal pattern is consistent with credential guessing; it does not establish that the attempts caused the success.", orDash(s.User), s.Host, len(chain)-1)
		findings = append(findings, newFinding(s.CaseID, r.ID(), title, model.SeverityHigh, model.ConfidenceHigh, desc, []string{"T1110", "T1078"}, chain))
	}
	return findings
}

// ---------- Rule 7: Execution -> persistence temporal correlation ----------

type executionThenPersistence struct{}

func (executionThenPersistence) ID() string { return "execution-persistence-temporal" }

const persistenceWindow = 15 * time.Minute

// Inputs names the event types this rule reads. Every event it can
// match is among them; the engine loads only these, so a rule's memory is
// bounded by what it reads, not by the case.
func (r executionThenPersistence) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventProcessCreate, model.EventPrefetchExecution, model.EventRegistryRunKey, model.EventScheduledTaskCreate, model.EventRegistryPersistence, model.EventServiceInstall}}
}

func (r executionThenPersistence) Evaluate(events []model.Event) []model.Finding {
	execs := append(append([]model.Event{}, byType(events, model.EventProcessCreate)...), byType(events, model.EventPrefetchExecution)...)

	var persistence []model.Event
	persistence = append(persistence, byType(events, model.EventRegistryRunKey)...)
	persistence = append(persistence, byType(events, model.EventScheduledTaskCreate)...)
	// Phase 4: registry persistence locations beyond Run/RunOnce
	// (Winlogon/IFEO/AppInit_DLLs/service ImagePath) and service
	// installation are both "this binary is now set to run again later"
	// mechanisms just as much as a Run key or scheduled task is, so they
	// belong in the same execution-then-persistence temporal check.
	persistence = append(persistence, byType(events, model.EventRegistryPersistence)...)
	persistence = append(persistence, byType(events, model.EventServiceInstall)...)

	// Index execs by (host, target) so each persistence event's lookup
	// below is O(1) instead of rescanning every execution in the case --
	// see rule.go's eventKey/indexEvents doc.
	execsByHostTarget := indexEvents(execs, func(e model.Event) string { return eventKey(e.Host, execTarget(e)) })

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
		ex, ok := bestExecutionMatch(execsByHostTarget[eventKey(p.Host, target)], p, target)
		if !ok {
			continue
		}
		mechanism, techniques := persistenceMechanism(p)
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

// persistenceMechanism names the persistence mechanism a persistence event
// represents and the ATT&CK technique(s) it maps to, for
// executionThenPersistence's finding text. Registry persistence is
// further split by regpersist's classification (stored in
// Extra["registry_persistence_type"] by the parser that produced it) so a
// Winlogon or IFEO hijack is described -- and mapped -- accurately rather
// than lumped in with a plain Run key.
func persistenceMechanism(p model.Event) (mechanism string, techniques []string) {
	switch p.EventType {
	case model.EventScheduledTaskCreate:
		return "scheduled task", []string{"T1053.005"}
	case model.EventServiceInstall:
		return "service installation", []string{"T1543.003"}
	case model.EventRegistryPersistence:
		switch p.Extra["registry_persistence_type"] {
		case "winlogon":
			return "Winlogon Shell/Userinit hijack", []string{"T1547.004"}
		case "ifeo":
			return "Image File Execution Options debugger hijack", []string{"T1546.012"}
		case "appinit_dlls":
			return "AppInit_DLLs", []string{"T1547.001"}
		case "service_image_path":
			return "service ImagePath modification", []string{"T1543.003"}
		default:
			return "registry persistence", []string{"T1547.001"}
		}
	default: // model.EventRegistryRunKey
		return "registry Run key", []string{"T1547.001"}
	}
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

// =====================================================================
// Phase 4 rules -- "Expand Windows DFIR Triage Coverage". Each rule below
// exists because it was explicitly prioritized by that phase and is
// backed by a specific new event type from internal/parsers; none of them
// invent an indicator the underlying artifact doesn't actually carry. See
// docs/detection-engine.md for the full rationale per rule.
// =====================================================================

// ---------- Rule 8: Office application spawning a non-PowerShell script interpreter ----------

type officeSpawnsScriptInterpreter struct{}

func (officeSpawnsScriptInterpreter) ID() string { return "office-spawns-script-interpreter" }

var vbsExt = regexp.MustCompile(`(?i)\.vbs\b`)
var jsExt = regexp.MustCompile(`(?i)\.(js|jse)\b`)

// scriptTechniqueFor maps a child process (and, where the interpreter
// itself doesn't determine the scripting language, its command line) to
// the ATT&CK sub-technique the evidence actually supports. wscript.exe
// and cscript.exe can run either VBScript or JScript -- rather than
// guessing from the process name alone (explicitly disallowed -- "do not
// map ATT&CK based purely on process names"), the command line's script
// file extension is inspected; if that's inconclusive too, only the
// parent T1059 (Command and Scripting Interpreter) is returned, which
// doesn't claim a specific language.
func scriptTechniqueFor(processName, commandLine string) string {
	switch processName {
	case "cmd.exe":
		return "T1059.003"
	case "mshta.exe":
		return "T1218.005"
	case "wscript.exe", "cscript.exe":
		switch {
		case vbsExt.MatchString(commandLine):
			return "T1059.005"
		case jsExt.MatchString(commandLine):
			return "T1059.007"
		default:
			return "T1059"
		}
	default:
		return "T1059"
	}
}

// Inputs names the event types this rule reads. Every event it can
// match is among them; the engine loads only these, so a rule's memory is
// bounded by what it reads, not by the case.
func (r officeSpawnsScriptInterpreter) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventProcessCreate}}
}

func (r officeSpawnsScriptInterpreter) Evaluate(events []model.Event) []model.Finding {
	var findings []model.Finding
	for _, e := range byType(events, model.EventProcessCreate) {
		if !procclass.IsOffice(e.ParentProcessName) {
			continue
		}
		if e.ProcessName != "cmd.exe" && e.ProcessName != "wscript.exe" && e.ProcessName != "cscript.exe" && e.ProcessName != "mshta.exe" {
			continue
		}
		technique := scriptTechniqueFor(e.ProcessName, e.CommandLine)
		title := fmt.Sprintf("Office application %s spawned %s", e.ParentProcessName, e.ProcessName)
		desc := fmt.Sprintf(
			"%s launched %s (PID %d) at %s on host %s, user %s, command line: %s. Office applications spawning a "+
				"scripting interpreter is a common initial-execution pattern for malicious document macros/payloads.",
			e.ParentProcessName, e.ProcessName, e.PID, e.Timestamp.Format(time.RFC3339), e.Host, orDash(e.User), truncate(e.CommandLine, 300))
		findings = append(findings, newFinding(e.CaseID, r.ID(), title, model.SeverityHigh, model.ConfidenceMedium,
			desc, []string{technique, "T1204.002"}, []model.Event{e}))
	}
	return findings
}

// ---------- Rule 9: Suspicious parent/child process lineage beyond interpreter->LOLBin ----------

type suspiciousParentChildLineage struct{}

func (suspiciousParentChildLineage) ID() string { return "suspicious-parent-child-lineage" }

// corroborated reports whether a child process-create event has evidence
// beyond just "this parent is unusual for this child" -- a suspicious
// install path, or (for an interpreter child) a suspicious command-line
// indicator. Requiring corroboration before escalating severity is what
// keeps this rule from flagging every ordinary explorer.exe->cmd.exe an
// administrator opens (see this phase's explicit "do not flag every
// unusual process as malicious" instruction).
func corroborated(e model.Event) bool {
	if procclass.HasSuspiciousPath(e.ProcessPath) || procclass.HasSuspiciousPath(e.CommandLine) {
		return true
	}
	return len(indicatorsIn(e.CommandLine)) > 0
}

// Inputs names the event types this rule reads. Every event it can
// match is among them; the engine loads only these, so a rule's memory is
// bounded by what it reads, not by the case.
func (r suspiciousParentChildLineage) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventProcessCreate}}
}

func (r suspiciousParentChildLineage) Evaluate(events []model.Event) []model.Finding {
	var findings []model.Finding
	for _, e := range byType(events, model.EventProcessCreate) {
		var reason string
		severity, confidence := model.SeverityLow, model.ConfidenceLow

		switch e.ParentProcessName {
		case "services.exe":
			// services.exe is the Service Control Manager's own process;
			// its direct children are the services it starts. A service
			// host from a non-standard path or invoking a script
			// interpreter is unusual -- legitimate services run signed
			// binaries from Program Files/System32.
			if !(procclass.HasSuspiciousPath(e.ProcessPath) || procclass.IsScriptHost(e.ProcessName) || procclass.IsPowerShell(e.ProcessName)) {
				continue
			}
			reason = "services.exe (the Service Control Manager) directly spawning a scripting interpreter or a process from a non-standard path"
			severity, confidence = model.SeverityHigh, model.ConfidenceMedium

		case "explorer.exe":
			// explorer.exe launching a script interpreter is routine
			// (a user or administrator double-clicking a script/shortcut)
			// -- reported as a low-confidence observation unless
			// corroborated by a suspicious path or command-line indicator.
			if !(procclass.IsScriptHost(e.ProcessName) || procclass.IsPowerShell(e.ProcessName)) {
				continue
			}
			reason = "explorer.exe (user-initiated) launching a scripting interpreter"
			if corroborated(e) {
				severity, confidence = model.SeverityMedium, model.ConfidenceMedium
			}

		case "svchost.exe":
			// Services legitimately create children (including via DCOM and
			// scheduled tasks). Parent name alone is not an anomaly, nor is
			// absence of a path evidence of an unusual installation path.
			if e.ProcessName == "" || !corroborated(e) {
				continue
			}
			reason = "svchost.exe child with corroborating user-writable path or suspicious command indicators; lineage alone was not used"
			severity, confidence = model.SeverityHigh, model.ConfidenceMedium

		default:
			continue
		}

		title := fmt.Sprintf("Suspicious process lineage: %s -> %s", e.ParentProcessName, e.ProcessName)
		desc := fmt.Sprintf(
			"%s (PID %d) at %s on host %s: %s. Path: %q, command line: %s.",
			e.ProcessName, e.PID, e.Timestamp.Format(time.RFC3339), e.Host, reason, orDash(e.ProcessPath), truncate(e.CommandLine, 300))
		findings = append(findings, newFinding(e.CaseID, r.ID(), title, severity, confidence,
			desc, []string{"T1059"}, []model.Event{e}))
	}
	return findings
}

// ---------- Rule 10: Service installation persistence ----------

type servicePersistence struct{}

func (servicePersistence) ID() string { return "service-persistence" }

// Inputs names the event types this rule reads. Every event it can
// match is among them; the engine loads only these, so a rule's memory is
// bounded by what it reads, not by the case.
func (r servicePersistence) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventServiceInstall}}
}

func (r servicePersistence) Evaluate(events []model.Event) []model.Finding {
	var findings []model.Finding
	for _, e := range byType(events, model.EventServiceInstall) {
		suspicious := procclass.HasSuspiciousPath(e.FilePath) || procclass.IsScriptHost(e.ProcessName) || procclass.IsPowerShell(e.ProcessName)
		severity, confidence := model.SeverityLow, model.ConfidenceLow
		if suspicious {
			severity, confidence = model.SeverityHigh, model.ConfidenceMedium
		}
		title := fmt.Sprintf("Service installed: %s", orDash(e.Extra["service_name"]))
		desc := fmt.Sprintf(
			"Service %q was installed on host %s at %s, image path %q, start type %s. A single service "+
				"installation is a weak indicator on its own -- reported as an observed persistence mechanism, "+
				"not a malware verdict; see correlated findings for corroborating evidence.",
			orDash(e.Extra["service_name"]), e.Host, e.Timestamp.Format(time.RFC3339), orDash(e.FilePath), orDash(e.Extra["start_type"]))
		if suspicious {
			desc += " The service binary is in a user-writable/non-standard location, or invokes a scripting interpreter -- both raise confidence."
		}
		findings = append(findings, newFinding(e.CaseID, r.ID(), title, severity, confidence, desc,
			[]string{"T1543.003"}, []model.Event{e}))
	}
	return findings
}

// ---------- Rule 11: Registry persistence beyond Run/RunOnce keys ----------

type registryPersistenceExtended struct{}

func (registryPersistenceExtended) ID() string { return "registry-persistence-extended" }

// Inputs names the event types this rule reads. Every event it can
// match is among them; the engine loads only these, so a rule's memory is
// bounded by what it reads, not by the case.
func (r registryPersistenceExtended) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventRegistryPersistence}}
}

func (r registryPersistenceExtended) Evaluate(events []model.Event) []model.Finding {
	var findings []model.Finding
	for _, e := range byType(events, model.EventRegistryPersistence) {
		mechanism, techniques := persistenceMechanism(e)
		suspicious := procclass.HasSuspiciousPath(e.FilePath)
		severity, confidence := model.SeverityMedium, model.ConfidenceLow
		// Winlogon/IFEO hijacks are inherently more targeted than a Run
		// key (they require modifying a specific, narrow key that has no
		// legitimate everyday use for most software), so they start at a
		// higher baseline severity even without a suspicious path.
		if e.Extra["registry_persistence_type"] == "winlogon" || e.Extra["registry_persistence_type"] == "ifeo" {
			severity, confidence = model.SeverityHigh, model.ConfidenceMedium
		}
		if suspicious {
			severity, confidence = model.SeverityHigh, model.ConfidenceMedium
		}
		title := fmt.Sprintf("Registry persistence (%s): %s", mechanism, e.RegistryPath)
		desc := fmt.Sprintf(
			"A %s was observed at %s on host %s: %s set to %q. This location is not a plain Run/RunOnce key -- "+
				"%s is a less common autostart/hijack mechanism than a Run key, which raises baseline confidence "+
				"that this is intentional persistence rather than incidental configuration.",
			mechanism, e.Timestamp.Format(time.RFC3339), e.Host, e.RegistryPath, orDash(e.FilePath), mechanism)
		findings = append(findings, newFinding(e.CaseID, r.ID(), title, severity, confidence, desc,
			techniques, []model.Event{e}))
	}
	return findings
}

// ---------- Rule 12: Explicit credential use (4648) ----------

type explicitCredentialUse struct{}

func (explicitCredentialUse) ID() string { return "explicit-credential-use" }

// Inputs names the event types this rule reads. Every event it can
// match is among them; the engine loads only these, so a rule's memory is
// bounded by what it reads, not by the case.
func (r explicitCredentialUse) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventLogonExplicitCreds}}
}

func (r explicitCredentialUse) Evaluate(events []model.Event) []model.Finding {
	var findings []model.Finding
	for _, e := range byType(events, model.EventLogonExplicitCreds) {
		// A single explicit-credential logon (runas, a mapped drive with
		// alternate creds, a scheduled task's "run as" account, etc.) is
		// routine administrative activity on its own -- reported as a
		// low-confidence observation; escalation requires corroboration
		// from another finding or correlation (see
		// internal/correlate/credential_chain.go's credential-abuse
		// chain), never asserted here alone.
		title := fmt.Sprintf("Explicit credential logon: %s -> %s", orDash(e.User), orDash(e.Extra["target_user_name"]))
		desc := fmt.Sprintf(
			"Process %q on host %s used explicit credentials for user %q to access %q at %s. This is routine for "+
				"RunAs, scheduled tasks, and mapped drives with alternate credentials -- reported as an observation, "+
				"not a credential-theft verdict.",
			orDash(e.ProcessPath), e.Host, orDash(e.Extra["target_user_name"]), orDash(e.Extra["target_server_name"]), e.Timestamp.Format(time.RFC3339))
		findings = append(findings, newFinding(e.CaseID, r.ID(), title, model.SeverityLow, model.ConfidenceLow,
			desc, []string{"T1078"}, []model.Event{e}))
	}
	return findings
}

// ---------- Rule 13: Privileged logon observed (4672) ----------

type privilegedLogonObserved struct{}

func (privilegedLogonObserved) ID() string { return "privileged-logon-observed" }

// Inputs names the event types this rule reads. Every event it can
// match is among them; the engine loads only these, so a rule's memory is
// bounded by what it reads, not by the case.
func (r privilegedLogonObserved) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventPrivilegedLogon}}
}

func (r privilegedLogonObserved) Evaluate(events []model.Event) []model.Finding {
	var findings []model.Finding
	for _, e := range byType(events, model.EventPrivilegedLogon) {
		title := fmt.Sprintf("Privileged logon: %s", orDash(e.User))
		desc := fmt.Sprintf(
			"User %q was assigned special/administrative privileges at logon on host %s at %s. Administrator-"+
				"equivalent logons are routine for legitimate administrative activity -- reported as an "+
				"observation; see brute-force/credential-abuse correlations for cases where this follows "+
				"suspicious authentication activity.",
			orDash(e.User), e.Host, e.Timestamp.Format(time.RFC3339))
		findings = append(findings, newFinding(e.CaseID, r.ID(), title, model.SeverityLow, model.ConfidenceLow,
			desc, []string{"T1078"}, []model.Event{e}))
	}
	return findings
}

// ---------- Rule 14: Process execution immediately followed by network connection ----------

type networkAfterExecution struct{}

func (networkAfterExecution) ID() string { return "network-after-execution" }

const networkAfterExecWindow = 5 * time.Minute

// Inputs names the event types this rule reads. Every event it can
// match is among them; the engine loads only these, so a rule's memory is
// bounded by what it reads, not by the case.
func (r networkAfterExecution) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventProcessCreate, model.EventNetworkConnection}}
}

func (r networkAfterExecution) Evaluate(events []model.Event) []model.Finding {
	execs := byType(events, model.EventProcessCreate)
	netConns := byType(events, model.EventNetworkConnection)
	netConnsByHostProc := indexEvents(netConns, func(e model.Event) string { return eventKey(e.Host, e.ProcessName) })

	var findings []model.Finding
	for _, ex := range execs {
		// Memory socket observations are evaluated by memory-process-signals,
		// with acquisition/PID/lifetime checks and explicit socket-state caveats.
		if ex.ArtifactType == model.ArtifactMemoryAnalysis {
			continue
		}
		// Gated on process behavior (a scripting interpreter/LOLBin, or a
		// process from a suspicious path), never on the network
		// destination or port -- see this phase's explicit "do not use
		// simplistic 'non-standard port = malicious'" instruction. Port
		// number plays no role in this rule at all.
		interpreter := procclass.IsPowerShell(ex.ProcessName) || procclass.IsScriptHost(ex.ProcessName)
		suspiciousExec := procclass.HasSuspiciousPath(ex.ProcessPath)
		if !interpreter && !suspiciousExec {
			continue
		}
		var conn model.Event
		found := false
		for _, n := range netConnsByHostProc[eventKey(ex.Host, ex.ProcessName)] {
			if n.Host != ex.Host || n.ProcessName != ex.ProcessName {
				continue
			}
			if ex.PID > 0 && n.PID > 0 && ex.PID != n.PID {
				continue
			}
			if n.Timestamp.Before(ex.Timestamp) || n.Timestamp.Sub(ex.Timestamp) > networkAfterExecWindow {
				continue
			}
			if !found || n.Timestamp.Before(conn.Timestamp) {
				conn, found = n, true
			}
		}
		if !found {
			continue
		}

		severity, confidence := model.SeverityMedium, model.ConfidenceLow
		techniques := []string{"T1071"}
		if interpreter {
			techniques = append(techniques, "T1059.001")
		}
		if suspiciousExec || len(indicatorsIn(ex.CommandLine)) > 0 {
			severity, confidence = model.SeverityHigh, model.ConfidenceMedium
		}

		title := fmt.Sprintf("%s made a network connection shortly after execution", ex.ProcessName)
		desc := fmt.Sprintf(
			"%q executed at %s on host %s, then made a network connection to %s at %s (%s later). Execution "+
				"immediately followed by outbound network activity from a scripting interpreter or "+
				"non-standard-path binary is consistent with payload retrieval or command-and-control, though "+
				"many legitimate administrative scripts also reach out to the network -- destination/port were "+
				"not used to assess severity here, only the executing process's own behavior.",
			ex.ProcessPath, ex.Timestamp.Format(time.RFC3339), ex.Host, orDash(conn.NetworkDest), conn.Timestamp.Format(time.RFC3339),
			humanizeDuration(conn.Timestamp.Sub(ex.Timestamp)))
		findings = append(findings, newFinding(ex.CaseID, r.ID(), title, severity, confidence, desc,
			techniques, []model.Event{ex, conn}))
	}
	return findings
}

// ---------- Rule 15: Remote interactive (RDP) logon observed ----------

type remoteLogonObserved struct{}

func (remoteLogonObserved) ID() string { return "remote-logon-observed" }

// windowsLogonTypeRemoteInteractive is Windows' LogonType 10 -- RDP (or
// another remote-desktop-protocol-compatible client). This is the one
// LogonType value unambiguous enough to map to a specific ATT&CK
// technique (T1021.001); LogonType 3 ("Network") is used by SMB, WinRM,
// and many other protocols and can't be disambiguated from the LogonType
// field alone, so it is deliberately not mapped to any T1021 sub-technique
// here.
const windowsLogonTypeRemoteInteractive = "10"

// Inputs names the event types this rule reads. Every event it can
// match is among them; the engine loads only these, so a rule's memory is
// bounded by what it reads, not by the case.
func (r remoteLogonObserved) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventLogonSuccess}}
}

func (r remoteLogonObserved) Evaluate(events []model.Event) []model.Finding {
	var findings []model.Finding
	for _, e := range byType(events, model.EventLogonSuccess) {
		if e.Extra["logon_type"] != windowsLogonTypeRemoteInteractive {
			continue
		}
		title := fmt.Sprintf("Remote interactive (RDP) logon: %s", orDash(e.User))
		desc := fmt.Sprintf(
			"User %q logged on to host %s via a remote-interactive (RDP) session at %s, source %s. Remote "+
				"administration over RDP is routine in most environments -- reported as an observation, not a "+
				"lateral-movement verdict.",
			orDash(e.User), e.Host, e.Timestamp.Format(time.RFC3339), orDash(e.NetworkSource))
		findings = append(findings, newFinding(e.CaseID, r.ID(), title, model.SeverityLow, model.ConfidenceLow,
			desc, []string{"T1021.001"}, []model.Event{e}))
	}
	return findings
}
