package detect

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"tracefall/internal/authseq"
	"tracefall/internal/cmdsem"
	"tracefall/internal/hostid"
	"tracefall/internal/model"
	"tracefall/internal/procclass"
)

// All returns every registered detection rule, in a fixed order so
// Analyze output ordering is stable across runs.
func All() []Rule {
	return append([]Rule{
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
	}, append(append(append(windowsServerRules(), sqlRules()...), containerRules()...), windowsToolRules()...)...)
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
			e.ParentProcessName, e.ProcessName, e.PID, fmtTime(e.Timestamp), e.Host, orDash(e.User))
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
		indicators := conservativePowerShellIndicators(e.CommandLine, e.EventType == model.EventPowerShellScript)
		if len(indicators) == 0 {
			continue
		}
		findings = append(findings, r.finding(e, e.CommandLine, indicators))
	}

	for _, e := range byType(events, model.EventPowerShellScript) {
		indicators := conservativePowerShellIndicators(e.CommandLine, e.EventType == model.EventPowerShellScript)
		if len(indicators) == 0 {
			continue
		}
		findings = append(findings, r.finding(e, e.CommandLine, indicators))
	}

	return orderInvocationFindings(findings)
}

func (r powershellEncodedCommand) finding(e model.Event, cmd string, indicators []string) model.Finding {
	title := "PowerShell command/script review"
	desc := fmt.Sprintf(
		"PowerShell activity on host %s (user %s) at %s matched %d review indicator(s): %s. The record does not establish successful execution, malicious intent or authorization. Command/script: %s",
		e.Host, orDash(e.User), fmtTime(e.Timestamp), len(indicators), strings.Join(indicators, ", "), truncate(cmdsem.Redact(cmd), 300))
	severity, confidence := powerShellEvidenceLevel(indicators)
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
			orDash(e.Extra["value_name"]), orDash(e.FilePath), e.RegistryPath, e.Host, fmtTime(e.Timestamp))
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
		severity, confidence, indicators := taskActionEvidence(e)
		if len(indicators) == 0 {
			severity, confidence = "low", "low"
			reason := "configuration observation only; action interpretation uncertain or routine"
			if e.CommandLine == "" || e.ProcessName == "" {
				reason = "configuration observation only; normalized action missing"
			}
			indicators = []string{reason}
		}
		title := fmt.Sprintf("Scheduled Task action review: %s", orDash(e.Extra["task_name"]))
		when := "registration date is not recorded in the task file"
		if !e.Timestamp.IsZero() {
			when = "author-recorded registration date " + fmtTime(e.Timestamp)
		} else if local := e.Extra["timestamp_local"]; local != "" {
			when = "registration date " + local + " (local time, zone not recorded)"
		}
		desc := fmt.Sprintf(
			"Scheduled Task configuration %q (author/principal %s; %s) on host %s, action: %q. Action indicators: %s. "+
				"The configuration does not establish creation by an actor, execution, successful persistence or malicious intent. Any task-file date is author-recorded, not independently verified.",
			orDash(e.Extra["task_name"]), orDash(e.User), when, orDash(e.Host), truncate(cmdsem.Redact(e.CommandLine), 200), strings.Join(indicators, ", "))
		findings = append(findings, newFinding(e.CaseID, r.ID(), title, severity, confidence, desc,
			[]string{"T1053.005"}, []model.Event{e}))
	}
	return orderInvocationFindings(findings)
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
		// Self-nesting is common shell plumbing, including copied interpreters.
		// It establishes neither payload staging nor an authorization verdict.
		self := e.ParentProcessName == e.ProcessName || (procclass.IsPowerShell(e.ParentProcessName) && procclass.IsPowerShell(e.ProcessName))
		strong := self && strongNestedInvocation(e)
		severity, confidence := model.SeverityHigh, model.ConfidenceMedium
		if self && !strong {
			severity, confidence = model.SeverityLow, model.ConfidenceLow
		}
		childSuspicious := self || strong || procclass.HasSuspiciousPath(e.ProcessPath) || procclass.IsScriptHost(e.ProcessName)
		if !childSuspicious {
			continue
		}
		title := fmt.Sprintf("Suspicious execution chain: %s -> %s", e.ParentProcessName, e.ProcessName)
		desc := fmt.Sprintf(
			"%s is recorded as the parent of %s (PID %d, path %q) at %s on host %s. This is a process-ancestry review lead; "+
				"the relationship does not establish successful payload execution, malicious intent or authorization.",
			e.ParentProcessName, e.ProcessName, e.PID, orDash(e.ProcessPath), fmtTime(e.Timestamp), e.Host)
		if strong {
			desc += " Self-nesting priority was raised because the child command also has encoded/hidden or dynamic/download/decode invocation evidence."
		}
		findings = append(findings, newFinding(e.CaseID, r.ID(), title, severity, confidence,
			desc, []string{"T1059", "T1059.001"}, []model.Event{e}))
	}
	return orderInvocationFindings(findings)
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

// Identity contradictions can be recorded on any event type, not only on
// execution/configuration rows. Read the full inventory for this rule rather
// than silently dropping those blockers in the filtered production path.
func (r executionThenPersistence) Inputs() model.EventFilter {
	return model.EventFilter{All: true}
}

func (r executionThenPersistence) Evaluate(events []model.Event) []model.Finding {
	names := hostid.AcquisitionNames(events)
	execs := append(append([]model.Event{}, byType(events, model.EventProcessCreate)...), byType(events, model.EventPrefetchExecution)...)
	key := func(e model.Event) string { return eventKey(e.CaseID+"\x00"+names[e.ID], execTarget(e)) }
	indexed := indexEvents(execs, key)
	var persistence []model.Event
	for _, typ := range []string{model.EventRegistryRunKey, model.EventScheduledTaskCreate, model.EventRegistryPersistence, model.EventServiceInstall} {
		persistence = append(persistence, byType(events, typ)...)
	}
	sort.Slice(persistence, func(i, j int) bool {
		if !persistence[i].Timestamp.Equal(persistence[j].Timestamp) {
			return persistence[i].Timestamp.Before(persistence[j].Timestamp)
		}
		return persistence[i].ID < persistence[j].ID
	})
	var findings []model.Finding
	for _, p := range persistence {
		target := persistenceTarget(p)
		if target == "" || names[p.ID] == "" || !temporalRecorded(p) {
			continue
		}
		ex, ok := bestExecutionMatch(indexed[key(p)], p, target, names)
		if !ok {
			continue
		}
		path, _ := temporalTargetPath(p)
		exPath, _ := temporalTargetPath(ex)
		severity, confidence := model.SeverityLow, model.ConfidenceLow
		basis := "Only the basename matches; the full target identity is uncertain."
		if path != "" && exPath != "" {
			basis = "The recorded full target paths match case-insensitively; path equality does not prove file-content identity."
			if ex.EventType == model.EventProcessCreate {
				severity, confidence = model.SeverityMedium, model.ConfidenceMedium
			}
		}
		observation := "process-start observation"
		if ex.EventType == model.EventPrefetchExecution {
			observation = "Prefetch approximate execution observation"
			basis += " Prefetch is approximate execution evidence, not a precise process-start instant."
		}
		mechanism, techniques := persistenceMechanism(p)
		title := fmt.Sprintf("%s: execution observation before %s configuration (temporal context)", target, mechanism)
		desc := fmt.Sprintf("A %s for %q is recorded at %s on host %s; %s configuration referencing that target is recorded at %s (%s later). %s This temporal context does not establish the configuration writer, intentional persistence, malice, or successful payload effects. Configuration time is not proof of execution or of when the setting took effect.", observation, target, fmtTime(ex.Timestamp), p.Host, mechanism, fmtTime(p.Timestamp), humanizeDuration(p.Timestamp.Sub(ex.Timestamp)), basis)
		findings = append(findings, newFinding(p.CaseID, r.ID(), title, severity, confidence, desc, techniques, []model.Event{ex, p}))
	}
	return findings
}

// Select context, not a process-instance or writer attribution. Prefer exact
// paths, then process starts over approximate Prefetch, then latest time/ID.
func bestExecutionMatch(execs []model.Event, p model.Event, target string, names map[string]string) (model.Event, bool) {
	var best model.Event
	found := false
	pp, conflict := temporalTargetPath(p)
	if conflict || !temporalRecorded(p) {
		return best, false
	}
	rank := func(e model.Event) int {
		path, _ := temporalTargetPath(e)
		n := 0
		if pp != "" && path != "" {
			n += 2
		}
		if e.EventType == model.EventProcessCreate {
			n++
		}
		return n
	}
	for _, ex := range execs {
		if names[ex.ID] == "" || names[ex.ID] != names[p.ID] || ex.CaseID != p.CaseID || execTarget(ex) != target || !temporalRecorded(ex) {
			continue
		}
		ep, bad := temporalTargetPath(ex)
		if bad || (ep != "" && pp != "" && ep != pp) {
			continue
		}
		exact := ep != "" && pp != ""
		if !exact && (p.CollectionID == "" || ex.CollectionID == "") {
			continue
		}
		// Cross-acquisition references require known scopes and exact full paths.
		// Basename-only uncertainty stays within its original acquisition.
		if ex.CollectionID != p.CollectionID && (!exact || ex.CollectionID == "" || p.CollectionID == "") {
			continue
		}
		if !p.Timestamp.After(ex.Timestamp) || !withinWindow(ex.Timestamp, p.Timestamp, persistenceWindow) {
			continue
		}
		if !found || rank(ex) > rank(best) || (rank(ex) == rank(best) && (ex.Timestamp.After(best.Timestamp) || (ex.Timestamp.Equal(best.Timestamp) && ex.ID < best.ID))) {
			best, found = ex, true
		}
	}
	return best, found
}

func temporalRecorded(e model.Event) bool {
	return !e.Timestamp.IsZero() && e.ArtifactType != model.ArtifactMemoryAnalysis && e.Extra["timestamp_basis"] != "memory_snapshot"
}

// persistenceMechanism names the persistence mechanism a persistence event
// represents and the ATT&CK technique(s) it maps to, for
// executionThenPersistence's finding text. Registry persistence is
// further split by regpersist's classification (stored in
// Extra["registry_persistence_type"] by the parser that produced it) so a
// Winlogon or IFEO configuration is named separately from a plain Run key;
// the location alone does not establish a malicious hijack.
func persistenceMechanism(p model.Event) (mechanism string, techniques []string) {
	switch p.EventType {
	case model.EventScheduledTaskCreate:
		return "scheduled task", []string{"T1053.005"}
	case model.EventServiceInstall:
		return "service installation", []string{"T1543.003"}
	case model.EventRegistryPersistence:
		switch p.Extra["registry_persistence_type"] {
		case "winlogon":
			return "Winlogon launch configuration", []string{"T1547.004"}
		case "ifeo":
			return "Image File Execution Options debugger configuration", []string{"T1546.012"}
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
		return strings.ToLower(e.ProcessName)
	}
	return ""
}

func execTarget(e model.Event) string {
	return strings.ToLower(e.ProcessName)
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
			e.ParentProcessName, e.ProcessName, e.PID, fmtTime(e.Timestamp), e.Host, orDash(e.User), truncate(e.CommandLine, 300))
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
			e.ProcessName, e.PID, fmtTime(e.Timestamp), e.Host, reason, orDash(e.ProcessPath), truncate(e.CommandLine, 300))
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
			orDash(e.Extra["service_name"]), e.Host, fmtTime(e.Timestamp), orDash(cmdsem.Redact(e.FilePath)), orDash(e.Extra["start_type"]))
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
		// The stock Winlogon Shell and Userinit values are the operating
		// system's own configuration; they stay in the timeline but are
		// not a lead. Any other value there is.
		if e.Extra["registry_persistence_type"] == "winlogon" && isDefaultWinlogonValue(e.RegistryPath, e.FilePath) {
			continue
		}
		// A snapshot service ImagePath outside any suspicious location is
		// configuration: it stays in the timeline but is not a lead. (A
		// service dropped into a system directory therefore cannot be told
		// from a stock one without a baseline; that is a stated limit.)
		if e.Extra["persistence_lead"] == "false" {
			continue
		}
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
			mechanism, fmtTime(e.Timestamp), e.Host, e.RegistryPath, orDash(e.FilePath), mechanism)
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
			orDash(e.ProcessPath), e.Host, orDash(e.Extra["target_user_name"]), orDash(e.Extra["target_server_name"]), fmtTime(e.Timestamp))
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
	// One finding per (case, host, account). A domain controller records a
	// 4672 for every service and machine-account logon, so one finding per
	// event buries the few that matter; the count, window and privileges
	// state the whole run, and the cited events are its two ends.
	type key struct{ caseID, host, user string }
	groups := map[key][]model.Event{}
	for _, e := range byType(events, model.EventPrivilegedLogon) {
		// Events whose host is not recorded cannot be merged across
		// acquisitions: each collection keeps its own unknown host.
		h := strings.ToLower(e.Host)
		if h == "" {
			h = "\x00" + e.CollectionID
		}
		k := key{e.CaseID, h, strings.ToLower(e.User)}
		groups[k] = append(groups[k], e)
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.caseID != b.caseID {
			return a.caseID < b.caseID
		}
		if a.host != b.host {
			return a.host < b.host
		}
		return a.user < b.user
	})

	var findings []model.Finding
	for _, k := range keys {
		evs := groups[k]
		sort.SliceStable(evs, func(i, j int) bool {
			if !evs[i].Timestamp.Equal(evs[j].Timestamp) {
				return evs[i].Timestamp.Before(evs[j].Timestamp)
			}
			return evs[i].ID < evs[j].ID
		})
		first := evs[0]
		logons := map[string]bool{}
		privs := map[string]bool{}
		for _, e := range evs {
			if id := e.Extra["logon_id"]; id != "" {
				logons[id] = true
			}
			for _, p := range strings.Fields(e.Extra["privilege_list"]) {
				privs[p] = true
			}
		}
		names := make([]string, 0, len(privs))
		for p := range privs {
			names = append(names, p)
		}
		sort.Strings(names)
		if len(names) > 12 {
			names = append(names[:12], fmt.Sprintf("(+%d more)", len(names)-12))
		}
		title := fmt.Sprintf("Privileged logon: %s on %s", orDash(first.User), orDash(first.Host))
		if len(evs) > 1 {
			title += fmt.Sprintf(" (%d logons)", len(evs))
		}
		desc := fmt.Sprintf(
			"User %q was assigned special/administrative privileges at logon on host %s: %d privileged logon(s) across %d logon session(s), first at %s, last at %s.",
			orDash(first.User), orDash(first.Host), len(evs), len(logons),
			fmtTime(first.Timestamp), fmtTime(evs[len(evs)-1].Timestamp))
		if len(names) > 0 {
			desc += " Privileges recorded: " + strings.Join(names, ", ") + "."
		}
		if len(evs) > supportingCap {
			desc += fmt.Sprintf(" Only the first and last %d events are cited here; all %d are in the timeline under event ID 4672 for this account.", supportingCap/2, len(evs))
		}
		desc += " Administrator-equivalent logons are routine for legitimate administrative and service activity -- reported as an observation; see brute-force/credential-abuse correlations for cases where this follows suspicious authentication activity."
		findings = append(findings, newFinding(first.CaseID, r.ID(), title, model.SeverityLow, model.ConfidenceLow,
			desc, []string{"T1078"}, capEvents(evs)))
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
			if n.Timestamp.IsZero() || ex.Timestamp.IsZero() {
				continue // no recorded time, no order
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
			ex.ProcessPath, fmtTime(ex.Timestamp), ex.Host, orDash(conn.NetworkDest), fmtTime(conn.Timestamp),
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
			orDash(e.User), e.Host, fmtTime(e.Timestamp), orDash(e.NetworkSource))
		findings = append(findings, newFinding(e.CaseID, r.ID(), title, model.SeverityLow, model.ConfidenceLow,
			desc, []string{"T1021.001"}, []model.Event{e}))
	}
	return findings
}

// isDefaultWinlogonValue reports whether a Winlogon launch value holds the
// stock Windows setting: Shell is explorer.exe and Userinit is userinit.exe
// in the system directory (Windows writes a trailing comma).
func isDefaultWinlogonValue(registryPath, data string) bool {
	i := strings.LastIndex(registryPath, `\`)
	if i < 0 {
		return false
	}
	name := strings.ToLower(registryPath[i+1:])
	v := strings.ToLower(strings.TrimRight(strings.TrimSpace(data), ", "))
	switch name {
	case "shell":
		return v == "explorer.exe"
	case "userinit":
		return v == "userinit.exe" || v == `c:\windows\system32\userinit.exe` || v == `%systemroot%\system32\userinit.exe`
	case "vmapplet":
		return v == "systempropertiesperformance.exe /pagefile"
	}
	return false
}
