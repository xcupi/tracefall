package detect

import "sort"

// The rule catalog: what each rule is, and on what basis it assigns the
// severity and confidence it does.
//
// Severity in Tracefall is RULE-DRIVEN, not scored. Each rule decides,
// from concrete conditions in the evidence, which level to assign --
// there is no points model at the finding level, and this file does not
// introduce one. What it adds is the missing half: an explanation of the
// reasoning, so a finding's severity can be justified to an investigator
// (and challenged by one) instead of appearing as a bare label.
//
// The catalog is DECLARATIVE and lives next to the rules it describes.
// It is not derived by inspecting rule code, because that would be a
// guess; and it cannot silently drift, because
// TestCatalog_CoversEveryRegisteredRule fails the build if a rule is
// added without an entry or an entry outlives its rule.
//
// Nothing here changes what any rule assigns. Removing this file would
// leave every finding's severity and confidence byte-for-byte identical.

// RuleDoc describes one detection rule's severity reasoning.
type RuleDoc struct {
	ID    string `json:"rule_id"`
	Title string `json:"title"`
	// What the rule observes, in one sentence an investigator can read.
	Detects string `json:"detects"`
	// BaseSeverity/BaseConfidence are what the rule assigns when only its
	// minimum conditions are met.
	BaseSeverity   string `json:"base_severity"`
	BaseConfidence string `json:"base_confidence"`
	// MaxSeverity/MaxConfidence are what it assigns when every escalating
	// condition is present. Equal to the base values for a rule that does
	// not escalate.
	MaxSeverity   string `json:"max_severity"`
	MaxConfidence string `json:"max_confidence"`
	// Escalates lists the concrete, evidence-backed conditions that raise
	// this rule's severity above its base. Empty for a fixed-severity
	// rule.
	Escalates []string `json:"escalates,omitempty"`
	// Basis explains why the base level is what it is -- in particular
	// why a weak-on-its-own signal is deliberately NOT reported as high.
	Basis string `json:"basis"`
	// Techniques are the ATT&CK technique IDs this rule maps to.
	Techniques []string `json:"attack_techniques,omitempty"`
}

// ruleDocs is keyed by Rule.ID(). Values are the levels the rule code in
// rules.go actually assigns.
var ruleDocs = map[string]RuleDoc{
	"brute-force-then-success-sequence": {
		Title:        "Failed logons then success, ordered within a log that has no year",
		Detects:      "Three or more failed logons for one account from one address, each close to the one before it in the same log file, followed within thirty minutes by a successful logon for the same account from the same address.",
		BaseSeverity: "high", BaseConfidence: "medium", MaxSeverity: "high", MaxConfidence: "medium",
		Basis:      "Same shape as the dated brute-force rule, for logs that carry no year. Order comes from line numbers and the distance between stamps in ONE file; the date is unknown and no year is guessed. Confidence is medium, not high, because relative time cannot be checked against another source and the pattern is also a person mistyping a password. The account and the address must both match, so one source cannot be blamed for another's failures. Lines from different files, or across a New Year, are never joined.",
		Techniques: []string{"T1110", "T1078"},
	},
	"web-attack-indicators": {
		Title:        "Web requests that resemble an attack",
		Detects:      "Requests in a web server access log, grouped by source address and kind, whose URL or user agent resembles SQL injection, path traversal, command injection, cross-site scripting, a web shell, a vulnerability scanner or a probe of an administration interface.",
		BaseSeverity: "low", BaseConfidence: "low", MaxSeverity: "high", MaxConfidence: "medium",
		Escalates:  []string{"Five or more such requests from one source, or more than one kind from the same source (confidence to medium)", "A web-shell request answered with a 2xx status (severity to high)"},
		Basis:      "The log shows what was asked and what status came back, never what the application did, so every finding is worded as an attempt. Single words are not matched, only constructs that do not occur in ordinary browsing (union select, ../../, php://). A single hit on an administration URL is background noise on any public server, so that kind needs three requests. A scanner is identified by its self-declared user agent, which an attacker controls, so it is low severity.",
		Techniques: []string{"T1190", "T1505.003", "T1595.002", "T1595.003"},
	},
	"account-change-observed": {
		Title:        "Local account created or added to a privileged group",
		Detects:      "A system log recording a new local account, or an account added to a group that grants administrative power or remote access.",
		BaseSeverity: "low", BaseConfidence: "medium", MaxSeverity: "high", MaxConfidence: "high",
		Escalates:  []string{"Account added to an administrative or remote-access group (severity to high)", "Account created with user id 0 (severity and confidence to high)"},
		Basis:      "The record shows the change was applied, not who asked for it. Accounts with no login shell and a system-range id are skipped because package installs create them routinely. Deletions, password changes and other group changes stay on the timeline without a finding.",
		Techniques: []string{"T1136.001", "T1098"},
	},
	"database-insecure-account": {
		Title:        "Database server reported administrator accounts without a password",
		Detects:      "The database server's own start-up check logging that administrator accounts have no password.",
		BaseSeverity: "medium", BaseConfidence: "high", MaxSeverity: "medium", MaxConfidence: "high",
		Basis:      "The server itself reported it, so confidence in the observation is high. Severity is medium because the log shows the weakness existed, not that anyone used it. The log has no year, so duration is reported as a number of warnings, not a date range.",
		Techniques: []string{"T1078.001"},
	},
	"system-change-command": {
		Title:        "Command that changes the firewall, persistence or accounts",
		Detects:      "A command line that adds or removes a firewall rule, turns the firewall off, installs a scheduled task, service, Run key, cron entry or authorized key, or creates an account or adds one to a group.",
		BaseSeverity: "low", BaseConfidence: "low", MaxSeverity: "high", MaxConfidence: "medium",
		Escalates:  []string{"Firewall turned off or flushed, a persistence mechanism installed, or an account created (severity to medium)", "Membership of an administrative group, a root-equivalent account, an authorized key, an Image File Execution Options key or a WMI subscription (severity to high)", "The command line of a process that started, rather than a sudo or history line (confidence to medium)"},
		Basis:      "Administrators run these commands as often as attackers do, so the finding is a lead. Confidence follows what the source proves: a process record shows a start, sudo shows an authorisation, shell history shows typing; none shows the change took effect. Commands that only list state are not matched, and secrets typed on a command line are never copied into a finding. Repeats of the same action by the same account on the same host are one finding with a count.",
		Techniques: []string{"T1562.004", "T1053.005", "T1053.003", "T1543.003", "T1547.001", "T1098", "T1136.001"},
	},
	"rdp-connection-burst": {
		Title:        "Many Remote Desktop connections from one client",
		Detects:      "A packet capture showing at least fifty separate connections from one client to one server's Remote Desktop port.",
		BaseSeverity: "medium", BaseConfidence: "low", MaxSeverity: "high", MaxConfidence: "medium",
		Escalates:  []string{"A later connection from the same client carried real traffic, i.e. a session got past the handshake (severity to high, confidence to medium)"},
		Basis:      "The capture proves the connections were attempted, not that any logon failed or succeeded: Remote Desktop is encrypted. The same shape comes from password guessing, a scanner, a health check or a client with a stale saved credential, so confidence stays low until a session follows, and even then the server's own logon events decide.",
		Techniques: []string{"T1110.001", "T1021.001"},
	},
	"executable-over-http-from-address": {
		Title:        "Executable fetched over HTTP from a bare address",
		Detects:      "A packet capture showing a program (Windows executable, ELF, MSI, Java archive) delivered whole, with status 200, over unencrypted HTTP from a server addressed by IP rather than by name.",
		BaseSeverity: "medium", BaseConfidence: "medium", MaxSeverity: "medium", MaxConfidence: "medium",
		Basis:      "The capture proves the bytes reached the client and gives their hash, so the observation is solid. It does not show the file was saved or run, or what it does; internal tooling is also served from bare addresses. Severity stays medium and the finding is a lead to match against the client's own records.",
		Techniques: []string{"T1105"},
	},
	"memory-process-signals": {
		Title:        "Corroborated memory process review",
		Detects:      "One process-level lead for private executable PE memory, independently corroborated executable regions, a successfully compared process-list discrepancy, or writable-image execution with a remote socket in the same acquisition.",
		BaseSeverity: "medium", BaseConfidence: "low", MaxSeverity: "high", MaxConfidence: "medium",
		Escalates: []string{"Private executable PE memory plus a writable image path or remote socket", "Private executable memory plus encoded/dynamic/download or remote execution command indicators"},
		Basis:     "RWX memory alone is common in JIT runtimes and is not a finding. Writable-path installers with sockets are low-confidence review leads, not malware verdicts. Joins require matching acquisition, host, PID, process name and lifetime. Socket state is preserved as observed; an attempt or closed socket is not asserted to be a successful C2 connection.",
	},
	"office-spawns-powershell": {
		Title:        "Office application spawned PowerShell",
		Detects:      "A Microsoft Office process created a PowerShell child process.",
		BaseSeverity: "high", BaseConfidence: "medium",
		MaxSeverity: "high", MaxConfidence: "medium",
		Basis:      "Office applications have no legitimate reason to launch PowerShell in most environments, so the parent/child relationship alone is a strong signal. Confidence stays medium because a small number of legitimate macro-based business tools do this.",
		Techniques: []string{"T1566", "T1059.001"},
	},
	"powershell-encoded-command": {
		Title:        "PowerShell execution with suspicious command indicators",
		Detects:      "PowerShell launch options or unquoted download/dynamic-expression invocation constructs in a recorded command or script.",
		BaseSeverity: "low", BaseConfidence: "low",
		MaxSeverity: "high", MaxConfidence: "medium",
		Escalates:  []string{"Encoded, hidden, download or dynamic-expression invocation (medium/medium)", "Encoded plus hidden, or dynamic expression plus download/Base64 conversion (high/medium)"},
		Basis:      "No-profile and execution-policy bypass, alone or together, are low-confidence automation leads. Repeated tokens do not corroborate themselves. Quoted literal data and comments are excluded; Base64 conversion or a web API request alone stays on the timeline. Encoded payloads are not decoded and remain medium-confidence review leads, never benign verdicts. The lexical selector is not an interpreter and the record does not establish successful execution or malicious intent.",
		Techniques: []string{"T1059.001", "T1027"},
	},
	"new-registry-run-key": {
		Title:        "Registry Run Key persistence",
		Detects:      "A Run/RunOnce value was observed pointing at an executable.",
		BaseSeverity: "low", BaseConfidence: "low",
		MaxSeverity: "high", MaxConfidence: "medium",
		Escalates:  []string{"The Run key target is in a user-writable or non-standard directory"},
		Basis:      "Run keys are used by ordinary software constantly, so a Run key by itself is an observation, not a verdict. A target under a user-writable path is what distinguishes it.",
		Techniques: []string{"T1547.001"},
	},
	"new-scheduled-task": {
		Title:        "Scheduled Task action review",
		Detects:      "Observed task configuration with action-level invocation or user-writable-target evidence; routine configuration stays on the timeline.",
		BaseSeverity: "low", BaseConfidence: "low",
		MaxSeverity: "high", MaxConfidence: "medium",
		Escalates: []string{
			"Encoded, hidden, download or dynamic invocation (medium/medium); Temp/AppData/Public/Downloads action target alone (medium/low)",
			"Remote script/loader action, encoded plus hidden, dynamic plus download/decode, or hidden plus user-writable action target (high/medium)",
		},
		Basis:      "Task configuration does not prove actor creation, execution or malicious persistence. Task-file dates are author-recorded. Task names and system directories are not allowlists; ProgramData or an interpreter alone is not an alert. No-profile/bypass alone remain low/low leads. Only the normalized command action is assessed; missing or unsupported actions retain timeline evidence without a finding.",
		Techniques: []string{"T1053.005"},
	},
	"suspicious-process-chain": {
		Title:        "Suspicious process ancestry",
		Detects:      "An interpreter parent with a non-standard-path or script-host child; self-nesting additionally requires strong invocation evidence.",
		BaseSeverity: "high", BaseConfidence: "medium",
		MaxSeverity: "high", MaxConfidence: "medium",
		Basis:      "Self-nesting alone, including a writable interpreter path, is not selected. A self-nested child requires encoded plus hidden, or dynamic expression plus download/decode invocation evidence. Existing distinct-child gates are retained. The record names a parent relationship, not successful payload execution or malicious intent.",
		Techniques: []string{"T1059"},
	},
	"brute-force-then-success": {
		Title:        "Repeated logon failures followed by a success",
		Detects:      "A burst of failed logons for one account on one host, followed by a successful logon within the correlation window.",
		BaseSeverity: "high", BaseConfidence: "high",
		MaxSeverity: "high", MaxConfidence: "high",
		Basis:      "Confidence is high because the pattern is counted from concrete authentication events on the same host and account, not inferred.",
		Techniques: []string{"T1110"},
	},
	"execution-persistence-temporal": {
		Title:        "Execution followed by persistence",
		Detects:      "A process executed and a persistence mechanism referencing the same target was established shortly afterwards.",
		BaseSeverity: "critical", BaseConfidence: "high",
		MaxSeverity: "critical", MaxConfidence: "high",
		Basis:      "This is the only rule that asserts critical severity, because it requires two independent behaviours linked by a shared target and a bounded time window -- a materially stronger claim than either observation alone.",
		Techniques: []string{"T1547.001", "T1053.005"},
	},
	"office-spawns-script-interpreter": {
		Title:        "Office application spawned a script interpreter",
		Detects:      "A Microsoft Office process created a scripting-host child process (wscript, cscript, mshta, regsvr32, ...).",
		BaseSeverity: "high", BaseConfidence: "medium",
		MaxSeverity: "high", MaxConfidence: "medium",
		Basis:      "Same reasoning as the PowerShell variant: the parent/child relationship is the signal.",
		Techniques: []string{"T1566", "T1059"},
	},
	"suspicious-parent-child-lineage": {
		Title:        "Suspicious parent/child process lineage",
		Detects:      "A service-manager/svchost child with independent path or command indicators, or an explorer-launched script interpreter observation.",
		BaseSeverity: "low", BaseConfidence: "low",
		MaxSeverity: "high", MaxConfidence: "medium",
		Escalates: []string{
			"The child is a scripting interpreter or living-off-the-land binary",
			"The child image path is user-writable or non-standard",
		},
		Basis:      "Unusual lineage is weak alone -- legitimate software spawns unexpected children -- so it is reported as an observation until the child itself is also suspicious.",
		Techniques: []string{"T1059"},
	},
	"service-persistence": {
		Title:        "Service installation persistence",
		Detects:      "A Windows service was installed, or a service ImagePath was observed.",
		BaseSeverity: "low", BaseConfidence: "low",
		MaxSeverity: "high", MaxConfidence: "medium",
		Escalates: []string{
			"The service image path is user-writable or non-standard",
			"The service runs a scripting interpreter or living-off-the-land binary",
		},
		Basis:      "Service installation is routine on a managed system; the image path is what carries the signal.",
		Techniques: []string{"T1543.003"},
	},
	"registry-persistence-extended": {
		Title:        "Registry persistence outside Run keys",
		Detects:      "A Winlogon, IFEO, AppInit_DLLs or service-ImagePath persistence location was written.",
		BaseSeverity: "medium", BaseConfidence: "low",
		MaxSeverity: "high", MaxConfidence: "medium",
		Escalates:  []string{"The value data points at a user-writable or non-standard path"},
		Basis:      "These locations are modified far less often than Run keys by legitimate software, so the base severity is a step higher -- but the target path still determines whether it is escalated.",
		Techniques: []string{"T1547", "T1546.008", "T1546.012"},
	},
	"explicit-credential-use": {
		Title:        "Logon using explicit credentials",
		Detects:      "An account was used to authenticate explicitly from within another user's session (runas and equivalents).",
		BaseSeverity: "low", BaseConfidence: "low",
		MaxSeverity: "medium", MaxConfidence: "medium",
		Escalates:  []string{"The invoking process is a scripting interpreter or living-off-the-land binary"},
		Basis:      "Explicit credential use is a normal administrative action; it is recorded for timeline and correlation value rather than asserted as malicious.",
		Techniques: []string{"T1078"},
	},
	"privileged-logon-observed": {
		Title:        "Privileged logon observed",
		Detects:      "Special privileges were assigned to a new logon session.",
		BaseSeverity: "low", BaseConfidence: "low",
		MaxSeverity: "high", MaxConfidence: "medium",
		Escalates:  []string{"The same account also has failed-logon or explicit-credential activity in the case"},
		Basis:      "Administrators log on with privileges constantly. This is timeline context unless other authentication anomalies involve the same account.",
		Techniques: []string{"T1078"},
	},
	"network-after-execution": {
		Title:        "Network connection shortly after execution",
		Detects:      "A process made an outbound connection soon after being created.",
		BaseSeverity: "medium", BaseConfidence: "low",
		MaxSeverity: "high", MaxConfidence: "medium",
		Escalates:  []string{"The executing image is in a user-writable or non-standard path"},
		Basis:      "Most processes make network connections. The origin of the binary is what makes the sequence noteworthy.",
		Techniques: []string{"T1071"},
	},
	"grafana-login-failure-burst": {
		Title:        "Burst of failed Grafana logins from one client address",
		Detects:      "Five or more POST /login requests answered 401 from one address, each within two minutes of the one before, in one source (container log or grafana.log).",
		BaseSeverity: "medium", BaseConfidence: "medium",
		MaxSeverity: "high", MaxConfidence: "medium",
		Escalates:  []string{"A session in Grafana's database created from the same address within thirty minutes after the last failure (severity to high)"},
		Basis:      "Grafana's default log records an anonymous 401 and not the account tried, so the count is of failed requests, not of guesses at one account. Its database lists attempts only for accounts that exist and prunes them. The address can be a proxy or container gateway. Counts from the container log and grafana.log are never added together because they can record the same requests.",
		Techniques: []string{"T1110"},
	},
	"cryptnet-executable-retrieval": {
		Title:        "A file was retrieved through the Windows CryptoAPI URL cache",
		Detects:      "A CryptoAPI URL cache entry whose cached object is an executable, archive or ELF file, or whose URL ends like a program, script or archive when the cached object is not available.",
		BaseSeverity: "medium", BaseConfidence: "low",
		MaxSeverity: "high", MaxConfidence: "medium",
		Escalates:  []string{"The cached object starts with an executable header (high, medium confidence)"},
		Basis:      "An entry shows that Windows retrieved the URL and when; it does not name the program that asked. certutil -urlcache -f produces one, and so does Windows validating a certificate, which is why only executables, archives and program-like names are reported. It does not show the file was run.",
		Techniques: []string{"T1105"},
	},
	"defender-mpcmdrun-misuse": {
		Title:        "MpCmdRun.exe used to download a file or remove Defender signatures",
		Detects:      "A run recorded in MpCmdRun.log with -DownloadFile, or with -RemoveDefinitions -All.",
		BaseSeverity: "medium", BaseConfidence: "medium",
		MaxSeverity: "high", MaxConfidence: "medium",
		Escalates:  []string{"-DownloadFile (high)"},
		Basis:      "The log records the command and a local time with no zone, not the outcome. Administrators also remove all signatures to repair a broken update.",
		Techniques: []string{"T1105", "T1562"},
	},
	"av-threat-detected": {
		Title:        "The antimalware engine recorded a threat detection or a blocked process creation",
		Detects:      "Detection (1116), action (1117, 1118, 1119) records of the Defender Operational log and DETECTIONEVENT lines of the Defender support log, grouped by host and threat label; and, separately per host, 'Process creation blocked' lines of the support log.",
		BaseSeverity: "low", BaseConfidence: "medium",
		MaxSeverity: "high", MaxConfidence: "medium",
		Escalates:  []string{"The engine's recorded severity: Low (low), Moderate (medium), High or Severe (high). A group with no recorded severity, and a blocked process creation, are medium"},
		Basis:      "The finding states what the engine recorded: it detected or blocked something under its own label. It does not show that the resource ran, that a command or transfer completed, or that a payload was removed or recovered: a Remove action with error code 0 describes the engine's action only. A CmdLine resource is a command-line string, not a file. Repeated records of one detection ID are counted once as a detection. Support-log lines carry no zone and stay undated.",
		Techniques: nil,
	},
	"grafana-extra-server-admin": {
		Title:        "Grafana account with server-administrator rights besides the first account",
		Detects:      "A non-service account flagged as Grafana server administrator in grafana.db whose id is not the lowest in that database.",
		BaseSeverity: "medium", BaseConfidence: "medium",
		MaxSeverity: "medium", MaxConfidence: "medium",
		Basis:      "The database does not show who created the account or from where, and administrators are added for legitimate work. The lowest id is taken as the account Grafana creates at install, which is an assumption about the database and not a recorded fact.",
		Techniques: []string{"T1136"},
	},
	"grafana-datasource-credential": {
		Title:        "Grafana stores a credential for a data source",
		Detects:      "A data source in grafana.db whose password or secure settings are stored (the value is never read).",
		BaseSeverity: "low", BaseConfidence: "high",
		MaxSeverity: "low", MaxConfidence: "high",
		Basis:      "An inventory of exposure: if Grafana was reached by an attacker the stored credential is reachable. It is not evidence that the credential was used.",
		Techniques: []string{"T1552"},
	},
	"container-risky-configuration": {
		Title:        "Container configured with access to the host",
		Detects:      "A container host configuration that is privileged, mounts the Docker socket or the host root, shares the host's process or network namespace, adds a dangerous capability, or publishes a port on all interfaces.",
		BaseSeverity: "low", BaseConfidence: "high",
		MaxSeverity: "high", MaxConfidence: "high",
		Escalates:  []string{"Privileged, Docker socket mount or host root mount (high)", "Host PID or network, sensitive host mount, or a dangerous capability (medium)"},
		Basis:      "Configuration, not an incident: it records what the container was allowed to do, not that anything used it. The file does not show what ran inside the container.",
		Techniques: []string{"T1611"},
	},
	"container-secret-in-environment": {
		Title:        "Container keeps secrets in its environment",
		Detects:      "A container configuration with environment variables whose names indicate a password, secret, token, key, credential, DSN or connection string.",
		BaseSeverity: "low", BaseConfidence: "high",
		MaxSeverity: "low", MaxConfidence: "high",
		Basis:      "The match is on the variable name only and values are never shown. A harmless variable can match, and a secret can sit under an ordinary name.",
		Techniques: []string{"T1552"},
	},
	"sql-login-failure-burst": {
		Title:        "Burst of failed SQL Server logins from one client address",
		Detects:      "Five or more failed SQL Server logins from one client address, each within two minutes of the one before, in one source file (or one dated host and instance).",
		BaseSeverity: "medium", BaseConfidence: "medium",
		MaxSeverity: "high", MaxConfidence: "high",
		Escalates:  []string{"Two or more distinct login names from the same client, or three distinct names that did not exist (confidence to high)", "A successful SQL login from the same client, for one of the failed names, within thirty minutes in the same clock scope (severity to high)"},
		Basis:      "The engine records failed attempts, so the count is of recorded failures. The default error log does not record successful logins, so nothing in it shows whether a guess later worked; a success is only known from Audit, Extended Events or the Application log. The client address can be a proxy or a container gateway. Text logs carry no zone: order and distance come from the local reading inside one file, and the local time is never presented as UTC.",
		Techniques: []string{"T1110"},
	},
	"sql-risky-config-enabled": {
		Title:        "SQL Server configuration option changed to a risky setting",
		Detects:      "A recorded SQL Server message that a configuration option such as xp_cmdshell, Ole Automation Procedures, Ad Hoc Distributed Queries, external scripts, CLR or Database Mail was changed to a non-zero value, or that CLR strict security was changed to 0.",
		BaseSeverity: "low", BaseConfidence: "high",
		MaxSeverity: "medium", MaxConfidence: "high",
		Escalates:  []string{"The option is xp_cmdshell, Ole Automation Procedures, external scripts enabled or Ad Hoc Distributed Queries (severity to medium)"},
		Basis:      "The log records that the change was applied, with high confidence in that fact. It does not show who made it, nor whether the feature was used afterwards. Changes to show advanced options and Agent XPs are routine and are not reported; a change to 0 of any other option is hardening and is not reported.",
		Techniques: []string{"T1059", "T1562"},
	},
	"sql-disabled-component-attempt": {
		Title:        "Attempt to use a disabled SQL Server component",
		Detects:      "A recorded SQL Server message that access to a procedure of a disabled component was blocked.",
		BaseSeverity: "low", BaseConfidence: "medium",
		MaxSeverity: "low", MaxConfidence: "medium",
		Basis:      "The engine blocked the call, so the procedure did not run on this instance at that time. The message names neither the caller nor the statement. Routine administration tools can also trigger it.",
		Techniques: []string{"T1059"},
	},
	"sql-audit-stopped-while-running": {
		Title:        "SQL Server audit stopped while the log continues",
		Detects:      "A Server Audit state change from STARTED to SHUTTING_DOWN or STOPPED that is followed later, in the same log, by other engine records that are not shutdown messages.",
		BaseSeverity: "low", BaseConfidence: "low",
		MaxSeverity: "low", MaxConfidence: "low",
		Basis:      "A normal instance shutdown also stops audits, which is why this only fires when the log continues afterwards with records that are not themselves shutdown messages. An audit can be stopped by routine maintenance. The record does not show who stopped it.",
		Techniques: []string{"T1562"},
	},
	"remote-logon-observed": {
		Title:        "Remote logon observed",
		Detects:      "A network or remote-interactive logon succeeded.",
		BaseSeverity: "low", BaseConfidence: "low",
		MaxSeverity: "low", MaxConfidence: "low",
		Basis:      "Recorded for timeline and correlation value only. Remote logons are routine and this rule never asserts more than that one occurred.",
		Techniques: []string{"T1021"},
	},
}

// Catalog returns every rule's severity documentation, ordered by rule
// ID so the output is stable.
func Catalog() []RuleDoc {
	out := make([]RuleDoc, 0, len(ruleDocs))
	for id, doc := range ruleDocs {
		doc.ID = id
		out = append(out, doc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// DocFor returns one rule's documentation. The second result reports
// whether the rule is known -- a finding produced by a build that had a
// rule this one does not is explained without it rather than with an
// invented entry.
func DocFor(ruleID string) (RuleDoc, bool) {
	doc, ok := ruleDocs[ruleID]
	if !ok {
		return RuleDoc{}, false
	}
	doc.ID = ruleID
	return doc, true
}
