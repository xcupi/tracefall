// Package attck is Tracefall's MITRE ATT&CK mapping layer. It is the only
// place technique IDs, names, and tactics are defined; detection rules
// reference techniques by ID only (see internal/detect), and the UI never
// hard-codes technique metadata -- it always resolves through Lookup.
package attck

// Technique describes one MITRE ATT&CK technique or sub-technique.
type Technique struct {
	ID     string `json:"id"` // e.g. "T1059.001"
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
	URL    string `json:"url"`
}

// registry is the fixed set of techniques Tracefall Phase 1 knows how to
// map to. Expand this table (and the rules that reference it) to add
// coverage -- nothing outside this package needs to change.
var registry = map[string]Technique{
	"T1059": {
		ID: "T1059", Name: "Command and Scripting Interpreter",
		Tactic: "Execution",
		URL:    "https://attack.mitre.org/techniques/T1059/",
	},
	"T1059.001": {
		ID: "T1059.001", Name: "Command and Scripting Interpreter: PowerShell",
		Tactic: "Execution",
		URL:    "https://attack.mitre.org/techniques/T1059/001/",
	},
	"T1547.001": {
		ID: "T1547.001", Name: "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
		Tactic: "Persistence, Privilege Escalation",
		URL:    "https://attack.mitre.org/techniques/T1547/001/",
	},
	"T1053.005": {
		ID: "T1053.005", Name: "Scheduled Task/Job: Scheduled Task",
		Tactic: "Execution, Persistence, Privilege Escalation",
		URL:    "https://attack.mitre.org/techniques/T1053/005/",
	},
	"T1078": {
		ID: "T1078", Name: "Valid Accounts",
		Tactic: "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
		URL:    "https://attack.mitre.org/techniques/T1078/",
	},
	"T1110": {
		ID: "T1110", Name: "Brute Force",
		Tactic: "Credential Access",
		URL:    "https://attack.mitre.org/techniques/T1110/",
	},
	"T1105": {
		ID: "T1105", Name: "Ingress Tool Transfer",
		Tactic: "Command and Control",
		URL:    "https://attack.mitre.org/techniques/T1105/",
	},
	"T1562": {
		ID: "T1562", Name: "Impair Defenses",
		Tactic: "Defense Evasion",
		URL:    "https://attack.mitre.org/techniques/T1562/",
	},
	"T1552": {
		ID: "T1552", Name: "Unsecured Credentials",
		Tactic: "Credential Access",
		URL:    "https://attack.mitre.org/techniques/T1552/",
	},
	"T1611": {
		ID: "T1611", Name: "Escape to Host",
		Tactic: "Privilege Escalation",
		URL:    "https://attack.mitre.org/techniques/T1611/",
	},
	"T1136": {
		ID: "T1136", Name: "Create Account",
		Tactic: "Persistence",
		URL:    "https://attack.mitre.org/techniques/T1136/",
	},
	"T1566.001": {
		ID: "T1566.001", Name: "Phishing: Spearphishing Attachment",
		Tactic: "Initial Access",
		URL:    "https://attack.mitre.org/techniques/T1566/001/",
	},
	"T1204.002": {
		ID: "T1204.002", Name: "User Execution: Malicious File",
		Tactic: "Execution",
		URL:    "https://attack.mitre.org/techniques/T1204/002/",
	},
	"T1027": {
		ID: "T1027", Name: "Obfuscated Files or Information",
		Tactic: "Defense Evasion",
		URL:    "https://attack.mitre.org/techniques/T1027/",
	},
	"T1071": {
		ID: "T1071", Name: "Application Layer Protocol",
		Tactic: "Command and Control",
		URL:    "https://attack.mitre.org/techniques/T1071/",
	},

	// Phase 4 additions -- each backed by a specific new detection rule
	// (internal/detect/rules.go) that only assigns it when its own
	// deterministic logic actually supports it. See
	// docs/detection-engine.md.
	"T1059.003": {
		ID: "T1059.003", Name: "Command and Scripting Interpreter: Windows Command Shell",
		Tactic: "Execution",
		URL:    "https://attack.mitre.org/techniques/T1059/003/",
	},
	"T1059.005": {
		ID: "T1059.005", Name: "Command and Scripting Interpreter: Visual Basic",
		Tactic: "Execution",
		URL:    "https://attack.mitre.org/techniques/T1059/005/",
	},
	"T1059.007": {
		ID: "T1059.007", Name: "Command and Scripting Interpreter: JavaScript",
		Tactic: "Execution",
		URL:    "https://attack.mitre.org/techniques/T1059/007/",
	},
	"T1543.003": {
		ID: "T1543.003", Name: "Create or Modify System Process: Windows Service",
		Tactic: "Persistence, Privilege Escalation",
		URL:    "https://attack.mitre.org/techniques/T1543/003/",
	},
	"T1218.005": {
		ID: "T1218.005", Name: "System Binary Proxy Execution: Mshta",
		Tactic: "Defense Evasion",
		URL:    "https://attack.mitre.org/techniques/T1218/005/",
	},
	"T1547.004": {
		ID: "T1547.004", Name: "Boot or Logon Autostart Execution: Winlogon Helper DLL",
		Tactic: "Persistence, Privilege Escalation",
		URL:    "https://attack.mitre.org/techniques/T1547/004/",
	},
	"T1546.012": {
		ID: "T1546.012", Name: "Event Triggered Execution: Image File Execution Options Injection",
		Tactic: "Persistence, Privilege Escalation, Defense Evasion",
		URL:    "https://attack.mitre.org/techniques/T1546/012/",
	},
	"T1021.001": {
		ID: "T1021.001", Name: "Remote Services: Remote Desktop Protocol",
		Tactic: "Lateral Movement",
		URL:    "https://attack.mitre.org/techniques/T1021/001/",
	},
}

// Lookup returns the technique metadata for id, and whether it was found.
func Lookup(id string) (Technique, bool) {
	t, ok := registry[id]
	return t, ok
}

// All returns every technique Tracefall currently knows how to map to,
// used by the /cases/{id}/attack endpoint to describe coverage.
func All() []Technique {
	out := make([]Technique, 0, len(registry))
	for _, t := range registry {
		out = append(out, t)
	}
	return out
}

// Resolve maps a list of technique IDs to their full metadata, skipping
// any ID not present in the registry rather than failing -- a rule
// referencing an unregistered ID is a bug to fix in this file, not a
// reason to crash the pipeline.
func Resolve(ids []string) []Technique {
	out := make([]Technique, 0, len(ids))
	for _, id := range ids {
		if t, ok := registry[id]; ok {
			out = append(out, t)
		}
	}
	return out
}
