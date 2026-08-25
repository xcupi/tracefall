// Package procclass holds small, fixed process/path classification
// tables (Office applications, PowerShell hosts, common living-off-the-
// land binaries, user-writable path markers) shared by the detection
// engine (internal/detect) and correlation engine (internal/correlate).
// Neither of those packages depends on the other; this package is their
// shared foundation so the same process is classified the same way by
// both, without one importing the other's rule internals.
package procclass

import "strings"

var officeProcesses = set("winword.exe", "excel.exe", "powerpnt.exe", "mspub.exe", "outlook.exe", "onenote.exe", "acrobat.exe", "acrord32.exe")
var powershellProcesses = set("powershell.exe", "powershell_ise.exe", "pwsh.exe")
var scriptHostProcesses = set("wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe", "cmd.exe")

// suspiciousPathMarkers flags paths under user-writable / non-standard
// install locations -- legitimate software installs to Program Files or
// System32; malware dropped by a phishing chain typically lands in one
// of these instead.
var suspiciousPathMarkers = []string{
	`\appdata\`, `\temp\`, `\programdata\`, `\users\public\`, `\downloads\`,
}

func set(vals ...string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}

// IsOffice reports whether processName (lowercased base name, as produced
// by internal/normalize.ProcessName) is a common Office application.
func IsOffice(processName string) bool { return officeProcesses[processName] }

// IsPowerShell reports whether processName is a PowerShell host.
func IsPowerShell(processName string) bool { return powershellProcesses[processName] }

// IsScriptHost reports whether processName is a common scripting/LOLBin
// host (wscript, mshta, rundll32, cmd, etc.).
func IsScriptHost(processName string) bool { return scriptHostProcesses[processName] }

// HasSuspiciousPath reports whether p contains a user-writable or
// non-standard directory marker (AppData, Temp, ProgramData, etc.).
func HasSuspiciousPath(p string) bool {
	p = strings.ToLower(p)
	for _, marker := range suspiciousPathMarkers {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}
