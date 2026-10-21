// Package regpersist classifies a registry key/value path against the
// fixed set of well-known persistence locations Tracefall recognizes --
// Run/RunOnce keys, Winlogon Shell/Userinit, Image File Execution Options
// (IFEO) debugger hijacking, AppInit_DLLs, and a Windows service's
// ImagePath. It exists so the exact same evidence-backed classification
// applies regardless of which artifact told Tracefall about the key: a
// point-in-time RECmd hive snapshot (internal/parsers/recmd) and a
// real-time Sysmon registry event (internal/parsers/evtxcsv) both call
// Classify rather than each guessing independently, matching
// internal/procclass's precedent of one shared, fixed classification
// table used by more than one caller.
package regpersist

import "strings"

// Kind identifies which known persistence location a registry path
// matched, or KindNone if it isn't one Tracefall recognizes as
// persistence-relevant.
type Kind string

const (
	KindNone             Kind = ""
	KindRunKey           Kind = "run_key"
	KindWinlogon         Kind = "winlogon"
	KindIFEO             Kind = "ifeo"
	KindAppInitDLLs      Kind = "appinit_dlls"
	KindServiceImagePath Kind = "service_image_path"
)

// Classify inspects a registry key path (and, for the service ImagePath
// case, the value name) and reports which persistence location it is, if
// any. keyPath is matched case-insensitively, as Windows registry paths
// are.
// winlogonLaunchValues are the Winlogon values Windows uses to start a
// program for the logon session.
var winlogonLaunchValues = map[string]bool{
	"shell": true, "userinit": true, "taskman": true, "appsetup": true,
	"vmapplet": true, "uihost": true, "ginadll": true,
}

func Classify(keyPath, valueName string) Kind {
	lower := strings.ToLower(keyPath)

	switch {
	case strings.Contains(lower, `\microsoft\windows\currentversion\run`):
		// Covers both ...\Run and ...\RunOnce (RunOnce is a prefix match
		// of Run, so no separate case is needed).
		return KindRunKey

	case strings.Contains(lower, `\microsoft\windows nt\currentversion\winlogon`):
		// Only the Winlogon key itself, and only the values that start a
		// program at logon. Its subkeys (GPExtensions, Notify, ...) hold
		// ordinary configuration, and so do its other values.
		if strings.HasSuffix(strings.TrimRight(lower, `\`), `\winlogon`) && winlogonLaunchValues[strings.ToLower(valueName)] {
			return KindWinlogon
		}
		return KindNone

	case strings.Contains(lower, `\microsoft\windows nt\currentversion\image file execution options`):
		// Only a Debugger value directly under a per-executable subkey
		// redirects execution. Mitigation flags such as GlobalFlag or
		// DisableExceptionChainValidation, and the DllNXOptions list, do not.
		rest := lower[strings.Index(lower, `image file execution options`)+len(`image file execution options`):]
		rest = strings.Trim(rest, `\`)
		if rest != "" && !strings.Contains(rest, `\`) && rest != "dllnxoptions" && strings.EqualFold(valueName, "Debugger") {
			return KindIFEO
		}
		return KindNone

	case strings.Contains(lower, `\microsoft\windows nt\currentversion\silentprocessexit\`) && strings.EqualFold(valueName, "MonitorProcess"):
		// A program started when the named process exits: the same
		// redirection as an IFEO debugger.
		return KindIFEO

	case strings.Contains(lower, `\microsoft\windows nt\currentversion\windows`) && strings.EqualFold(valueName, "AppInit_DLLs"):
		return KindAppInitDLLs

	case strings.EqualFold(valueName, "ImagePath") && isServiceKey(lower):
		return KindServiceImagePath

	default:
		return KindNone
	}
}

// isServiceKey reports whether lower is a service's own key,
// ...\Services\<name>, not one of its subkeys (Parameters, Enum, ...),
// which can also carry an ImagePath-named value.
func isServiceKey(lower string) bool {
	i := strings.LastIndex(lower, `\services\`)
	if i < 0 {
		return false
	}
	name := strings.Trim(lower[i+len(`\services\`):], `\`)
	return name != "" && !strings.Contains(name, `\`)
}
