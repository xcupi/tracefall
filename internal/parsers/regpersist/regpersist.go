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
func Classify(keyPath, valueName string) Kind {
	lower := strings.ToLower(keyPath)

	switch {
	case strings.Contains(lower, `\microsoft\windows\currentversion\run`):
		// Covers both ...\Run and ...\RunOnce (RunOnce is a prefix match
		// of Run, so no separate case is needed).
		return KindRunKey

	case strings.Contains(lower, `\microsoft\windows nt\currentversion\winlogon`):
		return KindWinlogon

	case strings.Contains(lower, `\microsoft\windows nt\currentversion\image file execution options`):
		return KindIFEO

	case strings.Contains(lower, `\microsoft\windows nt\currentversion\windows`) && strings.EqualFold(valueName, "AppInit_DLLs"):
		return KindAppInitDLLs

	case strings.Contains(lower, `\services\`) && strings.EqualFold(valueName, "ImagePath"):
		return KindServiceImagePath

	default:
		return KindNone
	}
}
