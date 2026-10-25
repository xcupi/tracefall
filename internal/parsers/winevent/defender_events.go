package winevent

import (
	"strings"

	"tracefall/internal/cmdsem"
	"tracefall/internal/model"
)

const defenderProvider = "Microsoft-Windows-Windows Defender"
const defenderChannel = "Microsoft-Windows-Windows Defender/Operational"

// Bounds for the free-text fields of a Defender record.
const (
	defenderMaxInputBytes    = 16 << 10 // bytes of a resource that are scanned for secrets
	defenderMaxResourceBytes = 2048     // bytes of the redacted resource that are kept
	defenderMaxFieldBytes    = 512
)

// normalizeDefenderEvent maps the antimalware engine's detection and action
// records of the Defender Operational log:
//
//	1116  threat detected
//	1117  action taken on the threat
//	1118  action failed (non-critical)
//	1119  action failed (critical)
//
// The EventData names are the manifest's own, with spaces ("Threat Name"),
// which a real 1116/1117 record carries. 1118 and 1119 share the template of
// 1117 in the provider manifest; no real 1118/1119 record has been read, so
// their layout is not verified against evidence. Every other Defender ID
// (scan start/stop, signature update, 5007 configuration change, ...) stays
// unmapped on purpose: they are routine, very frequent, and record no
// detection. The IDs are claimed only under the Defender provider and channel;
// the same numbers elsewhere are not reinterpreted.
//
// A record that carries neither a threat name nor a detection ID is not
// mapped: an under-specified detection is worse than none.
func normalizeDefenderEvent(ev *model.Event, in Input) (handled, mapped bool) {
	switch in.EventID {
	case 1116, 1117, 1118, 1119:
	default:
		return false, false
	}
	if !strings.EqualFold(in.Provider, defenderProvider) {
		return false, false
	}
	if !strings.EqualFold(in.Channel, defenderChannel) {
		return true, false
	}
	p := in.Data
	if strings.TrimSpace(p["Threat Name"]) == "" && strings.TrimSpace(p["Detection ID"]) == "" {
		return true, false
	}

	setExtra(ev, "threat_name", truncateExtra(p["Threat Name"], defenderMaxFieldBytes))
	setExtra(ev, "threat_id", p["Threat ID"])
	setExtra(ev, "severity_name", p["Severity Name"])
	setExtra(ev, "severity_id", p["Severity ID"])
	setExtra(ev, "category_name", p["Category Name"])
	setExtra(ev, "category_id", p["Category ID"])
	setExtra(ev, "detection_id", p["Detection ID"])
	setExtra(ev, "detection_time_recorded", p["Detection Time"])
	setExtra(ev, "detection_user", p["Detection User"])
	setExtra(ev, "remediation_user", p["Remediation User"])
	setExtra(ev, "process_name_recorded", p["Process Name"])
	setExtra(ev, "source_name", p["Source Name"])
	setExtra(ev, "origin_name", p["Origin Name"])
	setExtra(ev, "execution_name", p["Execution Name"])
	setExtra(ev, "type_name", p["Type Name"])
	setExtra(ev, "status_code", p["Status Code"])
	setExtra(ev, "state", p["State"])
	setExtra(ev, "action_id", p["Action ID"])
	setExtra(ev, "action_name", p["Action Name"])
	setExtra(ev, "error_code", p["Error Code"])
	setExtra(ev, "error_description", truncateExtra(p["Error Description"], defenderMaxFieldBytes))
	setExtra(ev, "additional_actions", truncateExtra(p["Additional Actions String"], defenderMaxFieldBytes))
	setExtra(ev, "security_intelligence_version", truncateExtra(p["Security intelligence Version"], defenderMaxFieldBytes))
	setExtra(ev, "engine_version", truncateExtra(p["Engine Version"], defenderMaxFieldBytes))
	setExtra(ev, "product_version", p["Product Version"])

	res := p["Path"]
	kind, scheme := AntimalwareResourceKind(res)
	if res != "" {
		if len(res) > defenderMaxInputBytes {
			res = res[:defenderMaxInputBytes]
			ev.Extra["resource_truncated"] = "true"
		}
		res = cmdsem.Redact(res)
		if len(res) > defenderMaxResourceBytes {
			res = res[:defenderMaxResourceBytes]
			ev.Extra["resource_truncated"] = "true"
		}
		setExtra(ev, "resource", res)
		ev.Extra["resource_kind"] = kind
		setExtra(ev, "resource_scheme", scheme)
	}

	resourceNote := "The resource is the engine's recorded path or string."
	switch kind {
	case "command_line":
		resourceNote = "The resource is a command-line string, not a file: it names no file on disk and is not a process start."
	case "file":
		resourceNote = "The resource is a file path the engine recorded; it does not show who wrote the file or whether it ran."
	}

	switch in.EventID {
	case 1116:
		ev.EventType = model.EventAntimalwareDetection
		ev.Extra["evidence_meaning"] = "The antimalware engine recorded that it detected a threat in the resource, under its own detection label."
		ev.Extra["limitations"] = resourceNote + " The label is the engine's recorded name, not an independently computed family. " +
			"A detection does not show that the resource ran or that any command completed, and the action field of a detection record is the engine's pending action, not an outcome. " +
			"Records of one detection ID (detection, action) are separate observations of the same engine."
	default:
		ev.EventType = model.EventAntimalwareAction
		switch in.EventID {
		case 1117:
			ev.Extra["action_outcome"] = "action_reported"
			ev.Extra["evidence_meaning"] = "The antimalware engine recorded the action it took on a detection, with the status and error code shown."
		case 1118:
			ev.Extra["action_outcome"] = "action_failed"
			ev.Extra["evidence_meaning"] = "The antimalware engine recorded that an action on a detection failed (non-critical error), with the error code shown."
		case 1119:
			ev.Extra["action_outcome"] = "action_failed_critical"
			ev.Extra["evidence_meaning"] = "The antimalware engine recorded that an action on a detection failed (critical error), with the error code shown."
		}
		ev.Extra["limitations"] = "The action, error code and error text describe the antimalware action status only. A Remove action with error code 0 does not show that a transfer, a command or a file write completed or was undone, " +
			"nor that a payload was recovered or removed from disk. " + resourceNote + " The label is the engine's recorded name, not an independently computed family."
		if in.EventID != 1117 {
			ev.Extra["limitations"] += " The field layout of this event ID follows the 1117 template and was not verified on a real record."
		}
	}
	return true, true
}

// AntimalwareResourceKind classifies a resource string by the scheme the
// engine writes before the first colon ("CmdLine:_..." or "file:_..."). Only
// the two schemes seen in real records are named; anything else is "other"
// with its scheme kept, never guessed. Shared with the Defender text-log reader.
func AntimalwareResourceKind(res string) (kind, scheme string) {
	i := strings.Index(res, ":")
	if i < 2 || i > 24 {
		return "other", ""
	}
	scheme = res[:i]
	switch strings.ToLower(scheme) {
	case "cmdline":
		return "command_line", scheme
	case "file":
		return "file", scheme
	}
	return "other", scheme
}
