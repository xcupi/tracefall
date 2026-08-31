// Package winevent holds the ONE canonical mapping from a Windows event
// (channel, provider, event ID, and its EventData name/value payload) to
// a normalized internal/model.Event.
//
// It exists because Tracefall now learns about the same Windows event
// from two different sources: EvtxECmd's CSV export
// (internal/parsers/evtxcsv) and the raw binary event log
// (internal/parsers/evtx). Those two must normalize an identical record
// to identical fields, or Event.ComputeDedupHash would produce two
// different identities for one real-world event and the same evidence,
// collected two ways, would be counted twice by every detection rule.
//
// Sharing the table makes that agreement a property of the code rather
// than of two switch statements that happen to match today. It is the
// same precedent internal/parsers/regpersist set for registry
// persistence classification: one fixed table, more than one caller.
//
// Adding support for another channel/EventID pair is a new case in the
// switch here, and both parsers gain it at once.
package winevent

import (
	"fmt"
	"strconv"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/normalize"
	"tracefall/internal/parsers/regpersist"
)

// Input is one Windows event, in the shape both sources can supply.
//
// Data is the EventData/UserData payload as name→value pairs: the raw
// event log carries these directly as <Data Name="k">v</Data> elements,
// and EvtxECmd flattens the same pairs into its PayloadData columns.
type Input struct {
	Channel  string
	Provider string
	EventID  int
	Data     map[string]string

	// RemoteHost and Description are EvtxECmd conveniences with no
	// equivalent in the raw log; both are optional and every use below
	// treats them as a fallback, never as the primary source of a field.
	RemoteHost  string
	Description string
}

// Normalize fills in ev's event-type-specific fields. It returns false
// for a channel/EventID pair Tracefall has no mapping for, which the
// caller treats as "record parsed but not emitted as an event" -- an
// under-specified event is worse than none.
//
// ev must already carry the source-independent fields (timestamp, host,
// user, provider, event ID, artifact type, parser, provenance); this
// only adds what depends on the event's meaning.
func Normalize(ev *model.Event, in Input) bool {
	payload := in.Data
	channel := strings.ToLower(in.Channel)
	eventID := strconv.Itoa(in.EventID)
	switch {
	case channel == "security" && eventID == "4624":
		ev.EventType = model.EventLogonSuccess
		ev.User = firstNonEmpty(payload["TargetUserName"], ev.User)
		ev.Extra["logon_type"] = payload["LogonType"]
		ev.Extra["target_user_sid"] = payload["TargetUserSid"]
		ev.Extra["subject_user_name"] = payload["SubjectUserName"]
		ev.NetworkSource = payload["IpAddress"]
		ev.Extra["workstation_name"] = payload["WorkstationName"]
		return true

	case channel == "security" && eventID == "4625":
		ev.EventType = model.EventLogonFailure
		ev.User = firstNonEmpty(payload["TargetUserName"], ev.User)
		ev.Extra["logon_type"] = payload["LogonType"]
		ev.Extra["failure_reason"] = firstNonEmpty(payload["Status"], payload["FailureReason"])
		ev.Extra["sub_status"] = payload["SubStatus"]
		ev.NetworkSource = payload["IpAddress"]
		ev.Extra["workstation_name"] = payload["WorkstationName"]
		return true

	case channel == "security" && eventID == "4688":
		ev.EventType = model.EventProcessCreate
		newProc := firstNonEmpty(payload["NewProcessName"], payload["NewProcessId"])
		ev.ProcessPath = newProc
		ev.ProcessName = normalize.ProcessName(newProc)
		ev.CommandLine = payload["CommandLine"]
		parentProc := payload["ParentProcessName"]
		ev.ParentProcessPath = parentProc
		ev.ParentProcessName = normalize.ProcessName(parentProc)
		ev.PID = normalize.Int64(hexOrDec(payload["NewProcessId"]))
		ev.PPID = normalize.Int64(hexOrDec(payload["ProcessId"]))
		ev.User = firstNonEmpty(payload["SubjectUserName"], ev.User)
		return true

	// 4648: a logon was attempted using explicit credentials (runas,
	// mapped drive with alternate creds, scheduled task "run as", etc.)
	// -- feeds explicitCredentialUse and the credential-abuse
	// correlation (internal/correlate/credential_chain.go).
	case channel == "security" && eventID == "4648":
		ev.EventType = model.EventLogonExplicitCreds
		ev.User = firstNonEmpty(payload["SubjectUserName"], ev.User)
		ev.Extra["target_user_name"] = payload["TargetUserName"]
		ev.Extra["target_server_name"] = payload["TargetServerName"]
		ev.NetworkSource = firstNonEmpty(payload["IpAddress"], in.RemoteHost)
		ev.ProcessPath = payload["ProcessName"]
		ev.ProcessName = normalize.ProcessName(payload["ProcessName"])
		return true

	// 4672: special/administrative privileges were assigned to a new
	// logon -- feeds privilegedLogonObserved.
	case channel == "security" && eventID == "4672":
		ev.EventType = model.EventPrivilegedLogon
		ev.User = firstNonEmpty(payload["SubjectUserName"], ev.User)
		ev.Extra["privilege_list"] = truncateExtra(payload["PrivilegeList"], 500)
		return true

	// 4768/4769: Kerberos TGT/service-ticket requests -- authentication
	// visibility on the timeline and available to entity/temporal
	// correlation; Phase 4 doesn't add a bespoke rule for these alone
	// (see docs/detection-engine.md).
	case channel == "security" && eventID == "4768":
		ev.EventType = model.EventKerberosTGTRequest
		ev.User = firstNonEmpty(payload["TargetUserName"], ev.User)
		ev.NetworkSource = firstNonEmpty(payload["IpAddress"], in.RemoteHost)
		ev.Extra["auth_package"] = "Kerberos"
		ev.Extra["ticket_encryption_type"] = payload["TicketEncryptionType"]
		return true

	case channel == "security" && eventID == "4769":
		ev.EventType = model.EventKerberosServiceTicket
		ev.User = firstNonEmpty(payload["TargetUserName"], ev.User)
		ev.NetworkSource = firstNonEmpty(payload["IpAddress"], in.RemoteHost)
		ev.Extra["service_name"] = payload["ServiceName"]
		ev.Extra["ticket_encryption_type"] = payload["TicketEncryptionType"]
		return true

	// 4776: the domain controller validated credentials for an NTLM
	// logon.
	case channel == "security" && eventID == "4776":
		ev.EventType = model.EventNTLMAuth
		ev.User = firstNonEmpty(payload["TargetUserName"], ev.User)
		ev.Extra["auth_package"] = "NTLM"
		ev.Extra["workstation_name"] = payload["Workstation"]
		ev.Extra["error_code"] = payload["ErrorCode"]
		return true

	// PowerShell 4104 (script block logging, full text) and 4103 (module
	// logging, pipeline/parameter payload) both carry command content
	// worth scanning for suspicious indicators -- both are normalized to
	// the same EventPowerShellScript type so powershellEncodedCommand
	// evaluates either source identically; log_type in Extra preserves
	// which one it actually was.
	case strings.Contains(channel, "powershell") && eventID == "4104":
		ev.EventType = model.EventPowerShellScript
		ev.CommandLine = firstNonEmpty(payload["ScriptBlockText"], in.Description)
		ev.FilePath = payload["Path"]
		ev.ProcessName = "powershell.exe"
		ev.Extra["log_type"] = "script_block"
		ev.Extra["script_block_id"] = payload["ScriptBlockId"]
		ev.Extra["message_number"] = payload["MessageNumber"]
		return true

	case strings.Contains(channel, "powershell") && eventID == "4103":
		ev.EventType = model.EventPowerShellScript
		ev.CommandLine = firstNonEmpty(payload["Payload"], in.Description)
		ev.ProcessName = "powershell.exe"
		ev.Extra["log_type"] = "module_logging"
		ev.Extra["context_info"] = truncateExtra(payload["ContextInfo"], 500)
		return true

	// System 7045 (Service Control Manager): a new service was installed
	// -- the classic service-persistence signal, feeds servicePersistence
	// and the service-installation correlation
	// (internal/correlate/service_chain.go).
	case channel == "system" && strings.Contains(strings.ToLower(in.Provider), "service control manager") && eventID == "7045":
		ev.EventType = model.EventServiceInstall
		ev.Extra["service_name"] = payload["ServiceName"]
		ev.Extra["start_type"] = payload["StartType"]
		ev.Extra["service_type"] = payload["ServiceType"]
		ev.User = firstNonEmpty(payload["AccountName"], ev.User)
		imagePath := payload["ImagePath"]
		ev.FilePath = imagePath
		ev.ProcessName = normalize.ExecutableFromCommandLine(imagePath)
		ev.ProcessPath = imagePath
		return true

	// Sysmon Event ID 1 (ProcessCreate): a second, independent source of
	// process-creation evidence alongside Security 4688, with a few
	// fields 4688 doesn't carry (ParentCommandLine, IntegrityLevel,
	// OriginalFileName, hash). Normalized to the same EventProcessCreate
	// type so every process-based rule and correlation already written
	// for 4688 evaluates Sysmon process-creates identically -- a case
	// collected with only Sysmon (no Security auditing enabled) gets full
	// coverage, not a second-class subset.
	case strings.Contains(channel, "sysmon") && eventID == "1":
		ev.EventType = model.EventProcessCreate
		image := payload["Image"]
		ev.ProcessPath = image
		ev.ProcessName = normalize.ProcessName(image)
		ev.CommandLine = payload["CommandLine"]
		parentImage := payload["ParentImage"]
		ev.ParentProcessPath = parentImage
		ev.ParentProcessName = normalize.ProcessName(parentImage)
		ev.PID = normalize.Int64(payload["ProcessId"])
		ev.PPID = normalize.Int64(payload["ParentProcessId"])
		ev.User = firstNonEmpty(payload["User"], ev.User)
		ev.Extra["parent_command_line"] = payload["ParentCommandLine"]
		ev.Extra["integrity_level"] = payload["IntegrityLevel"]
		ev.Extra["original_file_name"] = payload["OriginalFileName"]
		if payload["SignatureStatus"] != "" {
			ev.Extra["signature_status"] = payload["SignatureStatus"]
		}
		return true

	case strings.Contains(channel, "sysmon") && eventID == "3":
		ev.EventType = model.EventNetworkConnection
		ev.ProcessName = normalize.ProcessName(payload["Image"])
		ev.ProcessPath = payload["Image"]
		ev.NetworkSource = firstNonEmpty(payload["SourceIp"], in.RemoteHost)
		ev.NetworkDest = payload["DestinationIp"]
		ev.NetworkDestPort = normalize.Int(payload["DestinationPort"])
		ev.Extra["destination_hostname"] = payload["DestinationHostname"]
		ev.PID = normalize.Int64(payload["ProcessId"])
		return true

	// Sysmon Event ID 11 (FileCreate): a process wrote a file -- most
	// useful for observing a payload land on disk (e.g. under AppData or
	// Downloads) shortly before it's executed.
	case strings.Contains(channel, "sysmon") && eventID == "11":
		ev.EventType = model.EventFileCreate
		image := payload["Image"]
		ev.ProcessName = normalize.ProcessName(image)
		ev.ProcessPath = image
		ev.FilePath = payload["TargetFilename"]
		ev.PID = normalize.Int64(payload["ProcessId"])
		return true

	// Sysmon Event ID 12/13 (RegistryEvent: CreateKey/SetValue): a
	// real-time registry write, classified against the same fixed
	// persistence-location table (internal/parsers/regpersist) the RECmd
	// hive-snapshot parser uses, so the same key reported by either
	// artifact normalizes to the same EventType. A write to a location
	// regpersist doesn't recognize is dropped rather than emitted as an
	// under-specified event -- Tracefall doesn't attempt general registry
	// activity monitoring, only the fixed persistence locations Phase 4A
	// prioritized.
	case strings.Contains(channel, "sysmon") && (eventID == "12" || eventID == "13"):
		targetObject := payload["TargetObject"]
		keyPath, valueName := splitRegistryTarget(targetObject)
		kind := regpersist.Classify(keyPath, valueName)
		if kind == regpersist.KindNone {
			return false
		}
		if kind == regpersist.KindRunKey {
			ev.EventType = model.EventRegistryRunKey
		} else {
			ev.EventType = model.EventRegistryPersistence
			ev.Extra["registry_persistence_type"] = string(kind)
		}
		valueData := payload["Details"]
		ev.RegistryPath = targetObject
		ev.FilePath = valueData
		ev.ProcessName = normalize.ExecutableFromCommandLine(valueData)
		image := payload["Image"]
		ev.Extra["writing_process"] = image
		ev.Extra["value_name"] = valueName
		ev.Extra["value_data"] = valueData
		ev.PID = normalize.Int64(payload["ProcessId"])
		return true

	// Sysmon Event ID 22 (DNSEvent): a process resolved a domain name.
	// NetworkDest carries the queried domain (rather than an IP, as it
	// does for EventNetworkConnection) so DNS activity still groups under
	// the "network" category and participates in entity/temporal
	// correlation the same way any other network-adjacent event does.
	case strings.Contains(channel, "sysmon") && eventID == "22":
		ev.EventType = model.EventDNSQuery
		image := payload["Image"]
		ev.ProcessName = normalize.ProcessName(image)
		ev.ProcessPath = image
		queryName := payload["QueryName"]
		ev.NetworkDest = queryName
		ev.Extra["dns_query"] = queryName
		ev.Extra["query_status"] = payload["QueryStatus"]
		ev.PID = normalize.Int64(payload["ProcessId"])
		return true

	default:
		return false
	}
}

// splitRegistryTarget splits a Sysmon TargetObject registry path (e.g.
// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater`) into its
// key path and trailing value name, matching how RECmd reports KeyPath
// and ValueName as separate fields for the same real-world location.
func splitRegistryTarget(targetObject string) (keyPath, valueName string) {
	idx := strings.LastIndex(targetObject, `\`)
	if idx < 0 {
		return targetObject, ""
	}
	return targetObject[:idx], targetObject[idx+1:]
}

// truncateExtra bounds a payload field before it's stored in Extra --
// some fields (PrivilegeList, PowerShell ContextInfo) can be long, and
// Extra is for triage-useful metadata, not an unbounded blob store.
func truncateExtra(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// hexOrDec normalizes a PID that may be rendered in hex (as Windows
// Security auditing does, e.g. "0x1a2c") or decimal.
func hexOrDec(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		var v int64
		fmt.Sscanf(s, "0x%x", &v)
		return fmt.Sprint(v)
	}
	return s
}
