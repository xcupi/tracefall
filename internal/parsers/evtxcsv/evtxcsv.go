// Package evtxcsv parses the CSV output of EvtxECmd (Eric Zimmerman's
// Windows Event Log parser, run by KAPE's !EZParser module against
// collected .evtx files). Tracefall consumes this CSV rather than raw
// binary .evtx directly: EvtxECmd already resolves each event's Maps
// definition into named PayloadData fields, which is exactly the
// structured extraction Tracefall needs, and re-implementing the .evtx
// binary format and Maps engine from scratch would spend Phase 1's budget
// on a solved problem instead of on detection/correlation. Raw .evtx
// parsing is a natural Phase 2 addition behind the same ArtifactParser
// interface.
//
// One parser instance covers three distinct KAPE-priority artifacts --
// Security 4624/4625/4688, PowerShell 4104, and (as a bonus, since it
// costs nothing extra) Sysmon Network Connect -- because they all arrive
// in the same EvtxECmd CSV shape. Extending coverage to another
// channel/EventID pair is a new case in the switch in toEvent, not a new
// parser.
package evtxcsv

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/normalize"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/regpersist"
)

const parserName = "evtxcsv@1"

// Parser implements parsers.ArtifactParser for EvtxECmd CSV output.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactWindowsEventLog }

// Detect matches EvtxECmd's default output naming convention, e.g.
// "20240115143022_EvtxECmd_Output.csv", anywhere under the evidence root.
func (Parser) Detect(relPath string) bool {
	base := strings.ToLower(filepath.Base(relPath))
	return strings.Contains(base, "evtxecmd") && strings.HasSuffix(base, ".csv")
}

// row is one EvtxECmd CSV record, keyed by the real tool's column names.
type row struct {
	TimeCreated    string
	EventId        string
	Provider       string
	Channel        string
	ComputerName   string
	UserName       string
	RemoteHost     string
	MapDescription string
	PayloadData1   string
	PayloadData2   string
	PayloadData3   string
	PayloadData4   string
	PayloadData5   string
	PayloadData6   string
	RecordNumber   string
}

func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("evtxcsv: reading header: %w", err)
	}
	col := indexColumns(header)

	var out parsers.ParseResult
	rowNum := 1
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return parsers.ParseResult{}, fmt.Errorf("evtxcsv: row %d: %w", rowNum, err)
		}
		rowNum++

		rw := row{
			TimeCreated:    get(rec, col, "TimeCreated"),
			EventId:        get(rec, col, "EventId"),
			Provider:       get(rec, col, "Provider"),
			Channel:        get(rec, col, "Channel"),
			ComputerName:   get(rec, col, "ComputerName"),
			UserName:       get(rec, col, "UserName"),
			RemoteHost:     get(rec, col, "RemoteHost"),
			MapDescription: get(rec, col, "MapDescription"),
			PayloadData1:   get(rec, col, "PayloadData1"),
			PayloadData2:   get(rec, col, "PayloadData2"),
			PayloadData3:   get(rec, col, "PayloadData3"),
			PayloadData4:   get(rec, col, "PayloadData4"),
			PayloadData5:   get(rec, col, "PayloadData5"),
			PayloadData6:   get(rec, col, "PayloadData6"),
			RecordNumber:   get(rec, col, "RecordNumber"),
		}

		payload := parsePayload(strings.Join([]string{
			rw.PayloadData1, rw.PayloadData2, rw.PayloadData3,
			rw.PayloadData4, rw.PayloadData5, rw.PayloadData6,
		}, "; "))

		ts, ok := normalize.Timestamp(rw.TimeCreated)
		if !ok {
			// No usable timestamp -- this record can't be placed on the
			// timeline, so it's dropped rather than defaulting to a
			// fabricated time that would corrupt correlation.
			continue
		}

		ev := model.Event{
			Timestamp:       ts,
			Host:            normalize.Host(rw.ComputerName),
			User:            normalize.User(rw.UserName),
			Provider:        rw.Channel,
			EventID:         normalize.Int(rw.EventId),
			ArtifactType:    model.ArtifactWindowsEventLog,
			Parser:          parserName,
			Confidence:      1.0,
			SourceReference: "row:" + fmt.Sprint(rowNum-1),
			Extra:           map[string]string{},
		}
		if !toEvent(&ev, rw, payload) {
			// Channel/EventId combination we don't have a mapping for
			// yet -- skip rather than emit an under-specified event.
			continue
		}

		rawJSON, _ := json.Marshal(rec)
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, model.RawEvidence{
			SourceReference: ev.SourceReference,
			Raw:             string(rawJSON),
		})
	}
	return out, nil
}

// toEvent fills in the event-type-specific fields of ev based on channel
// and Windows Event ID. Returns false if this row's channel/EventId pair
// isn't one Tracefall maps.
//
// Phase 4 extends this switch with additional Security/System Event IDs
// and additional Sysmon event types -- each addition was prioritized
// because it feeds a specific detection rule or correlation added in the
// same phase (see internal/detect/rules.go and internal/correlate), not
// added merely because EvtxECmd happens to expose it. See
// docs/detection-engine.md for the full list and rationale.
func toEvent(ev *model.Event, rw row, payload map[string]string) bool {
	channel := strings.ToLower(rw.Channel)
	switch {
	case channel == "security" && rw.EventId == "4624":
		ev.EventType = model.EventLogonSuccess
		ev.User = firstNonEmpty(payload["TargetUserName"], ev.User)
		ev.Extra["logon_type"] = payload["LogonType"]
		ev.Extra["target_user_sid"] = payload["TargetUserSid"]
		ev.Extra["subject_user_name"] = payload["SubjectUserName"]
		ev.NetworkSource = payload["IpAddress"]
		ev.Extra["workstation_name"] = payload["WorkstationName"]
		return true

	case channel == "security" && rw.EventId == "4625":
		ev.EventType = model.EventLogonFailure
		ev.User = firstNonEmpty(payload["TargetUserName"], ev.User)
		ev.Extra["logon_type"] = payload["LogonType"]
		ev.Extra["failure_reason"] = firstNonEmpty(payload["Status"], payload["FailureReason"])
		ev.Extra["sub_status"] = payload["SubStatus"]
		ev.NetworkSource = payload["IpAddress"]
		ev.Extra["workstation_name"] = payload["WorkstationName"]
		return true

	case channel == "security" && rw.EventId == "4688":
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
	case channel == "security" && rw.EventId == "4648":
		ev.EventType = model.EventLogonExplicitCreds
		ev.User = firstNonEmpty(payload["SubjectUserName"], ev.User)
		ev.Extra["target_user_name"] = payload["TargetUserName"]
		ev.Extra["target_server_name"] = payload["TargetServerName"]
		ev.NetworkSource = firstNonEmpty(payload["IpAddress"], rw.RemoteHost)
		ev.ProcessPath = payload["ProcessName"]
		ev.ProcessName = normalize.ProcessName(payload["ProcessName"])
		return true

	// 4672: special/administrative privileges were assigned to a new
	// logon -- feeds privilegedLogonObserved.
	case channel == "security" && rw.EventId == "4672":
		ev.EventType = model.EventPrivilegedLogon
		ev.User = firstNonEmpty(payload["SubjectUserName"], ev.User)
		ev.Extra["privilege_list"] = truncateExtra(payload["PrivilegeList"], 500)
		return true

	// 4768/4769: Kerberos TGT/service-ticket requests -- authentication
	// visibility on the timeline and available to entity/temporal
	// correlation; Phase 4 doesn't add a bespoke rule for these alone
	// (see docs/detection-engine.md).
	case channel == "security" && rw.EventId == "4768":
		ev.EventType = model.EventKerberosTGTRequest
		ev.User = firstNonEmpty(payload["TargetUserName"], ev.User)
		ev.NetworkSource = firstNonEmpty(payload["IpAddress"], rw.RemoteHost)
		ev.Extra["auth_package"] = "Kerberos"
		ev.Extra["ticket_encryption_type"] = payload["TicketEncryptionType"]
		return true

	case channel == "security" && rw.EventId == "4769":
		ev.EventType = model.EventKerberosServiceTicket
		ev.User = firstNonEmpty(payload["TargetUserName"], ev.User)
		ev.NetworkSource = firstNonEmpty(payload["IpAddress"], rw.RemoteHost)
		ev.Extra["service_name"] = payload["ServiceName"]
		ev.Extra["ticket_encryption_type"] = payload["TicketEncryptionType"]
		return true

	// 4776: the domain controller validated credentials for an NTLM
	// logon.
	case channel == "security" && rw.EventId == "4776":
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
	case strings.Contains(channel, "powershell") && rw.EventId == "4104":
		ev.EventType = model.EventPowerShellScript
		ev.CommandLine = firstNonEmpty(payload["ScriptBlockText"], rw.MapDescription)
		ev.FilePath = payload["Path"]
		ev.ProcessName = "powershell.exe"
		ev.Extra["log_type"] = "script_block"
		ev.Extra["script_block_id"] = payload["ScriptBlockId"]
		ev.Extra["message_number"] = payload["MessageNumber"]
		return true

	case strings.Contains(channel, "powershell") && rw.EventId == "4103":
		ev.EventType = model.EventPowerShellScript
		ev.CommandLine = firstNonEmpty(payload["Payload"], rw.MapDescription)
		ev.ProcessName = "powershell.exe"
		ev.Extra["log_type"] = "module_logging"
		ev.Extra["context_info"] = truncateExtra(payload["ContextInfo"], 500)
		return true

	// System 7045 (Service Control Manager): a new service was installed
	// -- the classic service-persistence signal, feeds servicePersistence
	// and the service-installation correlation
	// (internal/correlate/service_chain.go).
	case channel == "system" && strings.Contains(strings.ToLower(rw.Provider), "service control manager") && rw.EventId == "7045":
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
	case strings.Contains(channel, "sysmon") && rw.EventId == "1":
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

	case strings.Contains(channel, "sysmon") && rw.EventId == "3":
		ev.EventType = model.EventNetworkConnection
		ev.ProcessName = normalize.ProcessName(payload["Image"])
		ev.ProcessPath = payload["Image"]
		ev.NetworkSource = firstNonEmpty(payload["SourceIp"], rw.RemoteHost)
		ev.NetworkDest = payload["DestinationIp"]
		ev.NetworkDestPort = normalize.Int(payload["DestinationPort"])
		ev.Extra["destination_hostname"] = payload["DestinationHostname"]
		ev.PID = normalize.Int64(payload["ProcessId"])
		return true

	// Sysmon Event ID 11 (FileCreate): a process wrote a file -- most
	// useful for observing a payload land on disk (e.g. under AppData or
	// Downloads) shortly before it's executed.
	case strings.Contains(channel, "sysmon") && rw.EventId == "11":
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
	case strings.Contains(channel, "sysmon") && (rw.EventId == "12" || rw.EventId == "13"):
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
	case strings.Contains(channel, "sysmon") && rw.EventId == "22":
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

func indexColumns(header []string) map[string]int {
	m := make(map[string]int, len(header))
	for i, h := range header {
		m[strings.TrimSpace(h)] = i
	}
	return m
}

func get(rec []string, col map[string]int, name string) string {
	i, ok := col[name]
	if !ok || i >= len(rec) {
		return ""
	}
	return strings.TrimSpace(rec[i])
}

// parsePayload parses EvtxECmd's Maps-derived "Key: Value; Key2: Value2"
// payload format into a lookup map.
func parsePayload(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return out
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
