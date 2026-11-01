package winevent

import (
	"strings"

	"tracefall/internal/model"
)

const psOperationalProvider = "Microsoft-Windows-PowerShell"
const psOperationalChannel = "Microsoft-Windows-PowerShell/Operational"

// ContextInfo labels read from a 4100 record and the Extra key each becomes.
// The values come from a free-text block of "Label = value" lines.
var psContextLabels = map[string]string{
	"Severity": "severity", "Host Name": "host_name", "Host Version": "host_version", "Host ID": "host_id",
	"Host Application": "host_application", "Engine Version": "engine_version", "Runspace ID": "runspace_id",
	"Pipeline ID": "pipeline_id", "Command Name": "command_name", "Command Type": "command_type",
	"Script Name": "script_name", "Command Path": "command_path", "Sequence Number": "sequence_number",
	"User": "context_user", "Connected User": "connected_user", "Shell ID": "shell_id",
}

// Labels whose value can carry a path, command line or secret and is redacted.
var psContextRedacted = map[string]bool{"host_application": true, "script_name": true, "command_path": true, "command_name": true}

const psContextBytes = 500

// normalizePowerShellErrorEvent maps Microsoft-Windows-PowerShell/Operational
// 4100: an error raised while a pipeline executed. The record carries
// ContextInfo (host, command, user), UserData and Payload ("Error Message = ..."
// and "Fully Qualified Error ID = ..."). It is an error report, not a command:
// the lifecycle IDs (8196, 12039, 40961, 40962, 53504) are noise and unmapped.
func normalizePowerShellErrorEvent(ev *model.Event, in Input) (handled, mapped bool) {
	if in.EventID != 4100 {
		return false, false
	}
	if !strings.EqualFold(in.Provider, psOperationalProvider) || !strings.EqualFold(in.Channel, psOperationalChannel) {
		return true, false
	}
	p := in.Data
	ctx, payload := p["ContextInfo"], p["Payload"]
	if len(ctx) > psMaxValueBytes {
		ctx = ctx[:psMaxValueBytes]
	}
	if len(payload) > psMaxValueBytes {
		payload = payload[:psMaxValueBytes]
	}
	fields := map[string]string{}
	for i, line := range strings.Split(ctx, "\n") {
		if i >= psMaxLines {
			break
		}
		label, val, found := strings.Cut(strings.TrimSpace(line), "=")
		key, wanted := psContextLabels[strings.TrimSpace(label)]
		if !found || !wanted {
			continue
		}
		if _, seen := fields[key]; !seen {
			fields[key] = strings.TrimSpace(val)
		}
	}
	msg, hasMsg, fqid, hasFQID := psErrorPayload(payload)
	if len(fields) == 0 && !hasMsg && !hasFQID {
		return true, false // nothing identifiable: under-specified.
	}
	ev.EventType = model.EventPowerShellPipelineError
	ev.User = dashToEmpty(fields["context_user"])
	for key, val := range fields {
		if psContextRedacted[key] {
			v, cut := boundedRedacted(val, psMaxFieldBytes)
			val = v
			if cut {
				ev.Extra[key+"_truncated"] = "true"
			}
		}
		ev.Extra[key] = truncateExtra(val, psMaxFieldBytes)
	}
	if hasMsg {
		v, cut := boundedRedacted(msg, psMaxFieldBytes)
		ev.Extra["error_message"] = v
		if cut {
			ev.Extra["error_message_truncated"] = "true"
		}
	}
	if hasFQID {
		v, cut := boundedRedacted(fqid, psMaxFieldBytes)
		ev.Extra["fully_qualified_error_id"] = v
		if cut {
			ev.Extra["fully_qualified_error_id_truncated"] = "true"
		}
	}
	if ctx != "" {
		v, cut := boundedRedacted(ctx, psContextBytes)
		ev.Extra["context_info"] = v
		if cut {
			ev.Extra["context_info_truncated"] = "true"
		}
	}
	ev.Extra["action"] = "pipeline_error"
	ev.Extra["outcome"] = "failure"
	ev.Extra["evidence_meaning"] = "PowerShell recorded an error raised while a pipeline executed, with the host, command and error text shown."
	ev.Extra["limitations"] = "An error report, not a command: it does not establish what the user intended, that the failing command had any effect, or malicious intent, and it is not script content (see script block logging for that). The host application, script and error text are bounded and redacted and may be incomplete."
	return true, true
}

// psErrorPayload reads "Error Message = ..." (possibly several lines) and
// "Fully Qualified Error ID = ..." from a 4100 Payload.
func psErrorPayload(payload string) (msg string, hasMsg bool, fqid string, hasFQID bool) {
	const fqLabel = "Fully Qualified Error ID ="
	body := payload
	if i := strings.Index(payload, fqLabel); i >= 0 {
		rest := payload[i+len(fqLabel):]
		fqid, _, _ = strings.Cut(rest, "\n")
		fqid, hasFQID = strings.TrimSpace(fqid), true
		body = payload[:i]
	}
	const msgLabel = "Error Message ="
	if t := strings.TrimSpace(body); strings.HasPrefix(t, msgLabel) {
		return strings.TrimSpace(t[len(msgLabel):]), true, fqid, hasFQID
	}
	return "", false, fqid, hasFQID
}
