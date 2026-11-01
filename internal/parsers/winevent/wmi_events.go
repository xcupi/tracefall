package winevent

import (
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/normalize"
)

const wmiActivityProvider = "Microsoft-Windows-WMI-Activity"
const wmiActivityChannel = "Microsoft-Windows-WMI-Activity/Operational"

// Bounds for the free-text fields of a WMI-Activity record.
const wmiQueryBytes = 1024
const wmiFieldBytes = 512

// normalizeWMIActivityEvent maps two WMI-Activity Operational records. Their
// payload is UserData: the reader flattens the child elements of the
// Operation_* root into the names used below.
//
//	5860  Operation_TemporaryEssStarted  a temporary event consumer started
//	      (NamespaceName, Query, User, Processid, ClientMachine, PossibleCause)
//	5858  Operation_ClientFailure        a client operation failed
//	      (Id, ClientMachine, User, ClientProcessId, Component, Operation,
//	       ResultCode, PossibleCause)
//
// 5857 (provider loaded) is routine and stays unmapped. Both mapped records are
// configuration/attempt evidence only: a temporary consumer exists while its
// client process runs and says nothing about whether an event matched or an
// action ran, and a failed query is an attempt that did not complete.
func normalizeWMIActivityEvent(ev *model.Event, in Input) (handled, mapped bool) {
	switch in.EventID {
	case 5858, 5860:
	default:
		return false, false
	}
	if !strings.EqualFold(in.Provider, wmiActivityProvider) || !strings.EqualFold(in.Channel, wmiActivityChannel) {
		return true, false
	}
	p := in.Data
	pid := func(v string) {
		if n := normalize.Int64(strings.TrimSpace(v)); n > 0 {
			ev.PID = n
		}
	}
	switch in.EventID {
	case 5860:
		if strings.TrimSpace(p["Query"]) == "" && strings.TrimSpace(p["NamespaceName"]) == "" {
			return true, false
		}
		ev.EventType = model.EventWMIActivity
		ev.User = dashToEmpty(strings.TrimSpace(p["User"]))
		setRecorded(ev, "namespace", p, "NamespaceName")
		if q, ok := p["Query"]; ok {
			v, cut := boundedRedacted(q, wmiQueryBytes)
			ev.Extra["query"] = v
			if cut {
				ev.Extra["query_truncated"] = "true"
			}
		}
		setRecorded(ev, "client_process_id", p, "Processid")
		pid(p["Processid"])
		setRecorded(ev, "client_machine", p, "ClientMachine")
		setRecorded(ev, "possible_cause", p, "PossibleCause")
		ev.Extra["action"] = "temporary_event_consumer_started"
		ev.Extra["outcome"] = "observed"
		ev.Extra["evidence_meaning"] = "WMI-Activity recorded that a temporary event consumer (a non-persistent WMI event subscription) started for the namespace and query shown, from the client process, machine and user shown."
		ev.Extra["limitations"] = "Registration evidence only. It does not establish that any event matched the query, that any action ran or code executed (execution), or malicious intent: legitimate management and monitoring software registers temporary consumers. A temporary consumer ends with its client process and is not the persistent subscription stored in the WMI repository. The user and machine are as recorded."
	case 5858:
		if strings.TrimSpace(p["Operation"]) == "" {
			if _, hasResult := p["ResultCode"]; !hasResult {
				return true, false
			}
		}
		ev.EventType = model.EventWMIActivity
		ev.User = dashToEmpty(strings.TrimSpace(p["User"]))
		setRecorded(ev, "operation_id", p, "Id")
		setRecorded(ev, "client_machine", p, "ClientMachine")
		setRecorded(ev, "client_process_id", p, "ClientProcessId")
		pid(p["ClientProcessId"])
		setRecorded(ev, "component", p, "Component")
		if op, ok := p["Operation"]; ok {
			v, cut := boundedRedacted(op, wmiFieldBytes)
			ev.Extra["operation"] = v
			if cut {
				ev.Extra["operation_truncated"] = "true"
			}
		}
		setRecorded(ev, "result_code", p, "ResultCode")
		setRecorded(ev, "possible_cause", p, "PossibleCause")
		ev.Extra["action"] = "client_operation_failed"
		ev.Extra["outcome"] = "failure"
		ev.Extra["evidence_meaning"] = "WMI-Activity recorded that a WMI client operation failed, with the operation text and result code shown."
		ev.Extra["limitations"] = "A failed attempt: it does not establish what the operation was meant to achieve, that it succeeded elsewhere, or malicious intent; WMI clients fail routinely. The result code is retained as recorded without interpretation. The operation text may be incomplete (bounded and redacted)."
	}
	return true, true
}
