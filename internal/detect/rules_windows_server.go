package detect

import (
	"sort"
	"strings"

	"tracefall/internal/model"
)

func windowsServerRules() []Rule { return []Rule{windowsLogCleared{}, windowsAuditPolicyChanged{}} }

type windowsLogCleared struct{}

func (windowsLogCleared) ID() string { return "windows-event-log-cleared" }
func (windowsLogCleared) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventLogCleared}}
}
func (r windowsLogCleared) Evaluate(events []model.Event) []model.Finding {
	var out []model.Finding
	for _, e := range byType(events, model.EventLogCleared) {
		validSource := e.ArtifactType == model.ArtifactWindowsEventLog && strings.EqualFold(e.Extra["event_provider"], "Microsoft-Windows-Eventlog")
		validID := (e.EventID == 1102 && strings.EqualFold(e.Extra["event_channel"], "Security")) || (e.EventID == 104 && strings.EqualFold(e.Extra["event_channel"], "System"))
		if !validSource || !validID || e.Extra["outcome"] != "success" {
			continue
		}
		// Do not echo untrusted payload fields (which can include secrets). The
		// supporting event retains the actor, log name and raw-evidence reference.
		desc := "Windows Event Log recorded a log-clearing action. Review the linked event for the recorded actor, session and affected log. This can be authorized maintenance; it does not establish malicious intent, which records were lost, backup availability, or completeness of the supplied evidence. Corroborate with change authorization, central logging and independently acquired backups."
		out = append(out, newFinding(e.CaseID, r.ID(), "Windows event log clearing recorded", model.SeverityLow, model.ConfidenceHigh, desc, []string{"T1070.001"}, []model.Event{e}))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
			return out[i].FirstSeen.Before(out[j].FirstSeen)
		}
		return out[i].SupportingEvents[0] < out[j].SupportingEvents[0]
	})
	return out
}

type windowsAuditPolicyChanged struct{}

func (windowsAuditPolicyChanged) ID() string { return "windows-audit-policy-changed" }
func (windowsAuditPolicyChanged) Inputs() model.EventFilter {
	return model.EventFilter{Types: []string{model.EventAuditPolicyChange}}
}
func (r windowsAuditPolicyChanged) Evaluate(events []model.Event) []model.Finding {
	var out []model.Finding
	for _, e := range byType(events, model.EventAuditPolicyChange) {
		if e.ArtifactType != model.ArtifactWindowsEventLog || e.EventID != 4719 || !strings.EqualFold(e.Extra["event_provider"], "Microsoft-Windows-Security-Auditing") || !strings.EqualFold(e.Extra["event_channel"], "Security") || e.Extra["outcome"] != "success" {
			continue
		}
		desc := "Windows Security auditing recorded a system audit policy change. Review the linked event for the recorded actor, logon ID, subcategory GUID and verbatim change tokens. This can be authorized administration or Group Policy; it does not by itself establish disabled auditing, malicious intent, or the effective policy afterwards. Corroborate with approved policy changes, resultant policy and independently collected logs."
		out = append(out, newFinding(e.CaseID, r.ID(), "Windows audit policy change recorded", model.SeverityLow, model.ConfidenceHigh, desc, []string{"T1562.002"}, []model.Event{e}))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
			return out[i].FirstSeen.Before(out[j].FirstSeen)
		}
		return out[i].SupportingEvents[0] < out[j].SupportingEvents[0]
	})
	return out
}

func init() {
	ruleDocs["windows-audit-policy-changed"] = RuleDoc{
		Title: "Windows audit policy change recorded", Detects: "Provider- and channel-verified Security 4719 audit policy change records.",
		BaseSeverity: model.SeverityLow, MaxSeverity: model.SeverityLow, BaseConfidence: model.ConfidenceHigh, MaxConfidence: model.ConfidenceHigh,
		Basis: "High confidence in the recorded change, not in malicious intent or disabled auditing. Low severity because authorized policy management also emits these records; verbatim change tokens do not alone establish the effective policy afterwards.", Techniques: []string{"T1562.002"},
	}
	ruleDocs["windows-event-log-cleared"] = RuleDoc{
		Title: "Windows event log clearing recorded", Detects: "Provider- and channel-verified Windows Event Log 1102 or 104 log-clearing records.",
		BaseSeverity: model.SeverityLow, MaxSeverity: model.SeverityLow, BaseConfidence: model.ConfidenceHigh, MaxConfidence: model.ConfidenceHigh,
		Basis: "High confidence in the recorded action, not in malicious intent. Low severity because authorized maintenance also clears logs; the linked evidence cannot establish which records were lost or whether backups exist.", Techniques: []string{"T1070.001"},
	}
}
