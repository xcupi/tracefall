package detect

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers/winevent"
)

func windowsFindingEvents(t *testing.T, id int, channel, provider string) []model.Event {
	t.Helper()
	var out []model.Event
	for _, key := range []string{"b", "a"} {
		e := model.Event{ID: key, Timestamp: time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC), ArtifactType: model.ArtifactWindowsEventLog, EventID: id, Extra: map[string]string{}}
		if !winevent.Normalize(&e, winevent.Input{EventID: id, Channel: channel, Provider: provider, Data: map[string]string{"SubjectUserName": "alice", "SubjectLogonId": "0x42", "Channel": "Application", "AuditPolicyChanges": "%%8448", "TaskContent": "FakeSecret123!", "CommandLine": "net user alice FakeSecret123!"}}) {
			t.Fatal("test event not mapped")
		}
		out = append(out, e)
	}
	return out
}

func assertWindowsChangeLead(t *testing.T, id int, channel, provider, ruleID string) {
	t.Helper()
	events := windowsFindingEvents(t, id, channel, provider)
	filter := func(e []model.Event) []model.Finding {
		var out []model.Finding
		for _, f := range Run("case01", e) {
			if f.RuleID == ruleID {
				f.CreatedAt = time.Time{}
				out = append(out, f)
			}
		}
		return out
	}
	got := filter(events)
	if len(got) != 2 {
		t.Fatalf("got %d %s findings, want two source-linked leads", len(got), ruleID)
	}
	for _, f := range got {
		if f.Severity != model.SeverityLow || f.Confidence != model.ConfidenceHigh {
			t.Errorf("presence alone escalated finding: %+v", f)
		}
		if len(f.SupportingEvents) != 1 || f.SupportingEvents[0] == "" {
			t.Error("missing evidence link")
		}
		if !strings.Contains(f.Description, "authorized") || !strings.Contains(f.Description, "does not") {
			t.Error("missing limitations")
		}
		if strings.Contains(f.Description+f.Title, "FakeSecret123!") {
			t.Error("credential leak")
		}
	}
	reverse := []model.Event{events[1], events[0]}
	if !reflect.DeepEqual(got, filter(reverse)) {
		t.Error("findings depend on input order")
	}
	for _, mutate := range []func(*model.Event){
		func(e *model.Event) { e.Extra["event_provider"] = "Other" },
		func(e *model.Event) { e.Extra["event_channel"] = "Application" },
		func(e *model.Event) { e.EventID = 9999 },
		func(e *model.Event) { e.ArtifactType = model.ArtifactMemoryAnalysis },
		func(e *model.Event) { e.Extra["outcome"] = "failure" },
		func(e *model.Event) { e.Extra["outcome"] = "unknown" },
		func(e *model.Event) { delete(e.Extra, "outcome") },
	} {
		e := windowsFindingEvents(t, id, channel, provider)[0]
		mutate(&e)
		if len(filter([]model.Event{e})) != 0 {
			t.Error("unsupported provider/channel/id/source/outcome produced lead")
		}
	}
}

func TestWindowsServiceInstallLeadRedactsCredentials(t *testing.T) {
	e := model.Event{ID: "svc", Timestamp: time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC), ArtifactType: model.ArtifactWindowsEventLog, EventID: 4697, Extra: map[string]string{}}
	command := `C:\Windows\System32\net.exe user alice FakeSecret123!`
	if !winevent.Normalize(&e, winevent.Input{EventID: 4697, Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing", Data: map[string]string{"ServiceName": "Maintenance", "ServiceFileName": command}}) {
		t.Fatal("service not mapped")
	}
	if e.FilePath != command {
		t.Fatal("stored evidence was modified")
	}
	found := false
	for _, f := range Run("case01", []model.Event{e}) {
		if f.RuleID == "service-persistence" {
			found = true
		}
		if strings.Contains(f.Title+f.Description, "FakeSecret123!") {
			t.Errorf("credential leaked from %s", f.RuleID)
		}
	}
	if !found {
		t.Fatal("existing service rule not exercised")
	}
}

func TestWindowsAuditPolicyLead(t *testing.T) {
	assertWindowsChangeLead(t, 4719, "Security", "Microsoft-Windows-Security-Auditing", "windows-audit-policy-changed")
}

func TestWindowsLogClearLead(t *testing.T) {
	for _, tc := range []struct {
		id      int
		channel string
	}{{1102, "Security"}, {104, "System"}} {
		t.Run(tc.channel, func(t *testing.T) {
			assertWindowsChangeLead(t, tc.id, tc.channel, "Microsoft-Windows-Eventlog", "windows-event-log-cleared")
		})
	}
}
