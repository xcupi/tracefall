package correlate

import (
	"reflect"
	"strings"
	"testing"
	"time"
	"tracefall/internal/model"
)

func explicitSequence() []model.Event {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return []model.Event{
		{ID: "credential", CaseID: "case01", CollectionID: "collection01", Host: "host01", User: "alice", EventType: model.EventLogonExplicitCreds, Timestamp: base, Extra: map[string]string{"target_user_name": "carol", "target_domain": "domain01"}},
		{ID: "process", CaseID: "case01", CollectionID: "collection01", Host: "host01", User: "carol", EventType: model.EventProcessCreate, ProcessName: "agent.exe", PID: 111, Timestamp: base.Add(time.Minute), Extra: map[string]string{"subject_domain": "domain01", "logon_id": "0x123"}},
		{ID: "network", CaseID: "case01", CollectionID: "collection01", Host: "host01", User: "carol", EventType: model.EventNetworkConnection, ProcessName: "agent.exe", PID: 111, Timestamp: base.Add(2 * time.Minute), Extra: map[string]string{"subject_domain": "domain01", "logon_id": "0x123"}},
	}
}
func TestExplicitCredentialRelationshipIsHypothetical(t *testing.T) {
	got := buildCredentialAbuseChains("case01", explicitSequence())
	if len(got) != 1 {
		t.Fatalf("want useful relationship, got %+v", got)
	}
	es := explicitSequence()
	for i, j := 0, len(es)-1; i < j; i, j = i+1, j-1 {
		es[i], es[j] = es[j], es[i]
	}
	if other := buildCredentialAbuseChains("case01", es); !reflect.DeepEqual(got, other) {
		t.Fatalf("credential relationship depends on input order: %+v vs %+v", got, other)
	}
	text := strings.ToLower(got[0].Description)
	if !strings.Contains(text, "hypothetical") || !strings.Contains(text, "not establish") || strings.Contains(text, "evidenced sequence") || strings.Contains(strings.ToLower(got[0].Title), "abuse") {
		t.Fatalf("unbound credentials overclaim execution: %+v", got)
	}
}

func TestExplicitCredentialContextIsolation(t *testing.T) {
	for _, name := range []string{"account", "domain", "session", "followup_account", "followup_domain", "followup_session", "followup_pid", "case", "collection", "zero", "tie", "memory", "remote_target"} {
		t.Run(name, func(t *testing.T) {
			es := explicitSequence()
			switch name {
			case "account":
				es[1].User = "alice"
			case "domain":
				es[1].Extra["subject_domain"] = "domain02"
			case "session":
				es[0].Extra["target_logon_id"] = "0x456"
			case "followup_account":
				es[2].User = "alice"
			case "followup_domain":
				es[2].Extra["subject_domain"] = "domain02"
			case "followup_session":
				es[2].Extra["logon_id"] = "0x456"
			case "followup_pid":
				es[2].PID = 999
			case "case":
				es[1].CaseID = "case02"
			case "collection":
				es[1].CollectionID = "collection02"
			case "zero":
				es[0].Timestamp = time.Time{}
			case "tie":
				es[1].Timestamp = es[0].Timestamp
			case "memory":
				es[1].ArtifactType = model.ArtifactMemoryAnalysis
			case "remote_target":
				es[0].Extra["target_server_name"] = "host02"
			}
			if got := buildCredentialAbuseChains("case01", es); len(got) != 0 {
				t.Fatalf("cross-context or nonordered credential relationship: %+v", got)
			}
		})
	}
}

func TestExplicitCredentialRejectsStaleProcessIdentity(t *testing.T) {
	for _, kind := range []string{"reuse", "exit", "child_guid"} {
		t.Run(kind, func(t *testing.T) {
			es := explicitSequence()
			switch kind {
			case "reuse":
				p := es[1]
				p.ID = "reused"
				p.ProcessName = "other.exe"
				p.Timestamp = p.Timestamp.Add(30 * time.Second)
				es = append(es, p)
			case "exit":
				es[1].Extra["exit_time"] = es[1].Timestamp.Add(30 * time.Second).Format(time.RFC3339)
			case "child_guid":
				es[1].Extra["process_guid"] = "guid01"
				es[2].EventType = model.EventProcessCreate
				es[2].ProcessName = "child.exe"
				es[2].ParentProcessName = "agent.exe"
				es[2].PID = 222
				es[2].PPID = 111
				es[2].Extra["parent_process_guid"] = "guid02"
			}
			if got := buildCredentialAbuseChains("case01", es); len(got) != 0 {
				t.Fatalf("stale or contradictory process identity: %+v", got)
			}
		})
	}
}

func TestExplicitCredentialMissingTargetDomainRetainsQualifiedHypothesis(t *testing.T) {
	es := explicitSequence()
	delete(es[0].Extra, "target_domain")
	got := buildCredentialAbuseChains("case01", es)
	if len(got) != 1 || !strings.Contains(strings.ToLower(got[0].Description), "unknown target domain") {
		t.Fatalf("missing target-domain field should retain an explicitly qualified name hypothesis: %+v", got)
	}
	// The same name running in two domains leaves no unique account hypothesis.
	p := es[1]
	p.ID = "other-domain"
	p.Timestamp = p.Timestamp.Add(10 * time.Second)
	p.Extra = map[string]string{"subject_domain": "domain02", "logon_id": "0x456"}
	es = append(es, p)
	if got := buildCredentialAbuseChains("case01", es); len(got) != 0 {
		t.Fatalf("unknown target domain must not select across known domains: %+v", got)
	}
}
