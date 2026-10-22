package model

import (
	"testing"
	"time"
)

func TestSQLAgentMessageIdentity(t *testing.T) {
	a := Event{ArtifactType: ArtifactSQLAgentLog, EventType: EventSQLAgentMessage, SourceReference: "line:1", Extra: map[string]string{"message": "informational", "agent_message_id": "100", "sql_source": "?"}}
	b := a
	b.Extra = map[string]string{"message": "informational", "agent_message_id": "101", "sql_source": "?"}
	if a.ComputeDedupHash() == b.ComputeDedupHash() {
		t.Fatal("different Agent record identifiers collapsed")
	}
}

func TestMSSQLScopedPayloadIdentity(t *testing.T) {
	for _, a := range []Event{
		{ArtifactType: ArtifactSQLInstance, EventType: EventSQLInstance, SourceReference: `value:Setup\Version`, Extra: map[string]string{"registry_value_data": "16.0"}},
		{ArtifactType: ArtifactWindowsEventLog, EventType: EventSQLMessage, Provider: "MSSQLSERVER", Timestamp: time.Date(2026, 1, 15, 9, 15, 30, 0, time.UTC), Extra: map[string]string{"sql_record_data": `{"param1":"first"}`}},
	} {
		b := a
		b.Extra = map[string]string{}
		for k, v := range a.Extra {
			b.Extra[k] = v + " changed"
		}
		if a.ComputeDedupHash() == b.ComputeDedupHash() {
			t.Errorf("SQL payload collapsed artifact=%s", a.ArtifactType)
		}
		b = a
		b.CollectionID = "another"
		b.SourceFileID = "recollected"
		b.RawEvidenceID = "raw-again"
		if a.ComputeDedupHash() != b.ComputeDedupHash() {
			t.Fatal("recollection split")
		}
	}
}
