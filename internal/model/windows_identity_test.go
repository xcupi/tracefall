package model

import (
	"testing"
	"time"
)

func TestWindowsIdentity_SemanticDistinctions(t *testing.T) {
	changes := map[string]func(*Event){
		"source IP":       func(e *Event) { e.NetworkSource = "203.0.113.2" },
		"channel":         func(e *Event) { e.Provider = "System" },
		"record":          func(e *Event) { e.Extra["evtx_record_id"] = "2" },
		"domain":          func(e *Event) { e.Extra["target_domain"] = "DOMAIN02" },
		"session":         func(e *Event) { e.Extra["logon_id"] = "0x22" },
		"object":          func(e *Event) { e.Extra["object_name"] = "carol" },
		"group member":    func(e *Event) { e.Extra["member_sid"] = "S-1-5-21-1002" },
		"script block":    func(e *Event) { e.Extra["script_block_id"] = "block02" },
		"script fragment": func(e *Event) { e.Extra["message_number"] = "2" },
		"script text":     func(e *Event) { e.CommandLine = "Get-Service" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			makeEvent := func() Event {
				return Event{ArtifactType: ArtifactWindowsEventLog, Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Host: "host01", User: "alice", Provider: "Security", NetworkSource: "203.0.113.1", Extra: map[string]string{}}
			}
			a, b := makeEvent(), makeEvent()
			change(&b)
			if a.ComputeDedupHash() == b.ComputeDedupHash() {
				t.Fatal("distinct Windows observations collapsed")
			}
			a.CaseID = "case02"
			a.CollectionID = "collection02"
			a.SourceFileID = "file02"
			a.SourceReference = "row:99"
			a.Parser = "another parser"
			a.Extra["evtx_partial_parse"] = "recovery note"
			if a.ComputeDedupHash() != makeEvent().ComputeDedupHash() {
				t.Fatal("recollection/provenance changed identity")
			}
		})
	}
}
