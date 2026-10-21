package api

import (
	"fmt"
	"strings"
	"testing"

	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/model"
)

// This deliberately exercises persistence and observation provenance, not just
// ParseResult length. Two failed logons tie on time/user/host. The same native
// record is also repeated within a file, exported to CSV, and recollected.
func TestWindowsIdentity_PersistedFailedLogons(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Windows record identity")
	record := func(id uint64, ip string) evtxgen.Event {
		return evtxgen.Event{RecordID: id, Timestamp: nativeBase, Computer: "host01", Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing", EventID: 4625, Data: map[string]string{"TargetUserName": "alice", "LogonType": "3", "IpAddress": ip}}
	}
	rows := []evtxgen.Event{record(1, "203.0.113.1"), record(2, "203.0.113.2"), record(1, "203.0.113.1")}
	data := evtxgen.Build(rows)
	var csv strings.Builder
	csv.WriteString("TimeCreated,EventId,Provider,Channel,ComputerName,PayloadData1,RecordNumber\n")
	for _, r := range rows {
		fmt.Fprintf(&csv, "%s,4625,Microsoft-Windows-Security-Auditing,Security,host01,TargetUserName: alice; LogonType: 3; IpAddress: %s,%d\n", nativeBase.Format("2006-01-02T15:04:05.0000000Z"), r.Data["IpAddress"], r.RecordID)
	}
	for i := 0; i < 2; i++ {
		disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{"Logs/Security.evtx": data, "EvtxECmd_Output.csv": []byte(csv.String()), "collection-note.txt": {byte('0' + i)}})
		importAllFrom(t, mux, c.ID, disc)
		var timeline []model.Event
		doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
		ips := map[string]int{}
		for _, ev := range timeline {
			if ev.EventType != model.EventLogonFailure {
				continue
			}
			ips[ev.NetworkSource]++
			prov := getJSON[EventProvenance](t, mux, "/api/cases/"+c.ID+"/events/"+ev.ID)
			want := 2 * (i + 1)
			if ev.NetworkSource == "203.0.113.1" {
				want *= 2
			}
			if len(prov.Observations) != want {
				t.Errorf("IP %s has %d observations, want %d", ev.NetworkSource, len(prov.Observations), want)
			}
			raws := map[string]bool{}
			for _, o := range prov.Observations {
				if o.RawEvidenceID == "" || o.SourceFileID == "" || o.SourceReference == "" {
					t.Errorf("lost source provenance: %+v", o)
				}
				raws[o.RawEvidenceID] = true
			}
			if len(raws) != want {
				t.Errorf("lost distinct raw records: %d, want %d", len(raws), want)
			}
		}
		if len(ips) != 2 || ips["203.0.113.1"] != 1 || ips["203.0.113.2"] != 1 {
			t.Fatalf("import %d persisted IPs %v; want two distinct logons, duplicate rows/recollections collapsed", i+1, ips)
		}
	}
}

func TestTaskTime_PersistedNativeConfigurations(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Task configuration clocks")
	task := func(date string) []byte {
		return []byte(`<Task><RegistrationInfo><Date>` + date + `</Date><Author>alice</Author></RegistrationInfo><Actions><Exec><Command>cmd.exe</Command></Exec></Actions></Task>`)
	}
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Windows/System32/Tasks/Task01": task(""),
		"Windows/System32/Tasks/Task02": task("2026-01-15T09:17:30"),
		"Windows/System32/Tasks/Task03": task("2026-01-15T09:17:30+07:00"),
	})
	if disc.SupportedCount != 3 {
		t.Fatalf("discovered %d supported files, want three native tasks", disc.SupportedCount)
	}
	importAllFrom(t, mux, c.ID, disc)
	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &events)
	if len(events) != 3 {
		t.Fatalf("persisted %d tasks, want three", len(events))
	}
	for _, e := range events {
		name := e.Extra["task_name"]
		if (name == "Task03") == e.Timestamp.IsZero() {
			t.Errorf("task %s has wrong instant/undated status: %v", name, e.Timestamp)
		}
		if e.Extra["evidence_kind"] != "task_configuration" {
			t.Errorf("lost configuration meaning: %+v", e)
		}
	}
}
