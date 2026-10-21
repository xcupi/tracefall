package detect

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// An event without a timestamp is evidence with an unknown time. No finding
// may print the zero time as if it were a date, or use it as a window bound.
func TestRules_UndatedEventsNeverPrintYearOne(t *testing.T) {
	dated := mustTime("2026-01-15T09:00:00Z")
	mk := func(id, typ string, at time.Time, mod func(*model.Event)) model.Event {
		e := model.Event{ID: id, CaseID: "c", EventType: typ, Host: "host01", User: "alice", Timestamp: at,
			ProcessName: "powershell.exe", ProcessPath: `C:\Users\alice\AppData\Local\Temp\x.exe`, ParentProcessName: "winword.exe",
			CommandLine: `powershell.exe -nop -w hidden -enc AAAA`, FilePath: `C:\Users\alice\AppData\Local\Temp\x.exe`,
			RegistryPath: `HKLM\SYSTEM\ControlSet001\Services\svc01\ImagePath`, PID: 10, NetworkSource: "203.0.113.5", NetworkDest: "198.51.100.7", NetworkDestPort: 443,
			Extra: map[string]string{"service_name": "svc01", "start_type": "auto", "task_name": "T", "registry_persistence_type": "service_image_path", "target_user_name": "bob", "target_server_name": "srv"}}
		if mod != nil {
			mod(&e)
		}
		return e
	}
	var events []model.Event
	for i, typ := range []string{
		model.EventProcessCreate, model.EventServiceInstall, model.EventRegistryPersistence, model.EventRegistryRunKey,
		model.EventScheduledTaskCreate, model.EventLogonExplicitCreds, model.EventPrivilegedLogon, model.EventNetworkConnection,
		model.EventLogonSuccess, model.EventLogonFailure,
	} {
		events = append(events, mk("u"+string(rune('a'+i)), typ, time.Time{}, nil))
		events = append(events, mk("d"+string(rune('a'+i)), typ, dated, nil))
	}
	for _, r := range All() {
		for _, f := range r.Evaluate(events) {
			if strings.Contains(f.Title+" "+f.Description, "0001-01-01") {
				t.Errorf("rule %s printed the zero time: %s", r.ID(), f.Description)
			}
			if !f.FirstSeen.IsZero() && f.FirstSeen.Year() < 1900 {
				t.Errorf("rule %s window starts at year %d", r.ID(), f.FirstSeen.Year())
			}
		}
	}
}

func TestTimeRange_IgnoresUnknownTimes(t *testing.T) {
	at := mustTime("2026-01-15T09:00:00Z")
	first, last := timeRange([]model.Event{{Timestamp: time.Time{}}, {Timestamp: at}, {Timestamp: at.Add(time.Hour)}})
	if !first.Equal(at) || !last.Equal(at.Add(time.Hour)) {
		t.Fatalf("window %s..%s must span only the dated events", first, last)
	}
	if f, l := timeRange([]model.Event{{}}); !f.IsZero() || !l.IsZero() {
		t.Fatal("an all-undated set has no window")
	}
}

// Two events with no recorded time have no order. A rule that reports "A,
// then B shortly after" would be inventing the sequence.
func TestTemporalRules_UndatedEventsAreNotASequence(t *testing.T) {
	ex := model.Event{ID: "ex", CaseID: "c", EventType: model.EventProcessCreate, Host: "host01", ProcessName: "x.exe", ProcessPath: `C:\Users\alice\AppData\Local\Temp\x.exe`, PID: 5}
	run := model.Event{ID: "run", CaseID: "c", EventType: model.EventRegistryRunKey, Host: "host01", FilePath: `C:\Users\alice\AppData\Local\Temp\x.exe`, ProcessName: "x.exe"}
	net := model.Event{ID: "net", CaseID: "c", EventType: model.EventNetworkConnection, Host: "host01", ProcessName: "x.exe", PID: 5, NetworkDest: "198.51.100.7"}
	events := []model.Event{ex, run, net}
	if got := (executionThenPersistence{}).Evaluate(events); len(got) != 0 {
		t.Errorf("execution-then-persistence fired on undated events: %+v", got)
	}
	if got := (networkAfterExecution{}).Evaluate(events); len(got) != 0 {
		t.Errorf("network-after-execution fired on undated events: %+v", got)
	}
}
