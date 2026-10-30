package correlate

import (
	"reflect"
	"strings"
	"testing"
	"time"
	"tracefall/internal/model"
	"tracefall/internal/parsers/winevent"
)

const taskGUID = "{11111111-2222-3333-4444-555555555555}"

func taskRecord(t *testing.T, id string, n int) model.Event {
	t.Helper()
	e := model.Event{ID: id, CaseID: "case", CollectionID: "capture", Host: "host01", EventID: n, ArtifactType: model.ArtifactWindowsEventLog, Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	if !winevent.Normalize(&e, winevent.Input{EventID: n, Provider: "Microsoft-Windows-TaskScheduler", Channel: "Microsoft-Windows-TaskScheduler/Operational", Data: map[string]string{"InstanceId": taskGUID, "TaskInstanceId": taskGUID, "TaskName": `\Maintenance\Cleanup`}}) {
		t.Fatal("normalize")
	}
	return e
}
func TestTaskInstanceContextGuards(t *testing.T) {
	for name, change := range map[string]func(*model.Event){
		"case": func(e *model.Event) { e.CaseID = "other" }, "empty_case": func(e *model.Event) { e.CaseID = "" },
		"host": func(e *model.Event) { e.Host = "host02" }, "unknown_host": func(e *model.Event) { e.Host = "" },
		"capture": func(e *model.Event) { e.CollectionID = "other" }, "empty_capture": func(e *model.Event) { e.CollectionID = "" },
		"guid":           func(e *model.Event) { e.Extra["task_instance_id"] = "not-guid" },
		"both_malformed": func(e *model.Event) { e.Extra["task_instance_id"] = "bad" },
		"provider":       func(e *model.Event) { e.Extra["event_provider"] = "Other" }, "channel": func(e *model.Event) { e.Extra["event_channel"] = "Other" },
		"event_id": func(e *model.Event) { e.EventID = 129 }, "action": func(e *model.Event) { e.Extra["action"] = "task_started" },
		"memory": func(e *model.Event) { e.ArtifactType = model.ArtifactMemoryAnalysis }, "snapshot": func(e *model.Event) { e.Extra["timestamp_basis"] = "memory_snapshot" },
		"empty_id": func(e *model.Event) { e.ID = "" }, "duplicate_id": func(e *model.Event) { e.ID = "a" },
		"name_conflict": func(e *model.Event) { e.Extra["task_name"] = `\Other` },
	} {
		t.Run(name, func(t *testing.T) {
			a, b := taskRecord(t, "a", 200), taskRecord(t, "b", 202)
			change(&b)
			if name == "both_malformed" {
				a.Extra["task_instance_id"] = "bad"
			}
			if got := BuildTaskInstanceContexts("case", []model.Event{a, b}); len(got) != 0 {
				t.Fatalf("unsafe context: %+v", got)
			}
		})
	}
}
func TestTaskInstanceContextObservations(t *testing.T) {
	for _, code := range []string{"absent", "", "-", "0", "bad-token"} {
		t.Run(code, func(t *testing.T) {
			a, b, c := taskRecord(t, "a", 200), taskRecord(t, "b", 201), taskRecord(t, "c", 202)
			b.Extra["task_instance_id"] = strings.Trim(taskGUID, "{}")
			b.Extra["task_name"] = strings.ToUpper(a.Extra["task_name"])
			a.Extra["action_name"] = "SENSITIVE-DUMMY"
			c.Extra["result_code"] = code
			if code == "absent" {
				delete(c.Extra, "result_code")
			}
			before := c.Extra["result_code"]
			a.Timestamp = time.Time{}
			b.Timestamp = b.Timestamp.Add(48 * time.Hour)
			got := BuildTaskInstanceContexts("case", []model.Event{c, b, a, taskRecord(t, "launch", 129)})
			if len(got) != 1 {
				t.Fatalf("missing context: %+v", got)
			}
			x := got[0]
			if !x.FirstSeen.Equal(c.Timestamp) || !x.LastSeen.Equal(b.Timestamp) {
				t.Fatalf("known-only window: %+v", x)
			}
			for _, term := range []string{"action completed=1", "action failure=1", "missing record is not proof", "not program success", "undated=1"} {
				if !strings.Contains(x.Description, term) {
					t.Fatalf("missing caveat %q: %s", term, x.Description)
				}
			}
			if strings.Contains(x.Description, "SENSITIVE-DUMMY") || strings.Contains(x.Description, "then") || c.Extra["result_code"] != before {
				t.Fatal("source/prose corruption")
			}
			reversed := BuildTaskInstanceContexts("case", []model.Event{a, b, c})
			if !reflect.DeepEqual(got, reversed) {
				t.Fatal("shuffle changed context")
			}
			a.Timestamp = time.Time{}
			b.Timestamp = time.Time{}
			c.Timestamp = time.Time{}
			zero := BuildTaskInstanceContexts("case", []model.Event{a, b, c})[0]
			if !zero.FirstSeen.IsZero() || !zero.LastSeen.IsZero() || !strings.Contains(zero.Description, "time not recorded") {
				t.Fatalf("invented unknown window: %+v", zero)
			}
		})
	}
}
func taskProcessPair(t *testing.T) (model.Event, model.Event) {
	a := taskRecord(t, "launch", 129)
	a.Extra["process_id"] = "0x1092"
	a.Extra["process_path"] = `C:\Tools\worker.exe`
	p := model.Event{ID: "process", CaseID: a.CaseID, CollectionID: a.CollectionID, Host: a.Host, Timestamp: a.Timestamp, EventType: model.EventProcessCreate, PID: 4242, ProcessPath: `c:/tools/WORKER.exe`, ArtifactType: model.ArtifactWindowsEventLog}
	return a, p
}
func TestTaskProcessContextPositive(t *testing.T) {
	a, p := taskProcessPair(t)
	for _, delta := range []time.Duration{-2 * time.Second, 0, 2 * time.Second} {
		p.Timestamp = a.Timestamp.Add(delta)
		got := BuildTaskProcessContexts("case", []model.Event{p, a})
		if len(got) != 1 || len(got[0].EventIDs) != 2 {
			t.Fatalf("compatible launch/start missing: %+v", got)
		}
	}
}
func TestTaskProcessContextGuards(t *testing.T) {
	for name, change := range map[string]func(*model.Event, *model.Event){
		"engine_only": func(a, p *model.Event) { delete(a.Extra, "process_id"); a.Extra["engine_pid"] = "4242" },
		"pid_zero":    func(a, p *model.Event) { a.Extra["process_id"] = "0" }, "pid_padded": func(a, p *model.Event) { a.Extra["process_id"] = " 4242 " }, "pid_bad": func(a, p *model.Event) { a.Extra["process_id"] = "4242x" }, "pid_partial": func(a, p *model.Event) { a.Extra["process_id"] = "0x" },
		"case": func(a, p *model.Event) { p.CaseID = "other" }, "capture": func(a, p *model.Event) { p.CollectionID = "other" }, "empty_capture": func(a, p *model.Event) { a.CollectionID = ""; p.CollectionID = "" },
		"host": func(a, p *model.Event) { p.Host = "host02" }, "empty_host": func(a, p *model.Event) { a.Host = ""; p.Host = "" },
		"provider": func(a, p *model.Event) { a.Extra["event_provider"] = "Other" }, "channel": func(a, p *model.Event) { a.Extra["event_channel"] = "Other" }, "id_mismatch": func(a, p *model.Event) { a.EventID = 202 },
		"action_mismatch": func(a, p *model.Event) { a.Extra["action"] = "task_action_failed" }, "pid_mismatch": func(a, p *model.Event) { p.PID = 900 },
		"memory": func(a, p *model.Event) { p.ArtifactType = model.ArtifactMemoryAnalysis }, "snapshot": func(a, p *model.Event) { a.Extra["timestamp_basis"] = "memory_snapshot" },
		"undated": func(a, p *model.Event) { p.Timestamp = time.Time{} }, "distance": func(a, p *model.Event) { p.Timestamp = a.Timestamp.Add(2001 * time.Millisecond) },
		"path_basename": func(a, p *model.Event) { a.Extra["process_path"] = "worker.exe" }, "path_args": func(a, p *model.Event) { a.Extra["process_path"] = `"C:\Tools\worker.exe" -q` },
		"path_dot": func(a, p *model.Event) { a.Extra["process_path"] = `C:\Tools\..\Tools\worker.exe` }, "path_unknown": func(a, p *model.Event) { p.ProcessPath = "" },
		"path_env": func(a, p *model.Event) { a.Extra["process_path"] = `%SYSTEMROOT%\worker.exe` }, "path_short": func(a, p *model.Event) { a.Extra["process_path"] = `C:\TOOLS~1\worker.exe` },
		"empty_id": func(a, p *model.Event) { p.ID = "" }, "duplicate_id": func(a, p *model.Event) { p.ID = a.ID },
		"expired": func(a, p *model.Event) {
			p.Extra = map[string]string{"exit_time": a.Timestamp.Add(-time.Second).Format(time.RFC3339Nano)}
		},
		"guid_conflict": func(a, p *model.Event) {
			a.Extra["process_guid"] = taskGUID
			p.Extra = map[string]string{"process_guid": "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, p := taskProcessPair(t)
			change(&a, &p)
			if got := BuildTaskProcessContexts("case", []model.Event{a, p}); len(got) != 0 {
				t.Fatalf("unsafe process association: %+v", got)
			}
		})
	}
	for _, delta := range []time.Duration{0, -time.Second, -3 * time.Second} {
		t.Run(delta.String(), func(t *testing.T) {
			a, p := taskProcessPair(t)
			other := p
			other.ID = "reuse"
			other.ProcessPath = `C:\Other\different.exe`
			other.Timestamp = a.Timestamp.Add(delta)
			if got := BuildTaskProcessContexts("case", []model.Event{a, p, other}); len(got) != 0 {
				t.Fatalf("ambiguous observed PID reuse: %+v", got)
			}
		})
	}
}
func taskContexts(cs []model.Correlation) []model.Correlation {
	var out []model.Correlation
	for _, c := range cs {
		if c.Type == model.CorrelationTaskInstanceContext || c.Type == model.CorrelationTaskProcessContext {
			out = append(out, c)
		}
	}
	return out
}
func TestTaskContextEngineStreamedIdentity(t *testing.T) {
	for _, process := range []bool{false, true} {
		a, b := taskRecord(t, "a", 200), taskRecord(t, "b", 202)
		builder := BuildTaskInstanceContexts
		if process {
			a, b = taskProcessPair(t)
			builder = BuildTaskProcessContexts
		}
		b.Host = "host01.corp.example"
		metadata := model.Event{ID: "metadata", CaseID: "case", Host: "host01", CollectionID: "capture", EventType: "unrelated_metadata", Extra: map[string]string{"domain": "corp.example"}}
		events := []model.Event{a, b, metadata}
		direct := builder("case", events)
		if len(direct) != 1 {
			t.Fatalf("validated alias lost process=%v: %+v", process, direct)
		}
		all := taskContexts(Run("case", events))
		if !reflect.DeepEqual(direct, all) {
			t.Fatalf("engine omitted context: direct=%+v engine=%+v", direct, all)
		}
		streamed, err := RunFrom("case", model.SliceSource(events))
		if err != nil || !reflect.DeepEqual(all, taskContexts(streamed)) {
			t.Fatal("stream parity", err)
		}
		metadata.Extra["domain"] = "other.example"
		for _, got := range [][]model.Correlation{builder("case", events), taskContexts(Run("case", events))} {
			if len(got) != 0 {
				t.Fatalf("unrelated domain contradiction ignored: %+v", got)
			}
		}
	}
}
func TestTaskInstanceContextContradictoryCapture(t *testing.T) {
	for _, field := range []string{"task_started", "user_context"} {
		t.Run(field, func(t *testing.T) {
			a, b := taskRecord(t, "a", 100), taskRecord(t, "b", 202)
			events := []model.Event{a, b}
			if field == "task_started" {
				other := taskRecord(t, "second-start", 100)
				other.Timestamp = a.Timestamp.Add(24 * time.Hour)
				events = append(events, other)
			} else {
				a.Extra["user_context"] = "LAB\\alice"
				b.Extra["user_context"] = "LAB\\carol"
			}
			if got := BuildTaskInstanceContexts("case", events); len(got) != 0 {
				t.Fatalf("contradictory capture joined: %+v", got)
			}
		})
	}
}
func TestTaskContextDuplicateUntypedID(t *testing.T) {
	for _, process := range []bool{false, true} {
		a, b := taskRecord(t, "a", 200), taskRecord(t, "b", 202)
		builder := BuildTaskInstanceContexts
		if process {
			a, b = taskProcessPair(t)
			builder = BuildTaskProcessContexts
		}
		collision := model.Event{ID: a.ID, CaseID: a.CaseID, CollectionID: a.CollectionID, Host: a.Host, EventType: "unrelated"}
		events := []model.Event{a, b, collision}
		if got := builder("case", events); len(got) != 0 {
			t.Fatalf("direct duplicate accepted: %+v", got)
		}
		if got := taskContexts(Run("case", events)); len(got) != 0 {
			t.Fatalf("filtered load erased actual ID collision: %+v", got)
		}
	}
}
func TestTaskContextRejectsContradictoryAdapterFields(t *testing.T) {
	for _, field := range []string{"provider", "outcome"} {
		a, b := taskRecord(t, "a", 200), taskRecord(t, "b", 202)
		if field == "provider" {
			b.Provider = "Security"
		} else {
			b.Extra["outcome"] = "success"
		}
		if got := BuildTaskInstanceContexts("case", []model.Event{a, b}); len(got) != 0 {
			t.Fatalf("contradictory normalized field %s accepted: %+v", field, got)
		}
	}
}
func TestTaskContextEvidenceUnchangedAndUnsupportedInputs(t *testing.T) {
	a, b := taskRecord(t, "a", 200), taskRecord(t, "b", 202)
	for _, token := range []string{"", "bad", "{11111111-2222-3333-4444-555555555555", "urn:uuid:11111111-2222-3333-4444-555555555555", "11111111222233334444555555555555", "00000000-0000-0000-0000-000000000000", " " + taskGUID} {
		a.Extra["task_instance_id"] = token
		b.Extra["task_instance_id"] = token
		if got := BuildTaskInstanceContexts("case", []model.Event{a, b}); len(got) != 0 {
			t.Errorf("nonliteral GUID accepted %q", token)
		}
	}
	a, b = taskRecord(t, "a", 200), taskRecord(t, "b", 202)
	for _, unsupported := range []model.Event{taskRecord(t, "launch", 129), taskRecord(t, "config", 106)} {
		if got := BuildTaskInstanceContexts("case", []model.Event{a, unsupported}); len(got) != 0 {
			t.Fatal("configuration/129/singleton invented instance link")
		}
	}
	for _, builder := range []func(string, []model.Event) []model.Correlation{BuildTaskInstanceContexts, BuildTaskProcessContexts} {
		events := []model.Event{a, b}
		copies := make([]model.Event, len(events))
		for i, e := range events {
			copies[i] = e
			copies[i].Extra = map[string]string{}
			for k, v := range e.Extra {
				copies[i].Extra[k] = v
			}
		}
		builder("case", events)
		if !reflect.DeepEqual(events, copies) {
			t.Fatal("derived builder rewrote source literals")
		}
	}
	for _, token := range []string{"4242", "0x1092", "0X1092", "0004242"} {
		launch, p := taskProcessPair(t)
		launch.Extra["process_id"] = token
		if got := BuildTaskProcessContexts("case", []model.Event{launch, p}); len(got) != 1 {
			t.Errorf("valid recorded PID rejected %q", token)
		}
		if launch.Extra["process_id"] != token {
			t.Fatal("PID token rewritten")
		}
	}
}
func TestTaskInstanceContextPartial(t *testing.T) {
	a, b := taskRecord(t, "a", 200), taskRecord(t, "b", 202)
	got := BuildTaskInstanceContexts("case", []model.Event{a, b})
	if len(got) != 1 || len(got[0].EventIDs) != 2 {
		t.Fatalf("partial instance context missing: %+v", got)
	}
}
