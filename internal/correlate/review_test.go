package correlate

import (
	"strings"
	"testing"
	"time"
	"tracefall/internal/clockskew"
	"tracefall/internal/hostid"
	"tracefall/internal/model"
)

func reviewFact(id, host, coll, ip string) model.Event {
	return model.Event{ID: id, CaseID: "case", Host: host, CollectionID: coll, EventType: model.EventRegistryKeyLastWrite, Extra: map[string]string{"registry_value_name": "ComputerName", "ip_origin": ip + "=static"}}
}
func TestReviewRunFromProcessIdentityProjection(t *testing.T) {
	base := time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)
	parent := model.Event{ID: "office", CaseID: "case", CollectionID: "one", Host: "host01", Timestamp: base, EventType: model.EventProcessCreate, ProcessName: "winword.exe", PID: 100, ArtifactType: model.ArtifactWindowsEventLog}
	child := parent
	child.ID = "ps"
	child.Timestamp = base.Add(time.Minute)
	child.ProcessName = "powershell.exe"
	child.PID = 101
	child.PPID = 100
	child.ParentProcessName = "winword.exe"
	facts := []model.Event{reviewFact("a", "host01.a.example", "three", "10.0.0.6"), reviewFact("b", "host01.b.example", "four", "10.0.0.7")}
	events := append([]model.Event{parent, child}, facts...)
	for order := 0; order < 2; order++ {
		got, err := RunFrom("case", model.SliceSource(events))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range got {
			if c.Type == model.CorrelationProcessChain {
				t.Fatalf("case-wide ambiguous short name received positive lineage attribution: %+v", c)
			}
		}
		events[0], events[3] = events[3], events[0]
	}
	// Proven aliases within the acquisition retain recorded PID lineage.
	child.Host = "host01.corp.example"
	got, err := RunFrom("case", model.SliceSource([]model.Event{parent, child}))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range got {
		if c.Type == model.CorrelationProcessChain && !strings.HasPrefix(c.Title, "Hypothetical") {
			found = true
		}
	}
	if !found {
		t.Fatalf("validated alias lineage lost: %+v", got)
	}
	if parent.Host != "host01" || child.Host != "host01.corp.example" {
		t.Fatal("raw hosts mutated")
	}
	// Entity and temporal references must not route around the same ambiguity.
	x := parent
	x.ID = "x"
	x.ProcessName = "worker.exe"
	y := x
	y.ID = "y"
	y.CollectionID = "two"
	y.ArtifactType = model.ArtifactPrefetch
	z := y
	z.ID = "z"
	z.CollectionID = "five"
	z.ArtifactType = model.ArtifactAmcache
	got, err = RunFrom("case", model.SliceSource(append([]model.Event{x, y, z}, facts...)))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got {
		if c.Type == model.CorrelationEntity || c.Type == model.CorrelationTemporal {
			t.Fatalf("ambiguous refs bypass validated comparison: %+v", c)
		}
	}
}

func TestReviewWebValidatedAliasAndClock(t *testing.T) {
	base := time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)
	facts := []model.Event{reviewFact("short", "host01", "one", "10.0.0.5"), reviewFact("full", "host01.corp.example", "one", "10.0.0.5")}
	cap := model.Event{ID: "http", Timestamp: base, EventType: model.EventWebRequest, ArtifactType: model.ArtifactNetworkCapture, NetworkSource: "10.0.0.5", Extra: map[string]string{"filename": "worker.exe", "response_sha256": "synthetic-hash", "reassembly": "complete", "status": "200"}}
	host := model.Event{ID: "host", Host: "host01", Timestamp: base.Add(time.Minute), EventType: model.EventProcessCreate, ProcessName: "worker.exe"}
	for _, name := range []string{"host01", "host01.corp.example"} {
		host.Host = name
		if got := BuildWebToHost("case", []model.Event{cap}, []model.Event{host}, hostid.Build(facts), nil); len(got) != 1 {
			t.Fatalf("validated alias %s rejected: %+v", name, got)
		}
		host.Timestamp = base.Add(48 * time.Hour)
		for _, subject := range []string{"host:host01.corp.example", "host:host01"} {
			skew := clockskew.Estimate{Subject: subject, Consistent: true, Lo: 48*time.Hour - time.Minute, Hi: 48*time.Hour - time.Minute}
			got := BuildWebToHost("case", []model.Event{cap}, []model.Event{host}, hostid.Build(facts), []clockskew.Estimate{skew})
			if len(got) != 1 || !strings.Contains(got[0].Description, "clock was estimated") {
				t.Fatalf("validated alias clock %s not applied for %s: %+v", subject, name, got)
			}
		}
		host.Timestamp = base.Add(time.Minute)
	}
	host.Host = "host01"
	collision := append(append([]model.Event{}, facts...), reviewFact("other", "host01.other.example", "two", "10.0.0.6"))
	if got := BuildWebToHost("case", []model.Event{cap}, []model.Event{host}, hostid.Build(collision), nil); len(got) != 0 {
		t.Fatalf("ambiguous host attributed: %+v", got)
	}
	shared := append(append([]model.Event{}, facts...), reviewFact("shared", "host02", "two", "10.0.0.5"))
	for _, c := range BuildWebToHost("case", []model.Event{cap}, []model.Event{host}, hostid.Build(shared), nil) {
		if strings.Contains(c.Description, "10.0.0.5 is ") {
			t.Fatalf("shared IP attributed: %+v", c)
		}
	}
	if host.Host != "host01" || !host.Timestamp.Equal(base.Add(time.Minute)) {
		t.Fatal("raw facts mutated")
	}
}
