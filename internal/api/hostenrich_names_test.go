package api

import (
	"testing"

	"tracefall/internal/model"
)

func TestUnambiguousHost_ShortAndQualifiedFormsOfOneMachine(t *testing.T) {
	ev := func(hosts ...string) []model.Event {
		out := make([]model.Event, 0, len(hosts))
		for _, h := range hosts {
			out = append(out, model.Event{Host: h})
		}
		return out
	}
	for _, tc := range []struct {
		name string
		in   []model.Event
		want string
	}{
		{"short and qualified", ev("HOST01", "host01.example.test", ""), "host01.example.test"},
		{"order independent", ev("host01.example.test", "HOST01"), "host01.example.test"},
		{"two qualified names with one label", ev("host01.a.test", "host01.b.test", "HOST01"), ""},
		{"different machines", ev("host01", "host02.example.test"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := unambiguousHost(tc.in); got != tc.want {
				t.Fatalf("unambiguousHost = %q want %q", got, tc.want)
			}
		})
	}
}

// One acquisition whose event log names the machine in qualified form and
// whose registry records name it in short form is one machine; its host-less
// records inherit the qualified spelling and say why.
func TestEnrichBatchHosts_ShortAndQualifiedNamesInOneCollection(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("short and qualified", "")
	if err != nil {
		t.Fatal(err)
	}
	batch := []pendingImport{
		{sourceFile: model.SourceFile{ID: "sf-log"}, events: []model.Event{{Host: "host01.example.test", EventType: model.EventProcessCreate}}},
		{sourceFile: model.SourceFile{ID: "sf-reg"}, events: []model.Event{{Host: "HOST01", EventType: model.EventRegistryRunKey}}},
		{sourceFile: model.SourceFile{ID: "sf-none"}, events: []model.Event{{Host: "", EventType: model.EventPrefetchExecution}}},
	}
	if err := svc.enrichBatchHosts(c.ID, "collection01", batch); err != nil {
		t.Fatal(err)
	}
	if got := batch[0].events[0].Host; got != "host01.example.test" {
		t.Fatalf("recorded host rewritten: %q", got)
	}
	if got := batch[1].events[0].Host; got != "HOST01" {
		t.Fatalf("recorded short host rewritten: %q", got)
	}
	e := batch[2].events[0]
	if e.Host != "host01.example.test" {
		t.Fatalf("host-less record host = %q, want the qualified name its collection records", e.Host)
	}
	if e.Extra["host_inherited_from"] != "collection" {
		t.Fatalf("inheritance basis not recorded: %v", e.Extra)
	}
	if batch[0].events[0].Extra["host_inherited_from"] != "" {
		t.Fatalf("a recorded host must not claim to be inherited: %v", batch[0].events[0].Extra)
	}
}

func TestEnrichBatchHosts_SourceFileBasisRecorded(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("file basis", "")
	if err != nil {
		t.Fatal(err)
	}
	batch := []pendingImport{
		{sourceFile: model.SourceFile{ID: "sf-a"}, events: []model.Event{{Host: "host01", EventType: model.EventProcessCreate}, {Host: "", EventType: model.EventProcessCreate}}},
		{sourceFile: model.SourceFile{ID: "sf-b"}, events: []model.Event{{Host: "host02", EventType: model.EventProcessCreate}}},
	}
	if err := svc.enrichBatchHosts(c.ID, "collection01", batch); err != nil {
		t.Fatal(err)
	}
	e := batch[0].events[1]
	if e.Host != "host01" || e.Extra["host_inherited_from"] != "source_file" {
		t.Fatalf("got host %q extra %v", e.Host, e.Extra)
	}
}

func TestEnrichBatchHosts_DifferentMachinesInOneCollectionStayUnknown(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("two machines", "")
	if err != nil {
		t.Fatal(err)
	}
	batch := []pendingImport{
		{sourceFile: model.SourceFile{ID: "sf-a"}, events: []model.Event{{Host: "host01.example.test", EventType: model.EventProcessCreate}}},
		{sourceFile: model.SourceFile{ID: "sf-b"}, events: []model.Event{{Host: "host02", EventType: model.EventRegistryRunKey}}},
		{sourceFile: model.SourceFile{ID: "sf-c"}, events: []model.Event{{Host: "", EventType: model.EventPrefetchExecution}}},
	}
	if err := svc.enrichBatchHosts(c.ID, "collection01", batch); err != nil {
		t.Fatal(err)
	}
	if got := batch[2].events[0]; got.Host != "" || got.Extra["host_inherited_from"] != "" {
		t.Fatalf("ambiguous collection inherited %q %v", got.Host, got.Extra)
	}
}
