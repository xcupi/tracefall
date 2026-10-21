package store

import (
	"sort"
	"testing"
	"time"

	"tracefall/internal/model"
)

// The store and an in-memory slice must give a consumer the same events for
// the same filter, or a rule would see different evidence in tests than in
// production.
func TestLoad_NamesFilterMatchesTheSliceSource(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	at := time.Date(2021, 4, 29, 18, 0, 0, 0, time.UTC)
	mk := func(id, typ, file, procPath, proc string) model.Event {
		return model.Event{ID: id, CaseID: "case-1", CollectionID: "collection-1", SourceFileID: "sf-1", Timestamp: at,
			EventType: typ, ArtifactType: model.ArtifactMFT, Parser: "mft@1", Confidence: 1,
			FilePath: file, ProcessPath: procPath, ProcessName: proc}
	}
	events := []model.Event{
		mk("a", model.EventFilesystemCreated, `C:\Windows\System32\Updater.EXE`, "", ""),
		mk("b", model.EventFilesystemCreated, `C:\Users\u\updater.exe.bak`, "", ""),
		mk("c", model.EventProcessCreate, "", `C:\Windows\System32\updater.exe`, "updater.exe"),
		mk("d", model.EventProcessCreate, "", "", "UPDATER.EXE"),
		mk("e", model.EventFilesystemCreated, "/opt/tools/updater.exe", "", ""),
		mk("f", model.EventFilesystemCreated, `C:\x\other.exe`, "", ""),
		mk("g", model.EventLogonSuccess, `C:\y\updater.exe`, "", ""), // a type the filter does not select
		mk("h", model.EventFilesystemCreated, `C:\x\100%_updater.exe`, "", ""),
	}
	if err := s.SaveEvents(events); err != nil {
		t.Fatal(err)
	}
	filter := model.EventFilter{
		Types: []string{model.EventFilesystemCreated, model.EventProcessCreate},
		Names: []string{"updater.exe", "Updater.exe"},
	}
	got, err := s.EventSourceFor("case-1").Load(filter)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := model.SliceSource(events).Load(filter)
	ids := func(ev []model.Event) []string {
		var out []string
		for _, e := range ev {
			out = append(out, e.ID)
		}
		sort.Strings(out)
		return out
	}
	g, w := ids(got), ids(want)
	if len(g) != len(w) {
		t.Fatalf("store %v, slice %v", g, w)
	}
	for i := range g {
		if g[i] != w[i] {
			t.Fatalf("store %v, slice %v", g, w)
		}
	}
	// a, c, d, e match; b (updater.exe.bak), f, g (wrong type) and h (a name with LIKE characters) do not.
	if len(g) != 4 || g[0] != "a" || g[1] != "c" || g[2] != "d" || g[3] != "e" {
		t.Fatalf("matched %v, want [a c d e]", g)
	}
	// LIKE wildcards in a requested name are literal.
	got, _ = s.EventSourceFor("case-1").Load(model.EventFilter{Types: []string{model.EventFilesystemCreated}, Names: []string{"100%_updater.exe"}})
	if len(got) != 1 || got[0].ID != "h" {
		t.Fatalf("a name with %% and _ must match literally: %v", ids(got))
	}
	got, _ = s.EventSourceFor("case-1").Load(model.EventFilter{Types: []string{model.EventFilesystemCreated}, Names: []string{"%"}})
	if len(got) != 0 {
		t.Fatalf("%% must not be a wildcard: %v", ids(got))
	}
}

func TestLoad_WithinRestrictsToTheNamedArtifacts_LikeTheSliceSource(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	at := time.Date(2021, 4, 29, 18, 0, 0, 0, time.UTC)
	mk := func(id, art string) model.Event {
		return model.Event{ID: id, CaseID: "case-1", CollectionID: "collection-1", SourceFileID: "sf-1", Timestamp: at,
			EventType: model.EventWebRequest, ArtifactType: art, Parser: "p@1", Confidence: 1}
	}
	events := []model.Event{mk("a", model.ArtifactNetworkCapture), mk("b", model.ArtifactWebAccessLog), mk("c", model.ArtifactNetworkCapture)}
	if err := s.SaveEvents(events); err != nil {
		t.Fatal(err)
	}
	f := model.EventFilter{Types: []string{model.EventWebRequest}, Within: []string{model.ArtifactNetworkCapture}}
	got, err := s.EventSourceFor("case-1").Load(f)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := model.SliceSource(events).Load(f)
	if len(got) != 2 || len(want) != 2 || got[0].ID != want[0].ID || got[1].ID != want[1].ID || got[0].ID == "b" || got[1].ID == "b" {
		t.Fatalf("store %d, slice %d", len(got), len(want))
	}
}
