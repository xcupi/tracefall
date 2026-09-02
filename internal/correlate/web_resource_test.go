package correlate_test

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/correlate"
	"tracefall/internal/model"
)

var webBase = time.Date(2026, 4, 18, 9, 0, 0, 0, time.UTC)

func webEvent(id, artifact, host string, at time.Time) model.Event {
	return model.Event{
		ID: id, Timestamp: at, ArtifactType: artifact, NetworkDest: host,
		EventType: map[string]string{
			model.ArtifactBrowserHistory: model.EventBrowserVisit,
			model.ArtifactBrowserCache:   model.EventBrowserCacheEntry,
		}[artifact],
	}
}

// A host in BOTH history and cache is corroborated, and the description
// keeps the two claims apart.
func TestWebResource_CorroboratesAcrossArtifacts(t *testing.T) {
	events := []model.Event{
		webEvent("h1", model.ArtifactBrowserHistory, "updates.example.test", webBase),
		webEvent("c1", model.ArtifactBrowserCache, "updates.example.test", webBase.Add(time.Minute)),
	}
	corrs := correlate.BuildWebResourceCorrelations("case", events)
	if len(corrs) != 1 {
		t.Fatalf("got %d correlations, want 1", len(corrs))
	}
	c := corrs[0]
	if c.Type != model.CorrelationWebResource {
		t.Errorf("type = %q", c.Type)
	}
	if len(c.EventIDs) != 2 {
		t.Errorf("event ids = %v", c.EventIDs)
	}
	if !c.FirstSeen.Equal(webBase) || !c.LastSeen.Equal(webBase.Add(time.Minute)) {
		t.Errorf("span = %s..%s", c.FirstSeen, c.LastSeen)
	}
	// The distinction between the two claims must survive into the text
	// the analyst reads.
	for _, phrase := range []string{"navigation", "response was received and stored", "makes no judgement"} {
		if !strings.Contains(c.Description, phrase) {
			t.Errorf("the description omits %q: %s", phrase, c.Description)
		}
	}
}

// A host seen ONLY in the cache produces no correlation: one source
// saying one thing is not corroboration, and must not read as a visit.
func TestWebResource_CacheAloneIsNotCorroboration(t *testing.T) {
	var events []model.Event
	for i := 0; i < 25; i++ {
		events = append(events, webEvent(
			"c"+string(rune('a'+i)), model.ArtifactBrowserCache, "ads.example.test",
			webBase.Add(time.Duration(i)*time.Minute)))
	}
	if corrs := correlate.BuildWebResourceCorrelations("case", events); len(corrs) != 0 {
		t.Errorf("cache alone produced %d correlations: %s", len(corrs), corrs[0].Description)
	}
}

// History alone is likewise not a cross-artifact correlation.
func TestWebResource_HistoryAloneIsNotCorroboration(t *testing.T) {
	events := []model.Event{
		webEvent("h1", model.ArtifactBrowserHistory, "example.test", webBase),
		webEvent("h2", model.ArtifactBrowserHistory, "example.test", webBase.Add(time.Hour)),
	}
	if corrs := correlate.BuildWebResourceCorrelations("case", events); len(corrs) != 0 {
		t.Errorf("history alone produced %d correlations", len(corrs))
	}
}

// Different hosts never merge.
func TestWebResource_HostsAreNotMerged(t *testing.T) {
	events := []model.Event{
		webEvent("h1", model.ArtifactBrowserHistory, "a.example.test", webBase),
		webEvent("c1", model.ArtifactBrowserCache, "b.example.test", webBase),
	}
	if corrs := correlate.BuildWebResourceCorrelations("case", events); len(corrs) != 0 {
		t.Errorf("two different hosts were correlated: %+v", corrs)
	}
}

// Deterministic: same input, same output, every time.
func TestWebResource_IsDeterministic(t *testing.T) {
	events := []model.Event{
		webEvent("c2", model.ArtifactBrowserCache, "b.example.test", webBase.Add(time.Minute)),
		webEvent("h1", model.ArtifactBrowserHistory, "a.example.test", webBase),
		webEvent("h2", model.ArtifactBrowserHistory, "b.example.test", webBase),
		webEvent("c1", model.ArtifactBrowserCache, "a.example.test", webBase.Add(2*time.Minute)),
	}
	first := correlate.BuildWebResourceCorrelations("case", events)
	if len(first) != 2 {
		t.Fatalf("got %d correlations, want 2", len(first))
	}
	for i := 0; i < 20; i++ {
		again := correlate.BuildWebResourceCorrelations("case", events)
		if len(again) != len(first) {
			t.Fatalf("run %d produced %d correlations", i, len(again))
		}
		for j := range first {
			if again[j].Title != first[j].Title || strings.Join(again[j].EventIDs, ",") != strings.Join(first[j].EventIDs, ",") {
				t.Fatalf("run %d differed at %d: %q vs %q", i, j, again[j].Title, first[j].Title)
			}
		}
	}
}

// This correlation carries no verdict: no severity, and a suspicious
// hostname is described exactly like a benign one.
func TestWebResource_CarriesNoVerdict(t *testing.T) {
	benign := correlate.BuildWebResourceCorrelations("case", []model.Event{
		webEvent("h1", model.ArtifactBrowserHistory, "cdn.example.test", webBase),
		webEvent("c1", model.ArtifactBrowserCache, "cdn.example.test", webBase),
	})
	scary := correlate.BuildWebResourceCorrelations("case", []model.Event{
		webEvent("h1", model.ArtifactBrowserHistory, "malware-c2.example.test", webBase),
		webEvent("c1", model.ArtifactBrowserCache, "malware-c2.example.test", webBase),
	})
	if len(benign) != 1 || len(scary) != 1 {
		t.Fatal("expected one correlation each")
	}
	if strings.Replace(scary[0].Description, "malware-c2", "cdn", -1) != benign[0].Description {
		t.Error("a suspicious-looking hostname is described differently from a benign one; this correlation must not judge")
	}
	// A correlation has no severity field at all -- it is a link, not a
	// verdict -- so the check that matters is that no severity word
	// leaks into the text either.
	for _, c := range append(benign, scary...) {
		for _, word := range []string{"malicious", "suspicious", "critical", "high risk"} {
			if strings.Contains(strings.ToLower(c.Title+c.Description), word) {
				t.Errorf("the correlation renders a verdict (%q): %s", word, c.Description)
			}
		}
	}
}

// Correlating browser artifacts must not disturb the existing engine.
func TestWebResource_LeavesOtherCorrelationTypesAlone(t *testing.T) {
	events := []model.Event{
		{ID: "p1", Timestamp: webBase, Host: "WS1", EventType: model.EventProcessCreate,
			ProcessName: "winword.exe", ArtifactType: model.ArtifactWindowsEventLog},
		{ID: "p2", Timestamp: webBase.Add(time.Minute), Host: "WS1", EventType: model.EventProcessCreate,
			ProcessName: "powershell.exe", ParentProcessName: "winword.exe", ArtifactType: model.ArtifactWindowsEventLog},
		webEvent("h1", model.ArtifactBrowserHistory, "example.test", webBase),
		webEvent("c1", model.ArtifactBrowserCache, "example.test", webBase),
	}
	byType := map[string]int{}
	for _, c := range correlate.Run("case", events) {
		byType[c.Type]++
	}
	if byType[model.CorrelationProcessChain] == 0 {
		t.Error("the process chain disappeared once browser events were present")
	}
	if byType[model.CorrelationWebResource] != 1 {
		t.Errorf("got %d web_resource correlations, want 1", byType[model.CorrelationWebResource])
	}
}
