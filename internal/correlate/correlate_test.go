package correlate

import (
	"testing"
	"time"

	"tracefall/internal/model"
)

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestBuildProcessChains(t *testing.T) {
	events := []model.Event{
		{ID: "1", Host: "H1", EventType: model.EventProcessCreate, ProcessName: "explorer.exe", Timestamp: mustTime("2026-01-15T09:00:00Z")},
		{ID: "2", Host: "H1", EventType: model.EventProcessCreate, ProcessName: "winword.exe", ParentProcessName: "explorer.exe", Timestamp: mustTime("2026-01-15T09:14:22Z")},
	}
	chains := BuildProcessChains("case-1", events)
	if len(chains) != 1 {
		t.Fatalf("got %d process chains, want 1", len(chains))
	}
	if chains[0].EventIDs[0] != "1" || chains[0].EventIDs[1] != "2" {
		t.Errorf("unexpected chain event order: %v", chains[0].EventIDs)
	}

	// A child with no matching parent process-create event yields no chain.
	orphan := []model.Event{
		{ID: "3", Host: "H1", EventType: model.EventProcessCreate, ProcessName: "cmd.exe", ParentProcessName: "nonexistent.exe", Timestamp: mustTime("2026-01-15T09:14:22Z")},
	}
	if got := BuildProcessChains("case-1", orphan); len(got) != 0 {
		t.Errorf("got %d chains for an unmatched parent, want 0", len(got))
	}
}

func TestBuildEntityCorrelations(t *testing.T) {
	events := []model.Event{
		{ID: "1", Host: "H1", EventType: model.EventProcessCreate, ArtifactType: model.ArtifactWindowsEventLog, ProcessName: "update.exe", Timestamp: mustTime("2026-01-15T09:15:10Z")},
		{ID: "2", Host: "H1", EventType: model.EventPrefetchExecution, ArtifactType: model.ArtifactPrefetch, ProcessName: "update.exe", Timestamp: mustTime("2026-01-15T09:15:11Z")},
	}
	corrs := BuildEntityCorrelations("case-1", events)
	if len(corrs) != 1 {
		t.Fatalf("got %d entity correlations, want 1", len(corrs))
	}
	if len(corrs[0].EventIDs) != 2 {
		t.Errorf("got %d linked events, want 2", len(corrs[0].EventIDs))
	}

	// A single artifact type shouldn't produce a correlation.
	single := events[:1]
	if got := BuildEntityCorrelations("case-1", single); len(got) != 0 {
		t.Errorf("got %d correlations for a single artifact type, want 0", len(got))
	}
}

func TestBuildTemporalClusters(t *testing.T) {
	base := mustTime("2026-01-15T09:14:00Z")
	events := []model.Event{
		{ID: "1", Host: "H1", ArtifactType: "a", Timestamp: base},
		{ID: "2", Host: "H1", ArtifactType: "b", Timestamp: base.Add(1 * time.Minute)},
		{ID: "3", Host: "H1", ArtifactType: "c", Timestamp: base.Add(2 * time.Minute)},
		// Big gap -- starts a new cluster that's too small to report.
		{ID: "4", Host: "H1", ArtifactType: "a", Timestamp: base.Add(1 * time.Hour)},
	}
	clusters := BuildTemporalClusters("case-1", events)
	if len(clusters) != 1 {
		t.Fatalf("got %d clusters, want 1", len(clusters))
	}
	if len(clusters[0].EventIDs) != 3 {
		t.Errorf("got %d events in cluster, want 3", len(clusters[0].EventIDs))
	}
}

func TestBuildActivityChains_FullNarrative(t *testing.T) {
	events := []model.Event{
		{ID: "logon", Host: "H1", User: "jdoe", EventType: model.EventLogonSuccess, Timestamp: mustTime("2026-01-15T09:00:00Z")},
		{ID: "office", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "winword.exe", ParentProcessName: "explorer.exe", Timestamp: mustTime("2026-01-15T09:14:22Z")},
		{ID: "ps", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", ParentProcessName: "winword.exe", Timestamp: mustTime("2026-01-15T09:14:47Z")},
		{ID: "payload", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "update.exe", ParentProcessName: "powershell.exe", Timestamp: mustTime("2026-01-15T09:15:10Z")},
		{ID: "persist", Host: "H1", User: "jdoe", EventType: model.EventRegistryRunKey, ProcessName: "update.exe", Timestamp: mustTime("2026-01-15T09:16:02Z")},
		{ID: "net", Host: "H1", User: "jdoe", EventType: model.EventNetworkConnection, ProcessName: "update.exe", NetworkDest: "203.0.113.77", Timestamp: mustTime("2026-01-15T09:18:05Z")},
	}
	chains := BuildActivityChains("case-1", events)
	if len(chains) != 1 {
		t.Fatalf("got %d activity chains, want 1", len(chains))
	}
	if len(chains[0].EventIDs) != 6 {
		t.Fatalf("got %d steps, want all 6 evidenced steps: %v", len(chains[0].EventIDs), chains[0].EventIDs)
	}
	want := []string{"logon", "office", "ps", "payload", "persist", "net"}
	for i, id := range want {
		if chains[0].EventIDs[i] != id {
			t.Errorf("step %d = %q, want %q (chain must not reorder or fabricate steps)", i, chains[0].EventIDs[i], id)
		}
	}
}

func TestBuildActivityChains_PartialEvidenceOnlyIncludesWhatExists(t *testing.T) {
	// No prior logon, no payload, no persistence, no network -- just the
	// Office -> PowerShell pivot. Must not be reported as a "chain" (the
	// office-spawns-powershell detection rule already covers this alone),
	// and must never fabricate the missing steps.
	events := []model.Event{
		{ID: "office", Host: "H1", EventType: model.EventProcessCreate, ProcessName: "winword.exe", ParentProcessName: "explorer.exe", Timestamp: mustTime("2026-01-15T09:14:22Z")},
		{ID: "ps", Host: "H1", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", ParentProcessName: "winword.exe", Timestamp: mustTime("2026-01-15T09:14:47Z")},
	}
	chains := BuildActivityChains("case-1", events)
	if len(chains) != 0 {
		t.Fatalf("got %d chains for a 2-step-only pivot, want 0 (no fabricated steps, no trivial chain)", len(chains))
	}
}

func TestRun_AssignsIDsAndIsDeterministic(t *testing.T) {
	events := []model.Event{
		{ID: "1", Host: "H1", EventType: model.EventProcessCreate, ProcessName: "explorer.exe", Timestamp: mustTime("2026-01-15T09:00:00Z")},
		{ID: "2", Host: "H1", EventType: model.EventProcessCreate, ProcessName: "winword.exe", ParentProcessName: "explorer.exe", Timestamp: mustTime("2026-01-15T09:14:22Z")},
	}
	out := Run("case-1", events)
	if len(out) == 0 {
		t.Fatal("expected at least one correlation")
	}
	for _, c := range out {
		if c.ID == "" {
			t.Error("correlation missing assigned ID")
		}
		if c.CaseID != "case-1" {
			t.Errorf("CaseID = %q, want case-1", c.CaseID)
		}
	}
}
