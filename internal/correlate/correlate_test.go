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
	corrs := BuildEntityCorrelations("case-1", refsOf(events))
	if len(corrs) != 1 {
		t.Fatalf("got %d entity correlations, want 1", len(corrs))
	}
	if len(corrs[0].EventIDs) != 2 {
		t.Errorf("got %d linked events, want 2", len(corrs[0].EventIDs))
	}

	// A single artifact type shouldn't produce a correlation.
	single := events[:1]
	if got := BuildEntityCorrelations("case-1", refsOf(single)); len(got) != 0 {
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
	clusters := BuildTemporalClusters("case-1", refsOf(events))
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

// =====================================================================
// Phase 4 correlation tests.
// =====================================================================

func TestBuildActivityChains_ScriptHostPivotBeyondPowerShell(t *testing.T) {
	// Phase 4: the Office-spawns-interpreter pivot isn't PowerShell-only
	// -- cmd.exe (and other script hosts) must be accepted too.
	events := []model.Event{
		{ID: "logon", Host: "H1", User: "jdoe", EventType: model.EventLogonSuccess, Timestamp: mustTime("2026-01-15T09:00:00Z")},
		{ID: "office", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "winword.exe", ParentProcessName: "explorer.exe", Timestamp: mustTime("2026-01-15T09:14:22Z")},
		{ID: "cmd", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "cmd.exe", ParentProcessName: "winword.exe", Timestamp: mustTime("2026-01-15T09:14:47Z")},
		{ID: "payload", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "update.exe", ParentProcessName: "cmd.exe", Timestamp: mustTime("2026-01-15T09:15:10Z")},
	}
	chains := BuildActivityChains("case-1", events)
	if len(chains) != 1 {
		t.Fatalf("got %d activity chains, want 1 (cmd.exe pivot must be recognized like powershell.exe)", len(chains))
	}
}

func TestBuildActivityChains_ServiceInstallAsPersistenceStep(t *testing.T) {
	events := []model.Event{
		{ID: "logon", Host: "H1", User: "jdoe", EventType: model.EventLogonSuccess, Timestamp: mustTime("2026-01-15T09:00:00Z")},
		{ID: "office", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "winword.exe", ParentProcessName: "explorer.exe", Timestamp: mustTime("2026-01-15T09:14:22Z")},
		{ID: "ps", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", ParentProcessName: "winword.exe", Timestamp: mustTime("2026-01-15T09:14:47Z")},
		{ID: "payload", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "update.exe", ParentProcessName: "powershell.exe", Timestamp: mustTime("2026-01-15T09:15:10Z")},
		{ID: "svcinstall", Host: "H1", User: "jdoe", EventType: model.EventServiceInstall, ProcessName: "update.exe", Timestamp: mustTime("2026-01-15T09:16:02Z")},
	}
	chains := BuildActivityChains("case-1", events)
	if len(chains) != 1 {
		t.Fatalf("got %d activity chains, want 1", len(chains))
	}
	found := false
	for _, id := range chains[0].EventIDs {
		if id == "svcinstall" {
			found = true
		}
	}
	if !found {
		t.Errorf("chain event IDs %v do not include the service-install persistence step", chains[0].EventIDs)
	}
}

func TestBuildCredentialChains_BruteForce(t *testing.T) {
	base := mustTime("2026-01-15T14:00:00Z")
	events := []model.Event{
		{ID: "1", Host: "H1", User: "svc", EventType: model.EventLogonFailure, Timestamp: base},
		{ID: "2", Host: "H1", User: "svc", EventType: model.EventLogonFailure, Timestamp: base.Add(1 * time.Minute)},
		{ID: "3", Host: "H1", User: "svc", EventType: model.EventLogonFailure, Timestamp: base.Add(2 * time.Minute)},
		{ID: "4", Host: "H1", User: "svc", EventType: model.EventLogonSuccess, Timestamp: base.Add(3 * time.Minute)},
	}
	chains := BuildCredentialChains("case-1", events)
	if len(chains) != 1 {
		t.Fatalf("got %d credential chains, want 1", len(chains))
	}
	if chains[0].Type != model.CorrelationCredentialChain {
		t.Errorf("correlation_type = %q, want %q", chains[0].Type, model.CorrelationCredentialChain)
	}
	if len(chains[0].EventIDs) != 4 {
		t.Errorf("got %d events in chain, want 4 (3 failures + success)", len(chains[0].EventIDs))
	}

	// Below threshold: no chain.
	if got := BuildCredentialChains("case-1", events[:2]); len(got) != 0 {
		t.Errorf("got %d chains for below-threshold failures, want 0", len(got))
	}
}

func TestBuildCredentialChains_CredentialAbuse(t *testing.T) {
	base := mustTime("2026-01-15T09:20:00Z")
	events := []model.Event{
		{ID: "explicit", Host: "H1", User: "jdoe", EventType: model.EventLogonExplicitCreds, Extra: map[string]string{"target_user_name": "svc-backup"}, Timestamp: base},
		{ID: "proc", Host: "H1", User: "svc-backup", EventType: model.EventProcessCreate, ProcessName: "backup-agent.exe", Timestamp: base.Add(1 * time.Minute)},
		{ID: "net", Host: "H1", User: "svc-backup", EventType: model.EventNetworkConnection, ProcessName: "backup-agent.exe", NetworkDest: "10.0.0.9", Timestamp: base.Add(2 * time.Minute)},
	}
	chains := BuildCredentialChains("case-1", events)
	if len(chains) != 1 {
		t.Fatalf("got %d credential-abuse chains, want 1: %+v", len(chains), chains)
	}
	if len(chains[0].EventIDs) != 3 {
		t.Errorf("got %d steps, want 3 (explicit creds -> process -> network)", len(chains[0].EventIDs))
	}

	// Explicit creds with no follow-on activity by that account: no chain
	// (the bare 4648 observation is still reported by detect's
	// explicitCredentialUse rule, just not as a correlation chain).
	bare := []model.Event{events[0]}
	if got := BuildCredentialChains("case-1", bare); len(got) != 0 {
		t.Errorf("got %d chains for explicit creds alone with no follow-on activity, want 0", len(got))
	}
}

func TestBuildServiceChains(t *testing.T) {
	base := mustTime("2026-01-15T09:22:00Z")
	events := []model.Event{
		{ID: "install", Host: "H1", EventType: model.EventServiceInstall, ProcessName: "weirdsvc.exe", Extra: map[string]string{"service_name": "WeirdSvc"}, Timestamp: base},
		{ID: "start", Host: "H1", EventType: model.EventProcessCreate, ProcessName: "weirdsvc.exe", Timestamp: base.Add(5 * time.Second)},
		{ID: "net", Host: "H1", EventType: model.EventNetworkConnection, ProcessName: "weirdsvc.exe", NetworkDest: "203.0.113.99", Timestamp: base.Add(10 * time.Second)},
	}
	chains := BuildServiceChains("case-1", events)
	if len(chains) != 1 {
		t.Fatalf("got %d service chains, want 1", len(chains))
	}
	if chains[0].Type != model.CorrelationServiceChain {
		t.Errorf("correlation_type = %q, want %q", chains[0].Type, model.CorrelationServiceChain)
	}
	if len(chains[0].EventIDs) != 3 {
		t.Errorf("got %d steps, want 3 (install -> start -> network)", len(chains[0].EventIDs))
	}

	// A service that never actually starts (no matching process-create):
	// no chain -- must not be fabricated.
	neverStarted := []model.Event{
		{ID: "install2", Host: "H1", EventType: model.EventServiceInstall, ProcessName: "neverruns.exe", Timestamp: base},
	}
	if got := BuildServiceChains("case-1", neverStarted); len(got) != 0 {
		t.Errorf("got %d chains for a service install with no corresponding process-create, want 0", len(got))
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

// TestRun_CorrelationIDsAreStableAcrossReanalysis is a Phase 6 regression
// test, the correlate-package counterpart of detect's identical test:
// Correlation.ID must be byte-identical across two separate Run() calls
// on unchanged evidence.
func TestRun_CorrelationIDsAreStableAcrossReanalysis(t *testing.T) {
	events := []model.Event{
		{ID: "1", Host: "H1", EventType: model.EventProcessCreate, ProcessName: "explorer.exe", Timestamp: mustTime("2026-01-15T09:00:00Z")},
		{ID: "2", Host: "H1", EventType: model.EventProcessCreate, ProcessName: "winword.exe", ParentProcessName: "explorer.exe", Timestamp: mustTime("2026-01-15T09:14:22Z")},
	}
	out1 := Run("case-1", events)
	out2 := Run("case-1", events)
	if len(out1) == 0 {
		t.Fatal("expected at least one correlation")
	}
	if len(out1) != len(out2) {
		t.Fatalf("non-deterministic correlation count across runs: %d vs %d", len(out1), len(out2))
	}
	for i := range out1 {
		if out1[i].ID != out2[i].ID {
			t.Errorf("correlation %d: ID differs across runs on unchanged evidence: %q vs %q (type %s)", i, out1[i].ID, out2[i].ID, out1[i].Type)
		}
	}
}

// refsOf projects test events to the references the temporal and entity
// correlators read.
func refsOf(events []model.Event) []model.EventRef {
	out := make([]model.EventRef, len(events))
	for i, e := range events {
		out[i] = model.RefOf(e)
	}
	return out
}
