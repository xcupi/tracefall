package investigate

import (
	"encoding/json"
	"strings"
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

// ---------------- grouping ----------------

func TestRun_SingleFindingBecomesOneInvestigation(t *testing.T) {
	events := []model.Event{
		{ID: "e1", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", ArtifactType: "windows_event_log", CollectionID: "c1", Timestamp: mustTime("2026-01-15T09:00:00Z")},
	}
	findings := []model.Finding{
		{ID: "f1", RuleID: "powershell-encoded-command", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium, SupportingEvents: []string{"e1"}, Techniques: []string{"T1059.001"}, FirstSeen: events[0].Timestamp, LastSeen: events[0].Timestamp},
	}
	invs := Run("case-1", events, findings, nil)
	if len(invs) != 1 {
		t.Fatalf("got %d investigations, want 1", len(invs))
	}
	inv := invs[0]
	if len(inv.FindingIDs) != 1 || inv.FindingIDs[0] != "f1" {
		t.Errorf("finding_ids = %v, want [f1]", inv.FindingIDs)
	}
	if len(inv.EventIDs) != 1 || inv.EventIDs[0] != "e1" {
		t.Errorf("event_ids = %v, want [e1]", inv.EventIDs)
	}
	if inv.CaseID != "case-1" {
		t.Errorf("case_id = %q, want case-1", inv.CaseID)
	}
}

func TestRun_UnrelatedFindingsSameHostStaySeparate(t *testing.T) {
	// Two findings on the SAME host and SAME user, but with entirely
	// disjoint supporting events and no correlation linking them, must
	// NOT be merged into one investigation -- "do not simply group
	// everything occurring on one host".
	events := []model.Event{
		{ID: "e1", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", Timestamp: mustTime("2026-01-15T09:00:00Z")},
		{ID: "e2", Host: "H1", User: "jdoe", EventType: model.EventRegistryRunKey, ProcessName: "unrelated.exe", Timestamp: mustTime("2026-01-16T14:00:00Z")}, // a full day later, unrelated
	}
	findings := []model.Finding{
		{ID: "f1", RuleID: "powershell-encoded-command", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium, SupportingEvents: []string{"e1"}, FirstSeen: events[0].Timestamp, LastSeen: events[0].Timestamp},
		{ID: "f2", RuleID: "new-registry-run-key", Severity: model.SeverityLow, Confidence: model.ConfidenceLow, SupportingEvents: []string{"e2"}, FirstSeen: events[1].Timestamp, LastSeen: events[1].Timestamp},
	}
	invs := Run("case-1", events, findings, nil) // no correlation links them
	if len(invs) != 2 {
		t.Fatalf("got %d investigations, want 2 (unrelated findings must stay separate even on the same host)", len(invs))
	}
}

func TestRun_CorrelationMergesFindings(t *testing.T) {
	events := []model.Event{
		{ID: "office", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "winword.exe", ParentProcessName: "explorer.exe", ArtifactType: "windows_event_log", CollectionID: "c1", Timestamp: mustTime("2026-01-15T09:14:22Z")},
		{ID: "ps", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", ParentProcessName: "winword.exe", ArtifactType: "windows_event_log", CollectionID: "c1", Timestamp: mustTime("2026-01-15T09:14:47Z")},
		{ID: "payload", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "update.exe", ParentProcessName: "powershell.exe", ArtifactType: "windows_event_log", CollectionID: "c1", Timestamp: mustTime("2026-01-15T09:15:10Z")},
		{ID: "persist", Host: "H1", User: "jdoe", EventType: model.EventRegistryRunKey, ProcessName: "update.exe", FilePath: `C:\Temp\update.exe`, ArtifactType: "registry_run_key", CollectionID: "c2", Timestamp: mustTime("2026-01-15T09:16:02Z")},
		{ID: "net", Host: "H1", User: "jdoe", EventType: model.EventNetworkConnection, ProcessName: "update.exe", NetworkDest: "203.0.113.77", ArtifactType: "windows_event_log", CollectionID: "c1", Timestamp: mustTime("2026-01-15T09:18:05Z")},
	}
	findings := []model.Finding{
		{ID: "f-exec", RuleID: "office-spawns-powershell", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium, SupportingEvents: []string{"ps"}, Techniques: []string{"T1059.001", "T1204.002"}, FirstSeen: events[1].Timestamp, LastSeen: events[1].Timestamp},
		{ID: "f-persist", RuleID: "execution-persistence-temporal", Severity: model.SeverityCritical, Confidence: model.ConfidenceHigh, SupportingEvents: []string{"payload", "persist"}, Techniques: []string{"T1547.001"}, FirstSeen: events[2].Timestamp, LastSeen: events[3].Timestamp},
		{ID: "f-net", RuleID: "network-after-execution", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium, SupportingEvents: []string{"payload", "net"}, Techniques: []string{"T1071"}, FirstSeen: events[2].Timestamp, LastSeen: events[4].Timestamp},
	}
	correlations := []model.Correlation{
		{ID: "chain1", Type: model.CorrelationActivityChain, Title: "Activity chain: exec(winword.exe) -> exec(powershell.exe) -> exec(update.exe) -> persist(registry) -> network(203.0.113.77)",
			EventIDs: []string{"office", "ps", "payload", "persist", "net"}, FirstSeen: events[0].Timestamp, LastSeen: events[4].Timestamp},
	}
	invs := Run("case-1", events, findings, correlations)
	if len(invs) != 1 {
		t.Fatalf("got %d investigations, want 1 (chain correlation should merge both findings)", len(invs))
	}
	inv := invs[0]
	if len(inv.FindingIDs) != 3 {
		t.Errorf("finding_ids = %v, want 3 findings merged", inv.FindingIDs)
	}
	if len(inv.EventIDs) != 5 {
		t.Errorf("event_ids = %v, want all 5 chain events", inv.EventIDs)
	}
	if len(inv.CollectionIDs) != 2 {
		t.Errorf("collection_ids = %v, want 2 (c1 and c2)", inv.CollectionIDs)
	}
	if inv.Category != model.InvestigationMultiStageAttack {
		t.Errorf("category = %q, want %q (execution+persistence+network)", inv.Category, model.InvestigationMultiStageAttack)
	}
	if inv.Severity != model.SeverityCritical {
		t.Errorf("severity = %q, want critical for this rich a case (score=%d)", inv.Severity, inv.Score)
	}
	if inv.Confidence != model.ConfidenceHigh {
		t.Errorf("confidence = %q, want high (chain-correlated, cross-collection, multi-artifact)", inv.Confidence)
	}
	if inv.Summary == "" {
		t.Error("expected a non-empty narrative")
	}
	if strings.Contains(strings.ToLower(inv.Summary), "attacker") {
		t.Errorf("narrative must never say 'the attacker': %q", inv.Summary)
	}
}

func TestRun_UnrelatedUsersStaySeparate(t *testing.T) {
	events := []model.Event{
		{ID: "e1", Host: "H1", User: "alice", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", Timestamp: mustTime("2026-01-15T09:00:00Z")},
		{ID: "e2", Host: "H1", User: "bob", EventType: model.EventProcessCreate, ProcessName: "cmd.exe", Timestamp: mustTime("2026-01-15T09:00:05Z")},
	}
	findings := []model.Finding{
		{ID: "f1", RuleID: "powershell-encoded-command", Severity: model.SeverityHigh, SupportingEvents: []string{"e1"}, FirstSeen: events[0].Timestamp, LastSeen: events[0].Timestamp},
		{ID: "f2", RuleID: "suspicious-parent-child-lineage", Severity: model.SeverityMedium, SupportingEvents: []string{"e2"}, FirstSeen: events[1].Timestamp, LastSeen: events[1].Timestamp},
	}
	invs := Run("case-1", events, findings, nil)
	if len(invs) != 2 {
		t.Fatalf("got %d investigations, want 2 (different users, no correlation)", len(invs))
	}
}

func TestRun_CorrelationWithoutFindingIsDropped(t *testing.T) {
	// A temporal cluster or entity correlation with no attached finding
	// is correlation context, not a risk-worthy investigation.
	events := []model.Event{
		{ID: "e1", Host: "H1", ArtifactType: "a", Timestamp: mustTime("2026-01-15T09:00:00Z")},
		{ID: "e2", Host: "H1", ArtifactType: "b", Timestamp: mustTime("2026-01-15T09:00:05Z")},
	}
	correlations := []model.Correlation{
		{ID: "c1", Type: model.CorrelationTemporal, EventIDs: []string{"e1", "e2"}, FirstSeen: events[0].Timestamp, LastSeen: events[1].Timestamp},
	}
	invs := Run("case-1", events, nil, correlations)
	if len(invs) != 0 {
		t.Fatalf("got %d investigations, want 0 (no finding attached)", len(invs))
	}
}

// TestRun_FindingWithDeletedEventProducesNonNilSlices reproduces a bug
// found during Phase 6 browser verification: deleting a source file
// (and its events) without re-running analysis leaves stale Findings
// whose SupportingEvents point at event IDs no longer in the case. Run
// still has to produce an Investigation for that finding (analysis
// hasn't been re-run, so it's correctly still shown, marked stale by
// the API layer) -- but with zero resolvable events, the accumulators
// that build Hosts/Users/Techniques/Tactics/CollectionIDs/SourceFileIDs
// never append anything, and every one of those fields is a plain
// []string with no `omitempty` (model/investigation.go). A Go nil
// slice and an empty slice both have len 0, but only the empty slice
// round-trips through encoding/json as `[]` -- a nil slice serializes
// as `null`, which crashed internal/web/static/app.js (renderInvestigationList
// calls .length/.join on inv.hosts unconditionally). See
// sortedUniqueStrings' doc comment (score.go) for the fix.
func TestRun_FindingWithDeletedEventProducesNonNilSlices(t *testing.T) {
	events := []model.Event{} // the finding's supporting event has been deleted
	findings := []model.Finding{
		{ID: "f1", RuleID: "new-scheduled-task", Severity: model.SeverityLow, Confidence: model.ConfidenceLow, SupportingEvents: []string{"e-deleted"}, Techniques: []string{"T1053.005"}},
	}
	invs := Run("case-1", events, findings, nil)
	if len(invs) != 1 {
		t.Fatalf("got %d investigations, want 1", len(invs))
	}
	inv := invs[0]
	for name, got := range map[string][]string{
		"Hosts": inv.Hosts, "Users": inv.Users, "Techniques": inv.Techniques,
		"Tactics": inv.Tactics, "CollectionIDs": inv.CollectionIDs, "SourceFileIDs": inv.SourceFileIDs,
	} {
		if got == nil {
			t.Errorf("%s is nil, want non-nil empty slice (would serialize as JSON null, not [])", name)
		}
	}
	b, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	for _, field := range []string{`"hosts":null`, `"users":null`, `"attack_techniques":null`, `"tactics":null`, `"collection_ids":null`, `"source_file_ids":null`} {
		if strings.Contains(string(b), field) {
			t.Errorf("serialized investigation contains %s -- frontend code calls .length/.join on this field unconditionally", field)
		}
	}
}

// ---------------- categorization ----------------

func TestCategorize_CredentialAlone(t *testing.T) {
	f := facetsFor([]string{"brute-force-then-success"})
	if got := categorize(f); got != model.InvestigationCredentialAttack {
		t.Errorf("categorize = %q, want %q", got, model.InvestigationCredentialAttack)
	}
}

func TestCategorize_ServicePersistence(t *testing.T) {
	f := facetsFor([]string{"service-persistence"})
	if got := categorize(f); got != model.InvestigationServicePersistence {
		t.Errorf("categorize = %q, want %q", got, model.InvestigationServicePersistence)
	}
}

func TestCategorize_ScriptBased(t *testing.T) {
	f := facetsFor([]string{"powershell-encoded-command"})
	if got := categorize(f); got != model.InvestigationScriptBasedAttack {
		t.Errorf("categorize = %q, want %q", got, model.InvestigationScriptBasedAttack)
	}
}

func TestCategorize_MultiStage(t *testing.T) {
	f := facetsFor([]string{"office-spawns-powershell", "execution-persistence-temporal", "network-after-execution"})
	if got := categorize(f); got != model.InvestigationMultiStageAttack {
		t.Errorf("categorize = %q, want %q", got, model.InvestigationMultiStageAttack)
	}
}

// ---------------- scoring ----------------

func TestComputeScore_SeverityLevels(t *testing.T) {
	// A finding's own severity, taken entirely alone (no corroboration),
	// maps to that same Investigation severity -- see the task's worked
	// example ("a suspicious PowerShell command may be Severity: HIGH")
	// and score.go's calibration comment.
	cases := []struct {
		sev  string
		want string
	}{
		{model.SeverityLow, model.SeverityLow},
		{model.SeverityMedium, model.SeverityMedium},
		{model.SeverityHigh, model.SeverityHigh},
	}
	for _, c := range cases {
		score, _ := computeScore(scoreInput{highestSeverity: c.sev})
		if got := severityForScore(score); got != c.want {
			t.Errorf("severity(%s alone) score=%d -> %q, want %q", c.sev, score, got, c.want)
		}
	}
}

func TestComputeScore_CriticalRequiresCorroboration(t *testing.T) {
	// A bare high-severity finding, nothing else, should not alone reach
	// CRITICAL -- only 30 (base) points.
	score, _ := computeScore(scoreInput{highestSeverity: model.SeverityHigh})
	if severityForScore(score) == model.SeverityCritical {
		t.Errorf("a lone high-severity finding scored %d and was labeled critical -- critical must require corroboration", score)
	}

	// Rich, corroborated case: critical base + execution + script +
	// persistence + network + chain + 3 tactics + artifact diversity +
	// cross-collection should comfortably clear the critical threshold.
	rich, reasons := computeScore(scoreInput{
		highestSeverity:  model.SeverityCritical,
		facets:           facetExecution | facetScriptInterpreter | facetPersistence | facetNetwork,
		hasChainCorr:     true,
		distinctTactics:  3,
		distinctArtifact: 2,
		distinctCollect:  2,
	})
	if severityForScore(rich) != model.SeverityCritical {
		t.Errorf("rich corroborated case scored %d (%v), want critical (>=80)", rich, reasons)
	}
}

func TestComputeScore_NoDoubleCounting(t *testing.T) {
	// Two different rule IDs that both carry facetExecution must only
	// add the execution bonus ONCE, not twice.
	facets := facetsFor([]string{"office-spawns-powershell", "suspicious-parent-child-lineage"})
	score1, reasons1 := computeScore(scoreInput{highestSeverity: model.SeverityHigh, facets: facets})

	facetsSingle := facetsFor([]string{"office-spawns-powershell"})
	score2, _ := computeScore(scoreInput{highestSeverity: model.SeverityHigh, facets: facetsSingle})

	// office-spawns-powershell alone already sets facetExecution|facetScriptInterpreter;
	// adding suspicious-parent-child-lineage (facetExecution only) must not add anything new.
	if score1 != score2 {
		t.Errorf("score with 2 execution-facet rules = %d, want equal to single-rule score %d (no double counting): reasons=%v", score1, score2, reasons1)
	}
}

func TestComputeScore_CrossCollectionOnlyForDistinctCollections(t *testing.T) {
	// Same collection repeated (as would happen if every group event's
	// first-observation collection is identical) must NOT trigger the
	// cross-collection bonus.
	scoreSame, _ := computeScore(scoreInput{highestSeverity: model.SeverityLow, distinctCollect: 1})
	scoreDiff, reasons := computeScore(scoreInput{highestSeverity: model.SeverityLow, distinctCollect: 2})
	if scoreDiff <= scoreSame {
		t.Errorf("expected a cross-collection bonus when distinctCollect=2 (got %d) vs distinctCollect=1 (got %d); reasons=%v", scoreDiff, scoreSame, reasons)
	}
}

// ---------------- confidence ----------------

func TestComputeConfidence_StandaloneFindingIsMedium(t *testing.T) {
	// Matches the task's worked example: "a suspicious PowerShell command
	// may be Severity HIGH, Confidence MEDIUM" -- a single finding with
	// its own medium confidence and nothing else corroborating it.
	confidence, _ := computeConfidence(confidenceInput{bestFindingConfidence: model.ConfidenceMedium, findingCount: 1})
	if confidence != model.ConfidenceMedium {
		t.Errorf("standalone medium-confidence finding -> investigation confidence = %q, want medium", confidence)
	}
}

func TestComputeConfidence_ChainCorrelatedIsHigh(t *testing.T) {
	confidence, rationale := computeConfidence(confidenceInput{
		bestFindingConfidence: model.ConfidenceHigh,
		hasChainCorr:          true,
		distinctArtifact:      2,
	})
	if confidence != model.ConfidenceHigh {
		t.Errorf("chain-correlated, multi-artifact case -> confidence = %q (%s), want high", confidence, rationale)
	}
}

func TestComputeConfidence_NotDerivedFromSeverity(t *testing.T) {
	// A LOW-confidence finding backed by a full chain correlation should
	// still be able to reach a meaningfully higher confidence than the
	// same finding alone -- confidence tracks corroboration, not severity
	// (severity isn't even an input to computeConfidence at all).
	alone, _ := computeConfidence(confidenceInput{bestFindingConfidence: model.ConfidenceLow})
	corroborated, _ := computeConfidence(confidenceInput{bestFindingConfidence: model.ConfidenceLow, hasChainCorr: true, distinctArtifact: 2, distinctCollect: 2})
	if confidenceRank[corroborated] <= confidenceRank[alone] {
		t.Errorf("corroborated low-confidence finding (%s) should score higher confidence than alone (%s)", corroborated, alone)
	}
}

// ---------------- narrative ----------------

func TestBuildNarrative_DeterministicAndEvidenceOnly(t *testing.T) {
	events := []model.Event{
		{ID: "office", Host: "WKSTN-SIM-001", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "winword.exe", ParentProcessName: "explorer.exe", Timestamp: mustTime("2026-01-15T09:13:00Z")},
		{ID: "ps", Host: "WKSTN-SIM-001", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", ParentProcessName: "winword.exe", Timestamp: mustTime("2026-01-15T09:13:30Z")},
		{ID: "persist", Host: "WKSTN-SIM-001", User: "jdoe", EventType: model.EventRegistryRunKey, ProcessName: "update.exe", FilePath: `C:\Temp\update.exe`, Timestamp: mustTime("2026-01-15T09:15:00Z")},
	}
	n1 := buildNarrative(events)
	n2 := buildNarrative(events)
	if n1 != n2 {
		t.Fatalf("narrative is not deterministic:\nfirst:  %q\nsecond: %q", n1, n2)
	}
	if n1 == "" {
		t.Fatal("expected a non-empty narrative")
	}
	for _, want := range []string{"WKSTN-SIM-001", "winword.exe", "powershell.exe"} {
		if !strings.Contains(n1, want) {
			t.Errorf("narrative %q missing expected evidence-derived term %q", n1, want)
		}
	}
	if strings.Contains(strings.ToLower(n1), "attacker") {
		t.Errorf("narrative must never say 'the attacker': %q", n1)
	}
}

// TestBuildNarrative_ChronologicalEvenWithUnrelatedLaterMergedEvent is a
// regression test for a real bug found during Phase 5 browser
// verification: an event pulled into the group by a correlation OTHER
// than the chain (e.g. a second, unrelated scheduled task merged in via
// an entity correlation) but timestamped BEFORE the chain's own steps
// must still be narrated in its correct chronological position, not
// appended after the chain regardless of its actual time.
func TestBuildNarrative_ChronologicalEvenWithUnrelatedLaterMergedEvent(t *testing.T) {
	events := []model.Event{
		// Earliest event, NOT part of any "chain" -- must be narrated FIRST.
		{ID: "early", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "explorer.exe", Timestamp: mustTime("2026-01-15T08:00:00Z")},
		{ID: "office", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "winword.exe", ParentProcessName: "explorer.exe", Timestamp: mustTime("2026-01-15T09:00:00Z")},
		{ID: "ps", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "powershell.exe", ParentProcessName: "winword.exe", Timestamp: mustTime("2026-01-15T09:01:00Z")},
	}
	n := buildNarrative(events)
	earlyIdx := strings.Index(n, "explorer.exe")
	wordIdx := strings.Index(n, "winword.exe")
	if earlyIdx == -1 || wordIdx == -1 {
		t.Fatalf("narrative missing expected process names: %q", n)
	}
	if earlyIdx > wordIdx {
		t.Errorf("narrative mentions winword.exe (09:00) before explorer.exe (08:00) -- not chronological: %q", n)
	}
}

// TestBuildNarrative_ContinuationNotAcrossInterveningClause is a
// regression test for a second real bug found in the same browser
// verification: a logon event interleaved between a process's own
// process-create clause and its child's process-create clause caused the
// child to be phrased as a continuation of the LOGON sentence ("...a
// successful logon for user jdoe, which spawned winword.exe"), wrongly
// implying the logon spawned the process. "which spawned X" must only
// continue the sentence that was actually ABOUT the parent process.
func TestBuildNarrative_ContinuationNotAcrossInterveningClause(t *testing.T) {
	events := []model.Event{
		{ID: "explorer", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "explorer.exe", Timestamp: mustTime("2026-01-15T08:59:50Z")},
		{ID: "logon", Host: "H1", User: "jdoe", EventType: model.EventLogonSuccess, Timestamp: mustTime("2026-01-15T09:00:00Z")},
		{ID: "office", Host: "H1", User: "jdoe", EventType: model.EventProcessCreate, ProcessName: "winword.exe", ParentProcessName: "explorer.exe", Timestamp: mustTime("2026-01-15T09:14:22Z")},
	}
	n := buildNarrative(events)
	if !strings.Contains(n, "explorer.exe") || !strings.Contains(n, "winword.exe") {
		t.Fatalf("narrative missing expected process names: %q", n)
	}
	// The bug produced "...a successful logon for user jdoe...which
	// spawned winword.exe" -- a continuation clause is only ever emitted
	// when winword.exe is phrased as "which spawned", so simply asserting
	// that phrasing never appears (winword.exe's own process-create
	// clause always starts fresh here, since a logon intervened) directly
	// rules the bug out; "which spawned" is exactly the continuation
	// marker that stitches onto whatever the current sentence is.
	if strings.Contains(n, "which spawned winword.exe") {
		t.Errorf("winword.exe wrongly phrased as a continuation (would attach onto the logon sentence, not explorer.exe's): %q", n)
	}
	var logonSentence string
	for _, s := range strings.Split(n, ". ") {
		if strings.Contains(s, "logon") {
			logonSentence = s
		}
	}
	if strings.Contains(logonSentence, "winword.exe") {
		t.Errorf("the logon sentence wrongly mentions winword.exe: %q", logonSentence)
	}
}

func TestBuildNarrative_EmptyForNoEvents(t *testing.T) {
	if got := buildNarrative(nil); got != "" {
		t.Errorf("buildNarrative(nil) = %q, want empty", got)
	}
}

// ---------------- determinism of Run's output ordering ----------------

func TestRun_DeterministicOutputOrder(t *testing.T) {
	events := []model.Event{
		{ID: "e1", Host: "H1", EventType: model.EventProcessCreate, ProcessName: "a.exe", Timestamp: mustTime("2026-01-15T09:00:00Z")},
		{ID: "e2", Host: "H1", EventType: model.EventProcessCreate, ProcessName: "b.exe", Timestamp: mustTime("2026-01-15T10:00:00Z")},
	}
	findings := []model.Finding{
		{ID: "f1", RuleID: "suspicious-process-chain", Severity: model.SeverityHigh, SupportingEvents: []string{"e1"}, FirstSeen: events[0].Timestamp, LastSeen: events[0].Timestamp},
		{ID: "f2", RuleID: "suspicious-process-chain", Severity: model.SeverityHigh, SupportingEvents: []string{"e2"}, FirstSeen: events[1].Timestamp, LastSeen: events[1].Timestamp},
	}
	r1 := Run("case-1", events, findings, nil)
	r2 := Run("case-1", events, findings, nil)
	if len(r1) != 2 || len(r2) != 2 {
		t.Fatalf("expected 2 investigations each run, got %d and %d", len(r1), len(r2))
	}
	if r1[0].Title != r2[0].Title || r1[1].Title != r2[1].Title {
		t.Errorf("non-deterministic ordering: run1=[%q,%q] run2=[%q,%q]", r1[0].Title, r1[1].Title, r2[0].Title, r2[1].Title)
	}
	if !r1[0].StartTime.Before(r1[1].StartTime) {
		t.Errorf("expected investigations sorted by start time ascending")
	}
	// Phase 6: IDs themselves (not just ordering) must be stable, since
	// analyst workflow state is keyed by investigation ID.
	if r1[0].ID != r2[0].ID || r1[1].ID != r2[1].ID {
		t.Errorf("investigation IDs differ across runs on unchanged input: run1=[%q,%q] run2=[%q,%q]", r1[0].ID, r1[1].ID, r2[0].ID, r2[1].ID)
	}
}
