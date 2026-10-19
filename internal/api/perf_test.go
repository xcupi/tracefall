package api

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/casefiles"
	"tracefall/internal/correlate"
	"tracefall/internal/detect"
	"tracefall/internal/investigate"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

// seedBenchCase creates a real SQLite-backed Service with n synthetic
// events (see syntheticEvents) already saved, findings/correlations
// already computed and saved via ReplaceAnalysis (so
// CaseSummary/Investigations benchmarks measure the read path a real
// analyzed case would hit, not an empty one), and returns it plus the
// case ID. Event insertion bypasses the CSV parse/discover/import
// pipeline entirely -- that pipeline's own cost is covered by the
// parser-level benchmarks in internal/parsers/*, this is specifically
// about detect/correlate/investigate and the dashboard read APIs.
func seedBenchCase(b *testing.B, n int) (*Service, string) {
	b.Helper()
	db, err := store.Open(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatalf("opening bench store: %v", err)
	}
	b.Cleanup(func() { db.Close() })
	svc := newPermissiveService(db, casefiles.NewStore(b.TempDir()))

	now := time.Now().UTC()
	caseID := "bench-case"
	if err := db.CreateCase(model.Case{ID: caseID, Name: fmt.Sprintf("bench case n=%d", n), Status: model.CaseStatusIngested, CreatedAt: now, UpdatedAt: now}); err != nil {
		b.Fatalf("seeding case: %v", err)
	}
	collectionID := "bench-collection"
	if err := db.SaveCollection(model.Collection{ID: collectionID, CaseID: caseID, CreatedAt: now, SourceType: model.SourceTypeLocalPath, IngestionStatus: model.CollectionStatusIngested}); err != nil {
		b.Fatalf("seeding collection: %v", err)
	}
	sourceFileID := "bench-sf"
	if err := db.SaveSourceFiles([]model.SourceFile{{
		ID: sourceFileID, CaseID: caseID, CollectionID: collectionID, ArtifactType: model.ArtifactWindowsEventLog,
		Parser: "bench@1", Supported: true, ImportStatus: model.SourceFileImported, DiscoveredAt: now,
	}}); err != nil {
		b.Fatalf("seeding source file: %v", err)
	}

	events := syntheticEvents(n)
	for i := range events {
		events[i].CaseID = caseID
		events[i].CollectionID = collectionID
		events[i].SourceFileID = sourceFileID
		events[i].Parser = "bench@1"
		events[i].DedupHash = events[i].ComputeDedupHash()
	}
	if err := db.SaveEvents(events); err != nil {
		b.Fatalf("seeding events: %v", err)
	}

	findings := detect.Run(caseID, events)
	correlations := correlate.Run(caseID, events)
	if err := db.ReplaceAnalysis(caseID, findings, correlations); err != nil {
		b.Fatalf("seeding analysis: %v", err)
	}

	return svc, caseID
}

// syntheticEvents generates n events across a small, realistic mix of
// hosts/users/event types -- NOT n independent unrelated events (which
// would understate real-world cost for internal/correlate's grouping
// logic), but repeating "sessions" of a logon followed by a short
// process-creation chain, occasionally with a persistence step and a
// network connection, spread across a fixed number of hosts. This is
// Phase 6's realistic-case-size benchmark input (section 18/19): 100,
// 1,000, 10,000, 100,000 events.
func syntheticEvents(n int) []model.Event {
	const hostCount = 20
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	events := make([]model.Event, 0, n)
	sessionID := 0
	for len(events) < n {
		host := fmt.Sprintf("WKSTN-SIM-%03d", sessionID%hostCount)
		user := fmt.Sprintf("user%02d", sessionID%15)
		t := base.Add(time.Duration(sessionID) * 90 * time.Second)
		sessionID++

		events = append(events,
			model.Event{ID: fmt.Sprintf("logon-%d", sessionID), Host: host, User: user, EventType: model.EventLogonSuccess, ArtifactType: model.ArtifactWindowsEventLog, Timestamp: t},
			model.Event{ID: fmt.Sprintf("office-%d", sessionID), Host: host, User: user, EventType: model.EventProcessCreate, ProcessName: "winword.exe", ParentProcessName: "explorer.exe", PID: int64(sessionID*10 + 1), ArtifactType: model.ArtifactWindowsEventLog, Timestamp: t.Add(5 * time.Second)},
			model.Event{ID: fmt.Sprintf("ps-%d", sessionID), Host: host, User: user, EventType: model.EventProcessCreate, ProcessName: "powershell.exe", ParentProcessName: "winword.exe", PID: int64(sessionID*10 + 2), PPID: int64(sessionID*10 + 1), CommandLine: "powershell.exe -nop -w hidden -enc AAAA", ArtifactType: model.ArtifactWindowsEventLog, Timestamp: t.Add(10 * time.Second)},
		)
		// Every 5th session also gets a payload + persistence + network
		// step, so correlate's activity-chain builder has real multi-step
		// narratives to find, not just isolated pivots.
		if sessionID%5 == 0 {
			events = append(events,
				model.Event{ID: fmt.Sprintf("payload-%d", sessionID), Host: host, User: user, EventType: model.EventProcessCreate, ProcessName: "update.exe", ParentProcessName: "powershell.exe", PID: int64(sessionID*10 + 3), PPID: int64(sessionID*10 + 2), ArtifactType: model.ArtifactWindowsEventLog, Timestamp: t.Add(15 * time.Second)},
				model.Event{ID: fmt.Sprintf("persist-%d", sessionID), Host: host, User: user, EventType: model.EventRegistryRunKey, ProcessName: "update.exe", FilePath: `C:\Temp\update.exe`, ArtifactType: model.ArtifactRegistryRunKey, Timestamp: t.Add(20 * time.Second)},
				model.Event{ID: fmt.Sprintf("net-%d", sessionID), Host: host, User: user, EventType: model.EventNetworkConnection, ProcessName: "update.exe", NetworkDest: "203.0.113.77", ArtifactType: model.ArtifactWindowsEventLog, Timestamp: t.Add(25 * time.Second)},
			)
		}
	}
	return events[:n]
}

func BenchmarkPipeline(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 100_000} {
		events := syntheticEvents(n)

		b.Run(fmt.Sprintf("detect_n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = detect.Run("bench-case", events)
			}
		})

		findings := detect.Run("bench-case", events)

		b.Run(fmt.Sprintf("correlate_n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = correlate.Run("bench-case", events)
			}
		})

		correlations := correlate.Run("bench-case", events)

		b.Run(fmt.Sprintf("investigate_n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = investigate.Run("bench-case", events, findings, correlations)
			}
		})

		b.Run(fmt.Sprintf("full_analyze_pipeline_n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				f := detect.Run("bench-case", events)
				c := correlate.Run("bench-case", events)
				_ = investigate.Run("bench-case", events, f, c)
			}
		})
	}
}

// BenchmarkCaseSummary measures GET /cases/{id}'s dashboard-response
// cost (CaseSummary + the investigate.Run it now includes) against a
// REAL SQLite-backed case seeded with n events, findings, and
// correlations -- this is the number that actually matters for "does
// the dashboard feel slow," as opposed to the pure in-memory algorithm
// benchmarks above.
func BenchmarkCaseSummary(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			svc, caseID := seedBenchCase(b, n)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := svc.CaseSummary(caseID); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkInvestigationsList measures GET /cases/{id}/investigations
// directly (the read-time investigate.Run call plus its store reads).
func BenchmarkInvestigationsList(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			svc, caseID := seedBenchCase(b, n)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := svc.Investigations(caseID); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
