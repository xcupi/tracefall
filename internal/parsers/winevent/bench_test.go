package winevent_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/evtx/evtxgen"
	nativeevtx "tracefall/internal/parsers/evtx"
	"tracefall/internal/parsers/registry"
	"tracefall/internal/regf/regfgen"
)

// Phase 20 benchmarks. The goal is not a speed target -- it is to
// confirm the parsers stay LINEAR and BOUNDED as evidence grows, which
// is the property that matters when an investigator points Tracefall at
// a 100 MB Security.evtx or a real SOFTWARE hive. Run with:
//
//	go test ./internal/parsers/winevent -bench . -benchmem -run '^$'
//
// -benchmem is the interesting part: allocated bytes per operation
// should scale with the number of RECORDS parsed, not with file size,
// because the readers hold one 64 KiB chunk (or one cell) at a time.

func benchLog(b *testing.B, records int) string {
	b.Helper()
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	events := make([]evtxgen.Event, 0, records)
	for i := 0; i < records; i++ {
		events = append(events, evtxgen.Event{
			RecordID: uint64(i + 1), Timestamp: base.Add(time.Duration(i) * time.Second),
			Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security",
			Computer: "WKSTN-042", EventID: 4624, ProcessID: 668, ThreadID: 1024,
			UserID: "S-1-5-18",
			Data: map[string]string{
				"TargetUserName": fmt.Sprintf("user%06d", i),
				"LogonType":      "3",
				"IpAddress":      "10.4.2.15",
			},
		})
	}
	path := filepath.Join(b.TempDir(), "bench.evtx")
	if err := os.WriteFile(path, evtxgen.Build(events), 0o644); err != nil {
		b.Fatal(err)
	}
	return path
}

func benchmarkEVTX(b *testing.B, records int) {
	path := benchLog(b, records)
	if info, err := os.Stat(path); err == nil {
		b.SetBytes(info.Size())
	}
	p := nativeevtx.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := p.Parse(path)
		if err != nil {
			b.Fatal(err)
		}
		if len(res.Events) != records {
			b.Fatalf("parsed %d events, want %d", len(res.Events), records)
		}
	}
}

func BenchmarkEVTX_1k(b *testing.B)   { benchmarkEVTX(b, 1_000) }
func BenchmarkEVTX_10k(b *testing.B)  { benchmarkEVTX(b, 10_000) }
func BenchmarkEVTX_100k(b *testing.B) { benchmarkEVTX(b, 100_000) }

// benchHive builds a hive with `keys` ordinary keys plus a handful of
// persistence locations, so traversal cost is measured against a
// realistic ratio of noise to signal.
func benchHive(b *testing.B, keys int) string {
	b.Helper()
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

	// Spread the keys across a tree rather than one enormous subkey list,
	// which is how a real hive is shaped.
	const perLevel = 100
	var branches []*regfgen.Key
	for made := 0; made < keys; {
		var leaves []*regfgen.Key
		for i := 0; i < perLevel && made < keys; i++ {
			leaves = append(leaves, regfgen.NewKey(fmt.Sprintf("Key%06d", made)).
				WithLastWrite(base).
				WithValues(regfgen.StringValue("Setting", "value")))
			made++
		}
		branches = append(branches, regfgen.NewKey(fmt.Sprintf("Branch%04d", len(branches)), leaves...).WithLastWrite(base))
	}

	run := regfgen.NewKey("Run").WithLastWrite(base).WithValues(
		regfgen.StringValue("AcmeTray", `C:\Program Files\Acme\tray.exe`),
	)
	cv := regfgen.NewKey("CurrentVersion", run)
	win := regfgen.NewKey("Windows", cv)
	ms := regfgen.NewKey("Microsoft", win)
	root := regfgen.NewKey("CMI-CreateHive{BENCH}", append(branches, ms)...).WithLastWrite(base)

	path := filepath.Join(b.TempDir(), "SOFTWARE")
	if err := os.WriteFile(path, regfgen.Build("SOFTWARE", root), 0o644); err != nil {
		b.Fatal(err)
	}
	return path
}

func benchmarkRegistry(b *testing.B, keys int) {
	path := benchHive(b, keys)
	if info, err := os.Stat(path); err == nil {
		b.SetBytes(info.Size())
	}
	p := registry.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.Parse(path); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRegistry_10kKeys(b *testing.B)  { benchmarkRegistry(b, 10_000) }
func BenchmarkRegistry_100kKeys(b *testing.B) { benchmarkRegistry(b, 100_000) }
