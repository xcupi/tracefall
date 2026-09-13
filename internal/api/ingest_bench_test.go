package api

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"testing"
	"time"

	"tracefall/internal/ingest"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

// Ingestion performance harness.
//
// Gated on TRACEFALL_AD1 because the evidence is not in the repository.
// Run:
//
//	TRACEFALL_AD1=/abs/path/upload.ad1 go test ./internal/api -run TestIngestBaseline -v -timeout 60m
//
// Everything here MEASURES. Nothing in this file changes behaviour.

func benchAD1(t *testing.T) string {
	t.Helper()
	path := os.Getenv("TRACEFALL_AD1")
	if path == "" {
		t.Skip("set TRACEFALL_AD1 to a real AD1 image to run the ingestion benchmarks")
	}
	return path
}

type ingestRun struct {
	Discovered   int
	Selected     int
	Imported     int
	Events       int
	Failures     int
	Skipped      int
	Wall         time.Duration
	PeakHeapMB   float64
	TotalAllocMB float64
	Mallocs      uint64
	NumGC        uint32
	GCPauseTotal time.Duration
	GCCPUFrac    float64
}

// runIngest performs one complete discover+import of the AD1 and reports
// what it cost. selectLimit bounds how many recommended files are
// imported; 0 means all of them.
func runIngest(t *testing.T, ad1Path string, selectLimit int) ingestRun {
	t.Helper()
	svc := newTestService(t)
	c, err := svc.CreateCase(fmt.Sprintf("bench %s %d", t.Name(), time.Now().UnixNano()), "")
	if err != nil {
		t.Fatal(err)
	}

	disc, err := svc.DiscoverEvidenceFromPath(c.ID, ad1Path)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	collectionID := disc.Collection.ID

	// The selection the UI's "recommended" default produces: every file
	// a parser claims.
	all, err := svc.store.ListSourceFilesByCollection(collectionID)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(all))
	for _, f := range all {
		if !f.Supported {
			continue
		}
		ids = append(ids, f.ID)
		if selectLimit > 0 && len(ids) >= selectLimit {
			break
		}
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	gcBefore := before.NumGC
	pauseBefore := before.PauseTotalNs

	start := time.Now()
	res, err := svc.ImportEvidence(c.ID, collectionID, ids)
	wall := time.Since(start)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	runtime.ReadMemStats(&after)

	events := 0
	for _, f := range res.Imported {
		events += f.EventCount
	}

	return ingestRun{
		Discovered:   len(all),
		Selected:     len(ids),
		Imported:     len(res.Imported),
		Events:       events,
		Failures:     len(res.ParseFailures),
		Skipped:      len(res.Skipped),
		Wall:         wall,
		PeakHeapMB:   float64(after.HeapAlloc) / 1e6,
		TotalAllocMB: float64(after.TotalAlloc-before.TotalAlloc) / 1e6,
		Mallocs:      after.Mallocs - before.Mallocs,
		NumGC:        after.NumGC - gcBefore,
		GCPauseTotal: time.Duration(after.PauseTotalNs - pauseBefore),
		GCCPUFrac:    after.GCCPUFraction,
	}
}

func (r ingestRun) report(t *testing.T, label string) {
	t.Helper()
	fps := float64(r.Imported) / r.Wall.Seconds()
	eps := float64(r.Events) / r.Wall.Seconds()
	t.Logf("%-10s wall=%-12v files=%-5d events=%-7d %6.1f files/s %8.0f events/s  "+
		"alloc=%7.0fMB mallocs=%9d gc=%3d pause=%-10v gcCPU=%.2f%% heap=%.0fMB fail=%d skip=%d",
		label, r.Wall.Round(time.Millisecond), r.Imported, r.Events, fps, eps,
		r.TotalAllocMB, r.Mallocs, r.NumGC, r.GCPauseTotal.Round(time.Microsecond),
		r.GCCPUFrac*100, r.PeakHeapMB, r.Failures, r.Skipped)
}

// TestIngestBaseline is Phase 1: the same workload three times, reported
// individually and by median.
func TestIngestBaseline(t *testing.T) {
	ad1 := benchAD1(t)
	limit := 0
	if v := os.Getenv("TRACEFALL_BENCH_LIMIT"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}

	info, err := os.Stat(ad1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("AD1: %s (%.0f MB)", ad1, float64(info.Size())/1e6)

	runs := make([]ingestRun, 0, 3)
	for i := 0; i < 3; i++ {
		r := runIngest(t, ad1, limit)
		r.report(t, fmt.Sprintf("run %d", i+1))
		runs = append(runs, r)
	}

	sort.Slice(runs, func(i, j int) bool { return runs[i].Wall < runs[j].Wall })
	med := runs[len(runs)/2]
	med.report(t, "MEDIAN")
	t.Logf("discovered=%d selected=%d", med.Discovered, med.Selected)
}

// TestIngestParserBreakdown is Phase 4: where parse time actually goes,
// by parser and by file. It parses only -- no database, no extraction --
// so the numbers are the parsers' own cost.
func TestIngestParserBreakdown(t *testing.T) {
	ad1 := benchAD1(t)
	svc := newTestService(t)
	c, err := svc.CreateCase("parser breakdown "+fmt.Sprint(time.Now().UnixNano()), "")
	if err != nil {
		t.Fatal(err)
	}
	disc, err := svc.DiscoverEvidenceFromPath(c.ID, ad1)
	if err != nil {
		t.Fatal(err)
	}
	files, err := svc.store.ListSourceFilesByCollection(disc.Collection.ID)
	if err != nil {
		t.Fatal(err)
	}

	type fileStat struct {
		path, parser string
		size         int64
		extract      time.Duration
		parse        time.Duration
		events       int
		allocBytes   uint64
	}
	var stats []fileStat
	col, _ := svc.store.GetCollection(disc.Collection.ID)

	// The indexed extractor, exactly as the import uses it -- otherwise
	// this harness would pay the per-file tree walk it exists to measure
	// the absence of.
	var extractor *ad1Extractor
	if col.SourceType == model.SourceTypeAD1 {
		var err error
		extractor, err = svc.newAD1Extractor(c.ID, disc.Collection.ID)
		if err != nil {
			t.Fatal(err)
		}
		defer extractor.Close()
	}

	for _, sf := range files {
		if !sf.Supported {
			continue
		}
		p := findParserFor(ingestRegistry(), sf.Parser)
		if p == nil {
			continue
		}
		var m0, m1 runtime.MemStats

		t0 := time.Now()
		if col.SourceType == model.SourceTypeAD1 {
			if err := extractor.extract(sf); err != nil {
				continue
			}
		}
		extract := time.Since(t0)

		runtime.ReadMemStats(&m0)
		t1 := time.Now()
		parsed, err := parseForBench(c.ID, disc.Collection.ID, sf, col.EvidenceDirectory, p)
		parse := time.Since(t1)
		runtime.ReadMemStats(&m1)
		if err != nil {
			continue
		}
		stats = append(stats, fileStat{
			path: sf.Path, parser: sf.Parser, size: sf.SizeBytes,
			extract: extract, parse: parse, events: len(parsed.Events),
			allocBytes: m1.TotalAlloc - m0.TotalAlloc,
		})
	}

	// Per-parser rollup.
	type agg struct {
		files, events  int
		parse, extract time.Duration
		alloc          uint64
	}
	byParser := map[string]*agg{}
	for _, s := range stats {
		a := byParser[s.parser]
		if a == nil {
			a = &agg{}
			byParser[s.parser] = a
		}
		a.files++
		a.events += s.events
		a.parse += s.parse
		a.extract += s.extract
		a.alloc += s.allocBytes
	}
	names := make([]string, 0, len(byParser))
	for n := range byParser {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return byParser[names[i]].parse > byParser[names[j]].parse })

	t.Log("PARSER                 FILES   TOTAL PARSE    AVG/FILE      EVENTS   EVENTS/S     ALLOC   EXTRACT")
	for _, n := range names {
		a := byParser[n]
		t.Logf("%-22s %5d %13v %11v %11d %10.0f %8.0fMB %9v",
			n, a.files, a.parse.Round(time.Millisecond), (a.parse / time.Duration(a.files)).Round(time.Microsecond),
			a.events, float64(a.events)/a.parse.Seconds(), float64(a.alloc)/1e6,
			a.extract.Round(time.Millisecond))
	}

	sort.Slice(stats, func(i, j int) bool { return stats[i].parse > stats[j].parse })
	t.Log("")
	t.Log("SLOWEST FILES:")
	for i, s := range stats {
		if i >= 20 {
			break
		}
		t.Logf("%2d. %-11v parse  %-9v extract  %6d events  %7.1fMB alloc  %8d bytes  %-18s %s",
			i+1, s.parse.Round(time.Microsecond), s.extract.Round(time.Microsecond), s.events,
			float64(s.allocBytes)/1e6, s.size, s.parser, truncPath(s.path))
	}

	sort.Slice(stats, func(i, j int) bool { return stats[i].events > stats[j].events })
	t.Log("")
	t.Log("HIGHEST EVENT COUNTS:")
	for i, s := range stats {
		if i >= 10 {
			break
		}
		t.Logf("%2d. %6d events  %-11v parse  %8d bytes  %-18s %s",
			i+1, s.events, s.parse.Round(time.Microsecond), s.size, s.parser, truncPath(s.path))
	}
}

func truncPath(p string) string {
	if i := strings.Index(p, "[root]/"); i >= 0 {
		p = p[i+7:]
	}
	if len(p) > 70 {
		return "..." + p[len(p)-67:]
	}
	return p
}

func ingestRegistry() []parsers.ArtifactParser { return ingest.Registry() }

func parseForBench(caseID, collectionID string, sf model.SourceFile, root string, p parsers.ArtifactParser) (parsers.ParseResult, error) {
	pf, err := ingest.ParseFile(caseID, collectionID, sf.ID, root, sf.Path, p)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	return parsers.ParseResult{Events: pf.Events, Raw: pf.Raw}, nil
}

// TestIngestProfile is Phase 2: one import with CPU, heap, mutex and
// block profiles written out.
func TestIngestProfile(t *testing.T) {
	ad1 := benchAD1(t)
	limit := 0
	if v := os.Getenv("TRACEFALL_BENCH_LIMIT"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	outDir := os.Getenv("TRACEFALL_PROF_DIR")
	if outDir == "" {
		outDir = t.TempDir()
	}

	// Mutex and block profiling are off by default and must be armed
	// before the work runs, or they record nothing.
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
	defer runtime.SetMutexProfileFraction(0)
	defer runtime.SetBlockProfileRate(0)

	cpuFile, err := os.Create(outDir + "/cpu.pprof")
	if err != nil {
		t.Fatal(err)
	}
	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		t.Fatal(err)
	}
	r := runIngest(t, ad1, limit)
	pprof.StopCPUProfile()
	cpuFile.Close()

	for _, name := range []string{"heap", "allocs", "mutex", "block", "goroutine"} {
		f, err := os.Create(outDir + "/" + name + ".pprof")
		if err != nil {
			t.Fatal(err)
		}
		if err := pprof.Lookup(name).WriteTo(f, 0); err != nil {
			t.Logf("writing %s profile: %v", name, err)
		}
		f.Close()
	}

	r.report(t, "PROFILED")
	t.Logf("profiles written to %s", outDir)
}
