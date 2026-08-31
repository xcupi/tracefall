package prefetchraw_test

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"tracefall/internal/parsers/browserhistory"
	"tracefall/internal/parsers/prefetchraw"
	"tracefall/internal/parsers/pshistory"
	"tracefall/internal/prefetch/prefetchgen"
)

// Phase 10A performance. The goal is not a speed target -- it is to
// confirm the new parsers are LINEAR and BOUNDED, so a triage collection
// holding a thousand Prefetch files or a large browser database stays
// usable. Run with:
//
//	go test ./internal/parsers/prefetchraw -bench . -benchmem -run '^$'

func pfBytes(i int) []byte {
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	return prefetchgen.Build(prefetchgen.File{
		Version:        30,
		ExecutableName: fmt.Sprintf("APP%04d.EXE", i),
		RunCount:       uint32(i%50 + 1),
		LastRunTimes:   []time.Time{base.Add(time.Duration(i) * time.Minute)},
		Filenames: []string{
			fmt.Sprintf(`\VOLUME{01d7}\PROGRAM FILES\APP%04d\APP%04d.EXE`, i, i),
			`\VOLUME{01d7}\WINDOWS\SYSTEM32\NTDLL.DLL`,
			`\VOLUME{01d7}\WINDOWS\SYSTEM32\KERNEL32.DLL`,
		},
		VolumeDevicePath: `\DEVICE\HARDDISKVOLUME2`,
	})
}

func benchmarkPrefetch(b *testing.B, n int) {
	dir := b.TempDir()
	paths := make([]string, n)
	var total int64
	for i := 0; i < n; i++ {
		data := pfBytes(i)
		p := filepath.Join(dir, fmt.Sprintf("APP%04d.EXE-A1B2C3D4.pf", i))
		if err := os.WriteFile(p, data, 0o644); err != nil {
			b.Fatal(err)
		}
		paths[i] = p
		total += int64(len(data))
	}
	b.SetBytes(total)
	parser := prefetchraw.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		events := 0
		for _, p := range paths {
			res, err := parser.Parse(p)
			if err != nil {
				b.Fatal(err)
			}
			events += len(res.Events)
		}
		if events != n {
			b.Fatalf("parsed %d events, want %d", events, n)
		}
	}
}

func BenchmarkPrefetch_1(b *testing.B)    { benchmarkPrefetch(b, 1) }
func BenchmarkPrefetch_100(b *testing.B)  { benchmarkPrefetch(b, 100) }
func BenchmarkPrefetch_1000(b *testing.B) { benchmarkPrefetch(b, 1000) }

// A large PowerShell history: 50,000 commands is far beyond anything a
// real console accumulates, which is the point.
func BenchmarkPowerShellHistory_50k(b *testing.B) {
	var buf []byte
	for i := 0; i < 50_000; i++ {
		buf = append(buf, []byte(fmt.Sprintf("Get-ChildItem -Path C:\\Users\\jdoe\\work\\dir%05d -Recurse\n", i))...)
	}
	path := filepath.Join(b.TempDir(), "ConsoleHost_history.txt")
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(buf)))
	parser := pshistory.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := parser.Parse(path)
		if err != nil {
			b.Fatal(err)
		}
		if len(res.Events) != 50_000 {
			b.Fatalf("events = %d", len(res.Events))
		}
	}
}

// A representative browser history: 50,000 visits is a heavy but
// realistic year of browsing.
func BenchmarkBrowserHistory_50kVisits(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "History")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		b.Fatal(err)
	}
	db.Exec(`CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)`)
	db.Exec(`CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER)`)
	tx, _ := db.Begin()
	base := (time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC).Unix() + 11644473600) * 1_000_000
	for i := 0; i < 50_000; i++ {
		tx.Exec(`INSERT INTO urls VALUES(?,?,?,?,?)`, i+1,
			fmt.Sprintf("https://site%05d.example.test/page", i), fmt.Sprintf("Page %d", i), 1, base+int64(i)*1_000_000)
		tx.Exec(`INSERT INTO visits VALUES(?,?,?,?)`, i+1, i+1, base+int64(i)*1_000_000, 805306368)
	}
	tx.Commit()
	db.Close()

	if info, err := os.Stat(path); err == nil {
		b.SetBytes(info.Size())
	}
	parser := browserhistory.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := parser.Parse(path)
		if err != nil {
			b.Fatal(err)
		}
		if len(res.Events) != 50_000 {
			b.Fatalf("events = %d", len(res.Events))
		}
	}
}
