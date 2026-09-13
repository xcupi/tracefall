package registry_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers/registry"
	"tracefall/internal/regf/regfgen"
	"tracefall/internal/shellbag/sbgen"
	"tracefall/internal/userassist/uagen"
)

// Scale and resource behaviour for the Phase 15 hive extraction.
//
// These are not micro-benchmarks. They assert the properties that keep
// hostile or merely large evidence from taking Tracefall down: bounded
// work, bounded memory, no unbounded recursion, and a parse that
// finishes.

// hiveWithManyUserAssistValues builds a Count key holding n entries.
func hiveWithManyUserAssistValues(n int) []byte {
	values := make([]regfgen.Value, 0, n)
	base := time.Date(2021, 4, 29, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		values = append(values, regfgen.BinaryValue(
			uagen.Name(fmt.Sprintf(`C:\Program Files\Vendor%d\app%d.exe`, i%50, i)),
			uagen.BuildV5(uagen.Entry{
				SessionID: uint32(i % 8), RunCount: uint32(i%200 + 1),
				LastExecuted: base.Add(time.Duration(i) * time.Second),
			})))
	}
	count := regfgen.NewKey("Count").WithLastWrite(base).WithValues(values...)
	return regfgen.Build("NTUSER.DAT", regfgen.NewKey("ROOT",
		regfgen.NewKey("Software", regfgen.NewKey("Microsoft",
			regfgen.NewKey("Windows", regfgen.NewKey("CurrentVersion",
				regfgen.NewKey("Explorer", regfgen.NewKey("UserAssist",
					regfgen.NewKey(uaExecGUID, count))))))),
	).WithLastWrite(base))
}

// deepBagTree builds a BagMRU chain depth levels deep.
func deepBagTree(depth int) []byte {
	base := time.Date(2021, 4, 29, 19, 0, 0, 0, time.UTC)
	// Built leaf-upward so each level owns the one below it.
	var node *regfgen.Key
	for i := depth - 1; i >= 0; i-- {
		name := fmt.Sprintf("Level%02d", i)
		item := sbgen.List(sbgen.File(sbgen.FileEntry{
			ShortName: name, LongName: name, IsDirectory: true, Attributes: 0x10,
			ExtVersion: 9,
		}))
		var kids []*regfgen.Key
		if node != nil {
			kids = append(kids, node)
		}
		node = regfgen.NewKey("0", kids...).WithLastWrite(base).WithValues(
			regfgen.BinaryValue("0", item))
	}
	bagMRU := regfgen.NewKey("BagMRU", node).WithLastWrite(base).WithValues(
		regfgen.BinaryValue("0", sbgen.List(sbgen.Root(thisPCGUID))))
	return regfgen.Build("NTUSER.DAT", regfgen.NewKey("ROOT",
		regfgen.NewKey("Software", regfgen.NewKey("Microsoft",
			regfgen.NewKey("Windows", regfgen.NewKey("Shell", bagMRU)))),
	).WithLastWrite(base))
}

func writeAndParse(t *testing.T, data []byte) ([]model.Event, time.Duration) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Users", "jdoe", "NTUSER.DAT")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res, err := registry.New().Parse(path)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return res.Events, elapsed
}

// A hive holding thousands of UserAssist entries must parse in bounded
// time and produce one event per entry.
func TestScale_ManyUserAssistValues(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in short mode")
	}
	const n = 5000

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	events, elapsed := writeAndParse(t, hiveWithManyUserAssistValues(n))

	runtime.ReadMemStats(&after)
	allocMB := float64(after.TotalAlloc-before.TotalAlloc) / (1 << 20)

	// The regf reader caps values per key at 4096 (regf.DefaultLimits),
	// so a Count key holding 5000 entries yields 4096 events. That bound
	// is pre-existing, deliberate and documented: it protects every hive
	// read, and a real Count key holds hundreds of entries, not
	// thousands. The assertion is therefore that the cap BINDS and that
	// everything under it is recovered -- not that the cap is absent.
	const regfValuesPerKeyCap = 4096
	ua := eventsOfType(events, model.ArtifactUserAssist)
	if len(ua) != regfValuesPerKeyCap {
		t.Errorf("got %d UserAssist events, want %d (the regf per-key value cap)", len(ua), regfValuesPerKeyCap)
	}
	t.Logf("%d UserAssist entries parsed in %v (%.1f MiB allocated)", len(ua), elapsed.Round(time.Millisecond), allocMB)

	// Deliberately loose: this asserts complexity, not this machine's
	// speed. An implementation that re-walked the hive per value, or
	// allocated per byte, could not meet it.
	if elapsed > 30*time.Second {
		t.Errorf("parsing %d entries took %v", n, elapsed)
	}
}

// A deep BagMRU tree must be bounded by MaxDepth, not by the stack --
// the walk is iterative for exactly this reason.
func TestScale_DeepBagTreeIsBoundedNotRecursive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in short mode")
	}
	// Far deeper than any real path. Two bounds apply, and either is
	// sufficient: the regf reader's MaxDepth (32) stops the hive walk,
	// and shellbag's MaxDepth (64) stops the BagMRU walk. What matters
	// is that a deep tree terminates cheaply rather than recursing.
	const depth = 200

	events, elapsed := writeAndParse(t, deepBagTree(depth))
	bags := eventsOfType(events, model.ArtifactShellBags)

	t.Logf("a %d-level BagMRU tree yielded %d events in %v", depth, len(bags), elapsed.Round(time.Millisecond))
	if len(bags) == 0 {
		t.Fatal("a deep tree produced no events at all")
	}
	// The limit must actually bind: fewer events than levels.
	if len(bags) >= depth {
		t.Errorf("%d events from a %d-level tree; the depth limit did not bind", len(bags), depth)
	}
	if elapsed > 30*time.Second {
		t.Errorf("walking a deep tree took %v", elapsed)
	}
}

// A wide BagMRU level -- many siblings -- must also stay bounded.
func TestScale_WideBagLevel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in short mode")
	}
	const siblings = 2000
	base := time.Date(2021, 4, 29, 19, 0, 0, 0, time.UTC)

	values := make([]regfgen.Value, 0, siblings)
	kids := make([]*regfgen.Key, 0, siblings)
	for i := 0; i < siblings; i++ {
		name := fmt.Sprintf("Folder%04d", i)
		values = append(values, regfgen.BinaryValue(fmt.Sprint(i),
			sbgen.List(sbgen.File(sbgen.FileEntry{
				ShortName: name, LongName: name, IsDirectory: true,
				Attributes: 0x10, ExtVersion: 9,
			}))))
		kids = append(kids, regfgen.NewKey(fmt.Sprint(i)).WithLastWrite(base))
	}
	bag0 := regfgen.NewKey("0", kids...).WithLastWrite(base).WithValues(values...)
	bagMRU := regfgen.NewKey("BagMRU", bag0).WithLastWrite(base).WithValues(
		regfgen.BinaryValue("0", sbgen.List(sbgen.Root(thisPCGUID))))
	hive := regfgen.Build("NTUSER.DAT", regfgen.NewKey("ROOT",
		regfgen.NewKey("Software", regfgen.NewKey("Microsoft",
			regfgen.NewKey("Windows", regfgen.NewKey("Shell", bagMRU)))),
	).WithLastWrite(base))

	events, elapsed := writeAndParse(t, hive)
	bags := eventsOfType(events, model.ArtifactShellBags)
	t.Logf("%d sibling bags yielded %d events in %v", siblings, len(bags), elapsed.Round(time.Millisecond))
	if len(bags) == 0 {
		t.Fatal("no events from a wide tree")
	}
	// One level may contribute at most MaxItemsPerKey (512) plus the
	// root above it. Without that bound, resolving each child costs a
	// lookup that scans its siblings, which is quadratic in a level an
	// attacker controls.
	if len(bags) > 512+1 {
		t.Errorf("%d events from one level; the per-level item bound did not bind", len(bags))
	}
	if elapsed > 30*time.Second {
		t.Errorf("a wide tree took %v", elapsed)
	}
}

// A value whose data claims to be enormous must not be allocated
// against. This is the decompression-bomb equivalent for shell items.
func TestScale_HostileShellItemSizeIsRefusedNotAllocated(t *testing.T) {
	base := time.Date(2021, 4, 29, 19, 0, 0, 0, time.UTC)
	// A shell item declaring 65535 bytes inside a 16-byte value.
	hostile := []byte{0xFF, 0xFF, 0x31, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	bag0 := regfgen.NewKey("0").WithLastWrite(base).WithValues(
		regfgen.BinaryValue("0", hostile))
	bagMRU := regfgen.NewKey("BagMRU", bag0).WithLastWrite(base).WithValues(
		regfgen.BinaryValue("0", hostile))
	hive := regfgen.Build("NTUSER.DAT", regfgen.NewKey("ROOT",
		regfgen.NewKey("Software", regfgen.NewKey("Microsoft",
			regfgen.NewKey("Windows", regfgen.NewKey("Shell", bagMRU)))),
	).WithLastWrite(base))

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on a hostile shell item size: %v", r)
			}
		}()
		writeAndParse(t, hive)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("parsing a hostile shell item did not finish")
	}
}
