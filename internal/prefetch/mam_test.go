package prefetch_test

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"tracefall/internal/prefetch"
	"tracefall/internal/prefetch/prefetchgen"
)

// MAM-compressed Prefetch support.
//
// The governing requirement is that compression is a CONTAINER, not a
// different artifact: the same Prefetch content must produce the same
// parsed result whether or not it arrived compressed.

func buildSCCA(t *testing.T) []byte {
	t.Helper()
	run := time.Date(2026, 4, 2, 11, 5, 0, 0, time.UTC)
	return prefetchgen.Build(prefetchgen.File{
		Version:        30,
		ExecutableName: "NOTEPAD.EXE",
		PrefetchHash:   0x1A2B3C4D,
		RunCount:       9,
		LastRunTimes:   []time.Time{run, run.Add(-3 * time.Hour), run.Add(-30 * time.Hour)},
		Filenames: []string{
			`\VOLUME{01d7}\WINDOWS\SYSTEM32\NOTEPAD.EXE`,
			`\VOLUME{01d7}\WINDOWS\SYSTEM32\NTDLL.DLL`,
			`\VOLUME{01d7}\WINDOWS\SYSTEM32\KERNEL32.DLL`,
		},
		VolumeDevicePath: `\DEVICE\HARDDISKVOLUME2`,
		VolumeSerial:     0xDEADBEEF,
		VolumeCreated:    run.Add(-900 * time.Hour),
	})
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "TEST.EXE-11111111.pf")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// THE equivalence test: identical content, two containers, one result.
func TestMAM_CompressedAndUncompressedAreEquivalent(t *testing.T) {
	plain := buildSCCA(t)
	compressed := prefetchgen.CompressMAM(plain)

	fromPlain, err := prefetch.ParseBytes(plain, prefetch.Limits{})
	if err != nil {
		t.Fatalf("uncompressed: %v", err)
	}
	fromMAM, err := prefetch.ParseBytes(compressed, prefetch.Limits{})
	if err != nil {
		t.Fatalf("compressed: %v", err)
	}

	// Everything forensic must match exactly.
	if fromPlain.Version != fromMAM.Version {
		t.Errorf("version: %d vs %d", fromPlain.Version, fromMAM.Version)
	}
	if fromPlain.ExecutableName != fromMAM.ExecutableName {
		t.Errorf("executable: %q vs %q", fromPlain.ExecutableName, fromMAM.ExecutableName)
	}
	if fromPlain.PrefetchHash != fromMAM.PrefetchHash {
		t.Errorf("hash: %08X vs %08X", fromPlain.PrefetchHash, fromMAM.PrefetchHash)
	}
	if fromPlain.RunCount != fromMAM.RunCount {
		t.Errorf("run count: %d vs %d", fromPlain.RunCount, fromMAM.RunCount)
	}
	if !reflect.DeepEqual(fromPlain.LastRunTimes, fromMAM.LastRunTimes) {
		t.Errorf("run times: %v vs %v", fromPlain.LastRunTimes, fromMAM.LastRunTimes)
	}
	if !reflect.DeepEqual(fromPlain.Filenames, fromMAM.Filenames) {
		t.Errorf("filenames differ")
	}
	if !reflect.DeepEqual(fromPlain.Volumes, fromMAM.Volumes) {
		t.Errorf("volumes differ")
	}
	if fromPlain.ExecutablePath != fromMAM.ExecutablePath {
		t.Errorf("executable path: %q vs %q", fromPlain.ExecutablePath, fromMAM.ExecutablePath)
	}

	// The ONLY permitted difference is the container metadata.
	if fromPlain.Compressed {
		t.Error("an uncompressed file reported itself compressed")
	}
	if !fromMAM.Compressed {
		t.Error("a MAM file did not report itself compressed")
	}
	if fromMAM.UncompressedSize != len(plain) {
		t.Errorf("uncompressed size = %d, want %d", fromMAM.UncompressedSize, len(plain))
	}
	if fromMAM.CompressedSize != len(compressed) {
		t.Errorf("compressed size = %d, want %d", fromMAM.CompressedSize, len(compressed))
	}

	// Normalising away the container metadata, the two are identical.
	a, b := fromPlain, fromMAM
	b.Compressed, b.CompressedSize, b.UncompressedSize = false, 0, 0
	a.Compressed, a.CompressedSize, a.UncompressedSize = false, 0, 0
	if !reflect.DeepEqual(a, b) {
		t.Error("parsed results differ beyond the container metadata")
	}
}

// Sniffing and classification must not depend on the container.
func TestMAM_IsRecognizedAsPrefetch(t *testing.T) {
	compressed := prefetchgen.CompressMAM(buildSCCA(t))
	if !prefetch.Sniff(compressed) {
		t.Error("a MAM Prefetch was not sniffed as Prefetch")
	}
	if !prefetch.IsCompressed(compressed) {
		t.Error("a MAM Prefetch was not detected as compressed")
	}
	if prefetch.IsCompressed(buildSCCA(t)) {
		t.Error("an uncompressed Prefetch was detected as compressed")
	}
	// A .pf extension alone must not imply compression.
	if prefetch.IsCompressed([]byte("not prefetch at all")) {
		t.Error("arbitrary bytes were detected as MAM-compressed")
	}
}

// Parsing from disk must work for both containers.
func TestMAM_ParseFromDisk(t *testing.T) {
	plain := buildSCCA(t)
	for name, data := range map[string][]byte{
		"uncompressed": plain,
		"compressed":   prefetchgen.CompressMAM(plain),
	} {
		t.Run(name, func(t *testing.T) {
			p, err := prefetch.Parse(writeTemp(t, data), prefetch.Limits{})
			if err != nil {
				t.Fatalf("%v", err)
			}
			if p.ExecutableName != "NOTEPAD.EXE" {
				t.Errorf("executable = %q", p.ExecutableName)
			}
			if len(p.LastRunTimes) != 3 {
				t.Errorf("run times = %d, want 3", len(p.LastRunTimes))
			}
		})
	}
}

// The original evidence must never be modified by parsing it.
func TestMAM_EvidenceIsNotModified(t *testing.T) {
	compressed := prefetchgen.CompressMAM(buildSCCA(t))
	path := writeTemp(t, compressed)

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, _ := os.Stat(path)

	for i := 0; i < 3; i++ {
		if _, err := prefetch.Parse(path, prefetch.Limits{}); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	afterInfo, _ := os.Stat(path)

	if !bytes.Equal(before, after) {
		t.Error("parsing modified the evidence on disk")
	}
	if beforeInfo.Size() != afterInfo.Size() {
		t.Error("parsing changed the evidence file size")
	}
	// The caller's buffer must not be mutated either: ParseBytes is
	// handed evidence that may be shared with hashing and provenance.
	buf := append([]byte(nil), compressed...)
	if _, err := prefetch.ParseBytes(buf, prefetch.Limits{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, compressed) {
		t.Error("ParseBytes mutated the buffer it was given")
	}
}

// Many compressed files in sequence must not leak state between them.
func TestMAM_NoCrossFileStateLeakage(t *testing.T) {
	type want struct {
		exe   string
		hash  uint32
		count int
	}
	var files [][]byte
	var wants []want
	base := time.Date(2026, 5, 5, 8, 0, 0, 0, time.UTC)
	for i := 0; i < 40; i++ {
		exe := string(rune('A'+i%26)) + "PP.EXE"
		// Distinct times, always: the parser deduplicates identical run
		// times on purpose (Windows repeats the newest value into unused
		// slots), so a fixture with a duplicate would be testing that
		// behaviour by accident instead of cross-file isolation.
		times := []time.Time{base.Add(time.Duration(i) * time.Minute)}
		if i%3 == 0 {
			times = append(times, base.Add(-time.Duration(i+1)*time.Hour))
		}
		files = append(files, prefetchgen.CompressMAM(prefetchgen.Build(prefetchgen.File{
			Version:        30,
			ExecutableName: exe,
			PrefetchHash:   uint32(0x1000 + i),
			RunCount:       uint32(i + 1),
			LastRunTimes:   times,
			Filenames:      []string{`\VOLUME{01d7}\` + exe},
		})))
		wants = append(wants, want{exe, uint32(0x1000 + i), len(times)})
	}
	// Interleave the order to catch any dependence on sequence.
	for pass := 0; pass < 3; pass++ {
		for i := range files {
			idx := i
			if pass == 1 {
				idx = len(files) - 1 - i
			}
			p, err := prefetch.ParseBytes(files[idx], prefetch.Limits{})
			if err != nil {
				t.Fatalf("pass %d file %d: %v", pass, idx, err)
			}
			if p.ExecutableName != wants[idx].exe {
				t.Errorf("pass %d file %d: executable = %q, want %q", pass, idx, p.ExecutableName, wants[idx].exe)
			}
			if p.PrefetchHash != wants[idx].hash {
				t.Errorf("pass %d file %d: hash = %08X, want %08X", pass, idx, p.PrefetchHash, wants[idx].hash)
			}
			if len(p.LastRunTimes) != wants[idx].count {
				t.Errorf("pass %d file %d: %d run times, want %d", pass, idx, len(p.LastRunTimes), wants[idx].count)
			}
		}
	}
}

// The same compressed file must parse identically every time.
func TestMAM_IsDeterministic(t *testing.T) {
	compressed := prefetchgen.CompressMAM(buildSCCA(t))
	first, err := prefetch.ParseBytes(compressed, prefetch.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		again, err := prefetch.ParseBytes(compressed, prefetch.Limits{})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d differed", i)
		}
	}
}

// A declared size beyond the limit must be refused before allocating.
func TestMAM_RespectsSizeLimit(t *testing.T) {
	compressed := prefetchgen.Compressed(1 << 30) // declares 1 GiB
	_, err := prefetch.ParseBytes(compressed, prefetch.Limits{MaxFileBytes: 1 << 20})
	if err == nil {
		t.Fatal("a 1 GiB declaration was accepted against a 1 MiB limit")
	}
}

// Malformed compressed evidence must never panic.
func TestMAM_MalformedNeverPanics(t *testing.T) {
	valid := prefetchgen.CompressMAM(buildSCCA(t))
	for cut := 0; cut <= len(valid); cut++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on truncation at %d: %v", cut, r)
				}
			}()
			_, _ = prefetch.ParseBytes(valid[:cut], prefetch.Limits{})
		}()
	}
	for i := 0; i < len(valid) && i < 400; i++ {
		mutated := append([]byte(nil), valid...)
		mutated[i] ^= 0xFF
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on byte flip at %d: %v", i, r)
				}
			}()
			p, err := prefetch.ParseBytes(mutated, prefetch.Limits{})
			// A corrupted file must either fail or produce a coherent
			// result -- never a partial one presented as complete.
			if err == nil && p.ExecutableName == "" && len(p.LastRunTimes) > 0 {
				t.Errorf("byte flip at %d produced run times with no executable", i)
			}
		}()
	}
}
