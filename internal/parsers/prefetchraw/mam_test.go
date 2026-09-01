package prefetchraw_test

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers/prefetchraw"
	"tracefall/internal/prefetch/prefetchgen"
)

func scca(t *testing.T) []byte {
	t.Helper()
	run := time.Date(2026, 6, 1, 14, 30, 0, 0, time.UTC)
	return prefetchgen.Build(prefetchgen.File{
		Version:        30,
		ExecutableName: "POWERSHELL.EXE",
		PrefetchHash:   0x0C0FFEE0,
		RunCount:       12,
		LastRunTimes:   []time.Time{run, run.Add(-2 * time.Hour)},
		Filenames:      []string{`\VOLUME{01d7}\WINDOWS\SYSTEM32\POWERSHELL.EXE`},
	})
}

func writePF(t *testing.T, data []byte, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The normalized EVENTS must be equivalent, not merely the parsed
// struct: this is what the timeline, detection and correlation engines
// actually consume.
func TestParser_CompressedAndUncompressedProduceEquivalentEvents(t *testing.T) {
	plain := scca(t)
	p := prefetchraw.New()

	fromPlain, err := p.Parse(writePF(t, plain, "A.EXE-11111111.pf"))
	if err != nil {
		t.Fatalf("uncompressed: %v", err)
	}
	fromMAM, err := p.Parse(writePF(t, prefetchgen.CompressMAM(plain), "A.EXE-11111111.pf"))
	if err != nil {
		t.Fatalf("compressed: %v", err)
	}

	if len(fromPlain.Events) == 0 {
		t.Fatal("no events from the uncompressed file")
	}
	if len(fromPlain.Events) != len(fromMAM.Events) {
		t.Fatalf("event counts differ: %d vs %d", len(fromPlain.Events), len(fromMAM.Events))
	}

	for i := range fromPlain.Events {
		a, b := fromPlain.Events[i], fromMAM.Events[i]
		if !a.Timestamp.Equal(b.Timestamp) {
			t.Errorf("event %d timestamp: %s vs %s", i, a.Timestamp, b.Timestamp)
		}
		for _, f := range []struct{ name, x, y string }{
			{"event type", a.EventType, b.EventType},
			{"artifact type", a.ArtifactType, b.ArtifactType},
			{"process name", a.ProcessName, b.ProcessName},
			{"process path", a.ProcessPath, b.ProcessPath},
			{"file path", a.FilePath, b.FilePath},
			{"parser", a.Parser, b.Parser},
			{"source reference", a.SourceReference, b.SourceReference},
		} {
			if f.x != f.y {
				t.Errorf("event %d %s: %q vs %q", i, f.name, f.x, f.y)
			}
		}
		if a.Confidence != b.Confidence {
			t.Errorf("event %d confidence: %v vs %v", i, a.Confidence, b.Confidence)
		}
		if a.ArtifactType != model.ArtifactPrefetch {
			t.Errorf("event %d artifact type = %q, want %q", i, a.ArtifactType, model.ArtifactPrefetch)
		}

		// Extra must match except for the additive container keys.
		plainExtra := map[string]string{}
		for k, v := range a.Extra {
			plainExtra[k] = v
		}
		mamExtra := map[string]string{}
		for k, v := range b.Extra {
			if strings.HasPrefix(k, "prefetch_container") ||
				strings.HasPrefix(k, "prefetch_compressed_bytes") ||
				strings.HasPrefix(k, "prefetch_uncompressed_bytes") {
				continue
			}
			mamExtra[k] = v
		}
		if !reflect.DeepEqual(plainExtra, mamExtra) {
			var keys []string
			for k := range mamExtra {
				if plainExtra[k] != mamExtra[k] {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			t.Errorf("event %d metadata differs beyond the container keys: %v", i, keys)
		}
	}

	// The container metadata IS present on the compressed one.
	if fromMAM.Events[0].Extra["prefetch_container"] == "" {
		t.Error("the compressed event does not record its container")
	}
	if fromPlain.Events[0].Extra["prefetch_container"] != "" {
		t.Error("an uncompressed event claims a MAM container")
	}
}

// Detection must not treat compression as a signal.
func TestParser_CompressionIsNotASignal(t *testing.T) {
	p := prefetchraw.New()
	res, err := p.Parse(writePF(t, prefetchgen.CompressMAM(scca(t)), "B.EXE-22222222.pf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Events {
		if e.Confidence != 0.9 {
			t.Errorf("confidence = %v, want the same 0.9 an uncompressed file gets", e.Confidence)
		}
		for k, v := range e.Extra {
			low := strings.ToLower(k + " " + v)
			for _, word := range []string{"malicious", "suspicious", "threat", "evasion"} {
				if strings.Contains(low, word) {
					t.Errorf("compression produced a maliciousness claim: %s=%s", k, v)
				}
			}
		}
	}
}

// The parser must still detect and parse both containers by content.
func TestParser_DetectsBothContainers(t *testing.T) {
	p := prefetchraw.New()
	plain := scca(t)
	if !p.DetectContent(plain[:16]) {
		t.Error("uncompressed Prefetch not detected by content")
	}
	if !p.DetectContent(prefetchgen.CompressMAM(plain)[:16]) {
		t.Error("MAM Prefetch not detected by content")
	}
	if p.DetectContent([]byte("this is not prefetch at all yeah")) {
		t.Error("arbitrary bytes detected as Prefetch")
	}
	if p.ArtifactType() != model.ArtifactPrefetch {
		t.Errorf("artifact type = %q", p.ArtifactType())
	}
}
