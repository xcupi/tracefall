package cmdsem

import (
	"strings"
	"testing"
	"time"
)

func TestURLSpans_QuoteBoundariesAndGeneralRedaction(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"double", `curl "https://alice:Dummy'Secret@api.example.test/download?private=first'DummyQuery#DummyFragment"`, `curl "https://<redacted>@api.example.test/download?private=first'DummyQuery#DummyFragment"`},
		{"bare", `curl https://alice:Dummy'Secret@api.example.test/down'load?private=first'DummyQuery#DummyFragment`, `curl https://<redacted>@api.example.test/down'load?private=first'DummyQuery#DummyFragment`},
		{"single", `curl 'https://alice:Dummy%27Secret@api.example.test/download?private=DummyQuery'`, `curl 'https://<redacted>@api.example.test/download?private=DummyQuery'`},
		{"consecutive", `curl 'https://api.example.test/download?private=DummyQuery'"https://alice:Dummy'Secret@second.example.test/second?private=DummyQuery"; echo keep`, `curl 'https://api.example.test/download?private=DummyQuery'"https://<redacted>@second.example.test/second?private=DummyQuery"; echo keep`},
		{"single authority boundary", `curl 'https://api.example.test'"https://alice:Dummy'Secret@second.example.test/second"`, `curl 'https://api.example.test'"https://<redacted>@second.example.test/second"`},
		{"uppercase", `curl "HtTp://alice:Dummy'Secret@api.example.test/download?private=DummyQuery"`, `curl "HtTp://<redacted>@api.example.test/download?private=DummyQuery"`},
		{"not URLs", `cat alice's-download.txt; echo alice@example.test`, `cat alice's-download.txt; echo alice@example.test`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Redact(tc.in); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestURLSpans_BoundedLongInput(t *testing.T) {
	// Smoke test, not a throughput benchmark: also cover nested URL candidates
	// without rescanning their suffixes or allocating an unbounded test fixture.
	text := `curl "https://alice:` + strings.Repeat("x", 1<<20) + `@api.example.test/download?private=first'` + strings.Repeat("https://nested.test/", 20000) + `#DummyFragment"`
	start := time.Now()
	got := Redact(text)
	if strings.Contains(got, strings.Repeat("x", 100)) || !strings.Contains(got, "api.example.test/download?private=first'") {
		t.Fatal("long authority redaction lost its contract")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("bounded input took %s", elapsed)
	}
	t.Logf("%d bytes redacted in %s", len(text), time.Since(start))
}
