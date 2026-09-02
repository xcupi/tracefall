package olecf_test

import (
	"bytes"
	"strings"
	"testing"

	"tracefall/internal/olecf"
	"tracefall/internal/olecf/olegen"
)

func sample() []olegen.Stream {
	return []olegen.Stream{
		{Name: "1", Data: bytes.Repeat([]byte("A"), 100)},
		{Name: "2", Data: bytes.Repeat([]byte("B"), 700)}, // spans mini sectors
		{Name: "DestList", Data: bytes.Repeat([]byte("D"), 40)},
	}
}

// A container's streams come back whole, by name, with their sizes.
func TestOLE_StreamsAreReadFromTheMiniStream(t *testing.T) {
	f, err := olecf.Open(olegen.Build(sample()), olecf.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if f.Version != 3 || f.SectorSize != 512 {
		t.Errorf("version/sector size = %d/%d", f.Version, f.SectorSize)
	}
	streams := f.Streams()
	if len(streams) != 3 {
		t.Fatalf("got %d streams, want 3: %+v", len(streams), streams)
	}
	for _, want := range sample() {
		e, ok := f.Find(want.Name)
		if !ok {
			t.Errorf("stream %q was not found", want.Name)
			continue
		}
		if e.Size != int64(len(want.Data)) {
			t.Errorf("%s: size = %d, want %d", want.Name, e.Size, len(want.Data))
		}
		got, err := f.Stream(e)
		if err != nil {
			t.Errorf("%s: %v", want.Name, err)
			continue
		}
		if !bytes.Equal(got, want.Data) {
			t.Errorf("%s: content differs (%d vs %d bytes)", want.Name, len(got), len(want.Data))
		}
		// Every entry carries its directory index, which is what a
		// provenance record cites.
		if e.Index <= 0 {
			t.Errorf("%s: no directory index recorded", want.Name)
		}
	}
	if len(f.Warnings) != 0 {
		t.Errorf("a well-formed container produced warnings: %v", f.Warnings)
	}
}

// Names are matched case-insensitively, as the format's consumers do.
func TestOLE_FindIsCaseInsensitive(t *testing.T) {
	f, err := olecf.Open(olegen.Build(sample()), olecf.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Find("destlist"); !ok {
		t.Error("DestList was not found case-insensitively")
	}
	if _, ok := f.Find("nosuchstream"); ok {
		t.Error("a stream that does not exist was found")
	}
}

// Detection is by signature and byte order, not by name.
func TestOLE_SniffRequiresSignatureAndByteOrder(t *testing.T) {
	good := olegen.Build(sample())
	if !olecf.Sniff(good) {
		t.Fatal("a valid container was not detected")
	}
	for name, data := range map[string][]byte{
		"signature":  olegen.Corrupt(good, "signature"),
		"byte order": olegen.Corrupt(good, "byte-order"),
		"short":      good[:16],
		"zeros":      make([]byte, 512),
		"text":       []byte(strings.Repeat("not a compound file ", 40)),
		"empty":      {},
	} {
		if olecf.Sniff(data) {
			t.Errorf("%s was detected as a compound file", name)
		}
	}
}

// A header this build cannot read is refused by name, never decoded
// with the wrong stride.
func TestOLE_UnsupportedHeadersAreRefused(t *testing.T) {
	good := olegen.Build(sample())
	for _, how := range []string{"version", "sector-shift", "mini-shift"} {
		_, err := olecf.Open(olegen.Corrupt(good, how), olecf.Limits{})
		if err == nil {
			t.Errorf("%s: an unsupported header was accepted", how)
			continue
		}
		if !strings.Contains(err.Error(), "unsupported") {
			t.Errorf("%s: the error does not name the problem: %v", how, err)
		}
	}
}

// Corrupt allocation pointers fail safely rather than reading wild
// offsets.
func TestOLE_CorruptPointersFailSafely(t *testing.T) {
	good := olegen.Build(sample())
	for _, how := range []string{"fat-count", "dir-start", "minifat-start"} {
		f, err := olecf.Open(olegen.Corrupt(good, how), olecf.Limits{})
		if err != nil {
			continue // a classified error is a fine outcome
		}
		// If it opened, nothing may claim to have read data it did not.
		for _, e := range f.Streams() {
			data, err := f.Stream(e)
			if err == nil && int64(len(data)) != e.Size {
				t.Errorf("%s: stream %q returned %d bytes for a declared %d",
					how, e.Name, len(data), e.Size)
			}
		}
	}
}

// Truncation at every sector boundary is survivable.
func TestOLE_TruncationIsSurvivable(t *testing.T) {
	good := olegen.Build(sample())
	for n := 0; n < len(good); n += 64 {
		f, err := olecf.Open(olegen.Truncate(good, n), olecf.Limits{})
		if err != nil {
			continue
		}
		for _, e := range f.Streams() {
			data, err := f.Stream(e)
			if err != nil {
				continue
			}
			// A stream that reports success must have delivered what it
			// promised; a short read is an error, never a silent partial.
			if int64(len(data)) != e.Size {
				t.Fatalf("truncated at %d: stream %q returned %d of %d bytes with no error",
					n, e.Name, len(data), e.Size)
			}
		}
	}
}

// Byte-flip fuzzing: no panic, no runaway allocation.
func TestOLE_ByteFlipsAreSurvivable(t *testing.T) {
	good := olegen.Build(sample())
	for i := 0; i < len(good); i += 17 {
		bad := append([]byte(nil), good...)
		bad[i] ^= 0xFF
		f, err := olecf.Open(bad, olecf.Limits{})
		if err != nil {
			continue
		}
		if len(f.Entries) > 1024 {
			t.Fatalf("offset %d produced %d directory entries", i, len(f.Entries))
		}
		for _, e := range f.Streams() {
			data, _ := f.Stream(e)
			if len(data) > 8<<20 {
				t.Fatalf("offset %d produced a %d-byte stream", i, len(data))
			}
		}
	}
}

// A limit refuses rather than allocates.
func TestOLE_LimitsAreEnforced(t *testing.T) {
	f, err := olecf.Open(olegen.Build(sample()), olecf.Limits{MaxStreamBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	e, _ := f.Find("2")
	if _, err := f.Stream(e); err == nil {
		t.Error("a stream above the ceiling was read anyway")
	}
}

// Reading is deterministic.
func TestOLE_IsDeterministic(t *testing.T) {
	data := olegen.Build(sample())
	first, err := olecf.Open(data, olecf.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := olecf.Open(data, olecf.Limits{})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if len(again.Entries) != len(first.Entries) {
			t.Fatalf("run %d: %d entries vs %d", i, len(again.Entries), len(first.Entries))
		}
		for j := range first.Entries {
			if again.Entries[j].Name != first.Entries[j].Name {
				t.Fatalf("run %d: entry %d differed", i, j)
			}
		}
	}
}

// An empty container opens and holds nothing.
func TestOLE_EmptyContainerIsValid(t *testing.T) {
	f, err := olecf.Open(olegen.Build(nil), olecf.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Streams()) != 0 {
		t.Errorf("an empty container reported %d streams", len(f.Streams()))
	}
}
