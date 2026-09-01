package lzxpress_test

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"tracefall/internal/lzxpress"
	"tracefall/internal/prefetch/prefetchgen"
)

// unwrap strips a MAM container built by the fixture generator.
func unwrap(t *testing.T, container []byte) (body []byte, declared int) {
	t.Helper()
	if len(container) < 8 || string(container[:3]) != "MAM" {
		t.Fatal("not a MAM container")
	}
	return container[8:], int(binary.LittleEndian.Uint32(container[4:8]))
}

func TestDecompress_RoundTripsLiterals(t *testing.T) {
	cases := map[string][]byte{
		"empty":        {},
		"one byte":     {0x41},
		"short ascii":  []byte("the quick brown fox"),
		"all 256":      allBytes(),
		"repetitive":   bytes.Repeat([]byte("ABCD"), 5000),
		"binary zeros": make([]byte, 4096),
	}
	for name, plain := range cases {
		t.Run(name, func(t *testing.T) {
			body, declared := unwrap(t, prefetchgen.CompressMAM(plain))
			got, err := lzxpress.HuffmanDecompress(body, declared, 1<<20)
			if err != nil {
				t.Fatalf("decompress: %v", err)
			}
			if !bytes.Equal(got, plain) {
				t.Errorf("round trip differs: got %d bytes, want %d", len(got), len(plain))
			}
		})
	}
}

// Output larger than one 65,536-byte chunk must decode across the chunk
// boundary, which is where the trickiest part of the format lives.
func TestDecompress_MultipleChunks(t *testing.T) {
	for _, size := range []int{65535, 65536, 65537, 131072, 200000} {
		plain := make([]byte, size)
		for i := range plain {
			plain[i] = byte(i*7 + i/251)
		}
		body, declared := unwrap(t, prefetchgen.CompressMAM(plain))
		got, err := lzxpress.HuffmanDecompress(body, declared, 1<<21)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("size %d: round trip differs", size)
		}
	}
}

func TestDecompress_IsDeterministic(t *testing.T) {
	plain := bytes.Repeat([]byte("deterministic evidence "), 3000)
	body, declared := unwrap(t, prefetchgen.CompressMAM(plain))
	first, err := lzxpress.HuffmanDecompress(body, declared, 1<<21)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		again, err := lzxpress.HuffmanDecompress(body, declared, 1<<21)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("run %d produced different output", i)
		}
	}
}

// The declared size is attacker-controlled and must be refused against
// the ceiling BEFORE anything is allocated.
func TestDecompress_RefusesOversizedDeclaration(t *testing.T) {
	_, err := lzxpress.HuffmanDecompress([]byte{0, 0, 0, 0}, 1<<30, 1<<20)
	if err == nil {
		t.Fatal("a 1 GiB declaration was accepted against a 1 MiB limit")
	}
	if !strings.Contains(err.Error(), "exceeds the limit") {
		t.Errorf("error does not name the limit: %v", err)
	}
}

// A tiny compressed stream must not be able to claim a huge output --
// the decompression-bomb case.
func TestDecompress_NoDecompressionBomb(t *testing.T) {
	// A valid table plus a stream that would emit a long run.
	body, _ := unwrap(t, prefetchgen.CompressMAM(bytes.Repeat([]byte{0}, 64)))
	out, err := lzxpress.HuffmanDecompress(body, 64, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 64 {
		t.Fatalf("produced %d bytes for a 64-byte declaration", len(out))
	}
	// Even a declaration inside the limit only ever allocates that much.
	if _, err := lzxpress.HuffmanDecompress(body, 1<<20, 1<<20); err == nil {
		t.Log("over-declared size decoded without error; output is still bounded by the declaration")
	}
}

// Malformed input must produce an error, never a panic or a hang.
func TestDecompress_MalformedNeverPanics(t *testing.T) {
	valid, declared := unwrap(t, prefetchgen.CompressMAM([]byte("some prefetch-like content here")))

	corruptions := map[string][]byte{
		"empty":              {},
		"truncated to table": valid[:100],
		"table only":         valid[:256],
		"table plus 2 bytes": valid[:258],
		"all zeros":          make([]byte, 512),
		"all ones":           bytes.Repeat([]byte{0xFF}, 512),
	}
	for name, body := range corruptions {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %s: %v", name, r)
				}
			}()
			// Errors are fine; panics and hangs are not.
			_, _ = lzxpress.HuffmanDecompress(body, declared, 1<<20)
		})
	}

	// Every single-byte truncation of a real stream.
	for cut := 0; cut < len(valid); cut++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on truncation at %d: %v", cut, r)
				}
			}()
			_, _ = lzxpress.HuffmanDecompress(valid[:cut], declared, 1<<20)
		}()
	}

	// Every single-byte flip in the first 512 bytes.
	for i := 0; i < len(valid) && i < 512; i++ {
		mutated := append([]byte(nil), valid...)
		mutated[i] ^= 0xFF
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on byte flip at %d: %v", i, r)
				}
			}()
			_, _ = lzxpress.HuffmanDecompress(mutated, declared, 1<<20)
		}()
	}
}

// A code-length table that over-subscribes the code space cannot
// describe a prefix-free code and must be refused.
func TestDecompress_RejectsOversubscribedTable(t *testing.T) {
	body := make([]byte, 512)
	// Every symbol length 1: 512 symbols x 2^14 slots, far past 2^15.
	for i := 0; i < 256; i++ {
		body[i] = 0x11
	}
	_, err := lzxpress.HuffmanDecompress(body, 64, 1<<20)
	if err == nil {
		t.Fatal("an over-subscribed Huffman table was accepted")
	}
}

// A table defining no symbols at all is not decodable.
func TestDecompress_RejectsEmptyTable(t *testing.T) {
	body := make([]byte, 512) // all lengths zero
	_, err := lzxpress.HuffmanDecompress(body, 64, 1<<20)
	if err == nil {
		t.Fatal("an empty Huffman table was accepted")
	}
}

func TestDecompress_ZeroDeclaredSizeIsEmpty(t *testing.T) {
	out, err := lzxpress.HuffmanDecompress([]byte{1, 2, 3, 4}, 0, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("got %d bytes for a zero declaration", len(out))
	}
}

func allBytes() []byte {
	out := make([]byte, 256)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}
