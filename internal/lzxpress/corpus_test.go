package lzxpress_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"tracefall/internal/lzxpress"
)

// Validation against REAL Windows 10 evidence.
//
// The fixture generator in prefetchgen is a literals-only encoder
// written alongside this decoder, so a round trip through it proves the
// two agree -- not that either matches what Windows produces. Only real
// evidence can show that, and the two bugs this implementation had were
// both found here and invisible to the round-trip tests:
//
//   - the extended match-length byte is consumed BEFORE the match
//     offset's extra bits, not after (4 of 81 files decoded, then 81)
//   - a chunk's successor begins at the reader's cursor with no
//     lookahead given back (54 of 81 files decoded, then 81)
//
// The corpus is a case directory in this working tree rather than
// committed fixtures: real Prefetch names software actually run on a
// real machine and cannot be checked in. The test skips when it is
// absent, so the suite still passes on a clean checkout -- and says so,
// rather than silently reporting success it did not earn.
func findPrefetchCorpus() string {
	matches, err := filepath.Glob("../../data/cases/*/collections/*/evidence/*/[root]/Windows/Prefetch")
	if err == nil && len(matches) > 0 {
		return matches[0]
	}
	// The evidence directory name embeds the image name, so fall back to
	// a walk rather than guessing at it.
	var found string
	_ = filepath.WalkDir("../../data/cases", func(path string, d os.DirEntry, err error) error {
		if err != nil || found != "" {
			return nil //nolint:nilerr // a missing corpus is a skip, not a failure
		}
		if d != nil && d.IsDir() && strings.EqualFold(d.Name(), "Prefetch") {
			found = path
		}
		return nil
	})
	return found
}

func TestDecompress_RealWindowsCorpus(t *testing.T) {
	dir := findPrefetchCorpus()
	if dir == "" {
		t.Skip("no real Prefetch corpus in this working tree; run against a case containing Windows 10/11 evidence")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("corpus unreadable: %v", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var mam, decoded, multiChunk int
	var totalOut int
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || len(raw) < 8 || string(raw[:3]) != "MAM" {
			continue
		}
		mam++
		declared := int(binary.LittleEndian.Uint32(raw[4:8]))
		if declared > 65536 {
			multiChunk++
		}
		out, err := lzxpress.HuffmanDecompress(raw[8:], declared, 64<<20)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(out) != declared {
			t.Errorf("%s: produced %d bytes, header declares %d", name, len(out), declared)
			continue
		}
		// The decisive check: the bytes must actually BE a Prefetch file.
		// A decoder that merely produced the right NUMBER of bytes would
		// pass a length check and fail this one.
		if len(out) < 84 || string(out[4:8]) != "SCCA" {
			t.Errorf("%s: decompressed output is not SCCA", name)
			continue
		}
		decoded++
		totalOut += len(out)
	}
	if mam == 0 {
		t.Skip("corpus contains no MAM-compressed Prefetch files")
	}
	if decoded != mam {
		t.Errorf("decoded %d of %d real MAM Prefetch files", decoded, mam)
	}
	t.Logf("decoded %d/%d real Windows MAM Prefetch files (%d multi-chunk, %d bytes)",
		decoded, mam, multiChunk, totalOut)
}

// The same evidence must decode identically every time.
func TestDecompress_RealCorpusIsDeterministic(t *testing.T) {
	dir := findPrefetchCorpus()
	if dir == "" {
		t.Skip("no real Prefetch corpus in this working tree")
	}
	entries, _ := os.ReadDir(dir)
	var checked int
	for _, e := range entries {
		if e.IsDir() || checked >= 8 {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil || len(raw) < 8 || string(raw[:3]) != "MAM" {
			continue
		}
		declared := int(binary.LittleEndian.Uint32(raw[4:8]))
		first, err := lzxpress.HuffmanDecompress(raw[8:], declared, 64<<20)
		if err != nil {
			continue
		}
		for i := 0; i < 5; i++ {
			again, err := lzxpress.HuffmanDecompress(raw[8:], declared, 64<<20)
			if err != nil {
				t.Fatalf("%s run %d: %v", e.Name(), i, err)
			}
			if string(first) != string(again) {
				t.Fatalf("%s run %d differed", e.Name(), i)
			}
		}
		checked++
	}
	if checked == 0 {
		t.Skip("no MAM files to check")
	}
	t.Logf("verified deterministic output for %d real files", checked)
}
