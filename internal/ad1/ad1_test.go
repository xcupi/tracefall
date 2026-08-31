package ad1_test

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"tracefall/internal/ad1"
	"tracefall/internal/ad1/ad1gen"
)

func writeTemp(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func build(t *testing.T, rootName string, files []ad1gen.File, chunkSize uint32) []byte {
	t.Helper()
	img, err := ad1gen.Build(rootName, files, chunkSize)
	if err != nil {
		t.Fatalf("ad1gen.Build: %v", err)
	}
	return img
}

func TestSniff_RecognizesAD1Magic(t *testing.T) {
	img := build(t, `C:\Users\jdoe\Desktop\Data`, []ad1gen.File{{Path: "doc.txt", Data: []byte("hi")}}, 0)
	isAD1, isEncrypted, err := ad1.Sniff(bytes.NewReader(img))
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if !isAD1 || isEncrypted {
		t.Errorf("Sniff = (%v, %v), want (true, false)", isAD1, isEncrypted)
	}
}

func TestSniff_RejectsNonAD1(t *testing.T) {
	for _, data := range [][]byte{
		[]byte("PK\x03\x04this is a zip"),
		[]byte("not an ad1 at all"),
		{},
		[]byte("short"),
	} {
		isAD1, isEncrypted, err := ad1.Sniff(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("ad1.Sniff(%q): unexpected error %v", data, err)
		}
		if isAD1 || isEncrypted {
			t.Errorf("ad1.Sniff(%q) = (%v, %v), want (false, false)", data, isAD1, isEncrypted)
		}
	}
}

func TestSniff_RecognizesADCRYPT(t *testing.T) {
	isAD1, isEncrypted, err := ad1.Sniff(bytes.NewReader([]byte("ADCRYPT\x00" + "rest of the file doesn't matter for sniffing")))
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if !isAD1 || !isEncrypted {
		t.Errorf("Sniff = (%v, %v), want (true, true)", isAD1, isEncrypted)
	}
}

func TestOpen_EncryptedContainerIsRejected(t *testing.T) {
	dir := t.TempDir()
	// A real ADCRYPT header is much longer; the magic alone is enough to
	// exercise Open's encryption check before it would attempt to parse
	// anything else.
	p := writeTemp(t, dir, "encrypted.ad1", append([]byte("ADCRYPT\x00"), make([]byte, 512)...))
	_, err := ad1.Open([]string{p}, ad1.DefaultLimits)
	if !errors.Is(err, ad1.ErrEncrypted) {
		t.Fatalf("Open encrypted image: got %v, want ad1.ErrEncrypted", err)
	}
}

func TestOpen_CorruptMagicIsRejected(t *testing.T) {
	dir := t.TempDir()
	p := writeTemp(t, dir, "bad.ad1", make([]byte, 1024))
	_, err := ad1.Open([]string{p}, ad1.DefaultLimits)
	if !errors.Is(err, ad1.ErrCorrupt) {
		t.Fatalf("Open corrupt image: got %v, want ad1.ErrCorrupt", err)
	}
}

func TestOpen_TruncatedFileIsRejected(t *testing.T) {
	dir := t.TempDir()
	img := build(t, `C:\Data`, []ad1gen.File{{Path: "a.txt", Data: []byte("hello")}}, 0)
	p := writeTemp(t, dir, "truncated.ad1", img[:600]) // cuts off mid-tree
	_, err := ad1.Open([]string{p}, ad1.DefaultLimits)
	if err == nil {
		t.Fatal("Open truncated image: got nil error, want a failure")
	}
	// Walking (not just opening) a truncated image must also fail
	// closed, never silently report zero/partial entries as complete.
}

func TestOpen_EmptyImageEnumeratesZeroEntries(t *testing.T) {
	dir := t.TempDir()
	img := build(t, `C:\Empty`, nil, 0)
	p := writeTemp(t, dir, "empty.ad1", img)
	c, err := ad1.Open([]string{p}, ad1.DefaultLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	var entries []ad1.Entry
	if err := c.Walk(func(e ad1.Entry) error { entries = append(entries, e); return nil }); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries in an empty image, want 0", len(entries))
	}
}

func TestOpen_UnsupportedVersionIsRejected(t *testing.T) {
	dir := t.TempDir()
	img := build(t, `C:\Data`, []ad1gen.File{{Path: "a.txt", Data: []byte("x")}}, 0)
	// Patch the version field (offset 512 + 16) from 4 to 3.
	broken := append([]byte(nil), img...)
	broken[512+16] = 3
	p := writeTemp(t, dir, "v3.ad1", broken)
	_, err := ad1.Open([]string{p}, ad1.DefaultLimits)
	if !errors.Is(err, ad1.ErrUnsupportedVersion) {
		t.Fatalf("Open v3 image: got %v, want ad1.ErrUnsupportedVersion", err)
	}
}

func TestWalkAndExtract_NestedPathsAndContent(t *testing.T) {
	dir := t.TempDir()
	fileA := []byte("root level file")
	fileB := []byte(strings.Repeat("nested content, chunked across multiple zlib chunks. ", 200))
	files := []ad1gen.File{
		{Path: "top.txt", Data: fileA, Modified: time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)},
		{Path: "Users/jdoe/Documents/deep/nested.txt", Data: fileB},
	}
	img := build(t, `C:\Users\jdoe\Desktop\Data`, files, 64) // tiny chunk size forces multiple chunks for fileB
	p := writeTemp(t, dir, "sample.ad1", img)

	c, err := ad1.Open([]string{p}, ad1.DefaultLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	if c.RootName() != `C:\Users\jdoe\Desktop\Data` {
		t.Errorf("RootName = %q", c.RootName())
	}

	entries := map[string]ad1.Entry{}
	if err := c.Walk(func(e ad1.Entry) error { entries[e.Path] = e; return nil }); err != nil {
		t.Fatalf("Walk: %v", err)
	}

	wantDirs := []string{"Users", "Users/jdoe", "Users/jdoe/Documents", "Users/jdoe/Documents/deep"}
	for _, d := range wantDirs {
		e, ok := entries[d]
		if !ok || !e.IsDir {
			t.Errorf("expected directory entry %q, got %+v (ok=%v)", d, e, ok)
		}
	}

	top, ok := entries["top.txt"]
	if !ok || top.IsDir {
		t.Fatalf("top.txt entry missing or wrong: %+v (ok=%v)", top, ok)
	}
	if top.SizeBytes != int64(len(fileA)) {
		t.Errorf("top.txt size = %d, want %d", top.SizeBytes, len(fileA))
	}
	if top.ModifiedAt.IsZero() || !top.ModifiedAt.Equal(time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("top.txt modified = %v, want 2026-01-15T09:00:00Z", top.ModifiedAt)
	}
	var buf bytes.Buffer
	n, err := c.Extract(top, &buf)
	if err != nil {
		t.Fatalf("Extract top.txt: %v", err)
	}
	if n != int64(len(fileA)) || !bytes.Equal(buf.Bytes(), fileA) {
		t.Errorf("Extract top.txt content mismatch: got %q (%d bytes)", buf.String(), n)
	}

	nested, ok := entries["Users/jdoe/Documents/deep/nested.txt"]
	if !ok {
		t.Fatalf("nested.txt entry missing; have: %v", keysOf(entries))
	}
	buf.Reset()
	n, err = c.Extract(nested, &buf)
	if err != nil {
		t.Fatalf("Extract nested.txt: %v", err)
	}
	if n != int64(len(fileB)) || !bytes.Equal(buf.Bytes(), fileB) {
		t.Errorf("Extract nested.txt content mismatch: got %d bytes, want %d", n, len(fileB))
	}
}

func TestWalk_EmbeddedHashesSurfaced(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hash me")
	sum5 := md5.Sum(data)
	sum1 := sha1.Sum(data)
	files := []ad1gen.File{{Path: "hashed.bin", Data: data, MD5: hex.EncodeToString(sum5[:]), SHA1: hex.EncodeToString(sum1[:])}}
	img := build(t, `C:\Data`, files, 0)
	p := writeTemp(t, dir, "hashed.ad1", img)

	c, err := ad1.Open([]string{p}, ad1.DefaultLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	var got ad1.Entry
	if err := c.Walk(func(e ad1.Entry) error {
		if e.Path == "hashed.bin" {
			got = e
		}
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if got.MD5 != hex.EncodeToString(sum5[:]) {
		t.Errorf("MD5 = %q, want %q", got.MD5, hex.EncodeToString(sum5[:]))
	}
	if got.SHA1 != hex.EncodeToString(sum1[:]) {
		t.Errorf("SHA1 = %q, want %q", got.SHA1, hex.EncodeToString(sum1[:]))
	}
}

func TestWalk_RawSizeFallbackWhenNoFileSizeMeta(t *testing.T) {
	dir := t.TempDir()
	data := []byte("twelve bytes")
	files := []ad1gen.File{{Path: "nometa.bin", Data: data, NoMetaAtAll: true}}
	img := build(t, `C:\Data`, files, 0)
	p := writeTemp(t, dir, "nometa.ad1", img)

	c, err := ad1.Open([]string{p}, ad1.DefaultLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	var got ad1.Entry
	if err := c.Walk(func(e ad1.Entry) error {
		if e.Path == "nometa.bin" {
			got = e
		}
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if got.SizeBytes != int64(len(data)) {
		t.Errorf("SizeBytes = %d, want %d (fallback to raw FileEntry.size)", got.SizeBytes, len(data))
	}
}

func TestOpen_SegmentedImageMissingSegmentsIsRejected(t *testing.T) {
	// Build a genuinely segmented image (declares segment_count=2) but
	// only provide the first segment -- must fail closed, not silently
	// enumerate whatever fits in segment 1.
	dir := t.TempDir()
	img := build(t, `C:\Data`, []ad1gen.File{{Path: "a.txt", Data: []byte("x")}}, 0)
	broken := append([]byte(nil), img...)
	// segment_count field is at offset 28 within the 512-byte segment header.
	broken[28] = 2
	p := writeTemp(t, dir, "seg1.ad1", broken)
	_, err := ad1.Open([]string{p}, ad1.DefaultLimits)
	if !errors.Is(err, ad1.ErrSegmentsMissing) {
		t.Fatalf("Open under-segmented image: got %v, want ad1.ErrSegmentsMissing", err)
	}
}

func TestOpen_TooManySegmentsRejected(t *testing.T) {
	dir := t.TempDir()
	img := build(t, `C:\Data`, []ad1gen.File{{Path: "a.txt", Data: []byte("x")}}, 0)
	p := writeTemp(t, dir, "one.ad1", img)
	limits := ad1.DefaultLimits
	limits.MaxSegments = 0
	_, err := ad1.Open([]string{p}, limits)
	if !errors.Is(err, ad1.ErrLimitExceeded) {
		t.Fatalf("Open with MaxSegments=0: got %v, want ad1.ErrLimitExceeded", err)
	}
}

func TestWalk_MaxEntriesLimitStopsUnboundedTraversal(t *testing.T) {
	// A handful of files with a MaxEntries cap smaller than the tree
	// (including its directory entries) must fail closed with
	// ad1.ErrLimitExceeded, never partially enumerate and call it done.
	dir := t.TempDir()
	var files []ad1gen.File
	for i := 0; i < 20; i++ {
		files = append(files, ad1gen.File{Path: "d" + strconv.Itoa(i) + "/f.txt", Data: []byte("x")})
	}
	img := build(t, `C:\Data`, files, 0)
	p := writeTemp(t, dir, "many.ad1", img)

	limits := ad1.DefaultLimits
	limits.MaxEntries = 5
	c, err := ad1.Open([]string{p}, limits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	err = c.Walk(func(e ad1.Entry) error { return nil })
	if !errors.Is(err, ad1.ErrLimitExceeded) {
		t.Fatalf("Walk with MaxEntries=5 over 40 entries: got %v, want ad1.ErrLimitExceeded", err)
	}
}

func TestExtract_PerFileLimitCapsDecompressedOutput(t *testing.T) {
	dir := t.TempDir()
	data := bytes.Repeat([]byte("A"), 10_000)
	files := []ad1gen.File{{Path: "big.bin", Data: data}}
	img := build(t, `C:\Data`, files, 1024)
	p := writeTemp(t, dir, "big.ad1", img)

	limits := ad1.DefaultLimits
	limits.MaxFileBytes = 1000 // much smaller than the real 10,000-byte file
	c, err := ad1.Open([]string{p}, limits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	var entry ad1.Entry
	if err := c.Walk(func(e ad1.Entry) error {
		if e.Path == "big.bin" {
			entry = e
		}
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}

	var buf bytes.Buffer
	_, err = c.Extract(entry, &buf)
	if !errors.Is(err, ad1.ErrLimitExceeded) {
		t.Fatalf("Extract over MaxFileBytes: got %v, want ad1.ErrLimitExceeded", err)
	}
}

func TestWalk_DeletedEntriesAreNotSilentlyDropped(t *testing.T) {
	dir := t.TempDir()
	files := []ad1gen.File{{Path: "recovered.txt", Data: []byte("recovered content")}}
	img := build(t, `C:\Data`, files, 0)
	// Patch the entry's type field (File=0) to Deleted=2. The single
	// top-level entry's fixed header starts right after the
	// LogicalImageHeader; `type` is at header-offset 40.
	broken := append([]byte(nil), img...)
	nameLen := len(`C:\Data`)
	entryStart := 512 + ad1.LogicalImageFixedSize + nameLen
	if broken[entryStart+40] != 0 {
		t.Fatalf("test setup assumption wrong: entry type byte wasn't 0 (File)")
	}
	broken[entryStart+40] = byte(ad1.EntryTypeDeleted)
	p := writeTemp(t, dir, "deleted.ad1", broken)

	c, err := ad1.Open([]string{p}, ad1.DefaultLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	found := false
	if err := c.Walk(func(e ad1.Entry) error {
		if e.Path == "recovered.txt" {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if !found {
		t.Error("an EntryTypeDeleted entry was silently dropped from the walk -- deleted-file recovery content must remain visible, never hidden")
	}
}

func TestWalk_PathTraversalNameIsRejected(t *testing.T) {
	dir := t.TempDir()
	files := []ad1gen.File{{Path: "innocuous.txt", Data: []byte("x")}}
	img := build(t, `C:\Data`, files, 0)

	// Overwrite the entry's name field with a path-traversal attempt of
	// the SAME byte length as the original name (so no other offset in
	// the image shifts) -- everything about the tree stays structurally
	// valid, only the name field's bytes change.
	name := "innocuous.txt"
	broken := append([]byte(nil), img...)
	nameLen := len(`C:\Data`)
	entryStart := 512 + ad1.LogicalImageFixedSize + nameLen
	nameFieldStart := entryStart + ad1.FileEntryFixedSize
	traversal := []byte("../../../../a")
	if len(traversal) != len(name) {
		t.Fatalf("test setup: traversal payload length %d != name length %d", len(traversal), len(name))
	}
	copy(broken[nameFieldStart:nameFieldStart+len(name)], traversal)
	p := writeTemp(t, dir, "traversal.ad1", broken)

	c, err := ad1.Open([]string{p}, ad1.DefaultLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	err = c.Walk(func(e ad1.Entry) error { return nil })
	if !errors.Is(err, ad1.ErrCorrupt) {
		t.Fatalf("Walk with a path-traversal entry name: got %v, want ad1.ErrCorrupt (must fail closed, never silently accept)", err)
	}
}

func TestOpen_NoSegmentsIsRejected(t *testing.T) {
	_, err := ad1.Open(nil, ad1.DefaultLimits)
	if err == nil {
		t.Fatal("Open with no segment paths: got nil error")
	}
}

func keysOf(m map[string]ad1.Entry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
