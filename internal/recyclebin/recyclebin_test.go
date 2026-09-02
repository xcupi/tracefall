package recyclebin_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/recyclebin"
	"tracefall/internal/recyclebin/rbgen"
)

var deleted = time.Date(2026, 5, 21, 14, 32, 8, 0, time.UTC)

func write(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Version 2 (Windows 10+): a length-prefixed path.
func TestRB_Version2IsParsed(t *testing.T) {
	rec, err := recyclebin.Parse(rbgen.Build(rbgen.Record{
		Version: 2, Size: 1048576, Deleted: deleted,
		Path: `C:\Users\jdoe\Documents\quarterly-report.docx`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Version != 2 {
		t.Errorf("version = %d", rec.Version)
	}
	if rec.OriginalSize != 1048576 {
		t.Errorf("size = %d", rec.OriginalSize)
	}
	if !rec.DeletionTime.Equal(deleted) {
		t.Errorf("deletion time = %s, want %s", rec.DeletionTime, deleted)
	}
	if rec.DeletionTime.Location() != time.UTC {
		t.Error("deletion time is not UTC")
	}
	if rec.OriginalPath != `C:\Users\jdoe\Documents\quarterly-report.docx` {
		t.Errorf("path = %q", rec.OriginalPath)
	}
	if rec.OriginalName() != "quarterly-report.docx" {
		t.Errorf("name = %q", rec.OriginalName())
	}
	if rec.OriginalDirectory() != `C:\Users\jdoe\Documents` {
		t.Errorf("directory = %q", rec.OriginalDirectory())
	}
	if len(rec.Warnings) != 0 {
		t.Errorf("a well-formed record produced warnings: %v", rec.Warnings)
	}
}

// Version 1 (Vista-8.1): a fixed 260-character field, zero-padded.
func TestRB_Version1IsParsed(t *testing.T) {
	data := rbgen.Build(rbgen.Record{
		Version: 1, Size: 4096, Deleted: deleted, Path: `D:\work\notes.txt`,
	})
	if len(data) != 544 {
		t.Fatalf("a version 1 record is 544 bytes; the fixture built %d", len(data))
	}
	rec, err := recyclebin.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Version != 1 {
		t.Errorf("version = %d", rec.Version)
	}
	if rec.OriginalPath != `D:\work\notes.txt` {
		t.Errorf("path = %q -- the fixed field's padding was not trimmed", rec.OriginalPath)
	}
	if rec.PathChars != 0 {
		t.Errorf("version 1 reported a declared path length of %d; its field is fixed", rec.PathChars)
	}
	if !rec.DeletionTime.Equal(deleted) {
		t.Errorf("deletion time = %s", rec.DeletionTime)
	}
}

// Unicode paths survive intact, including outside the BMP.
func TestRB_UnicodePathsAreDecoded(t *testing.T) {
	for _, path := range []string{
		`C:\Users\ökonom\Dokumente\Jahresbericht.docx`,
		`C:\Users\田中\書類\報告書.xlsx`,
		`C:\Users\j\Desktop\emoji-\U0001F5C2-file.txt`,
	} {
		for _, version := range []uint64{1, 2} {
			rec, err := recyclebin.Parse(rbgen.Build(rbgen.Record{
				Version: version, Size: 10, Deleted: deleted, Path: path,
			}))
			if err != nil {
				t.Fatalf("v%d %q: %v", version, path, err)
			}
			if rec.OriginalPath != path {
				t.Errorf("v%d: path = %q, want %q", version, rec.OriginalPath, path)
			}
		}
	}
}

// A long path is kept whole in version 2, and clipped to the fixed field
// in version 1 -- which is what the format does, not a parser limit.
func TestRB_LongPaths(t *testing.T) {
	long := `C:\Users\jdoe\` + strings.Repeat("deeply-nested-directory\\", 20) + "file.txt"

	v2, err := recyclebin.Parse(rbgen.Build(rbgen.Record{Version: 2, Deleted: deleted, Path: long}))
	if err != nil {
		t.Fatal(err)
	}
	if v2.OriginalPath != long {
		t.Errorf("version 2 lost path characters: got %d of %d", len(v2.OriginalPath), len(long))
	}

	v1, err := recyclebin.Parse(rbgen.Build(rbgen.Record{Version: 1, Deleted: deleted, Path: long}))
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(v1.OriginalPath)) > 260 {
		t.Errorf("version 1 returned %d characters from a 260-character field", len([]rune(v1.OriginalPath)))
	}
	if !strings.HasPrefix(long, v1.OriginalPath) {
		t.Error("the version 1 path is not a prefix of the real one; characters were invented")
	}
}

// Zero and very large sizes are recorded as they stand.
func TestRB_SizeExtremes(t *testing.T) {
	for _, size := range []uint64{0, 1, 1 << 40, 1<<64 - 1} {
		rec, err := recyclebin.Parse(rbgen.Build(rbgen.Record{
			Version: 2, Size: size, Deleted: deleted, Path: `C:\t\f.bin`,
		}))
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if rec.OriginalSize != size {
			t.Errorf("size = %d, want %d", rec.OriginalSize, size)
		}
	}
}

// A zero FILETIME means "not recorded"; an implausible one is discarded
// with a warning. Neither becomes a date on a timeline.
func TestRB_TimestampsAreNotInvented(t *testing.T) {
	zero, err := recyclebin.Parse(rbgen.Build(rbgen.Record{
		Version: 2, Path: `C:\t\f.bin`, HasRawTime: true, RawFileTime: 0,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !zero.DeletionTime.IsZero() {
		t.Errorf("a zero FILETIME became %s", zero.DeletionTime)
	}

	// A few thousand ticks past 1601: a real FILETIME, not a real date.
	implausible, err := recyclebin.Parse(rbgen.Build(rbgen.Record{
		Version: 2, Path: `C:\t\f.bin`, HasRawTime: true, RawFileTime: 100000,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !implausible.DeletionTime.IsZero() {
		t.Errorf("an implausible FILETIME became %s", implausible.DeletionTime)
	}
	if len(implausible.Warnings) == 0 {
		t.Error("the discarded timestamp was not reported")
	}
}

// An unsupported version is named, never decoded with version 2's
// layout.
func TestRB_UnsupportedVersionIsRefused(t *testing.T) {
	good := rbgen.Build(rbgen.Record{Version: 2, Deleted: deleted, Path: `C:\t\f.bin`})
	for _, v := range []uint64{0, 3, 4, 99, 1 << 40} {
		_, err := recyclebin.Parse(rbgen.WithVersion(good, v))
		if err == nil {
			t.Errorf("version %d was decoded anyway", v)
			continue
		}
		if !strings.Contains(err.Error(), "version") {
			t.Errorf("version %d: the error does not name the problem: %v", v, err)
		}
	}
}

// Truncation at every offset is survivable and never invents a path.
func TestRB_TruncationIsSurvivable(t *testing.T) {
	for _, version := range []uint64{1, 2} {
		good := rbgen.Build(rbgen.Record{
			Version: version, Size: 2048, Deleted: deleted,
			Path: `C:\Users\jdoe\Documents\report.docx`,
		})
		for n := 0; n < len(good); n++ {
			rec, err := recyclebin.Parse(rbgen.Truncate(good, n))
			if err != nil {
				continue
			}
			if rec.OriginalPath == "" {
				t.Fatalf("v%d truncated at %d: parsed with an empty path", version, n)
			}
			if !strings.HasPrefix(`C:\Users\jdoe\Documents\report.docx`, rec.OriginalPath) {
				t.Fatalf("v%d truncated at %d produced %q, which is not a prefix of the real path",
					version, n, rec.OriginalPath)
			}
		}
	}
}

// Detection is structural. A file that merely has an $I-like name, or
// merely starts with a small integer, is not a record.
func TestRB_SniffIsStructuralNotByName(t *testing.T) {
	good := rbgen.Build(rbgen.Record{Version: 2, Size: 10, Deleted: deleted, Path: `C:\t\f.bin`})
	if !recyclebin.Sniff(good) {
		t.Fatal("a valid record was not detected")
	}
	if !recyclebin.Sniff(rbgen.Build(rbgen.Record{Version: 1, Deleted: deleted, Path: `C:\t\f.bin`})) {
		t.Fatal("a valid version 1 record was not detected")
	}

	notRecords := map[string][]byte{
		"zeros":           make([]byte, 600),
		"text":            []byte(strings.Repeat("this file is called $IABCDEF.txt but is text ", 20)),
		"leading one":     append([]byte{1, 0, 0, 0, 0, 0, 0, 0}, make([]byte, 600)...),
		"no path":         rbgen.Build(rbgen.Record{Version: 2, Deleted: deleted, Path: "not-a-path"}),
		"unsupported ver": rbgen.WithVersion(good, 3),
		"zero deletion":   rbgen.Build(rbgen.Record{Version: 2, Path: `C:\t\f.bin`, HasRawTime: true, RawFileTime: 0}),
		"short":           good[:10],
		"empty":           {},
	}
	for name, data := range notRecords {
		if recyclebin.Sniff(data) {
			t.Errorf("%s was detected as an $I record", name)
		}
	}
}

// A random file with an $I-like filename must not parse as a record.
func TestRB_FilenameAloneProvesNothing(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "$IABCDEF.txt", []byte("just some text that happens to live here"))
	if _, err := recyclebin.ParseFile(p, recyclebin.Limits{}); err == nil {
		t.Fatal("a text file named like an $I record parsed as one")
	}
}

// $R pairing is an observation about the collection, not an assumption.
func TestRB_PairedRFileIsResolvedOnlyWhenPresent(t *testing.T) {
	if got := recyclebin.PairedName("$IA1B2C3.docx"); got != "$RA1B2C3.docx" {
		t.Errorf("paired name = %q", got)
	}
	if got := recyclebin.PairedName("notanirecord.bin"); got != "" {
		t.Errorf("a name with no $I prefix derived a pair: %q", got)
	}

	dir := t.TempDir()
	iPath := write(t, dir, "$IA1B2C3.docx", rbgen.Build(rbgen.Record{
		Version: 2, Size: 4096, Deleted: deleted, Path: `C:\Users\j\report.docx`,
	}))

	// No $R beside it yet: the pair is named but not claimed as found.
	pair := recyclebin.ResolvePair(iPath)
	if pair.Name != "$RA1B2C3.docx" {
		t.Errorf("pair name = %q", pair.Name)
	}
	if pair.Found {
		t.Error("a $R file that does not exist was reported as found")
	}

	// Now place it.
	write(t, dir, "$RA1B2C3.docx", make([]byte, 4096))
	pair = recyclebin.ResolvePair(iPath)
	if !pair.Found || pair.SizeBytes != 4096 {
		t.Errorf("pair = %+v, want found at 4096 bytes", pair)
	}
}

// Parsing is deterministic.
func TestRB_IsDeterministic(t *testing.T) {
	path := write(t, "", "$IZZZZZZ.docx", rbgen.Build(rbgen.Record{
		Version: 2, Size: 99, Deleted: deleted, Path: `C:\Users\j\a.docx`,
	}))
	first, err := recyclebin.ParseFile(path, recyclebin.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := recyclebin.ParseFile(path, recyclebin.Limits{})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if again.OriginalPath != first.OriginalPath || again.OriginalSize != first.OriginalSize ||
			!again.DeletionTime.Equal(first.DeletionTime) || again.Version != first.Version {
			t.Fatalf("run %d differed: %+v vs %+v", i, again, first)
		}
	}
}

// Byte-flip fuzzing: no panic, no runaway allocation, no invented path.
func TestRB_ByteFlipsAreSurvivable(t *testing.T) {
	good := rbgen.Build(rbgen.Record{
		Version: 2, Size: 2048, Deleted: deleted, Path: `C:\Users\jdoe\Documents\report.docx`,
	})
	for i := 0; i < len(good); i++ {
		bad := append([]byte(nil), good...)
		bad[i] ^= 0xFF
		rec, err := recyclebin.Parse(bad)
		if err != nil {
			continue
		}
		if len(rec.OriginalPath) > 1<<20 {
			t.Fatalf("offset %d produced a %d-character path", i, len(rec.OriginalPath))
		}
	}
}
