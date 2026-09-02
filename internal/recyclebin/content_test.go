package recyclebin_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/recyclebin"
	"tracefall/internal/recyclebin/rbgen"
)

var contentDeleted = time.Date(2026, 5, 21, 14, 32, 8, 0, time.UTC)

// pairDir writes an $I/$R pair (or half of one) into a fresh directory.
func pairDir(t *testing.T, id string, rec *rbgen.Record, content []byte) (dir, rPath string) {
	t.Helper()
	dir = t.TempDir()
	if rec != nil {
		if err := os.WriteFile(filepath.Join(dir, "$I"+id), rbgen.Build(*rec), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rPath = filepath.Join(dir, "$R"+id)
	if content != nil {
		if err := os.WriteFile(rPath, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, rPath
}

// The pairing rule is deterministic in both directions.
func TestContent_PairedNamesAreDerivedBothWays(t *testing.T) {
	for r, i := range map[string]string{
		"$RA1B2C3.docx": "$IA1B2C3.docx",
		"$Rabc":         "$Iabc",
		"$rA1B2C3.docx": "$iA1B2C3.docx",
	} {
		if got := recyclebin.PairedIName(r); got != i {
			t.Errorf("PairedIName(%q) = %q, want %q", r, got, i)
		}
	}
	for _, name := range []string{"notapair.txt", "$", "$X123", "", "R123"} {
		if got := recyclebin.PairedIName(name); got != "" {
			t.Errorf("PairedIName(%q) derived %q from a name that is not a $R file", name, got)
		}
	}
	// And round-trips with the existing $I -> $R direction.
	if got := recyclebin.PairedName(recyclebin.PairedIName("$RA1B2C3.docx")); got != "$RA1B2C3.docx" {
		t.Errorf("the pairing does not round-trip: %q", got)
	}
}

// A valid pair: content measured here, identity taken from the $I.
func TestContent_ValidPairResolvesAndHashes(t *testing.T) {
	body := []byte("the quick brown fox deleted this document")
	_, rPath := pairDir(t, "A1B2C3.docx", &rbgen.Record{
		Version: 2, Size: uint64(len(body)), Deleted: contentDeleted,
		Path: `C:\Users\jdoe\Documents\confidential-plan.docx`,
	}, body)

	content := recyclebin.ReadContent(rPath, 1<<20)
	if content.Status != recyclebin.ContentRecovered {
		t.Fatalf("status = %q, want recovered (%s)", content.Status, content.ReadError)
	}
	if content.SizeBytes != int64(len(body)) {
		t.Errorf("recovered size = %d, want %d", content.SizeBytes, len(body))
	}
	want := sha256.Sum256(body)
	if content.SHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("sha256 = %q, want %q", content.SHA256, hex.EncodeToString(want[:]))
	}
	// The $R's own name is an identifier, never the deleted file's name.
	if content.Name != "$RA1B2C3.docx" {
		t.Errorf("name = %q", content.Name)
	}

	pair := recyclebin.ResolveIRecord(rPath, recyclebin.Limits{})
	if !pair.Valid() {
		t.Fatalf("pairing did not resolve: %v", pair.Err)
	}
	if pair.IName != "$IA1B2C3.docx" {
		t.Errorf("paired $I = %q", pair.IName)
	}
	if pair.Record.OriginalPath != `C:\Users\jdoe\Documents\confidential-plan.docx` {
		t.Errorf("original path = %q", pair.Record.OriginalPath)
	}
	if pair.Record.OriginalName() != "confidential-plan.docx" {
		t.Errorf("original name = %q; the $R filename must never stand in for it", pair.Record.OriginalName())
	}
	if !pair.Record.DeletionTime.Equal(contentDeleted) {
		t.Errorf("deletion time = %s, want %s", pair.Record.DeletionTime, contentDeleted)
	}
	if pair.Record.OriginalSize != uint64(len(body)) {
		t.Errorf("original size = %d", pair.Record.OriginalSize)
	}
}

// An empty deleted file is recovered, not treated as a failure.
func TestContent_EmptyFileIsRecovered(t *testing.T) {
	_, rPath := pairDir(t, "E0.txt", &rbgen.Record{
		Version: 2, Size: 0, Deleted: contentDeleted, Path: `C:\t\empty.txt`,
	}, []byte{})
	c := recyclebin.ReadContent(rPath, 1<<20)
	if c.Status != recyclebin.ContentRecovered {
		t.Fatalf("status = %q", c.Status)
	}
	if c.SizeBytes != 0 {
		t.Errorf("size = %d", c.SizeBytes)
	}
	empty := sha256.Sum256(nil)
	if c.SHA256 != hex.EncodeToString(empty[:]) {
		t.Errorf("an empty file did not hash to the empty digest: %q", c.SHA256)
	}
}

// The $I is absent: content is still measured, identity is not invented.
func TestContent_MissingPairIsReportedNotGuessed(t *testing.T) {
	_, rPath := pairDir(t, "ORPHAN.docx", nil, []byte("orphaned content"))

	c := recyclebin.ReadContent(rPath, 1<<20)
	if c.Status != recyclebin.ContentRecovered || c.SHA256 == "" {
		t.Errorf("an orphan's content was not measured: %+v", c)
	}

	pair := recyclebin.ResolveIRecord(rPath, recyclebin.Limits{})
	if pair.Valid() {
		t.Fatal("a pairing resolved with no $I file present")
	}
	if pair.Found {
		t.Error("an absent $I was reported as found")
	}
	if pair.IName != "$IORPHAN.docx" {
		t.Errorf("the derivable $I name was not reported: %q", pair.IName)
	}
	if pair.Err == nil || !strings.Contains(pair.Err.Error(), "not collected") {
		t.Errorf("the error does not say the pair was not collected: %v", pair.Err)
	}
	// Nothing about the original file may be produced.
	if pair.Record.OriginalPath != "" || !pair.Record.DeletionTime.IsZero() {
		t.Errorf("metadata was invented for an orphan: %+v", pair.Record)
	}
}

// The $I is present but is not a record: reported as invalid, distinctly
// from absent.
func TestContent_InvalidPairingIsDistinctFromMissing(t *testing.T) {
	dir, rPath := pairDir(t, "BAD.docx", nil, []byte("content"))
	if err := os.WriteFile(filepath.Join(dir, "$IBAD.docx"), []byte("not a record at all"), 0o600); err != nil {
		t.Fatal(err)
	}

	pair := recyclebin.ResolveIRecord(rPath, recyclebin.Limits{})
	if pair.Valid() {
		t.Fatal("a non-record parsed as an $I")
	}
	if !pair.Found {
		t.Error("a present-but-invalid $I was reported as absent; the two are different findings")
	}
	if pair.Err == nil || !strings.Contains(pair.Err.Error(), "not a readable $I record") {
		t.Errorf("the error does not distinguish invalid from missing: %v", pair.Err)
	}
}

// An unsupported $I version is a pairing failure, not a silent success.
func TestContent_UnsupportedPairVersionFails(t *testing.T) {
	good := rbgen.Build(rbgen.Record{Version: 2, Size: 10, Deleted: contentDeleted, Path: `C:\t\f.bin`})
	dir, rPath := pairDir(t, "V9.bin", nil, []byte("content"))
	if err := os.WriteFile(filepath.Join(dir, "$IV9.bin"), rbgen.WithVersion(good, 9), 0o600); err != nil {
		t.Fatal(err)
	}
	pair := recyclebin.ResolveIRecord(rPath, recyclebin.Limits{})
	if pair.Valid() {
		t.Fatal("an unsupported version resolved as valid metadata")
	}
	if !strings.Contains(pair.Err.Error(), "version") {
		t.Errorf("the error does not name the version problem: %v", pair.Err)
	}
}

// A $R that cannot be read produces no hash and says so.
func TestContent_UnreadableContentClaimsNoRecovery(t *testing.T) {
	// A directory where the content file should be.
	dir := t.TempDir()
	rPath := filepath.Join(dir, "$RDIR.docx")
	if err := os.Mkdir(rPath, 0o755); err != nil {
		t.Fatal(err)
	}
	c := recyclebin.ReadContent(rPath, 1<<20)
	if c.Status != recyclebin.ContentUnreadable {
		t.Errorf("status = %q, want unreadable", c.Status)
	}
	if c.SHA256 != "" {
		t.Error("a hash was produced for content that was never read")
	}
	if c.ReadError == "" {
		t.Error("no reason was given for the failure")
	}

	// And a file that does not exist at all.
	missing := recyclebin.ReadContent(filepath.Join(dir, "$RNOPE.docx"), 1<<20)
	if missing.Status != recyclebin.ContentUnreadable || missing.SHA256 != "" {
		t.Errorf("a missing file was reported as %+v", missing)
	}
}

// Above the ceiling the size is recorded and the content is left alone.
// That is neither a recovery nor a failure, and must not be reported as
// either.
func TestContent_OversizeContentIsNotHashed(t *testing.T) {
	_, rPath := pairDir(t, "BIG.bin", nil, make([]byte, 4096))
	c := recyclebin.ReadContent(rPath, 1024)
	if c.Status != recyclebin.ContentTooLarge {
		t.Fatalf("status = %q, want the size-limit status", c.Status)
	}
	if c.SHA256 != "" {
		t.Error("content above the ceiling was hashed anyway")
	}
	if c.SizeBytes != 4096 {
		t.Errorf("size = %d, want 4096 -- the size is still measured", c.SizeBytes)
	}
	if len(c.Warnings) == 0 {
		t.Error("no warning explains why the content was not read")
	}
}

// Size mismatch preserves BOTH values and warns. Neither is adjusted.
func TestContent_SizeMismatchPreservesBothValues(t *testing.T) {
	recorded := uint64(1048576)
	body := []byte("a much smaller file than the record claims")
	_, rPath := pairDir(t, "MISMATCH.docx", &rbgen.Record{
		Version: 2, Size: recorded, Deleted: contentDeleted, Path: `C:\t\big.docx`,
	}, body)

	c := recyclebin.ReadContent(rPath, 1<<20)
	pair := recyclebin.ResolveIRecord(rPath, recyclebin.Limits{})
	if !pair.Valid() {
		t.Fatal("pairing failed")
	}

	matches, warning := recyclebin.CompareSize(pair.Record.OriginalSize, c.SizeBytes)
	if matches {
		t.Fatal("a mismatch was reported as a match")
	}
	if warning == "" {
		t.Fatal("a size mismatch produced no warning")
	}
	for _, want := range []string{"1048576", "both values are preserved"} {
		if !strings.Contains(warning, want) {
			t.Errorf("the warning omits %q: %s", want, warning)
		}
	}
	// Neither value moved.
	if pair.Record.OriginalSize != recorded {
		t.Errorf("the $I record's size was modified: %d", pair.Record.OriginalSize)
	}
	if c.SizeBytes != int64(len(body)) {
		t.Errorf("the measured size was modified: %d", c.SizeBytes)
	}

	// A matching pair reports a match and no warning.
	_, okPath := pairDir(t, "MATCH.docx", &rbgen.Record{
		Version: 2, Size: uint64(len(body)), Deleted: contentDeleted, Path: `C:\t\ok.docx`,
	}, body)
	okContent := recyclebin.ReadContent(okPath, 1<<20)
	okPair := recyclebin.ResolveIRecord(okPath, recyclebin.Limits{})
	m, w := recyclebin.CompareSize(okPair.Record.OriginalSize, okContent.SizeBytes)
	if !m || w != "" {
		t.Errorf("a matching pair reported mismatch=%v warning=%q", !m, w)
	}
}

// Reading is deterministic.
func TestContent_IsDeterministic(t *testing.T) {
	body := []byte("deterministic content")
	_, rPath := pairDir(t, "DET.bin", &rbgen.Record{
		Version: 2, Size: uint64(len(body)), Deleted: contentDeleted, Path: `C:\t\d.bin`,
	}, body)
	first := recyclebin.ReadContent(rPath, 1<<20)
	for i := 0; i < 20; i++ {
		again := recyclebin.ReadContent(rPath, 1<<20)
		if again.SHA256 != first.SHA256 || again.SizeBytes != first.SizeBytes || again.Status != first.Status {
			t.Fatalf("run %d differed: %+v vs %+v", i, again, first)
		}
	}
}

// The existing $I reader is untouched: a $I still parses on its own, and
// ResolvePair still reports the $R side.
func TestContent_ExistingIParserIsUnchanged(t *testing.T) {
	body := []byte("content")
	dir, _ := pairDir(t, "KEEP.docx", &rbgen.Record{
		Version: 2, Size: uint64(len(body)), Deleted: contentDeleted, Path: `C:\Users\j\keep.docx`,
	}, body)

	iPath := filepath.Join(dir, "$IKEEP.docx")
	rec, err := recyclebin.ParseFile(iPath, recyclebin.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if rec.OriginalPath != `C:\Users\j\keep.docx` || !rec.DeletionTime.Equal(contentDeleted) {
		t.Errorf("the $I parser's output changed: %+v", rec)
	}
	pair := recyclebin.ResolvePair(iPath)
	if !pair.Found || pair.Name != "$RKEEP.docx" || pair.SizeBytes != int64(len(body)) {
		t.Errorf("the $I side's pairing report changed: %+v", pair)
	}
}
