package recyclebincontent_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	parser "tracefall/internal/parsers/recyclebincontent"
	"tracefall/internal/recyclebin/rbgen"
)

var deleted = time.Date(2026, 5, 21, 14, 32, 8, 0, time.UTC)

// bin writes a Recycle Bin directory holding the requested halves.
func bin(t *testing.T, id string, rec *rbgen.Record, content []byte) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "$Recycle.Bin", "S-1-5-21-1004336348-1177238915-682003330-1001")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if rec != nil {
		if err := os.WriteFile(filepath.Join(dir, "$I"+id), rbgen.Build(*rec), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rPath := filepath.Join(dir, "$R"+id)
	if content != nil {
		if err := os.WriteFile(rPath, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return rPath
}

// only returns the single record a $R file produces.
func only(t *testing.T, path string) (model.RawEvidence, map[string]any) {
	t.Helper()
	res, err := parser.New().Parse(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(res.Events) != 0 {
		t.Fatalf("a $R file produced %d timeline events; the deletion is timestamped by the $I record", len(res.Events))
	}
	if len(res.Raw) != 1 {
		t.Fatalf("got %d raw records, want 1", len(res.Raw))
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(res.Raw[0].Raw), &decoded); err != nil {
		t.Fatalf("the record is not valid JSON: %v", err)
	}
	return res.Raw[0], decoded
}

// Detection: the format's naming rule, inside a Recycle Bin, and nowhere
// else. Content can never identify a $R file.
func TestParser_DetectionIsByPairNamingInsideARecycleBin(t *testing.T) {
	p := parser.New()
	for _, name := range []string{
		`C/$Recycle.Bin/S-1-5-21-1/$RA1B2C3.docx`,
		`C/$RECYCLE.BIN/S-1-5-21-1/$rA1B2C3.docx`,
		`D/RECYCLER/S-1-5-21-1/$RABC`,
	} {
		if !p.Detect(name) {
			t.Errorf("%q was not detected as recovered content", name)
		}
	}
	for _, name := range []string{
		// Right name, wrong place.
		"Users/j/Documents/$RA1B2C3.docx",
		// Right place, wrong name -- this is the metadata half.
		`C/$Recycle.Bin/S-1-5-21-1/$IA1B2C3.docx`,
		// Right place, no pair identifier.
		`C/$Recycle.Bin/S-1-5-21-1/$R`,
		`C/$Recycle.Bin/S-1-5-21-1/desktop.ini`,
		"",
	} {
		if p.Detect(name) {
			t.Errorf("%q was wrongly claimed as recovered content", name)
		}
	}
	// Content proves nothing about a $R file, so it is never consulted.
	for _, data := range [][]byte{
		[]byte("%PDF-1.7"), {0x4D, 0x5A}, make([]byte, 512), {},
	} {
		if p.DetectContent(data) {
			t.Error("a $R file was claimed by content; its bytes are the deleted file's bytes")
		}
	}
	if p.ArtifactType() != model.ArtifactRecycleBinContent {
		t.Errorf("artifact type = %q", p.ArtifactType())
	}
}

// A valid pair: content measured here, identity attributed to the $I.
func TestParser_ValidPairRecoversContentAndMetadata(t *testing.T) {
	body := []byte("the contents of a deliberately deleted document")
	path := bin(t, "A1B2C3.docx", &rbgen.Record{
		Version: 2, Size: uint64(len(body)), Deleted: deleted,
		Path: `C:\Users\jdoe\Documents\confidential-plan.docx`,
	}, body)

	raw, doc := only(t, path)

	// --- measured from THIS file ---
	content := doc["content"].(map[string]any)
	if content["status"] != "recovered" {
		t.Errorf("status = %v", content["status"])
	}
	if int64(content["recovered_size"].(float64)) != int64(len(body)) {
		t.Errorf("recovered size = %v, want %d", content["recovered_size"], len(body))
	}
	want := sha256.Sum256(body)
	if content["sha256"] != hex.EncodeToString(want[:]) {
		t.Errorf("sha256 = %v", content["sha256"])
	}
	if content["measured_from"] != "$RA1B2C3.docx" {
		t.Errorf("the hash is not attributed to the $R file: %v", content["measured_from"])
	}

	// --- taken from the PAIRED $I, and attributed to it ---
	meta := doc["metadata"].(map[string]any)
	if meta["resolved"] != true {
		t.Fatalf("the pairing did not resolve: %v", meta)
	}
	if meta["source"] != "$IA1B2C3.docx" {
		t.Errorf("metadata source = %v", meta["source"])
	}
	if meta["original_path"] != `C:\Users\jdoe\Documents\confidential-plan.docx` {
		t.Errorf("original path = %v", meta["original_path"])
	}
	if meta["original_name"] != "confidential-plan.docx" {
		t.Errorf("original name = %v", meta["original_name"])
	}
	if meta["deletion_time"] != "2026-05-21T14:32:08Z" {
		t.Errorf("deletion time = %v", meta["deletion_time"])
	}
	if int64(meta["original_size"].(float64)) != int64(len(body)) {
		t.Errorf("original size = %v", meta["original_size"])
	}
	if raw.SourceReference != "recyclebin-content:$RA1B2C3.docx" {
		t.Errorf("source reference = %q", raw.SourceReference)
	}
}

// The $R filename is never mistaken for the original filename.
func TestParser_RFilenameIsNeverTheOriginalName(t *testing.T) {
	body := []byte("x")
	path := bin(t, "ZZZZZZ.docx", &rbgen.Record{
		Version: 2, Size: 1, Deleted: deleted, Path: `C:\Users\j\quarterly-report.docx`,
	}, body)
	res, err := parser.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	// Not asserted through the JSON alone: the flat extra map is what a
	// UI renders, and it must not carry the $R name as an original name.
	raw := res.Raw[0].Raw
	if !strings.Contains(raw, `"original_name":"quarterly-report.docx"`) {
		t.Errorf("the original name did not come from the $I record: %s", raw)
	}
	if strings.Contains(raw, `"original_name":"$RZZZZZZ.docx"`) {
		t.Error("the $R filename was reported as the original filename")
	}
}

// Requirement 5, case by case.
func TestParser_EveryPairingOutcomeIsReportedDistinctly(t *testing.T) {
	body := []byte("content")

	t.Run("missing $I", func(t *testing.T) {
		path := bin(t, "ORPH.docx", nil, body)
		_, doc := only(t, path)
		if doc["pairing_status"] != "orphan" {
			t.Errorf("pairing status = %v, want orphan", doc["pairing_status"])
		}
		meta := doc["metadata"].(map[string]any)
		if meta["resolved"] != false {
			t.Error("an orphan resolved metadata")
		}
		for _, field := range []string{"original_path", "deletion_time", "original_size"} {
			if meta[field] != nil {
				t.Errorf("%s was invented for an orphan: %v", field, meta[field])
			}
		}
		// Content is still measured -- the file is real.
		if doc["content"].(map[string]any)["status"] != "recovered" {
			t.Error("an orphan's content was not measured")
		}
		if doc["content"].(map[string]any)["sha256"] == nil {
			t.Error("an orphan's content was not hashed")
		}
	})

	t.Run("invalid $I", func(t *testing.T) {
		path := bin(t, "BAD.docx", nil, body)
		if err := os.WriteFile(filepath.Join(filepath.Dir(path), "$IBAD.docx"),
			[]byte("this is not a metadata record"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, doc := only(t, path)
		if doc["pairing_status"] != "invalid" {
			t.Errorf("pairing status = %v, want invalid -- present but unreadable differs from absent",
				doc["pairing_status"])
		}
		if doc["metadata"].(map[string]any)["resolved"] != false {
			t.Error("an invalid pairing resolved metadata")
		}
	})

	t.Run("unreadable $R", func(t *testing.T) {
		path := bin(t, "DIR.docx", &rbgen.Record{
			Version: 2, Size: 10, Deleted: deleted, Path: `C:\t\f.docx`,
		}, nil)
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
		_, doc := only(t, path)
		content := doc["content"].(map[string]any)
		if content["status"] != "unreadable" {
			t.Errorf("status = %v, want unreadable", content["status"])
		}
		if content["sha256"] != nil {
			t.Error("a hash was reported for content that was never read")
		}
		if content["read_error"] == nil {
			t.Error("no reason was given for the failed read")
		}
		// The metadata still resolves -- the $I is fine.
		if doc["metadata"].(map[string]any)["resolved"] != true {
			t.Error("an unreadable $R prevented its $I from being read")
		}
	})

	t.Run("size mismatch", func(t *testing.T) {
		path := bin(t, "MIS.docx", &rbgen.Record{
			Version: 2, Size: 999999, Deleted: deleted, Path: `C:\t\big.docx`,
		}, body)
		_, doc := only(t, path)
		if int64(doc["metadata"].(map[string]any)["original_size"].(float64)) != 999999 {
			t.Error("the $I record's size was adjusted to match the file")
		}
		if int64(doc["content"].(map[string]any)["recovered_size"].(float64)) != int64(len(body)) {
			t.Error("the measured size was adjusted to match the record")
		}
		warnings := strings.Join(toStrings(doc["warnings"]), " ")
		if !strings.Contains(warnings, "999999") || !strings.Contains(warnings, "both values are preserved") {
			t.Errorf("the mismatch was not warned about: %s", warnings)
		}
	})
}

// Never claim recovery that did not happen.
func TestParser_NeverClaimsUnverifiedRecovery(t *testing.T) {
	path := bin(t, "GONE.docx", &rbgen.Record{
		Version: 2, Size: 5, Deleted: deleted, Path: `C:\t\gone.docx`,
	}, nil) // no $R written at all
	_, doc := only(t, path)
	content := doc["content"].(map[string]any)
	if content["status"] == "recovered" {
		t.Error("a file that does not exist was reported as recovered")
	}
	if content["sha256"] != nil {
		t.Error("a hash was produced for a file that was never read")
	}
}

// Provenance: every record says where each half of its story came from.
func TestParser_ProvenanceNamesBothSources(t *testing.T) {
	body := []byte("content")
	path := bin(t, "PROV.docx", &rbgen.Record{
		Version: 2, Size: uint64(len(body)), Deleted: deleted, Path: `C:\t\p.docx`,
	}, body)
	res, err := parser.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	raw := res.Raw[0].Raw
	for _, want := range []string{
		// The content half names the file it was measured from.
		`"measured_from":"$RPROV.docx"`,
		// The metadata half names the record it was taken from, twice:
		// on the pairing and on the metadata block itself.
		`"source":"$IPROV.docx"`,
		`"paired_i_file":"$IPROV.docx"`,
		// And the record says in words which facts are borrowed.
		"come from the paired $I record named above",
		"are measured from this file",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("the record does not state %q:\n%s", want, raw)
		}
	}
}

// Determinism.
func TestParser_IsDeterministic(t *testing.T) {
	body := []byte("deterministic")
	path := bin(t, "DET.bin", &rbgen.Record{
		Version: 2, Size: uint64(len(body)), Deleted: deleted, Path: `C:\t\d.bin`,
	}, body)
	p := parser.New()
	first, err := p.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := p.Parse(path)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if again.Raw[0].Raw != first.Raw[0].Raw || again.Raw[0].SourceReference != first.Raw[0].SourceReference {
			t.Fatalf("run %d differed", i)
		}
	}
}

func toStrings(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
