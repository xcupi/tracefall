package recyclebin_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	parser "tracefall/internal/parsers/recyclebin"
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

func record() []byte {
	return rbgen.Build(rbgen.Record{
		Version: 2, Size: 4096, Deleted: deleted, Path: `C:\Users\j\Documents\a.docx`,
	})
}

// Detection is structural only: no filename is ever claimed.
func TestParser_DetectionIsStructuralOnly(t *testing.T) {
	p := parser.New()
	for _, name := range []string{
		"$IA1B2C3.docx", `$Recycle.Bin/S-1-5-21-1/$IA1B2C3.docx`, "$I", "anything.bin",
	} {
		if p.Detect(name) {
			t.Errorf("%q was claimed by filename", name)
		}
	}
	if !p.DetectContent(record()) {
		t.Error("a real record was not content-detected")
	}
	for name, data := range map[string][]byte{
		"text":        []byte(strings.Repeat("not a record ", 40)),
		"zeros":       make([]byte, 600),
		"bad version": rbgen.WithVersion(record(), 9),
		"empty":       {},
	} {
		if p.DetectContent(data) {
			t.Errorf("%q was content-detected as a record", name)
		}
	}
	if p.ArtifactType() != model.ArtifactRecycleBin {
		t.Errorf("artifact type = %q", p.ArtifactType())
	}
}

// Exactly one event, labelled a deletion, never a write.
func TestParser_OneDeletionEvent(t *testing.T) {
	res, err := parser.New().Parse(write(t, "", "$IA1B2C3.docx", record()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 || len(res.Raw) != 1 {
		t.Fatalf("got %d events / %d raw records, want 1 each", len(res.Events), len(res.Raw))
	}
	e := res.Events[0]
	if e.EventType != model.EventRecycleBinDeletion {
		t.Errorf("event type = %q", e.EventType)
	}
	if !e.Timestamp.Equal(deleted) || e.Timestamp.Location() != time.UTC {
		t.Errorf("timestamp = %s", e.Timestamp)
	}
	if e.Extra["timestamp_meaning"] != "Recycle Bin deletion time" {
		t.Errorf("timestamp meaning = %q", e.Extra["timestamp_meaning"])
	}
	for _, banned := range []string{"modified", "write", "execution", "created"} {
		if strings.Contains(e.EventType, banned) {
			t.Errorf("event type %q reads as %q", e.EventType, banned)
		}
	}
	if e.Confidence != 1.0 {
		t.Errorf("confidence = %v; the record states the deletion time directly", e.Confidence)
	}
	if !strings.Contains(res.Raw[0].Raw, `"content_extracted":false`) {
		t.Error("the record does not state that the deleted content was not read")
	}
}

// A record with no usable time keeps its metadata and makes no event.
func TestParser_NoTimeMakesNoEvent(t *testing.T) {
	res, err := parser.New().Parse(write(t, "", "$IA1B2C3.docx", rbgen.Build(rbgen.Record{
		Version: 2, Size: 10, Path: `C:\t\f.bin`, HasRawTime: true, RawFileTime: 0,
	})))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		t.Errorf("got %d events from a record with no deletion time", len(res.Events))
	}
	if len(res.Raw) != 1 {
		t.Errorf("got %d raw records, want 1 metadata record", len(res.Raw))
	}
}

// The $I record never claims to carry the deleted content.
func TestParser_NeverClaimsTheContent(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "$IA1B2C3.docx", record())
	res, err := parser.New().Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	e := res.Events[0]
	if !strings.Contains(e.Extra["evidence_meaning"], "deleted content is in the paired $R file") {
		t.Errorf("the record does not say where the content is: %q", e.Extra["evidence_meaning"])
	}
	if !strings.Contains(e.Extra["paired_r_file_status"], "not present") {
		t.Errorf("an uncollected $R was not reported as absent: %q", e.Extra["paired_r_file_status"])
	}
}

func TestParser_IsDeterministic(t *testing.T) {
	path := write(t, "", "$IA1B2C3.docx", record())
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
		if again.Raw[0].Raw != first.Raw[0].Raw ||
			!again.Events[0].Timestamp.Equal(first.Events[0].Timestamp) {
			t.Fatalf("run %d differed", i)
		}
	}
}

func TestParser_RefusesNonRecords(t *testing.T) {
	_, err := parser.New().Parse(write(t, "", "$IA1B2C3.docx", []byte("just text, despite the name")))
	if err == nil {
		t.Fatal("a text file parsed as an $I record")
	}
}
