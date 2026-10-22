package ingest_test

import (
	"os"
	"path/filepath"
	"testing"
	"tracefall/internal/ingest"
)

func TestMSSQLRequiresRecognizableContentEvenEmpty(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "ERRORLOG"), nil, 0600)
	d, err := ingest.Discover(root, ingest.Registry())
	if err != nil {
		t.Fatal(err)
	}
	if len(d) != 1 || d[0].Supported {
		t.Fatal("empty generic name claimed", d)
	}
	if ingest.MatchParser("ERRORLOG", nil, ingest.Registry()) != nil {
		t.Fatal("headerless name claimed")
	}
}
