package api

import (
	"errors"
	"os"
	"testing"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
)

func TestParsedSpoolBudgetAndCleanup(t *testing.T) {
	p, err := newParsedSpool(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	name := p.file.Name()
	st, err := p.file.Stat()
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("spool permissions: %v %v", st, err)
	}
	p.bytes = 1 << 30
	err = p.append(ingest.ParsedFile{Events: []model.Event{{SourceReference: "line:1"}}})
	var limit *ingest.ProcessFailure
	if !errors.As(err, &limit) {
		t.Fatalf("budget must stop before writing: %v", err)
	}
	st, err = p.file.Stat()
	if err != nil || st.Size() != 0 {
		t.Fatalf("budget wrote bytes: %v %v", st, err)
	}
	p.close()
	if _, err = os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging file not removed: %v", err)
	}
}
