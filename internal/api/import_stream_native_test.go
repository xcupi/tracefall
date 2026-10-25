package api

import (
	"reflect"
	"strings"
	"testing"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
)

func TestNativeSpoolCompressedBudget(t *testing.T) {
	budget := &stagingBudget{limit: 16384}
	p, err := newParsedSpool(budget, model.ArtifactMFT)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	batch := ingest.ParsedFile{Events: []model.Event{{SourceReference: "mft:64-1:created", FilePath: strings.Repeat("a", 100000)}}, Raw: []model.RawEvidence{{SourceReference: "mft:64-1:created", Raw: strings.Repeat("raw", 100000)}}}
	if err = p.append(batch); err != nil {
		t.Fatalf("native spool did not compress within unchanged disk budget: %v", err)
	}
	if err = p.finishWrite(); err != nil {
		t.Fatal(err)
	}
	if p.compressor != nil || p.buffer.Cap() != 0 {
		t.Fatal("completed source retained compression buffers")
	}
	count := 0
	if err = p.each(func(got ingest.ParsedFile) error {
		count++
		if !reflect.DeepEqual(got, batch) {
			t.Fatal("staged evidence changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 || budget.used >= 16384 {
		t.Fatal(count, budget)
	}
}
