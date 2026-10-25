package api

import (
	"errors"
	"strings"
	"testing"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
)

func TestNativePersistenceCoalescingByteBoundAndSinkFailure(t *testing.T) {
	p, err := newParsedSpool(&stagingBudget{limit: 1 << 20}, model.ArtifactMFT)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	for i := 0; i < 2; i++ {
		if err = p.append(ingest.ParsedFile{Events: []model.Event{{SourceReference: "ref"}}, Raw: []model.RawEvidence{{SourceReference: "ref", Raw: strings.Repeat("a", 9<<20)}}}); err != nil {
			t.Fatal(err)
		}
	}
	if err = p.finishWrite(); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err = p.each(func(b ingest.ParsedFile) error {
		calls++
		if len(b.Events) != 1 {
			t.Fatal("decoded-byte budget was exceeded")
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatal(calls, err)
	}
	stop := errors.New("persistence stopped")
	calls = 0
	err = p.each(func(ingest.ParsedFile) error { calls++; return stop })
	if !errors.Is(err, stop) || calls != 1 {
		t.Fatal(calls, err)
	}
}
