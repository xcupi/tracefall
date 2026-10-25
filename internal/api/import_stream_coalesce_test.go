package api

import (
	"fmt"
	"testing"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
)

func TestNativePersistenceCoalescesWithinFixedBounds(t *testing.T) {
	p, err := newParsedSpool(&stagingBudget{limit: 1 << 20}, model.ArtifactMFT)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	for j := 0; j < 9; j++ {
		var b ingest.ParsedFile
		for i := 0; i < 128; i++ {
			ref := fmt.Sprintf("mft:%d-1:created", j*128+i)
			b.Events = append(b.Events, model.Event{SourceReference: ref})
			b.Raw = append(b.Raw, model.RawEvidence{SourceReference: ref, Raw: ref})
		}
		if err = p.append(b); err != nil {
			t.Fatal(err)
		}
	}
	if err = p.finishWrite(); err != nil {
		t.Fatal(err)
	}
	calls, total := 0, 0
	err = p.each(func(b ingest.ParsedFile) error {
		calls++
		total += len(b.Events)
		if len(b.Events) > 1024 || len(b.Events) != len(b.Raw) {
			t.Fatal("persistence batch bound/pairing")
		}
		for i, e := range b.Events {
			if e.SourceReference != b.Raw[i].SourceReference {
				t.Fatal("unpaired staged evidence")
			}
		}
		return nil
	})
	if err != nil || calls != 2 || total != 1152 {
		t.Fatalf("expected bounded coalescing, calls=%d total=%d err=%v", calls, total, err)
	}
}
