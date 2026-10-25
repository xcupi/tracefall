package ingest

import (
	"encoding/json"
	"testing"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

func TestStreamMultiEventRecordCoverage(t *testing.T) {
	batch := &parsers.ParseResult{}
	for _, ref := range []string{"mft:64-1:created", "mft:64-1:modified"} {
		batch.Events = append(batch.Events, model.Event{SourceReference: ref})
		batch.Raw = append(batch.Raw, model.RawEvidence{SourceReference: ref})
	}
	for _, covJSON := range []string{`{"records_read":0,"mapped":0,"emitted_events":2,"undated":2}`, `{"records_read":1,"mapped":2,"emitted_events":2,"undated":2}`} {
		var cov model.ParseCoverage
		if err := json.Unmarshal([]byte(covJSON), &cov); err != nil {
			t.Fatal(err)
		}
		_, _, err := runReviewFrames(t, []streamFrame{{Batch: batch}, {Done: true, Coverage: &cov}})
		if err == nil {
			t.Fatal("output without mapped source records accepted")
		}
	}
	for _, tc := range []struct {
		emitted int
		good    bool
	}{{2, true}, {1, false}, {3, false}, {-1, false}} {
		cov := &model.ParseCoverage{}
		data, _ := json.Marshal(map[string]any{"records_read": 1, "mapped": 1, "emitted_events": tc.emitted, "undated": 2})
		if err := json.Unmarshal(data, cov); err != nil {
			t.Fatal(err)
		}
		_, _, err := runReviewFrames(t, []streamFrame{{Batch: batch}, {Done: true, Coverage: cov}})
		if (err == nil) != tc.good {
			t.Fatalf("emitted=%d: %v", tc.emitted, err)
		}
	}
}
