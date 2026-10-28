package api

import (
	"context"
	"fmt"
	"os"
	"testing"

	"tracefall/internal/model"
)

func TestReport_CitedPaddedOnlyReferencesDoNotBecomeTimelineKeys(t *testing.T) {
	s, id, _ := citedFixture(t)
	refs := make([]string, 0, 520)
	raw := map[string]bool{}
	for i := 0; i < 520; i++ {
		ref := fmt.Sprintf(" event-%03d ", i)
		refs = append(refs, ref)
		raw[ref] = true
	}
	cor := model.Correlation{ID: "padded-only", CaseID: id, EventIDs: refs}
	file, c, err := s.spoolReportCited(context.Background(), id, refs, nil, []model.Correlation{cor})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Path)
	old, err := s.store.EventsByIDs(refs)
	if err != nil {
		t.Fatal(err)
	}
	want := reportTimeline(newTimelineAgg(), old, raw, nil)
	if len(want.Key) != 0 || want.KeyOmitted != 0 {
		t.Fatal("baseline fixture must have no exact raw cited membership")
	}
	if len(c.key) != len(want.Key) || c.keyOmitted != want.KeyOmitted {
		t.Fatalf("padded-only references changed key selection: key=%d omitted=%d; baseline key=%d omitted=%d", len(c.key), c.keyOmitted, len(want.Key), want.KeyOmitted)
	}
	if c.rows != 520 || len(c.meta) != 520 {
		t.Fatal("normalized attachment resolution was lost")
	}
	for _, ref := range refs {
		if _, ok := c.lookup(ref); ok {
			t.Fatal("padded reference incorrectly resolved for HTML")
		}
	}
}
