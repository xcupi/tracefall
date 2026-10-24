package api

import (
	"os"
	"strings"
	"testing"
)

// This contract guard also runs in the UI-only worktree, without batch backend symbols.
func TestUI_BatchReviewLocalPlanningInsideExistingCard(t *testing.T) {
	b, err := os.ReadFile("../web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"Build batch plan", "mountBatchReview", "distinct_successful_events", "unsynthesized_batches", "provider_binding", "primary_reviewed_events"} {
		if !strings.Contains(s, want) {
			t.Errorf("batch UI missing %q", want)
		}
	}
	if n := strings.Count(s, `class="panel external-card"`); n != 4 {
		t.Errorf("external cards = %d, want 4", n)
	}
}
