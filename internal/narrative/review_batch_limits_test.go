package narrative

import (
	"errors"
	"strings"
	"testing"
)

func TestReviewBatchFinalCombinedSizeIncludesAddedInstructions(t *testing.T) {
	p := &ReviewPrepared{Prepared: &Prepared{System: strings.Repeat("x", ReviewMaxBytes), User: "added synthesis/catalog text"}}
	if err := CheckReviewBatchSize(p); !errors.Is(err, ErrReviewTooLarge) {
		t.Fatalf("expanded system plus user exceeded hard packet limit but accepted: %v", err)
	}
	p.User = ""
	if err := CheckReviewBatchSize(p); err != nil || p.Privacy.PayloadBytes != ReviewMaxBytes {
		t.Fatalf("exact boundary/receipt: %v %+v", err, p.Privacy)
	}
}
