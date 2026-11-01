package ingest

import (
	"context"
	"time"
)

type segmentedStreamKey struct{}

// WithSegmentedStream marks a streaming parse whose consumer persists every
// batch durably before asking for the next one (store segmented admission).
// For such a parse the worker deadline is a stall limit -- it restarts after
// every consumed frame -- and the output cap bounds one run between frames,
// instead of one absolute deadline and one cumulative cap for the whole
// source. A parse without this mark keeps the original whole-source limits.
func WithSegmentedStream(ctx context.Context) context.Context {
	return context.WithValue(ctx, segmentedStreamKey{}, true)
}

func segmentedStream(ctx context.Context) bool {
	v, _ := ctx.Value(segmentedStreamKey{}).(bool)
	return v
}

// segmentedCeiling is the safety upper bound of a segmented parse that keeps
// making progress. It is deliberately generous; a stall is caught far earlier.
func (s Subprocess) segmentedCeiling() time.Duration {
	if s.SegmentedCeiling > 0 {
		return s.SegmentedCeiling
	}
	return 72 * time.Hour
}
