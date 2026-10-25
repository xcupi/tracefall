package parsers

import (
	"context"
	"tracefall/internal/model"
)

// RecordSink consumes a batch synchronously. Returning an error stops parsing;
// implementations must not retain the batch after returning without copying it.
// Raw remains positionally paired with Events, as in ParseResult.
type RecordSink func(ParseResult) error

// StreamingParser is an optional bounded alternative to Parse. Coverage is
// returned even on cancellation or failure; only a nil error means EOF was
// reached. A sink error must be propagated without reading the remaining file.
type StreamingParser interface {
	ParseStream(context.Context, string, ParseContext, RecordSink) (*model.ParseCoverage, error)
}
