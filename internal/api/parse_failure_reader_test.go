package api

import (
	"fmt"
	"strings"
	"testing"

	"tracefall/internal/parsers/mssqlxe"
)

// An optional reader that is not configured is not damaged evidence and not an
// internal fault. The analyst must be told the file is intact and what to set.
func TestClassifyParseError_OptionalReaderUnavailableIsNotAnInternalError(t *testing.T) {
	err := fmt.Errorf("%w: configure TRACEFALL_MSSQL_READER", mssqlxe.ErrReaderUnavailable)
	cat, msg := classifyParseError(err)
	if cat != ParseFailureOptionalReader {
		t.Fatalf("category = %q, want %q", cat, ParseFailureOptionalReader)
	}
	for _, want := range []string{"intact", "TRACEFALL_MSSQL_READER"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q must mention %q", msg, want)
		}
	}
}
