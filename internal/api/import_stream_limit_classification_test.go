package api

import (
	"fmt"
	"testing"
	"tracefall/internal/ntfs"
)

func TestNativeReaderSafetyLimitClassification(t *testing.T) {
	for _, tc := range []struct {
		err      error
		category string
	}{{ntfs.ErrLimitExceeded, ParseFailureLimit}, {ntfs.ErrCorrupt, ParseFailureCorrupt}, {ntfs.ErrNotUSN, ParseFailureUnsupported}, {ntfs.ErrUnsupportedUSNVersion, ParseFailureUnsupported}} {
		category, message := ClassifyParseError(fmt.Errorf("reader: %w", tc.err))
		if category != tc.category || message == "" {
			t.Fatalf("native error %v classified %q, expected %q", tc.err, category, tc.category)
		}
	}
}
