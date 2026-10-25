package usnjrnl_test

import (
	"context"
	"strings"
	"testing"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/usnjrnl"
)

func TestStreamReportsNonRecordRegions(t *testing.T) {
	b := nativeUSN()
	b = append(b, []byte("NONREC!!")...)
	// A random aligned block can have a plausible length but no USN version.
	b = append(b, 72, 0, 0, 0, 0, 0, 0, 0)
	b = append(b, make([]byte, 64)...)
	b = append(b, 0, 0, 0, 0, 4, 0, 0, 0) // no plausible USN record length
	b = append(b, 0, 0, 0, 0, 2, 0, 9, 0) // random words inside an already unrecognized region
	b = append(b, nativeUSN()...)         // a fully coherent next record restores framing
	n := 0
	cov, err := usnjrnl.New().ParseStream(context.Background(), write(t, b), parsers.ParseContext{}, func(b parsers.ParseResult) error { n += len(b.Events); return nil })
	if err != nil || n != 2 || cov.RecordsRead != 2 || cov.Mapped != 2 || len(cov.Notes) == 0 || !strings.Contains(strings.Join(cov.Notes, " "), "non-record") {
		t.Fatalf("non-record region not disclosed separately from decoded records: n=%d cov=%+v err=%v", n, cov, err)
	}
}
