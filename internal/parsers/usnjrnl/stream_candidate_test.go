package usnjrnl_test

import (
	"context"
	"encoding/binary"
	"testing"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/usnjrnl"
)

func TestStreamDoesNotInventRecordsFromUnknownBytes(t *testing.T) {
	fake := nativeUSN()
	binary.LittleEndian.PutUint64(fake[32:], 0)
	b := append([]byte("NONREC!!"), fake...)
	cov, err := usnjrnl.New().ParseStream(context.Background(), write(t, b), parsers.ParseContext{}, func(parsers.ParseResult) error { t.Fatal("invented event"); return nil })
	if err == nil || cov.RecordsRead != 0 {
		t.Fatalf("arbitrary bytes were promoted to a record: %+v %v", cov, err)
	}
}
