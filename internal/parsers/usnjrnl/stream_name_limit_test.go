package usnjrnl_test

import (
	"context"
	"encoding/binary"
	"testing"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/usnjrnl"
)

func TestStreamNameLimitFailsWithoutTruncation(t *testing.T) {
	b := make([]byte, 600)
	copy(b, nativeUSN())
	binary.LittleEndian.PutUint32(b, 600)
	binary.LittleEndian.PutUint16(b[56:], 540)
	for i := 60; i < 600; i += 2 {
		b[i] = 'a'
	}
	n := 0
	cov, err := usnjrnl.New().ParseStream(context.Background(), write(t, b), parsers.ParseContext{}, func(b parsers.ParseResult) error { n += len(b.Events); return nil })
	if err == nil || !cov.LimitReached || n != 0 {
		t.Fatalf("name was silently shortened: n=%d cov=%+v err=%v", n, cov, err)
	}
}
