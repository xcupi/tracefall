package usnjrnl_test

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/usnjrnl"
)

// Independently encoded MS-USN_RECORD_V2 layout; no production encoder.
func nativeUSN() []byte {
	b := make([]byte, 72)
	binary.LittleEndian.PutUint32(b, 72)
	binary.LittleEndian.PutUint16(b[4:], 2)
	binary.LittleEndian.PutUint64(b[8:], uint64(2)<<48|64)
	binary.LittleEndian.PutUint64(b[16:], uint64(5)<<48|5)
	binary.LittleEndian.PutUint64(b[24:], 128)
	binary.LittleEndian.PutUint64(b[32:], uint64(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix()+11644473600)*10000000)
	binary.LittleEndian.PutUint32(b[40:], 0x100)
	binary.LittleEndian.PutUint16(b[56:], 10)
	binary.LittleEndian.PutUint16(b[58:], 60)
	for i, c := range "a.txt" {
		binary.LittleEndian.PutUint16(b[60+i*2:], uint16(c))
	}
	return b
}
func TestStreamRejectsMalformedJournal(t *testing.T) {
	for _, kind := range []string{"truncated", "odd-name", "bad-offset", "surrogate", "truncated-next-record", "unsupported-version", "oversized-record", "misaligned-record"} {
		t.Run(kind, func(t *testing.T) {
			b := nativeUSN()
			switch kind {
			case "unsupported-version":
				binary.LittleEndian.PutUint16(b[4:], 4)
			case "oversized-record":
				binary.LittleEndian.PutUint32(b, 1<<30)
			case "misaligned-record":
				binary.LittleEndian.PutUint32(b, 71)
			case "truncated":
				b = b[:65]
			case "odd-name":
				binary.LittleEndian.PutUint16(b[56:], 9)
			case "bad-offset":
				binary.LittleEndian.PutUint16(b[58:], 74)
			case "surrogate":
				binary.LittleEndian.PutUint16(b[60:], 0xd800)
			case "truncated-next-record":
				b = append(b, 64, 0, 0, 0, 2, 0, 0, 0)
			}
			if kind == "oversized-record" || kind == "misaligned-record" {
				b = append(nativeUSN(), b...)
			}
			path := filepath.Join(t.TempDir(), "$J")
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			cov, err := usnjrnl.New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { return nil })
			if err == nil || cov.RecordsFailed == 0 {
				t.Fatalf("malformed source accepted: %+v %v", cov, err)
			}
		})
	}
}
