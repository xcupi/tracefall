package evtx_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"testing"

	rawevtx "tracefall/internal/evtx"
	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/parsers"
	parser "tracefall/internal/parsers/evtx"
)

// The EVTX chunk header's free-space offset (48) is the end of the
// allocated record area, not the end of the 64 KiB physical chunk.
// Construct corrupt framing independently of the reader: extend that area
// past a complete generated record, and recompute both chunk checksums.
func TestStreamRejectsResidualRecordHeader(t *testing.T) {
	for _, zero := range []bool{false, true} {
		for n := 0; n < 24; n++ {
			t.Run(fmt.Sprintf("zero=%t/bytes=%d", zero, n), func(t *testing.T) {
				path := writeLog(t, []evtxgen.Event{ev("Security", "Microsoft-Windows-Security-Auditing", 4624, map[string]string{"TargetUserName": "alice"})})
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if len(data) != 4096+65536 {
					t.Fatalf("fixture must contain one complete physical chunk: %d", len(data))
				}
				chunk := data[4096:]
				end := int(binary.LittleEndian.Uint32(chunk[48:52]))
				fragment := []byte{0x2a, 0x2a, 0, 0, 32, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
				if zero {
					clear(fragment)
				}
				copy(chunk[end:], fragment) // n=0 leaves these bytes in legitimate unused slack.
				binary.LittleEndian.PutUint32(chunk[48:52], uint32(end+n))
				binary.LittleEndian.PutUint32(chunk[52:56], crc32.ChecksumIEEE(chunk[512:end+n]))
				headerCRC := crc32.ChecksumIEEE(append(append([]byte(nil), chunk[:120]...), chunk[128:512]...))
				binary.LittleEndian.PutUint32(chunk[124:128], headerCRC)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}

				f, err := rawevtx.Open(path, rawevtx.Limits{Strict: true})
				if err != nil {
					t.Fatal(err)
				}
				seen := 0
				stats, err := f.Walk(func(rawevtx.Record) error { seen++; return nil })
				f.Close()
				wantFailed := 0
				if n > 0 {
					wantFailed = 1
				}
				if err != nil || seen != 1 || stats.ChunksRead != 1 || stats.ChunksFailed != 0 || stats.RecordsRead != 1 || stats.RecordsFailed != wantFailed {
					t.Errorf("residual framing not accounted: seen=%d stats=%+v err=%v want_failed=%d", seen, stats, err, wantFailed)
				}
				count := 0
				cov, err := parser.New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(b parsers.ParseResult) error { count += len(b.Events); return nil })
				if n == 0 {
					if err != nil || cov == nil || cov.RecordsFailed != 0 || count != 1 {
						t.Fatalf("unused slack rejected: cov=%+v err=%v count=%d", cov, err, count)
					}
				} else if !errors.Is(err, rawevtx.ErrCorrupt) || cov == nil || cov.RecordsFailed != 1 || cov.RecordsRead != 1 || cov.Mapped != 1 || cov.LimitReached {
					t.Fatalf("truncated record header certified complete: cov=%+v err=%v", cov, err)
				}
			})
		}
	}
}
