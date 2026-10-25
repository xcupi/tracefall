package mft_test

import (
	"context"
	"encoding/binary"
	"os"
	"testing"
	"tracefall/internal/ntfs/mftgen"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/mft"
)

func TestStreamRejectsMalformedTable(t *testing.T) {
	for _, kind := range []string{"non-file", "used-size", "truncated", "name-bounds", "surrogate"} {
		t.Run(kind, func(t *testing.T) {
			b := table(mftgen.File{RecordNumber: 64, SequenceNumber: 1, InUse: true, SI: si(), Names: []mftgen.Name{{Name: "file.txt", Namespace: 1, ParentRef: 40, ParentSeq: 1}}})
			switch kind {
			case "name-bounds", "surrogate":
				record := b[64*1024 : 65*1024]
				off := int(binary.LittleEndian.Uint16(record[20:]))
				for binary.LittleEndian.Uint32(record[off:]) != 0x30 {
					off += int(binary.LittleEndian.Uint32(record[off+4:]))
				}
				value := off + int(binary.LittleEndian.Uint16(record[off+20:]))
				if kind == "name-bounds" {
					record[value+64] = 255
				} else {
					binary.LittleEndian.PutUint16(record[value+66:], 0xd800)
				}
			case "non-file":
				b = append(b, make([]byte, 1024)...)
				b[len(b)-1024] = 1
			case "used-size":
				binary.LittleEndian.PutUint32(b[64*1024+24:], 2000)
			case "truncated":
				b = append(b, 1)
			}
			cov, err := mft.New().ParseStream(context.Background(), write(t, b), parsers.ParseContext{}, func(parsers.ParseResult) error { return nil })
			if err == nil || cov.RecordsFailed == 0 {
				t.Fatalf("accepted malformed %s: %+v %v", kind, cov, err)
			}
		})
	}
}
func TestStreamBeyondLegacySlotLimit(t *testing.T) {
	path := write(t, table())
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	// A sparse synthetic table has no retained per-slot state.
	if err = f.Truncate(1_000_001 * 1024); err != nil {
		t.Fatal(err)
	}
	f.Close()
	cov, err := mft.New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { return nil })
	if err != nil || cov.LimitReached {
		t.Fatalf("bounded scan still uses legacy slot cap: %+v %v", cov, err)
	}
}
func TestStreamBatchBoundWithMissingTimes(t *testing.T) {
	var files []mftgen.File
	for i := 0; i < 100; i++ {
		times := si()
		times.Accessed = times.Accessed.AddDate(-100, 0, 0)
		files = append(files, mftgen.File{RecordNumber: uint64(64 + i), SequenceNumber: 1, SI: times, Names: []mftgen.Name{{Name: "file.txt", Namespace: 1, ParentRef: 40, ParentSeq: 1}}})
	}
	_, err := mft.New().ParseStream(context.Background(), write(t, table(files...)), parsers.ParseContext{}, func(b parsers.ParseResult) error {
		if len(b.Events) > 128 {
			t.Fatalf("batch grew to %d", len(b.Events))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
