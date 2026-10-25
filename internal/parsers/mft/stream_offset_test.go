package mft_test

import (
	"context"
	"testing"
	"tracefall/internal/ntfs/mftgen"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/mft"
)

func TestStreamRetainsPhysicalOffset(t *testing.T) {
	path := write(t, table(mftgen.File{RecordNumber: 64, SequenceNumber: 1, SI: si(), Names: []mftgen.Name{{Name: "file.txt", Namespace: 1, ParentRef: 40, ParentSeq: 1}}}))
	_, err := mft.New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(b parsers.ParseResult) error {
		for _, e := range b.Events {
			if e.Extra["mft_record_number"] == "64" && (e.Extra["mft_record_offset"] != "65536" || e.Extra["mft_record_size"] != "1024") {
				t.Fatal("missing physical record location")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
