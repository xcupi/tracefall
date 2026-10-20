package ingest

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

// A large result must be written without first building the whole document in
// memory: that doubled a worker's memory use for a large file system table and
// ran it out of its address-space limit. This checks that the streamed form is
// the same document the one-shot encoding would give, so the reader needs no
// special case.
func TestWriteResult_IsTheSameDocumentAsAOneShotEncoding(t *testing.T) {
	res := parsers.ParseResult{}
	for i := 0; i < 500; i++ {
		res.Events = append(res.Events, model.Event{Timestamp: time.Unix(int64(i), 0).UTC(), EventType: "process_start", Host: "h"})
	}
	var streamed bytes.Buffer
	if err := writeResult(&streamed, res); err != nil {
		t.Fatal(err)
	}
	var a, b workerResponse
	if err := json.Unmarshal(streamed.Bytes(), &a); err != nil {
		t.Fatalf("streamed document is not valid JSON: %v", err)
	}
	oneShot, _ := json.Marshal(workerResponse{Result: &res})
	if err := json.Unmarshal(oneShot, &b); err != nil {
		t.Fatal(err)
	}
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	if !bytes.Equal(x, y) {
		t.Fatal("streamed result differs from the one-shot encoding")
	}
	if len(a.Result.Events) != 500 {
		t.Fatalf("events %d, want 500", len(a.Result.Events))
	}

	empty := bytes.Buffer{}
	if err := writeResult(&empty, parsers.ParseResult{}); err != nil || !json.Valid(empty.Bytes()) {
		t.Fatalf("an empty result is not valid JSON: %v %q", err, empty.String())
	}
}
