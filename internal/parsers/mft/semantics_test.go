package mft_test

import (
	"strings"
	"testing"

	"tracefall/internal/ntfs/mftgen"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/mft"
)

// $STANDARD_INFORMATION times can be set by software, $FILE_NAME times are
// carried only as context, and a free record is not a deletion instant.
func TestMFTEventsDoNotOverclaim(t *testing.T) {
	data := mftgen.Build([]mftgen.File{
		{RecordNumber: 0, SequenceNumber: 1, InUse: true, SI: si(), Names: nameOf("a.txt")},
		{RecordNumber: 1, SequenceNumber: 4, InUse: false, SI: si(), Names: nameOf("gone.txt")},
	})
	res, err := mft.New().Parse(write(t, data))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 8 {
		t.Fatalf("events=%d", len(res.Events))
	}
	for _, e := range res.Events {
		if e.User != "" || e.ProcessName != "" || e.Host != "" {
			t.Errorf("actor inferred")
		}
		x := e.Extra
		if x["timestamp_source"] != "$STANDARD_INFORMATION" {
			t.Errorf("source of the event time: %q", x["timestamp_source"])
		}
		c := x["evidence_caveat"]
		for _, want := range []string{"can be set by software", "timestomping", "$FILE_NAME times are context"} {
			if !strings.Contains(c, want) {
				t.Errorf("caveat lacks %q: %q", want, c)
			}
		}
		if x["fn_created"] == "" {
			t.Error("the $FILE_NAME times must stay as context")
		}
		free := x["allocation_state"] != "in use"
		if free && !strings.Contains(c, "a free record is not a deletion instant") {
			t.Errorf("free record without its caveat: %q", c)
		}
		if !free && strings.Contains(c, "free record") {
			t.Errorf("in-use record carries the free caveat")
		}
		for k, v := range x {
			l := strings.ToLower(k + "=" + v)
			for _, bad := range []string{"deleted at", "deletion time:", "was deleted", "deleted by", "created by user"} {
				if strings.Contains(l, bad) {
					t.Errorf("overclaiming text %q in %s", bad, k)
				}
			}
		}
	}
	_ = parsers.ParseResult{}
}
