package usnjrnl_test

import (
	"context"
	"strings"
	"testing"

	"tracefall/internal/ntfs/mftgen"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/usnjrnl"
)

// A journal record states that a change to a name was recorded and which
// reasons were recorded. It does not state who made the change or what the
// content became, and no field or string on the event may say so.
func TestUSNEventStatesOnlyWhatTheRecordRecords(t *testing.T) {
	reasons := []uint32{mftgen.ReasonFileDelete, mftgen.ReasonFileCreate, mftgen.ReasonRenameNewName, mftgen.ReasonDataOverwrite, mftgen.ReasonSecurityChange | mftgen.ReasonClose}
	var entries []mftgen.UsnEntry
	for i, r := range reasons {
		e := entry(i, "x.txt")
		e.Reason = r
		entries = append(entries, e)
	}
	var events []map[string]string
	_, err := usnjrnl.New().ParseStream(context.Background(), write(t, journal(entries...)), parsers.ParseContext{}, func(b parsers.ParseResult) error {
		for _, e := range b.Events {
			events = append(events, e.Extra)
			if e.User != "" || e.ProcessName != "" || e.CommandLine != "" || e.Host != "" {
				t.Errorf("an actor was inferred: user=%q process=%q", e.User, e.ProcessName)
			}
		}
		return nil
	})
	if err != nil || len(events) != len(reasons) {
		t.Fatalf("%v %d", err, len(events))
	}
	for _, x := range events {
		c := x["evidence_caveat"]
		for _, want := range []string{"does not state who or what made the change", "does not describe what the content became"} {
			if !strings.Contains(c, want) {
				t.Errorf("caveat lacks %q: %q", want, c)
			}
		}
		for k, v := range x {
			l := strings.ToLower(k + "=" + v)
			for _, bad := range []string{"deleted by", "created by", "modified by", "was deleted", "user deleted", "content changed", "overwritten by"} {
				if strings.Contains(l, bad) {
					t.Errorf("overclaiming text %q in %s", bad, k)
				}
			}
		}
		if x["usn_reason_flags"] == "" || x["usn_reason_hex"] == "" {
			t.Error("the recorded reasons must travel with the event")
		}
	}
}
