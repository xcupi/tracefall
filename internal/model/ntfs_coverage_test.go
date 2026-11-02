package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func ptr[T any](v T) *T { return &v }

func TestNtfsCoverage_MFTSummaryNamesEveryReasonClass(t *testing.T) {
	c := &ParseCoverage{EmittedEvents: ptr(40), RecordsRead: 12, Mapped: 8, Unmapped: 4, Ntfs: &NtfsCoverage{
		Source: NtfsSourceMFT, ZeroSlots: 3, FreeMapped: 2, UnmappedNonBase: 1, UnmappedNoName: 2, UnmappedNoTime: 1, AttributeListRecords: 5,
	}}
	s := c.NtfsSummary()
	for _, want := range []string{
		"12 records read", "8 mapped", "4 unmapped",
		"1 extension (non-base)", "2 without a file name", "1 without a standard-information time",
		"3 empty slots", "2 mapped records are marked free",
		"5 records with an attribute list",
		"40 events",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(strings.ToLower(s), "complete") && !strings.Contains(strings.ToLower(s), "not complete") && !strings.Contains(strings.ToLower(s), "incomplete") {
		t.Errorf("summary must not read as complete: %s", s)
	}
}

func TestNtfsCoverage_USNSummaryStatesNonRecordBytesAndOffset(t *testing.T) {
	c := &ParseCoverage{RecordsRead: 10, Mapped: 9, Unmapped: 1, Ntfs: &NtfsCoverage{
		Source: NtfsSourceUSN, NonRecordBytes: 4296, FirstNonRecordOffset: ptr(int64(1000)), UnmappedUndated: 1,
	}}
	s := c.NtfsSummary()
	for _, want := range []string{"4296 bytes were not decoded as journal records", "first at offset 1000", "1 without a usable timestamp"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q:\n%s", want, s)
		}
	}
	if !c.Incomplete() {
		t.Error("non-record bytes must make the source incomplete")
	}
}

func TestNtfsCoverage_FailedSourceSaysNoEventsIsNotNoActivity(t *testing.T) {
	c := &ParseCoverage{EmittedEvents: ptr(0), Ntfs: &NtfsCoverage{Source: NtfsSourceUSN, Failed: true, FailureClass: NtfsFailureNotAJournal, FailureOffset: ptr(int64(0)), NonRecordBytes: 100}}
	s := c.NtfsSummary()
	for _, want := range []string{"FAILED", "this source produced no events", "it is not evidence of no activity", "not a USN change journal", "offset 0"} {
		if !strings.Contains(s, want) {
			t.Errorf("failed summary lacks %q:\n%s", want, s)
		}
	}
	if !c.Measured() || !c.Incomplete() {
		t.Errorf("a failed NTFS source is a recorded, incomplete measurement: measured=%v incomplete=%v", c.Measured(), c.Incomplete())
	}
}

func TestNtfsCoverage_LimitReachedIsVisible(t *testing.T) {
	c := &ParseCoverage{LimitReached: true, Ntfs: &NtfsCoverage{Source: NtfsSourceMFT}}
	if s := c.NtfsSummary(); !strings.Contains(s, "stopped at a safety limit") {
		t.Errorf("limit not visible: %s", s)
	}
}

func TestNtfsCoverage_AbsentIsNotRecordedNeverComplete(t *testing.T) {
	var c *ParseCoverage
	if got := c.NtfsSummary(); got != "" {
		t.Errorf("nil coverage: %q", got)
	}
	old := &ParseCoverage{RecordsRead: 5, Mapped: 5}
	if got := old.NtfsSummary(); got != "" {
		t.Errorf("an import without NTFS detail must produce no NTFS claim: %q", got)
	}
	var back ParseCoverage
	if err := json.Unmarshal([]byte(`{"records_read":5,"mapped":5}`), &back); err != nil || back.Ntfs != nil {
		t.Fatalf("old JSON must read as no NTFS detail: %v %+v", err, back.Ntfs)
	}
}

func TestNtfsCoverage_RoundTripsThroughJSON(t *testing.T) {
	in := ParseCoverage{RecordsRead: 3, Ntfs: &NtfsCoverage{Source: NtfsSourceLogFile, LogRecords: 7, LogRecordsRetained: 5, Failed: true, FailureClass: NtfsFailureCorrupt}}
	b, _ := json.Marshal(in)
	var out ParseCoverage
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Ntfs == nil || *out.Ntfs != *in.Ntfs {
		t.Errorf("round trip lost data: %+v", out.Ntfs)
	}
}

func TestNtfsCoverage_LogFileSummaryDoesNotClaimEvents(t *testing.T) {
	c := &ParseCoverage{EmittedEvents: ptr(0), RecordsRead: 20, Unmapped: 20, Ntfs: &NtfsCoverage{Source: NtfsSourceLogFile, LogRecords: 20, LogRecordsRetained: 5}}
	s := c.NtfsSummary()
	for _, want := range []string{"20 log records decoded", "5 kept as detail", "no timestamp", "not a timeline"} {
		if !strings.Contains(s, want) {
			t.Errorf("logfile summary lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "deleted") || strings.Contains(s, "user ") {
		t.Errorf("logfile summary overclaims: %s", s)
	}
}
