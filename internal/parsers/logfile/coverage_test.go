package logfile_test

import (
	"strings"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/parsers/logfile"
)

// A log that decodes is a measured source with zero events, stated as such.
func TestLogParser_RecordsCoverageWithZeroEvents(t *testing.T) {
	res, err := logfile.New().Parse(write(t, sampleLog()))
	if err != nil {
		t.Fatal(err)
	}
	c := res.Coverage
	if c == nil || c.Ntfs == nil || c.Ntfs.Source != model.NtfsSourceLogFile {
		t.Fatalf("no $LogFile coverage: %+v", c)
	}
	if c.EmittedEvents == nil || *c.EmittedEvents != 0 {
		t.Fatalf("emitted events must be an explicit zero: %+v", c.EmittedEvents)
	}
	if c.Ntfs.LogRecords != 3 || c.Ntfs.LogRecordsRetained != 3 || c.RecordsRead != 3 || c.Mapped != 0 || c.Unmapped != 3 {
		t.Fatalf("counts: %+v read=%d mapped=%d unmapped=%d", c.Ntfs, c.RecordsRead, c.Mapped, c.Unmapped)
	}
	s := c.NtfsSummary()
	for _, want := range []string{"3 log records decoded", "no timestamp", "not a timeline", "0 events"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q: %s", want, s)
		}
	}
}
