package scheduledtasks

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTaskDate_ClockBasis(t *testing.T) {
	for _, tc := range []struct {
		date    string
		instant bool
	}{
		{"2026-01-15T09:17:30.0000000", false},
		{"2026-01-15T09:17:30.1234567", false},
		{"", false}, {"not-a-date", false},
		{"2026-01-15T09:17:30+07:00", true},
		{"2026-01-15T09:17:30Z", true},
	} {
		t.Run(tc.date, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "Task01.xml")
			writeUTF16(t, p, strings.Replace(sampleTaskXML, "2026-01-15T09:17:30.0000000", tc.date, 1))
			res, err := New().Parse(p)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Events) != 1 {
				t.Fatalf("got %d events; configuration must survive without a usable instant", len(res.Events))
			}
			e := res.Events[0]
			if tc.instant {
				want, err := time.Parse(time.RFC3339, tc.date)
				if err != nil {
					t.Fatal(err)
				}
				if !e.Timestamp.Equal(want) {
					t.Fatalf("instant %v != %v", e.Timestamp, want)
				}
			} else {
				if !e.Timestamp.IsZero() {
					t.Errorf("invented instant %v for %q", e.Timestamp, tc.date)
				}
				if tc.date != "" && e.Extra["timestamp_original"] != tc.date {
					t.Errorf("lost original reading: %v", e.Extra)
				}
				if strings.HasPrefix(tc.date, "2026") && (e.Extra["timestamp_local"] != tc.date || e.Extra["timestamp_basis"] != "task_registration_local_zone_unknown") {
					t.Errorf("missing local reading/basis: %v", e.Extra)
				}
			}
		})
	}
}
