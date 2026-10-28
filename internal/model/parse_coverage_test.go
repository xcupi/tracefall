package model

import (
	"encoding/json"
	"testing"
)

func TestParseCoverageMeasured(t *testing.T) {
	for _, raw := range []string{
		`null`, `{}`, `{"notes":["reader caveat"]}`, `{"hive_replay":{"state":"clean"}}`,
		`{"hive_replay":{"state":"not_recoverable"}}`,
		`{"hive_replay":{"state":"replayed"}}`,
		`{"hive_replay":{"state":"replayed_partial"}}`,
		`{"hive_replay":{"state":"no_logs"}}`,
		`{"hive_replay":{"state":"not_recoverable"},"notes":["gap"]}`,
		`{"companion_of":"vol1/SYSTEM"}`, `{"companion_of":"vol1/SYSTEM","notes":["gap"]}`,
		`{"companion_of":"vol1/SYSTEM","hive_replay":{"state":"replayed"}}`,
		`{"companion_of":"vol1/SYSTEM","hive_replay":{"state":"replayed"},"notes":["gap"]}`,
		`{"records_read":0,"mapped":0}`, `{"emitted_events":0,"notes":["gap"]}`,
	} {
		t.Run(raw, func(t *testing.T) {
			var c *ParseCoverage
			if err := json.Unmarshal([]byte(raw), &c); err != nil {
				t.Fatal(err)
			}
			want := raw == `{}` || raw == `{"records_read":0,"mapped":0}` || raw == `{"emitted_events":0,"notes":["gap"]}`
			if got := c.Measured(); got != want {
				t.Errorf("Measured()=%v want %v", got, want)
			}
			if c != nil && len(c.Notes) > 0 && !c.Incomplete() {
				t.Error("metadata caveat must remain incomplete independent of measurement")
			}
		})
	}
}

func TestParseCoverageMeasuredMetricsWithMetadata(t *testing.T) {
	metrics := []string{`"records_read":1`, `"mapped":1`, `"unmapped":1`, `"undated":1`, `"records_failed":1`, `"chunks_read":1`, `"chunks_failed":1`, `"limit_reached":true`, `"by_event":[{"event_id":1}]`, `"unlisted_records":1`, `"emitted_events":0`, `"emitted_events":2`}
	for _, metric := range metrics {
		t.Run(metric, func(t *testing.T) {
			raw := `{"companion_of":"vol1/SYSTEM","hive_replay":{"state":"clean"},"notes":["caveat"],` + metric + `}`
			var c ParseCoverage
			if err := json.Unmarshal([]byte(raw), &c); err != nil {
				t.Fatal(err)
			}
			if !c.Measured() {
				t.Fatal("actual metric must remain measured")
			}
		})
	}
}
