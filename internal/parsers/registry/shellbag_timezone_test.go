package registry

import (
	"testing"
	"time"

	"tracefall/internal/parsers"
	"tracefall/internal/shellbag"
)

// A file shell item whose DOS modified time is 2026-03-01 09:15:30 as the
// machine's local clock reads it.
func itemWithDOSModified() shellbag.Item {
	return shellbag.Item{
		Modified: shellbag.DOSTime{Year: 2026, Month: 3, Day: 1, Hour: 9, Minute: 15, Second: 30, Valid: true},
	}
}

func TestShellBagEvent_ConvertsLocalReadingsWhenTheZoneIsRecorded(t *testing.T) {
	basis := &parsers.TimeBasis{ActiveBiasMinutes: -420, Source: "SYSTEM hive ControlSet001 ActiveTimeBias"} // UTC+7
	ev, _ := shellBagEvent(itemWithDOSModified(), []string{"Desktop", "Notes"},
		`Software\Microsoft\Windows\Shell\BagMRU\0\1`, time.Date(2026, 3, 1, 2, 0, 0, 0, time.UTC),
		HiveNTUser, "host01", "alice", basis)

	if got := ev.Extra["shell_item_modified_utc"]; got != "2026-03-01T02:15:30Z" {
		t.Errorf("shell_item_modified_utc = %q, want 2026-03-01T02:15:30Z (09:15:30 local in UTC+7)", got)
	}
	if got := ev.Extra["shell_item_utc_basis"]; got == "" {
		t.Error("the converted value must name the offset's source")
	}
	// The local reading itself is kept untouched, and the event's timestamp
	// is still the key's own write time, not the converted DOS value.
	if ev.Extra["shell_item_modified_local"] != "2026-03-01 09:15:30" {
		t.Errorf("local reading changed: %q", ev.Extra["shell_item_modified_local"])
	}
	if !ev.Timestamp.Equal(time.Date(2026, 3, 1, 2, 0, 0, 0, time.UTC)) {
		t.Errorf("event timestamp moved to %v; only the key's write time may be the timestamp", ev.Timestamp)
	}
}

func TestShellBagEvent_NoConversionWithoutARecordedZone(t *testing.T) {
	ev, _ := shellBagEvent(itemWithDOSModified(), []string{"Desktop"},
		`Software\Microsoft\Windows\Shell\BagMRU\0`, time.Date(2026, 3, 1, 2, 0, 0, 0, time.UTC),
		HiveNTUser, "host01", "alice", nil)
	for k := range ev.Extra {
		if k == "shell_item_modified_utc" || k == "shell_item_utc_basis" {
			t.Errorf("%s present without a recorded zone; a local reading must not be turned into UTC", k)
		}
	}
	if ev.Extra["shell_item_modified_local"] != "2026-03-01 09:15:30" {
		t.Errorf("local reading missing without a zone: %q", ev.Extra["shell_item_modified_local"])
	}
}

func TestShellBagEvent_InvalidDOSFieldIsNotConverted(t *testing.T) {
	item := shellbag.Item{Modified: shellbag.DOSTime{Valid: false}}
	basis := &parsers.TimeBasis{ActiveBiasMinutes: -420, Source: "x"}
	ev, _ := shellBagEvent(item, []string{"Desktop"}, `Software\Microsoft\Windows\Shell\BagMRU\0`,
		time.Date(2026, 3, 1, 2, 0, 0, 0, time.UTC), HiveNTUser, "host01", "alice", basis)
	if _, ok := ev.Extra["shell_item_modified_utc"]; ok {
		t.Error("an absent DOS time must not get a converted value")
	}
}
