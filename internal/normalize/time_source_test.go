package normalize

import (
	"testing"
	"time"
)

func TestTimestamp_SourceClockContracts(t *testing.T) {
	for _, s := range []string{"2026-01-15T09:17:30.0000000Z", "2026-01-15 09:17:30", "2026-01-15T09:17:30.0000000"} {
		got, ok := Timestamp(s)
		if !ok || !got.Equal(time.Date(2026, 1, 15, 9, 17, 30, 0, time.UTC)) {
			t.Errorf("UTC-by-contract EZ Tools export changed: %q -> %v, %v", s, got, ok)
		}
	}
	for _, s := range []string{"2026-01-15T09:17:30", "2026-01-15T09:17:30.1234567"} {
		instant, local, ok := XMLTimestamp(s)
		if !ok || !instant.IsZero() || local != s {
			t.Errorf("local XML reading invented an instant/lost precision: %q -> %v, %q, %v", s, instant, local, ok)
		}
	}
	for _, s := range []string{"2026-01-15T09:17:30Z", "2026-01-15T16:17:30+07:00"} {
		instant, local, ok := XMLTimestamp(s)
		if !ok || local != "" || !instant.Equal(time.Date(2026, 1, 15, 9, 17, 30, 0, time.UTC)) {
			t.Errorf("explicit XML zone lost: %q -> %v, %q, %v", s, instant, local, ok)
		}
	}
	for _, s := range []string{"", "2026-99-99T09:17:30", "not-a-date"} {
		instant, local, ok := XMLTimestamp(s)
		if ok || !instant.IsZero() || local != "" {
			t.Errorf("invalid/absent XML date accepted: %q", s)
		}
	}
}
