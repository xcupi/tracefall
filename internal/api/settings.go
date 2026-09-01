package api

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Display settings (Phase 14).
//
// Tracefall stores and reasons about every timestamp as an INSTANT in
// UTC -- see internal/normalize.Timestamp. That does not change here and
// must not: the database, the hashes, the deduplication, the ordering
// and every analysis result stay exactly as they were.
//
// What this adds is a PRESENTATION preference. An analyst working an
// incident in Jakarta reads "2021-04-26 01:31:49 WIB" far more reliably
// than they convert "2021-04-25T18:31:49Z" in their head at 3am, and
// misreading a timestamp by seven hours is a real way to get an incident
// timeline wrong.
//
// Two rules make this safe, and both are enforced rather than assumed:
//
//  1. The setting is APPLICATION-WIDE and lives in its own table. It is
//     never written to a case or an evidence record, so it cannot travel
//     with exported evidence or be mistaken for a fact about it.
//  2. Conversion happens only at the point of DISPLAY. Nothing reads
//     this setting to decide what to store, how to order, or what to
//     analyze.

// SettingDisplayTimezone is the app_settings key holding the analyst's
// chosen display timezone, as an IANA identifier.
const SettingDisplayTimezone = "display_timezone"

// DefaultDisplayTimezone is UTC, and stays UTC unless an analyst
// deliberately changes it. Defaulting to the server's local zone would
// silently make two Tracefall installations disagree about what a
// timestamp says.
const DefaultDisplayTimezone = "UTC"

// ErrInvalidTimezone means the identifier is not in the IANA timezone
// database.
var ErrInvalidTimezone = errors.New("unknown timezone")

// DisplaySettings is the analyst-facing presentation configuration.
type DisplaySettings struct {
	// Timezone is a canonical IANA identifier ("UTC", "Asia/Jakarta").
	// Never a fixed offset: an offset cannot express daylight saving, so
	// "+07:00" would render half the year wrong for zones that observe
	// it.
	Timezone string `json:"timezone"`
	// Abbreviation and OffsetLabel describe the zone AS OF NOW, purely so
	// the UI can show "Asia/Jakarta -- WIB (UTC+07:00)". They are derived
	// on read and never stored, because they change with DST and a stored
	// copy would go stale.
	Abbreviation string `json:"abbreviation"`
	OffsetLabel  string `json:"offset_label"`
}

// DisplaySettings returns the current display preferences, falling back
// to UTC when nothing is set or when a stored value has become
// unloadable (a tzdb that no longer carries a zone, say). Falling back
// rather than failing means a bad setting can never make the dashboard
// unusable.
func (s *Service) DisplaySettings() (DisplaySettings, error) {
	tz := DefaultDisplayTimezone
	stored, ok, err := s.store.GetSetting(SettingDisplayTimezone)
	if err != nil {
		return DisplaySettings{}, err
	}
	if ok && strings.TrimSpace(stored) != "" {
		if _, lerr := time.LoadLocation(stored); lerr == nil {
			tz = stored
		}
	}
	return describeTimezone(tz), nil
}

// SetDisplayTimezone validates and stores a display timezone.
//
// Validation is a real tzdb lookup, not a pattern match: only an
// identifier the timezone database actually knows is accepted, so a
// typo ("Asia/Jakata") is refused at the point of entry rather than
// silently rendering everything in UTC afterwards.
func (s *Service) SetDisplayTimezone(tz string) (DisplaySettings, error) {
	tz = strings.TrimSpace(tz)
	if tz == "" {
		return DisplaySettings{}, fmt.Errorf("%w: no timezone given", ErrInvalidTimezone)
	}
	// A fixed offset is rejected deliberately. It looks like it works and
	// then silently produces wrong times across a DST boundary.
	if strings.HasPrefix(tz, "+") || strings.HasPrefix(tz, "-") {
		return DisplaySettings{}, fmt.Errorf("%w: %q is a fixed offset; use an IANA identifier such as Asia/Jakarta so daylight saving is handled correctly", ErrInvalidTimezone, tz)
	}
	// "Local" would resolve to whatever the SERVER's zone happens to be,
	// making the same evidence read differently on two installations.
	if strings.EqualFold(tz, "Local") {
		return DisplaySettings{}, fmt.Errorf("%w: %q depends on the server's own timezone; name the zone explicitly", ErrInvalidTimezone, tz)
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return DisplaySettings{}, fmt.Errorf("%w: %q is not in the IANA timezone database", ErrInvalidTimezone, tz)
	}
	if err := s.store.SetSetting(SettingDisplayTimezone, tz); err != nil {
		return DisplaySettings{}, err
	}
	// Changing a display preference is not a forensic event and is
	// deliberately NOT written to any case's audit log: it changes no
	// evidence, no analysis and no case.
	return describeTimezone(tz), nil
}

// describeTimezone renders the zone's current abbreviation and offset.
func describeTimezone(tz string) DisplaySettings {
	out := DisplaySettings{Timezone: tz, Abbreviation: "UTC", OffsetLabel: "UTC+00:00"}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return out
	}
	now := time.Now().In(loc)
	abbr, offset := now.Zone()
	out.Abbreviation = abbr
	sign := "+"
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	out.OffsetLabel = fmt.Sprintf("UTC%s%02d:%02d", sign, offset/3600, (offset%3600)/60)
	return out
}

// CommonTimezones is the shortlist the settings UI offers first.
//
// A shortlist, not the whole tzdb: the full database is ~600 entries and
// scrolling it is worse than typing. Any valid IANA identifier is still
// accepted by SetDisplayTimezone, so this list constrains convenience,
// never capability.
var CommonTimezones = []string{
	"UTC",
	"Asia/Jakarta",
	"Asia/Singapore",
	"Asia/Tokyo",
	"Asia/Kolkata",
	"Asia/Dubai",
	"Europe/London",
	"Europe/Berlin",
	"America/New_York",
	"America/Chicago",
	"America/Denver",
	"America/Los_Angeles",
	"Australia/Sydney",
}
