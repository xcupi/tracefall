package timezone

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/regf"
	"tracefall/internal/regf/regfgen"
)

// negDword is the registry bit pattern of a signed bias.
func negDword(v int32) uint32 { return uint32(v) }

// systemHive builds a SYSTEM hive with the given control set number and
// TimeZoneInformation values. Pass nil values to leave the key out.
func systemHive(t *testing.T, selectCurrent uint32, withSelect bool, tzValues []regfgen.Value, withTZ bool) *regf.Hive {
	t.Helper()
	var children []*regfgen.Key
	if withSelect {
		sel := regfgen.NewKey("Select").WithValues(regfgen.DWordValue("Current", selectCurrent))
		children = append(children, sel)
	}
	if withTZ {
		tz := regfgen.NewKey("TimeZoneInformation").WithValues(tzValues...)
		ctl := regfgen.NewKey("Control", tz)
		cs := regfgen.NewKey("ControlSet001", ctl)
		cs2 := regfgen.NewKey("ControlSet002", regfgen.NewKey("Control", tz))
		children = append(children, cs, cs2)
	}
	root := regfgen.NewKey("CMI-CreateHive{SYSTEM}", children...)
	path := filepath.Join(t.TempDir(), "SYSTEM")
	if err := os.WriteFile(path, regfgen.Build(`\??\C:\Windows\System32\config\SYSTEM`, root), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := regf.Open(path, regf.DefaultLimits())
	if err != nil {
		t.Fatalf("opening synthetic SYSTEM hive: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func TestFromSystemHive_ReadsActiveTimeBiasAndTheKeyName(t *testing.T) {
	// Jakarta is UTC+7: UTC = local + bias, so the bias is -420.
	h := systemHive(t, 1, true, []regfgen.Value{
		regfgen.StringValue("TimeZoneKeyName", "SE Asia Standard Time"),
		regfgen.DWordValue("ActiveTimeBias", negDword(-420)),
		regfgen.DWordValue("Bias", 0),
	}, true)
	b := FromSystemHive(h)
	if !b.Recorded || b.ActiveBiasMinutes != -420 || b.ValueUsed != "ActiveTimeBias" {
		t.Fatalf("basis = %+v; want recorded, bias -420 from ActiveTimeBias", b)
	}
	if b.KeyName != "SE Asia Standard Time" || b.ControlSet != "ControlSet001" {
		t.Errorf("key name / control set = %q / %q", b.KeyName, b.ControlSet)
	}
	local := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC) // a wall-clock reading
	if got := b.ToUTC(local); !got.Equal(time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC)) {
		t.Errorf("10:00 local in UTC+7 = %v, want 03:00 UTC", got)
	}
}

func TestFromSystemHive_WesternZoneHasAPositiveBias(t *testing.T) {
	// UTC-5: bias +300, so a local reading is later in UTC.
	h := systemHive(t, 1, true, []regfgen.Value{regfgen.DWordValue("ActiveTimeBias", 300)}, true)
	b := FromSystemHive(h)
	if !b.Recorded || b.ActiveBiasMinutes != 300 {
		t.Fatalf("basis = %+v; want bias +300", b)
	}
	if got := b.ToUTC(time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)); !got.Equal(time.Date(2026, 1, 1, 15, 0, 0, 0, time.UTC)) {
		t.Errorf("10:00 local in UTC-5 = %v, want 15:00 UTC", got)
	}
}

func TestFromSystemHive_FallsBackToBiasOnlyWhenActiveIsAbsent(t *testing.T) {
	h := systemHive(t, 1, true, []regfgen.Value{regfgen.DWordValue("Bias", 60)}, true)
	b := FromSystemHive(h)
	if !b.Recorded || b.ActiveBiasMinutes != 60 || b.ValueUsed != "Bias" {
		t.Fatalf("basis = %+v; want recorded from Bias", b)
	}
}

func TestFromSystemHive_UsesTheControlSetSelectNames(t *testing.T) {
	// Select\Current = 2 must read ControlSet002, not the usual ControlSet001.
	h := systemHive(t, 2, true, []regfgen.Value{regfgen.DWordValue("ActiveTimeBias", 0)}, true)
	if b := FromSystemHive(h); b.ControlSet != "ControlSet002" {
		t.Fatalf("control set = %q, want ControlSet002", b.ControlSet)
	}
}

func TestFromSystemHive_MissingPiecesAreReportedNotGuessed(t *testing.T) {
	cases := map[string]*regf.Hive{
		"no Select key":            systemHive(t, 0, false, nil, true),
		"no TimeZoneInformation":   systemHive(t, 1, true, nil, false),
		"TZI without a bias value": systemHive(t, 1, true, []regfgen.Value{regfgen.StringValue("TimeZoneKeyName", "UTC")}, true),
	}
	for name, h := range cases {
		b := FromSystemHive(h)
		if b.Recorded {
			t.Errorf("%s: basis recorded (%+v); a missing value must not produce an offset", name, b)
		}
		if b.Reason == "" {
			t.Errorf("%s: no reason given", name)
		}
	}
}

func TestBasis_ToUTCOnlyAppliesTheRecordedOffset(t *testing.T) {
	b := Basis{Recorded: true, ActiveBiasMinutes: -330} // UTC+5:30
	local := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if got := b.ToUTC(local); !got.Equal(time.Date(2026, 5, 31, 18, 30, 0, 0, time.UTC)) {
		t.Errorf("00:00 local in UTC+5:30 = %v, want 18:30 UTC the day before", got)
	}
}
