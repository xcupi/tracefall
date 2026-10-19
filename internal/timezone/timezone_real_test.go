package timezone

import (
	"os"
	"testing"

	"tracefall/internal/regf"
)

// Real-hive test: a SYSTEM hive from a real Windows image. Skipped unless
// TRACEFALL_REAL_SYSTEM points at it. The expected values were read with an
// independent reader, hivexget (libhivex 1.3.24), and are not taken from this
// package:
//
//	hivexget SYSTEM '\Select' Current                        -> 1
//	hivexget SYSTEM '\ControlSet001\Control\TimeZoneInformation'
//	    ActiveTimeBias = dword:000001e0   (480)
//	    TimeZoneKeyName = "Pacific Standard Time"
//
// 480 minutes with UTC = local + bias is UTC-8, which matches Pacific.
func TestReal_SystemHiveMatchesHivexget(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_SYSTEM")
	if path == "" {
		t.Skip("set TRACEFALL_REAL_SYSTEM to a real SYSTEM hive to run")
	}
	h, err := regf.Open(path, regf.DefaultLimits())
	if err != nil {
		t.Fatalf("opening the hive: %v", err)
	}
	defer h.Close()

	b := FromSystemHive(h)
	if !b.Recorded {
		t.Fatalf("basis not recorded: %s", b.Reason)
	}
	if b.ControlSet != "ControlSet001" || b.ActiveBiasMinutes != 480 || b.ValueUsed != "ActiveTimeBias" {
		t.Errorf("basis = %+v; hivexget reads ControlSet001, ActiveTimeBias 480", b)
	}
	if b.KeyName != "Pacific Standard Time" {
		t.Errorf("key name = %q; hivexget reads \"Pacific Standard Time\"", b.KeyName)
	}
}
