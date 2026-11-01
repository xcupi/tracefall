package winevent_test

import (
	"strings"
	"testing"

	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/model"
	"tracefall/internal/parsers/winevent"
)

func cfgInput(id int, data map[string]string) winevent.Input {
	return winevent.Input{Channel: avChannel, Provider: avProvider, EventID: id, Data: data}
}

func cfg5007(old, new string) map[string]string {
	return map[string]string{"Product Name": "Antimalware Product", "Product Version": "4.18.0.1", "Old Value": old, "New Value": new}
}

const wdRoot = `HKLM\SOFTWARE\Microsoft\Windows Defender\`

// A change is security-relevant by the registry-value PATH inside Old/New
// Value, never by the data or by a name appearing somewhere in the string.
func TestDefender5007_SecurityRelevantPathsAreMapped(t *testing.T) {
	for _, tc := range []struct {
		name, old, new, category, setting string
	}{
		{"exclusion path added", `Default\Exclusions\Paths\C:\Users\alice\tools = 0x0`, wdRoot + `Exclusions\Paths\C:\Users\alice\tools = 0x0`, "exclusion_path", `Exclusions\Paths\C:\Users\alice\tools`},
		{"exclusion extension", `Default\Exclusions\Extensions\ps1 = 0x0`, wdRoot + `Exclusions\Extensions\ps1 = 0x0`, "exclusion_extension", `Exclusions\Extensions\ps1`},
		{"exclusion process", wdRoot + `Exclusions\Processes\tool.exe = 0x0`, `Default\Exclusions\Processes\tool.exe = 0x0`, "exclusion_process", `Exclusions\Processes\tool.exe`},
		{"exclusion ip", `Default\Exclusions\IpAddresses\203.0.113.7 = 0x0`, wdRoot + `Exclusions\IpAddresses\203.0.113.7 = 0x0`, "exclusion_ip_address", `Exclusions\IpAddresses\203.0.113.7`},
		{"policy exclusion", `Default\Policy Manager\ExcludedPaths = 0x0`, wdRoot + `Policy Manager\ExcludedPaths = C:\x`, "exclusion_path", `Policy Manager\ExcludedPaths`},
		{"realtime monitoring", wdRoot + `Real-Time Protection\DisableRealtimeMonitoring = 0x0`, wdRoot + `Real-Time Protection\DisableRealtimeMonitoring = 0x1`, "protection_toggle", `Real-Time Protection\DisableRealtimeMonitoring`},
		{"behavior monitoring", `Default\Real-Time Protection\DisableBehaviorMonitoring = 0x0`, wdRoot + `Real-Time Protection\DisableBehaviorMonitoring = 0x1`, "protection_toggle", `Real-Time Protection\DisableBehaviorMonitoring`},
		{"ioav", wdRoot + `Real-Time Protection\DisableIOAVProtection = 0x0`, wdRoot + `Real-Time Protection\DisableIOAVProtection = 0x1`, "protection_toggle", `Real-Time Protection\DisableIOAVProtection`},
		{"script scanning", wdRoot + `Real-Time Protection\DisableScriptScanning = 0x0`, wdRoot + `Real-Time Protection\DisableScriptScanning = 0x1`, "protection_toggle", `Real-Time Protection\DisableScriptScanning`},
		{"antispyware policy", `Default\DisableAntiSpyware = 0x0`, `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 0x1`, "protection_toggle", `DisableAntiSpyware`},
		{"spynet reporting", wdRoot + `SpyNet\SpynetReporting = 0x2`, wdRoot + `SpyNet\SpynetReporting = 0x0`, "protection_toggle", `SpyNet\SpynetReporting`},
		{"submit samples", wdRoot + `SpyNet\SubmitSamplesConsent = 0x1`, wdRoot + `SpyNet\SubmitSamplesConsent = 0x2`, "protection_toggle", `SpyNet\SubmitSamplesConsent`},
		{"pua toggle", wdRoot + `MpEnablePus = 0x1`, wdRoot + `MpEnablePus = 0x0`, "protection_toggle", `MpEnablePus`},
		{"tamper", wdRoot + `Features\TamperProtection = 0x5`, wdRoot + `Features\TamperProtection = 0x4`, "protection_toggle", `Features\TamperProtection`},
		{"case differences", `HKLM\software\microsoft\WINDOWS DEFENDER\real-time protection\disablerealtimemonitoring = 0x0`, `default\Real-Time Protection\DisableRealtimeMonitoring = 0x1`, "protection_toggle", ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := cfgInput(5007, cfg5007(tc.old, tc.new))
			e, ok := g02Direct(in)
			if !ok {
				t.Fatal("security-relevant 5007 not mapped")
			}
			want := map[string]string{"config_category": tc.category, "old_value": tc.old, "new_value": tc.new, "action": "configuration_changed", "product_version": "4.18.0.1"}
			if tc.setting != "" {
				want["config_setting"] = tc.setting
			}
			g02Expect(t, e, "antimalware_configuration_change", "", "", want)
			for _, c := range []string{"not establish", "who", "authorized"} {
				if !strings.Contains(e.Extra["limitations"], c) {
					t.Errorf("limitations lacks %q: %q", c, e.Extra["limitations"])
				}
			}
			g02Parity(t, in)
			g02Gate(t, in)
		})
	}
}

// Routine platform/engine/signature housekeeping stays unmapped, including
// names that merely look like toggles but are not in the security set.
func TestDefender5007_RoutineChurnStaysUnmapped(t *testing.T) {
	for name, kv := range map[string][2]string{
		"toast trigger":                     {wdRoot + `UX Configuration\ToastOrSsoTrigger = 0x0`, wdRoot + `UX Configuration\ToastOrSsoTrigger = 0x1`},
		"maps failure time":                 {wdRoot + `SpyNet\LastMAPSFailureTimeString = a`, wdRoot + `SpyNet\LastMAPSFailureTimeString = b`},
		"config hash":                       {wdRoot + `CoreService\WdConfigHash = 0x1`, wdRoot + `CoreService\WdConfigHash = 0x2`},
		"service state":                     {`Default\IsServiceRunning = 0x0`, wdRoot + `IsServiceRunning = 0x1`},
		"engine sensor toggle":              {`Default\NIS\Consumers\IPS\DisableBmNetworkSensor = 0x0`, wdRoot + `NIS\Consumers\IPS\DisableBmNetworkSensor = 0x0`},
		"platform candidate":                {`Default\Diagnostics\LastKnownGoodPlatformCandidate = x`, wdRoot + `Diagnostics\LastKnownGoodPlatformCandidate = y`},
		"feature control":                   {wdRoot + `Features\Controls\211 = 0x0`, wdRoot + `Features\Controls\211 = 0x1`},
		"foreign key looks like exclusions": {`HKLM\SOFTWARE\Vendor\Exclusions\Paths\x = 0x0`, `HKLM\SOFTWARE\Vendor\Exclusions\Paths\x = 0x1`},
		"name only in the data":             {wdRoot + `CoreService\Note = Exclusions\Paths`, wdRoot + `CoreService\Note = DisableRealtimeMonitoring`},
		"disable-like in a foreign key":     {`HKLM\SOFTWARE\Vendor\DisableRealtimeMonitoring = 0x0`, `HKLM\SOFTWARE\Vendor\DisableRealtimeMonitoring = 0x1`},
		"root only embedded in the path":    {`Backup\HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\x = 0x0`, `Backup\HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x1`},
		"other hive":                        {`HKCU\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\x = 0x0`, `HKCU\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\x = 0x1`},
	} {
		t.Run(name, func(t *testing.T) {
			e, ok := g02Direct(cfgInput(5007, cfg5007(kv[0], kv[1])))
			if ok || e.EventType != "" {
				t.Fatalf("routine 5007 was mapped as %q", e.EventType)
			}
		})
	}
	// Both sides are inspected: relevance on only one side is enough.
	if _, ok := g02Direct(cfgInput(5007, cfg5007(wdRoot+`CoreService\WdConfigHash = 0x1`, wdRoot+`Exclusions\Paths\C:\x = 0x0`))); !ok {
		t.Error("relevant New Value alone must map")
	}
	// Under-specified: nothing to evaluate.
	for _, d := range []map[string]string{{}, {"Old Value": "", "New Value": ""}, {"Product Name": "Antimalware Product"}} {
		if _, ok := g02Direct(cfgInput(5007, d)); ok {
			t.Errorf("under-specified 5007 mapped: %v", d)
		}
	}
}

func TestDefender5007_ValuesAreBoundedAndRedacted(t *testing.T) {
	long := wdRoot + `Exclusions\Paths\` + strings.Repeat("A", 4000) + ` = 0x0`
	e, ok := g02Direct(cfgInput(5007, cfg5007(`Default\Exclusions\Paths\x = 0x0`, long)))
	if !ok {
		t.Fatal("not mapped")
	}
	if n := len(e.Extra["new_value"]); n == 0 || n > 700 {
		t.Errorf("new_value length %d is not bounded", n)
	}
	if e.Extra["new_value_truncated"] != "true" {
		t.Error("truncation must be stated")
	}
	secret := wdRoot + `Exclusions\Paths\C:\Users\alice\run.exe --password=hunter2 = 0x0`
	e, _ = g02Direct(cfgInput(5007, cfg5007(`Default\Exclusions\Paths\x = 0x0`, secret)))
	if strings.Contains(e.Extra["new_value"], "hunter2") || strings.Contains(e.Extra["config_setting"], "hunter2") {
		t.Errorf("secret survived redaction: %q / %q", e.Extra["new_value"], e.Extra["config_setting"])
	}
}

func TestDefender5004_FeatureConfiguration(t *testing.T) {
	data := map[string]string{"Product Name": "Antimalware Product", "Product Version": "4.18.0.1", "Feature Name": "Behavior Monitoring", "Configuration": "0", "Unused": "", "Feature ID": "7"}
	in := cfgInput(5004, data)
	e, ok := g02Direct(in)
	if !ok {
		t.Fatal("5004 not mapped")
	}
	g02Expect(t, e, "antimalware_configuration_change", "", "", map[string]string{
		"config_category": "realtime_protection_feature", "feature_name": "Behavior Monitoring", "configuration": "0", "feature_id": "7", "action": "realtime_feature_configured", "product_version": "4.18.0.1",
	}, "old_value", "new_value")
	if !strings.Contains(e.Extra["limitations"], "not interpret") {
		t.Errorf("the configuration value must not be interpreted as enabled/disabled: %q", e.Extra["limitations"])
	}
	g02Parity(t, in)
	g02Gate(t, in)
	// A recorded zero / empty / dash configuration is preserved literally; an absent key is absent.
	for _, v := range []string{"0", "", "-"} {
		d := map[string]string{"Feature Name": "On Access", "Configuration": v}
		e, _ := g02Direct(cfgInput(5004, d))
		if got, rec := e.Extra["configuration"]; !rec || got != v {
			t.Errorf("configuration %q not preserved literally: %q recorded=%v", v, got, rec)
		}
	}
	e, _ = g02Direct(cfgInput(5004, map[string]string{"Feature Name": "On Access"}))
	if _, rec := e.Extra["configuration"]; rec {
		t.Error("absent Configuration must stay absent")
	}
	for _, d := range []map[string]string{{}, {"Product Name": "x"}, {"Feature Name": " ", "Feature ID": ""}} {
		if _, ok := g02Direct(cfgInput(5004, d)); ok {
			t.Errorf("under-specified 5004 mapped: %v", d)
		}
	}
}

func TestDefender1013_HistoryDeleted(t *testing.T) {
	data := map[string]string{"Product Name": "Antimalware Product", "Product Version": "4.18.0.1", "Timestamp": "2026-03-04T05:06:07.000Z", "Unused": "", "Unused2": "", "Unused3": "", "Unused4": "", "Domain": "NT AUTHORITY", "User": "SYSTEM", "SID": "S-1-5-18"}
	in := cfgInput(1013, data)
	e, ok := g02Direct(in)
	if !ok {
		t.Fatal("1013 not mapped")
	}
	g02Expect(t, e, "antimalware_history_deleted", "SYSTEM", "", map[string]string{
		"action": "detection_history_deleted", "history_deleted_time_recorded": "2026-03-04T05:06:07.000Z", "user_domain": "NT AUTHORITY", "user_sid": "S-1-5-18", "product_version": "4.18.0.1",
	})
	for _, c := range []string{"retention", "does not establish"} {
		if !strings.Contains(e.Extra["limitations"], c) {
			t.Errorf("limitations lacks %q", c)
		}
	}
	g02Parity(t, in)
	g02Gate(t, in)
	// The record's timestamp is kept as recorded, never parsed into the event time.
	if !e.Timestamp.IsZero() {
		t.Errorf("event time must come from System, not the payload: %v", e.Timestamp)
	}
	// Dash user is "not applicable", not an account called "-".
	e, _ = g02Direct(cfgInput(1013, map[string]string{"Timestamp": "2026-03-04T05:06:07.000Z", "User": "-"}))
	if e.User != "" {
		t.Errorf("dash user = %q", e.User)
	}
	// Different users / times at the same instant are different records.
	d2 := map[string]string{"Timestamp": "2026-03-04T05:06:07.000Z", "Domain": "LAB", "User": "alice", "SID": "S-1-5-21-1001"}
	d3 := map[string]string{"Timestamp": "2026-03-04T05:06:08.000Z", "Domain": "LAB", "User": "alice", "SID": "S-1-5-21-1001"}
	g02Distinct(t, cfgInput(1013, d2), cfgInput(1013, d3))
	if _, ok := g02Direct(cfgInput(1013, map[string]string{"Product Name": "x"})); ok {
		t.Error("under-specified 1013 mapped")
	}
}

// 5007/5004 identity: records that differ only in the changed value stay distinct.
func TestDefenderConfigIdentity(t *testing.T) {
	a := cfgInput(5007, cfg5007(`Default\Exclusions\Paths\C:\a = 0x0`, wdRoot+`Exclusions\Paths\C:\a = 0x0`))
	b := cfgInput(5007, cfg5007(`Default\Exclusions\Paths\C:\b = 0x0`, wdRoot+`Exclusions\Paths\C:\b = 0x0`))
	g02Distinct(t, a, b)
	c := cfgInput(5004, map[string]string{"Feature Name": "On Access", "Configuration": "0", "Feature ID": "1"})
	d := cfgInput(5004, map[string]string{"Feature Name": "On Access", "Configuration": "1", "Feature ID": "1"})
	g02Distinct(t, c, d)
}

// The existing 1116-1119 behaviour is untouched by the new IDs.
func TestDefender1116Unchanged(t *testing.T) {
	evs := parseNative(t, []evtxgen.Event{avEvent(1, 1116, avData(nil))})
	if len(evs) != 1 || evs[0].EventType != model.EventAntimalwareDetection {
		t.Fatalf("1116 changed: %+v", evs)
	}
}
