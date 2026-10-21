package registry_test

import (
	"strings"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/regf"
	"tracefall/internal/regf/regfgen"
)

func identityControlSet(name, host, domain, ip, role string) *regfgen.Key {
	return regfgen.NewKey(name,
		regfgen.NewKey("Control",
			regfgen.NewKey("ComputerName", regfgen.NewKey("ComputerName").WithLastWrite(lastWrite).WithValues(regfgen.StringValue("ComputerName", host))),
			regfgen.NewKey("ProductOptions").WithValues(regfgen.StringValue("ProductType", role))),
		regfgen.NewKey("Services",
			regfgen.NewKey("Tcpip", regfgen.NewKey("Parameters", regfgen.NewKey("Interfaces", regfgen.NewKey("{AAAA}").WithValues(regfgen.MultiStringValue("IPAddress", []string{ip})))).WithValues(regfgen.StringValue("Domain", domain))),
			regfgen.NewKey("ExampleService").WithValues(regfgen.StringValue("ImagePath", `C:\Users\alice\AppData\Local\Temp\example.exe`))))
}

func selectedIdentityHive(selectKey *regfgen.Key) []byte {
	keys := []*regfgen.Key{
		identityControlSet("ControlSet001", "OLD-HOST", "old.example", "10.0.0.1", "WinNT"),
		identityControlSet("ControlSet002", "HOST02", "corp.example", "10.0.0.2", "LanmanNT"),
	}
	if selectKey != nil {
		keys = append(keys, selectKey)
	}
	return regfgen.Build(`\??\C:\Windows\System32\config\SYSTEM`, regfgen.NewKey("SYSTEM", keys...))
}

func hostnameObservation(events []model.Event) *model.Event {
	for i := range events {
		if events[i].Extra["registry_value_name"] == "ComputerName" {
			return &events[i]
		}
	}
	return nil
}

func TestSystemIdentity_UnknownSelectorDoesNotAttribute(t *testing.T) {
	cases := []struct {
		name    string
		values  []regfgen.Value
		missing bool
	}{
		{name: "no Select", missing: true},
		{name: "no Current"},
		{name: "wrong type", values: []regfgen.Value{regfgen.StringValue("Current", "2")}},
		{name: "zero", values: []regfgen.Value{regfgen.DWordValue("Current", 0)}},
		{name: "out of range", values: []regfgen.Value{regfgen.DWordValue("Current", 1000)}},
		{name: "missing set", values: []regfgen.Value{regfgen.DWordValue("Current", 3)}},
		{name: "conflicting Current", values: []regfgen.Value{regfgen.DWordValue("Current", 1), regfgen.DWordValue("current", 2)}},
		{name: "short DWORD", values: []regfgen.Value{{Name: "Current", Type: regf.RegDWord, Data: []byte{2, 0}}}},
		{name: "long DWORD", values: []regfgen.Value{{Name: "Current", Type: regf.RegDWord, Data: []byte{2, 0, 0, 0, 0}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			selector := regfgen.NewKey("Select").WithValues(tc.values...)
			if tc.missing {
				selector = nil
			}
			events := parseHive(t, writeHive(t, "SYSTEM", selectedIdentityHive(selector)))
			if len(events) == 0 {
				t.Fatal("expected unhosted persistence observations")
			}
			for _, e := range events {
				if e.Host != "" || e.Extra["domain"] != "" || e.Extra["host_role"] != "" || e.Extra["ip_addresses"] != "" {
					t.Errorf("unknown selector attributed identity: %+v", e)
				}
				if e.Extra["control_set_status"] != "unknown" || e.Extra["control_set_reason"] == "" || e.Extra["control_set"] != "" {
					t.Errorf("missing selection uncertainty: %v", e.Extra)
				}
			}
		})
	}
}

func TestSystemIdentity_SelectCurrentBigEndian(t *testing.T) {
	selector := regfgen.NewKey("Select").WithValues(regfgen.Value{Name: "cUrReNt", Type: regf.RegDWordBigEndian, Data: []byte{0, 0, 0, 2}})
	e := hostnameObservation(parseHive(t, writeHive(t, "SYSTEM", selectedIdentityHive(selector))))
	if e == nil || e.Host != "HOST02" {
		t.Fatalf("big-endian Current not selected: %+v", e)
	}
}

func TestSystemIdentity_SelectCurrentOverridesStaleControlSet(t *testing.T) {
	events := parseHive(t, writeHive(t, "SYSTEM", selectedIdentityHive(regfgen.NewKey("Select").WithValues(regfgen.DWordValue("Current", 2), regfgen.DWordValue("Default", 1), regfgen.DWordValue("LastKnownGood", 1)))))
	e := hostnameObservation(events)
	if e == nil {
		t.Fatal("no selected hostname observation")
	}
	if e.Host != "HOST02" || !strings.Contains(e.RegistryPath, `ControlSet002\Control\ComputerName`) {
		t.Fatalf("selected hostname/path = %q %q", e.Host, e.RegistryPath)
	}
	for k, want := range map[string]string{"domain": "corp.example", "ip_addresses": "10.0.0.2", "product_type": "LanmanNT", "host_role": "domain_controller", "control_set": "ControlSet002", "control_set_basis": `SYSTEM\Select\Current`} {
		if e.Extra[k] != want {
			t.Errorf("%s = %q, want %q", k, e.Extra[k], want)
		}
	}
	for _, ev := range events {
		if ev.Host != "HOST02" {
			t.Errorf("hive event host = %q", ev.Host)
		}
	}
}
