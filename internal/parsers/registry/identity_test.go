package registry_test

import (
	"strings"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/regf/regfgen"
)

// identityHive builds a SYSTEM hive for a domain controller with one static
// and one leased address, a loopback and an unspecified address that must be
// ignored.
func identityHive(productType string) []byte {
	computerName := regfgen.NewKey("ComputerName").WithLastWrite(lastWrite).WithValues(regfgen.StringValue("ComputerName", "DC-A"))
	computerNameParent := regfgen.NewKey("ComputerName", computerName)
	if1 := regfgen.NewKey("{AAAA}").WithValues(
		regfgen.MultiStringValue("IPAddress", []string{"10.0.0.10", "0.0.0.0"}),
		regfgen.StringValue("DhcpIPAddress", "10.0.0.77"),
		regfgen.StringValue("DhcpServer", "10.0.0.1"),
		regfgen.StringValue("DhcpDomain", "Corp.Example"),
	)
	if2 := regfgen.NewKey("{BBBB}").WithValues(regfgen.StringValue("DhcpIPAddress", "127.0.0.1"))
	interfaces := regfgen.NewKey("Interfaces", if1, if2)
	params := regfgen.NewKey("Parameters", interfaces).WithValues(regfgen.StringValue("Domain", "corp.example"))
	tcpip := regfgen.NewKey("Tcpip", params)
	services := regfgen.NewKey("Services", tcpip)
	opts := regfgen.NewKey("ProductOptions").WithValues(regfgen.StringValue("ProductType", productType))
	control := regfgen.NewKey("Control", computerNameParent, opts)
	cs1 := regfgen.NewKey("ControlSet001", control, services)
	root := regfgen.NewKey("CMI-CreateHive{SYSTEM}", cs1, regfgen.NewKey("Select").WithValues(regfgen.DWordValue("Current", 1))).WithLastWrite(lastWrite)
	return regfgen.Build(`\??\C:\Windows\System32\config\SYSTEM`, root)
}

func TestSystemHive_IdentityFields(t *testing.T) {
	events := parseHive(t, writeHive(t, "SYSTEM", identityHive("LanmanNT")))
	var e *model.Event
	for i := range events {
		if events[i].Extra["registry_value_name"] == "ComputerName" {
			e = &events[i]
		}
	}
	if e == nil {
		t.Fatal("no hostname event")
	}
	for k, want := range map[string]string{
		"domain": "corp.example", "ip_addresses": "10.0.0.10,10.0.0.77", "dhcp_servers": "10.0.0.1",
		"product_type": "LanmanNT", "host_role": "domain_controller",
	} {
		if e.Extra[k] != want {
			t.Errorf("Extra[%s] = %q, want %q", k, e.Extra[k], want)
		}
	}
	if !strings.Contains(e.Extra["ip_origin"], "10.0.0.10=static") || !strings.Contains(e.Extra["ip_origin"], "10.0.0.77=dhcp lease") {
		t.Errorf("each address must say where it came from: %q", e.Extra["ip_origin"])
	}
	if strings.Contains(e.Extra["ip_addresses"], "127.0.0.1") || strings.Contains(e.Extra["ip_addresses"], "0.0.0.0") {
		t.Errorf("loopback and unspecified addresses are not identity: %q", e.Extra["ip_addresses"])
	}
}

func TestSystemHive_RoleFollowsProductType(t *testing.T) {
	for pt, want := range map[string]string{"WinNT": "workstation", "ServerNT": "server", "LanmanNT": "domain_controller"} {
		events := parseHive(t, writeHive(t, "SYSTEM", identityHive(pt)))
		for _, e := range events {
			if e.Extra["registry_value_name"] == "ComputerName" && e.Extra["host_role"] != want {
				t.Errorf("%s -> %q, want %q", pt, e.Extra["host_role"], want)
			}
		}
	}
}

func TestSystemHive_WithNoNetworkKeysAddsNoIdentityFields(t *testing.T) {
	events := parseHive(t, writeHive(t, "SYSTEM", systemHive()))
	for _, e := range events {
		if e.Extra["registry_value_name"] == "ComputerName" {
			for _, k := range []string{"domain", "ip_addresses", "host_role"} {
				if e.Extra[k] != "" {
					t.Errorf("%s = %q was invented", k, e.Extra[k])
				}
			}
		}
	}
}

func TestSoftwareHive_OperatingSystem(t *testing.T) {
	cv := regfgen.NewKey("CurrentVersion").WithLastWrite(lastWrite).WithValues(
		regfgen.StringValue("ProductName", "Windows Server 2012 R2 Standard Evaluation"),
		regfgen.StringValue("CurrentBuild", "9600"),
		regfgen.StringValue("InstallationType", "Server"),
		regfgen.DWordValue("InstallDate", 1599000000),
	)
	nt := regfgen.NewKey("Windows NT", cv)
	ms := regfgen.NewKey("Microsoft", nt)
	root := regfgen.NewKey("CMI-CreateHive{SOFTWARE}", ms).WithLastWrite(lastWrite)
	events := parseHive(t, writeHive(t, "SOFTWARE", regfgen.Build(`\??\C:\Windows\System32\config\SOFTWARE`, root)))
	var e *model.Event
	for i := range events {
		if events[i].Extra["os_product_name"] != "" {
			e = &events[i]
		}
	}
	if e == nil {
		t.Fatalf("no OS event among %d events", len(events))
	}
	if e.Extra["os_product_name"] != "Windows Server 2012 R2 Standard Evaluation" || e.Extra["os_current_build"] != "9600" ||
		e.Extra["os_installation_type"] != "Server" || e.Extra["os_install_date_utc"] != "2020-09-01T22:40:00Z" {
		t.Errorf("extra %v", e.Extra)
	}
	if e.Host != "" {
		t.Errorf("a SOFTWARE hive carries no machine name; Host must stay empty for enrichment, got %q", e.Host)
	}
}
