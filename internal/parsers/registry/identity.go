package registry

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/regf"
)

// systemIdentity reads what a SYSTEM hive says about WHO this machine is on
// the network: its domain, the addresses it was configured with or leased, and
// what kind of machine Windows was installed as. It reads ControlSet001 only
// and returns nothing it did not find.
//
// Every address is labelled with where it came from. A DHCP lease is the last
// address the machine was given, which is not proof it held that address on
// the day of an incident; a static address is configuration. The labels travel
// into Extra["ip_origin"] so a reader can weigh them.
func systemIdentity(h *regf.Hive) map[string]string {
	out := map[string]string{}
	const tcpip = `ControlSet001\Services\Tcpip\Parameters`
	if k, err := h.OpenKey(tcpip); err == nil {
		for _, v := range k.Values {
			switch strings.ToLower(v.Name) {
			case "domain", "nv domain":
				if d := strings.TrimSpace(v.String()); d != "" && out["domain"] == "" {
					out["domain"] = strings.ToLower(d)
				}
			}
		}
	}
	type addr struct{ ip, origin string }
	var addrs []addr
	dhcpServers := map[string]bool{}
	ifaces, _ := h.ChildKeys(tcpip + `\Interfaces`)
	for _, ik := range ifaces {
		for _, v := range ik.Values {
			switch strings.ToLower(v.Name) {
			case "ipaddress":
				for _, s := range v.Strings() {
					addrs = append(addrs, addr{s, "static"})
				}
			case "dhcpipaddress":
				addrs = append(addrs, addr{v.String(), "dhcp lease"})
			case "dhcpserver":
				if s := strings.TrimSpace(v.String()); s != "" {
					dhcpServers[s] = true
				}
			case "dhcpdomain":
				if d := strings.TrimSpace(v.String()); d != "" && out["domain"] == "" {
					out["domain"] = strings.ToLower(d)
				}
			}
		}
	}
	seen := map[string]bool{}
	var ips, origins []string
	for _, a := range addrs {
		ip, err := netip.ParseAddr(strings.TrimSpace(a.ip))
		if err != nil || ip.IsUnspecified() || ip.IsLoopback() || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		ips = append(ips, ip.String())
		origins = append(origins, ip.String()+"="+a.origin)
	}
	sort.Strings(ips)
	sort.Strings(origins)
	if len(ips) > 0 {
		out["ip_addresses"] = strings.Join(ips, ",")
		out["ip_origin"] = strings.Join(origins, ";")
	}
	if len(dhcpServers) > 0 {
		var s []string
		for k := range dhcpServers {
			s = append(s, k)
		}
		sort.Strings(s)
		out["dhcp_servers"] = strings.Join(s, ",")
	}
	if k, err := h.OpenKey(`ControlSet001\Control\ProductOptions`); err == nil {
		for _, v := range k.Values {
			if strings.EqualFold(v.Name, "ProductType") {
				pt := strings.TrimSpace(v.String())
				out["product_type"] = pt
				switch strings.ToLower(pt) {
				case "lanmannt":
					out["host_role"] = "domain_controller"
				case "servernt":
					out["host_role"] = "server"
				case "winnt":
					out["host_role"] = "workstation"
				}
			}
		}
	}
	return out
}

// softwareIdentityEvent records the operating system a SOFTWARE hive says is
// installed. The hive carries no machine name, so the event has no Host; the
// collection-scoped host enrichment assigns one only when the collection has
// exactly one.
func softwareIdentityEvent(h *regf.Hive, hiveType HiveType) (model.Event, model.RawEvidence, bool) {
	const relKey = `Microsoft\Windows NT\CurrentVersion`
	k, err := h.OpenKey(relKey)
	if err != nil {
		return model.Event{}, model.RawEvidence{}, false
	}
	want := map[string]string{
		"productname": "os_product_name", "currentbuild": "os_current_build", "currentbuildnumber": "os_current_build",
		"editionid": "os_edition_id", "installationtype": "os_installation_type", "currentversion": "os_version",
		"releaseid": "os_release_id", "buildlabex": "os_build_lab",
	}
	extra := map[string]string{}
	var installDate time.Time
	for _, v := range k.Values {
		name := strings.ToLower(v.Name)
		if key, ok := want[name]; ok {
			if s := strings.TrimSpace(v.String()); s != "" && extra[key] == "" {
				extra[key] = s
			}
		}
		if name == "installdate" {
			if n, err := strconv.ParseUint(strings.TrimSpace(v.String()), 0, 64); err == nil && n > 0 && n < 4_102_444_800 {
				installDate = time.Unix(int64(n), 0).UTC()
			}
		}
	}
	if len(extra) == 0 {
		return model.Event{}, model.RawEvidence{}, false
	}
	if !installDate.IsZero() {
		extra["os_install_date_utc"] = installDate.Format("2006-01-02T15:04:05Z")
	}
	ts := h.LastModified()
	if !k.LastWrite.IsZero() {
		ts = k.LastWrite
	}
	keyPath := rootedPath(hiveType, relKey)
	extra["registry_hive"], extra["registry_hive_type"], extra["registry_key"] = string(hiveType), string(hiveType), keyPath
	extra["registry_last_write"] = ts.UTC().Format("2006-01-02T15:04:05Z")
	extra["observation"] = "Registry key last-write observed; the operating system the SOFTWARE hive records as installed"
	ev := model.Event{
		Timestamp: ts.UTC(), EventType: model.EventRegistryKeyLastWrite, RegistryPath: keyPath,
		ArtifactType: model.ArtifactRegistryHive, Parser: parserName, Confidence: 1.0,
		SourceReference: "key:" + keyPath, Extra: extra,
	}
	raw, _ := json.Marshal(extra)
	return ev, model.RawEvidence{SourceReference: ev.SourceReference, Raw: string(raw)}, true
}
