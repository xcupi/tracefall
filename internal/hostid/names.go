package hostid

import (
	"net/netip"
	"strings"
)

// Resolve returns the one machine name that every name in names describes,
// as an observed spelling, or ok=false when names holds no name or the names
// do not provably describe one machine.
//
// Rule: names are compared case-insensitively. They describe one machine when
// they are one name, or when exactly one fully qualified name (it contains a
// dot) is present and every other name is its first DNS label (the short
// form, e.g. the computer name a SYSTEM hive stores next to the FQDN an event
// log records). Two different fully qualified names are two machines even
// when their first labels match, and a short name equal to the first label of
// two different FQDNs is ambiguous. An IP address is never split into labels.
// The result is a spelling that was observed, the fully qualified one when
// there is one, the smallest in byte order when several spellings differ only
// in case or padding, so it does not depend on input order.
func Resolve(names []string) (string, bool) {
	spelling := map[string]string{} // lower-case form -> smallest observed spelling
	for _, n := range names {
		k := strings.ToLower(strings.TrimSpace(n))
		if k == "" {
			continue
		}
		if cur, ok := spelling[k]; !ok || n < cur {
			spelling[k] = n
		}
	}
	if len(spelling) == 0 {
		return "", false
	}
	var fqdn string
	var shorts []string
	for k := range spelling {
		if isDNSName(k) && strings.Contains(k, ".") {
			if fqdn != "" {
				return "", false // two different fully qualified names
			}
			fqdn = k
			continue
		}
		shorts = append(shorts, k)
	}
	if fqdn == "" {
		if len(shorts) == 1 {
			return spelling[shorts[0]], true
		}
		// Addresses are dotted but not DNS names; they were routed to shorts.
		return "", false
	}
	label := fqdn[:strings.Index(fqdn, ".")]
	for _, s := range shorts {
		if s != label {
			return "", false
		}
	}
	return spelling[fqdn], true
}

// isDNSName reports whether s may be treated as a DNS name that has labels:
// anything that is not an IP address literal.
func isDNSName(s string) bool {
	_, err := netip.ParseAddr(s)
	return err != nil
}
