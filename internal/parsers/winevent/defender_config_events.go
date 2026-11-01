package winevent

import (
	"strings"

	"tracefall/internal/cmdsem"
	"tracefall/internal/model"
)

// Defender Operational configuration and history records:
//
//	5007  the antimalware platform configuration changed (Old Value, New Value)
//	5004  a real-time protection feature configuration changed
//	      (Feature Name, Configuration, Feature ID)
//	1013  the platform deleted its history of detections (Timestamp, User)
//
// 5007 is the noisiest of them: a real log carries thousands of it, almost
// all of it the platform writing its own bookkeeping (UX toast triggers,
// cloud-lookup failure timestamps, configuration hashes, platform/engine
// candidates, feature-flag controls). Mapping them all would bury the few
// that matter, so a 5007 is mapped ONLY when the registry-value PATH inside
// Old Value or New Value is a setting that governs what Defender protects or
// scans (see defenderSecuritySetting). Everything else stays unmapped and
// counted in the coverage census; unmapped is not benign.

const defenderConfigFieldBytes = 512

// Registry roots Defender writes its settings under. "Default" is the form
// the platform prints for a value that had no stored setting. Matching is
// case-insensitive because the registry is.
var defenderSettingRoots = []string{
	`hklm\software\microsoft\windows defender\`,
	`hklm\software\policies\microsoft\windows defender\`,
	`default\`,
}

// Exclusion lists: any entry under these keys changes what Defender does not
// inspect. The excluded path/extension/process/address is the last part of
// the registry path itself.
var defenderExclusionPrefixes = []struct{ prefix, category string }{
	{`exclusions\paths\`, "exclusion_path"},
	{`exclusions\extensions\`, "exclusion_extension"},
	{`exclusions\processes\`, "exclusion_process"},
	{`exclusions\ipaddresses\`, "exclusion_ip_address"},
}

// Settings (path relative to the root, lower case) that switch protection or
// reporting off, or tune the tamper/cloud/PUA behaviour. Deliberately an exact
// list rather than "any value named Disable*": engine-internal toggles with
// such names (for example a network-sensor flag under NIS\Consumers) are
// written by the platform itself.
var defenderToggleSettings = map[string]bool{
	`disableantispyware`:                               true,
	`disableantivirus`:                                 true,
	`disableroutinelytakingaction`:                     true,
	`real-time protection\disablerealtimemonitoring`:   true,
	`real-time protection\disablebehaviormonitoring`:   true,
	`real-time protection\disableonaccessprotection`:   true,
	`real-time protection\disableioavprotection`:       true,
	`real-time protection\disablescriptscanning`:       true,
	`real-time protection\disablerawwritenotification`: true,
	`spynet\spynetreporting`:                           true,
	`spynet\submitsamplesconsent`:                      true,
	`spynet\disableblockatfirstseen`:                   true,
	`mpenablepus`:                                      true,
	`puaprotection`:                                    true,
	`features\tamperprotection`:                        true,
}

// Policy-Manager (MDM) exclusion values, which hold the whole list in one value.
var defenderPolicyExclusions = map[string]string{
	`policy manager\excludedpaths`:      "exclusion_path",
	`policy manager\excludedextensions`: "exclusion_extension",
	`policy manager\excludedprocesses`:  "exclusion_process",
}

// defenderSecuritySetting classifies the registry-value path of one Old/New
// Value string. The string is "<registry path> = <data>"; only the path
// decides relevance, so a toggle name that appears in the data or under a
// foreign key never matches.
func defenderSecuritySetting(value string) (setting, category string, ok bool) {
	path, _, _ := strings.Cut(value, " = ")
	path = strings.TrimSpace(path)
	lower := strings.ToLower(path)
	for _, root := range defenderSettingRoots {
		if !strings.HasPrefix(lower, root) {
			continue
		}
		rel, relLower := path[len(root):], lower[len(root):]
		for _, ex := range defenderExclusionPrefixes {
			if strings.HasPrefix(relLower, ex.prefix) {
				return rel, ex.category, true
			}
		}
		if c, found := defenderPolicyExclusions[relLower]; found {
			return rel, c, true
		}
		if defenderToggleSettings[relLower] {
			return rel, "protection_toggle", true
		}
		return "", "", false
	}
	return "", "", false
}

// boundedRedacted bounds a free-text value, masks secret shapes in what is
// kept, and reports whether anything was cut.
func boundedRedacted(s string, n int) (string, bool) {
	cut := false
	if len(s) > defenderMaxInputBytes {
		s, cut = s[:defenderMaxInputBytes], true
	}
	s = cmdsem.Redact(s)
	if len(s) > n {
		s, cut = s[:n], true
	}
	return s, cut
}

// setRecorded records p[src] under k when the record carries that key at all.
// Unlike setExtra it keeps an empty value, "-" and "0" exactly as recorded:
// for these families "recorded as empty/zero/dash" and "not present" are
// different facts.
func setRecorded(ev *model.Event, k string, p map[string]string, src string) {
	if v, ok := p[src]; ok {
		ev.Extra[k] = v
	}
}

func normalizeDefenderConfigEvent(ev *model.Event, in Input) (handled, mapped bool) {
	if !strings.EqualFold(in.Provider, defenderProvider) || !strings.EqualFold(in.Channel, defenderChannel) {
		return true, false
	}
	p := in.Data
	switch in.EventID {
	case 5007:
		oldV, hasOld := p["Old Value"]
		newV, hasNew := p["New Value"]
		oldSetting, oldCat, oldRel := defenderSecuritySetting(oldV)
		newSetting, newCat, newRel := defenderSecuritySetting(newV)
		if !(hasOld && oldRel) && !(hasNew && newRel) {
			return true, false
		}
		setting, category := newSetting, newCat
		if !newRel {
			setting, category = oldSetting, oldCat
		}
		ev.EventType = model.EventAntimalwareConfigChange
		ev.User = ""
		ev.Extra["action"] = "configuration_changed"
		ev.Extra["config_category"] = category
		v, _ := boundedRedacted(setting, defenderConfigFieldBytes)
		ev.Extra["config_setting"] = v
		for _, side := range []struct {
			key, val string
			has      bool
		}{{"old_value", oldV, hasOld}, {"new_value", newV, hasNew}} {
			if !side.has {
				continue
			}
			bounded, cut := boundedRedacted(side.val, defenderConfigFieldBytes)
			ev.Extra[side.key] = bounded
			if cut {
				ev.Extra[side.key+"_truncated"] = "true"
			}
		}
		setExtra(ev, "product_version", p["Product Version"])
		ev.Extra["evidence_meaning"] = "Microsoft Defender recorded a configuration change to a setting that governs what it protects or scans (" + category + "): the registry value path and the old and new values are shown as recorded."
		ev.Extra["limitations"] = "Records that the stored setting changed, not who changed it, by what means (policy, administrator, installer or malware) or whether it was authorized. Does not establish that protection is currently reduced: the data is retained as recorded without interpretation and a later record may reverse it. An unmapped 5007 is not proof of no change."
	case 5004:
		if strings.TrimSpace(p["Feature Name"]) == "" && strings.TrimSpace(p["Feature ID"]) == "" {
			return true, false
		}
		ev.EventType = model.EventAntimalwareConfigChange
		ev.User = ""
		ev.Extra["action"] = "realtime_feature_configured"
		ev.Extra["config_category"] = "realtime_protection_feature"
		setRecorded(ev, "feature_name", p, "Feature Name")
		setRecorded(ev, "configuration", p, "Configuration")
		setRecorded(ev, "feature_id", p, "Feature ID")
		setExtra(ev, "product_version", p["Product Version"])
		ev.Extra["evidence_meaning"] = "Microsoft Defender recorded that the configuration of a real-time protection feature changed, naming the feature and the configuration value."
		ev.Extra["limitations"] = "The configuration value is retained as recorded and Tracefall does not interpret it as enabled or disabled. Does not establish who or what changed it, or that protection is currently reduced."
	case 1013:
		ts, hasTs := p["Timestamp"]
		user, hasUser := p["User"]
		if !hasTs && !hasUser {
			return true, false
		}
		ev.EventType = model.EventAntimalwareHistoryDeleted
		ev.User = strings.TrimSpace(dashToEmpty(strings.TrimSpace(user)))
		ev.Extra["action"] = "detection_history_deleted"
		if hasTs {
			ev.Extra["history_deleted_time_recorded"] = ts
		}
		setRecorded(ev, "user_domain", p, "Domain")
		setRecorded(ev, "user_sid", p, "SID")
		setExtra(ev, "product_version", p["Product Version"])
		ev.Extra["evidence_meaning"] = "Microsoft Defender recorded that it deleted its stored history of detected malware and other potentially unwanted software."
		ev.Extra["limitations"] = "Defender also purges history automatically under its retention setting, so this does not establish a deliberate attempt to remove evidence and does not establish an actor (the user shown is the account recorded by the platform). It does not say which detections were removed; detection records in this log may still exist."
	}
	return true, true
}
