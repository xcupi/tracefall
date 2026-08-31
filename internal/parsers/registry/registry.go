// Package registry parses raw Windows registry hives (SYSTEM, SOFTWARE,
// NTUSER.DAT, SAM, SECURITY, UsrClass.dat, ...) into normalized events,
// reading the binary REGF format directly via internal/regf rather than
// depending on RECmd having been run first.
//
// It is deliberately NOT a general registry-to-timeline converter. A
// SOFTWARE hive holds hundreds of thousands of keys, and emitting an
// event per key would bury an investigator in noise while telling them
// nothing. Instead this extracts a fixed, targeted set of
// forensically-meaningful locations:
//
//   - the persistence locations internal/parsers/regpersist already
//     defines -- Run/RunOnce, Winlogon, IFEO, AppInit_DLLs, and service
//     ImagePath -- classified by that same shared table, so a key
//     reported by a RECmd CSV and by a raw hive is classified
//     identically;
//   - the machine hostname from a SYSTEM hive, which is the strongest
//     host attribution a registry artifact can offer.
//
// Nothing here writes to the hive, replays a transaction log, or touches
// the host registry API.
package registry

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/normalize"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/regpersist"
	"tracefall/internal/regf"
)

const parserName = "registry@1"

// Parser implements parsers.ArtifactParser and parsers.ContentDetector
// for raw registry hives.
type Parser struct {
	limits regf.Limits
}

func New() *Parser { return &Parser{limits: regf.DefaultLimits()} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactRegistryHive }

// hiveNames are the filenames Windows uses for the hives Tracefall
// recognizes by name. This is only a fast path -- DetectContent finds a
// hive whatever it is called, which matters because hives extracted from
// a triage image are routinely renamed.
var hiveNames = map[string]bool{
	"system": true, "software": true, "sam": true, "security": true,
	"default": true, "ntuser.dat": true, "usrclass.dat": true, "components": true,
}

func (Parser) Detect(relPath string) bool {
	return hiveNames[strings.ToLower(filepath.Base(relPath))]
}

// DetectContent identifies a hive by its REGF signature, so
// "SYSTEM.bak", "ntuser.dat.copy", or a hive with no extension at all is
// still recognized -- and a text file named SYSTEM is not.
func (Parser) DetectContent(header []byte) bool { return regf.Sniff(header) }

// HiveType is Tracefall's classification of which hive a file is.
type HiveType string

const (
	HiveUnknown  HiveType = "unknown"
	HiveSystem   HiveType = "SYSTEM"
	HiveSoftware HiveType = "SOFTWARE"
	HiveNTUser   HiveType = "NTUSER.DAT"
	HiveSAM      HiveType = "SAM"
	HiveSecurity HiveType = "SECURITY"
	HiveUsrClass HiveType = "UsrClass.dat"
)

// Parse walks the hive once, emitting an event for each targeted
// artifact it finds.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	h, err := regf.Open(absPath, p.limits)
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("registry: %w", err)
	}
	defer h.Close()

	hiveType := classifyHive(absPath, h)

	// The hostname is resolved first, because every event from a SYSTEM
	// hive can then legitimately carry it. Events from other hive types
	// keep an empty Host and are resolved by the collection-scoped host
	// enrichment in internal/api/hostenrich.go -- which is exactly where
	// "this collection has one unambiguous host" is decided, and the only
	// place that has the whole import in view.
	host := ""
	if hiveType == HiveSystem {
		host = systemHostname(h)
	}
	// An NTUSER.DAT belongs to exactly one user, and the evidence path is
	// the only thing that records which -- but only when the path really
	// carries it. Never guessed from anything else.
	user := ""
	if hiveType == HiveNTUser || hiveType == HiveUsrClass {
		user = userFromPath(absPath)
	}

	var out parsers.ParseResult

	if host != "" {
		ev, raw := hostnameEvent(h, host, hiveType)
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, raw)
	}

	_, walkErr := h.Walk(func(k regf.Key) error {
		for _, v := range k.Values {
			// Classified against the ROOTED path, so the shared
			// regpersist table sees the same spelling it sees from a
			// RECmd CSV or a Sysmon registry event.
			kind := regpersist.Classify(rootedPath(hiveType, k.Path), v.Name)
			if kind == regpersist.KindNone {
				continue
			}
			// A persistence location with no data is an empty slot, not
			// evidence of persistence.
			data := v.String()
			if strings.TrimSpace(data) == "" {
				continue
			}
			ev, raw := persistenceEvent(k, v, kind, hiveType, host, user)
			out.Events = append(out.Events, ev)
			out.Raw = append(out.Raw, raw)
		}
		return nil
	})
	if walkErr != nil {
		return parsers.ParseResult{}, fmt.Errorf("registry: walking hive: %w", walkErr)
	}
	return out, nil
}

// hiveRoot is the registry path prefix a hive's contents live under on a
// running system. Hive files hold paths relative to their own root, but
// every other source Tracefall reads -- Sysmon's TargetObject, RECmd's
// KeyPath -- reports the rooted path. Prefixing here means one registry
// location has ONE path spelling across all three sources, which is what
// lets regpersist.Classify (and an investigator reading the timeline)
// treat them as the same thing.
func hiveRoot(t HiveType) string {
	switch t {
	case HiveSystem:
		return `HKLM\SYSTEM`
	case HiveSoftware:
		return `HKLM\SOFTWARE`
	case HiveSAM:
		return `HKLM\SAM`
	case HiveSecurity:
		return `HKLM\SECURITY`
	case HiveNTUser:
		return `HKCU`
	case HiveUsrClass:
		return `HKCU\Software\Classes`
	default:
		return ""
	}
}

// rootedPath renders a hive-relative key path as the full registry path.
func rootedPath(hiveType HiveType, keyPath string) string {
	root := hiveRoot(hiveType)
	switch {
	case root == "":
		return keyPath
	case keyPath == "":
		return root
	default:
		return root + `\` + keyPath
	}
}

// persistenceEvent builds one normalized event for a persistence-relevant
// key/value.
func persistenceEvent(k regf.Key, v regf.Value, kind regpersist.Kind, hiveType HiveType, host, user string) (model.Event, model.RawEvidence) {
	keyPath := rootedPath(hiveType, k.Path)
	fullPath := keyPath
	if v.Name != "" {
		fullPath = keyPath + `\` + v.Name
	}
	data := v.String()

	// Run/RunOnce keep their own event type; everything else regpersist
	// recognizes shares the generic persistence type with the specific
	// location in Extra -- exactly the split the RECmd and Sysmon paths
	// already use, so one rule set covers all three sources.
	eventType := model.EventRegistryRunKey
	extra := map[string]string{
		"registry_hive":       string(hiveType),
		"registry_hive_type":  string(hiveType),
		"registry_key":        keyPath,
		"registry_value_name": v.Name,
		"registry_value_data": truncate(data, 1024),
		"registry_value_type": v.TypeName(),
		"registry_last_write": k.LastWrite.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if kind != regpersist.KindRunKey {
		eventType = model.EventRegistryPersistence
		extra["registry_persistence_type"] = string(kind)
	}

	ev := model.Event{
		// The hive records exactly one time for this key: when it was
		// last written. That is the only defensible timestamp, and the
		// event type/description say so rather than implying creation.
		Timestamp:       k.LastWrite.UTC(),
		Host:            host,
		User:            user,
		EventType:       eventType,
		RegistryPath:    fullPath,
		FilePath:        data,
		ProcessName:     normalize.ExecutableFromCommandLine(data),
		ArtifactType:    model.ArtifactRegistryHive,
		Parser:          parserName,
		Confidence:      1.0,
		SourceReference: "key:" + fullPath,
		Extra:           extra,
	}

	rawJSON, _ := json.Marshal(map[string]any{
		"hive_type":  string(hiveType),
		"key_path":   keyPath,
		"last_write": k.LastWrite.UTC(),
		"value_name": v.Name,
		"value_type": v.TypeName(),
		"value_data": truncate(data, 4096),
	})
	return ev, model.RawEvidence{SourceReference: ev.SourceReference, Raw: string(rawJSON)}
}

// hostnameEvent records the machine name recovered from a SYSTEM hive.
// It is emitted as an observation of a key's last-write time, not as an
// action: the hive says when ComputerName was last written and what it
// says, nothing more.
func hostnameEvent(h *regf.Hive, host string, hiveType HiveType) (model.Event, model.RawEvidence) {
	const relKey = `ControlSet001\Control\ComputerName\ComputerName`
	keyPath := rootedPath(hiveType, relKey)

	ts := h.LastModified()
	if k, err := h.OpenKey(relKey); err == nil && !k.LastWrite.IsZero() {
		ts = k.LastWrite
	}

	ev := model.Event{
		Timestamp:       ts.UTC(),
		Host:            host,
		EventType:       model.EventRegistryKeyLastWrite,
		RegistryPath:    keyPath + `\ComputerName`,
		ArtifactType:    model.ArtifactRegistryHive,
		Parser:          parserName,
		Confidence:      1.0,
		SourceReference: "key:" + keyPath,
		Extra: map[string]string{
			"registry_hive":       string(hiveType),
			"registry_hive_type":  string(hiveType),
			"registry_key":        keyPath,
			"registry_value_name": "ComputerName",
			"registry_value_data": host,
			"registry_last_write": ts.UTC().Format("2006-01-02T15:04:05Z"),
			"observation":         "Registry key last-write observed; machine hostname recorded in the SYSTEM hive",
		},
	}
	rawJSON, _ := json.Marshal(map[string]any{
		"hive_type":  string(hiveType),
		"key_path":   keyPath,
		"value_name": "ComputerName",
		"value_data": host,
		"last_write": ts.UTC(),
	})
	return ev, model.RawEvidence{SourceReference: ev.SourceReference, Raw: string(rawJSON)}
}

// systemHostname reads the machine name from a SYSTEM hive. Windows
// keeps several ControlSets and a CurrentControlSet symlink; this reads
// whichever control sets exist and accepts the name only when every one
// of them agrees, so a hive mid-rename never yields a guess. Returns ""
// when the name cannot be established -- never a fabricated host.
func systemHostname(h *regf.Hive) string {
	subkeys, err := h.Subkeys("")
	if err != nil {
		return ""
	}
	var found string
	for _, sk := range subkeys {
		if !strings.HasPrefix(strings.ToLower(sk), "controlset") {
			continue
		}
		k, err := h.OpenKey(sk + `\Control\ComputerName\ComputerName`)
		if err != nil {
			continue
		}
		for _, v := range k.Values {
			if !strings.EqualFold(v.Name, "ComputerName") {
				continue
			}
			name := strings.TrimSpace(v.String())
			if name == "" {
				continue
			}
			if found != "" && !strings.EqualFold(found, name) {
				// Two control sets disagree. Picking one would be a
				// guess, and a wrong host silently corrupts correlation
				// and deduplication for the whole collection.
				return ""
			}
			found = name
		}
	}
	return normalize.Host(found)
}

// classifyHive determines which hive this file is, preferring the hive's
// own embedded name (which travels with the file) over the name it
// happens to have on disk, and falling back to structure when both are
// unhelpful.
func classifyHive(path string, h *regf.Hive) HiveType {
	if t := hiveTypeFromName(h.EmbeddedName()); t != HiveUnknown {
		return t
	}
	if t := hiveTypeFromName(path); t != HiveUnknown {
		return t
	}
	// Last resort: a SYSTEM hive is the one with ControlSet keys at its
	// root, which no other hive has.
	if subs, err := h.Subkeys(""); err == nil {
		for _, s := range subs {
			if strings.HasPrefix(strings.ToLower(s), "controlset") {
				return HiveSystem
			}
		}
	}
	return HiveUnknown
}

func hiveTypeFromName(name string) HiveType {
	lower := strings.ToLower(strings.ReplaceAll(name, `\`, "/"))
	base := lower
	if i := strings.LastIndex(lower, "/"); i >= 0 {
		base = lower[i+1:]
	}
	switch {
	case base == "system" || strings.HasSuffix(base, "/system"):
		return HiveSystem
	case base == "software":
		return HiveSoftware
	case base == "sam":
		return HiveSAM
	case base == "security":
		return HiveSecurity
	case strings.HasPrefix(base, "ntuser.dat"):
		return HiveNTUser
	case strings.HasPrefix(base, "usrclass.dat"):
		return HiveUsrClass
	default:
		return HiveUnknown
	}
}

// userFromPath recovers the owning username of an NTUSER.DAT from its
// evidence path (".../Users/jdoe/NTUSER.DAT"). It returns "" unless the
// path genuinely contains a Users/<name> segment: an unknown user is
// recorded as unknown, never invented.
func userFromPath(path string) string {
	parts := strings.Split(strings.ReplaceAll(path, `\`, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "Users") || strings.EqualFold(parts[i], "Documents and Settings") {
			name := parts[i+1]
			if name != "" && !strings.EqualFold(name, "Public") && !strings.EqualFold(name, "Default") {
				return name
			}
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
