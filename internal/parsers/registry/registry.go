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
	"tracefall/internal/procclass"
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

// EventArtifactTypes declares the artifact types this parser's EVENTS
// carry beyond the type of the FILE itself.
//
// A hive file is classified as a registry hive, which is what it is. The
// UserAssist and ShellBags structures inside it are separate artifacts
// in every sense that matters to an analyst -- different evidence,
// different meaning, different forensic weight -- so their events say
// so, and the capability registry lists them as things Tracefall
// supports. See parsers.EventArtifactTypes.
func (Parser) EventArtifactTypes() []string {
	return []string{
		model.ArtifactUserAssist, model.ArtifactShellBags,
		model.ArtifactAmcache, model.ArtifactRecentDocs, model.ArtifactRunMRU,
		model.ArtifactTypedPaths, model.ArtifactOpenSaveMRU, model.ArtifactMUICache,
		model.ArtifactSAM,
	}
}

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

// ConfirmContent makes the filename match above a HINT rather than a
// verdict: a file called SAM, SYSTEM or NTUSER.DAT is only claimed when
// its bytes are actually a registry hive.
//
// Without this, any file that happened to carry one of those names was
// claimed by this parser, counted as supported evidence, and then failed
// at import -- so an analyst was told a hive was broken when in truth it
// was never a hive. Unrecognized is the honest answer, and it is the one
// ingest now gives. See parsers.ContentConfirmer.
func (Parser) ConfirmContent(header []byte) bool { return regf.Sniff(header) }

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
	return p.ParseWithContext(absPath, parsers.ParseContext{})
}

// ParseWithContext is Parse plus collection-scoped context. It exists
// for one artifact: a SAM hive's NT hashes are encrypted under a key
// that lives in the SYSTEM hive, so the SAM alone cannot decode them.
// See parsers.ParseContext and samaccount.go.
//
// Every other artifact this parser reads ignores ctx entirely, and the
// zero context reproduces Parse exactly.
func (p Parser) ParseWithContext(absPath string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
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
		user = normalize.UserFromEvidencePath(ctx.EvidencePath)
	}

	var out parsers.ParseResult

	if host != "" {
		ev, raw := hostnameEvent(h, host, hiveType)
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, raw)
	}
	if hiveType == HiveSoftware {
		if ev, raw, ok := softwareIdentityEvent(h, hiveType); ok {
			out.Events = append(out.Events, ev)
			out.Raw = append(out.Raw, raw)
		}
	}

	// Phase 15: the two user-activity structures a per-user hive holds.
	// Both are no-ops for a hive that does not contain them, and neither
	// can fail the parse -- a SYSTEM hive with no UserAssist tree is a
	// valid artifact with zero records of that kind, not an error. See
	// useractivity.go.
	uaEvents, uaRaw := p.userAssistEvents(h, hiveType, host, user)
	out.Events = append(out.Events, uaEvents...)
	out.Raw = append(out.Raw, uaRaw...)

	sbEvents, sbRaw := p.shellBagEvents(h, hiveType, host, user, ctx.TimeBasis)
	out.Events = append(out.Events, sbEvents...)
	out.Raw = append(out.Raw, sbRaw...)

	// Phase 16: Amcache, and the per-user MRU structures. Both are
	// no-ops for a hive that does not hold them -- an NTUSER.DAT has no
	// Amcache tree and an Amcache.hve has no RunMRU, and neither absence
	// is an error. See appactivity.go.
	amEvents, amRaw := p.amcacheEvents(h, host)
	out.Events = append(out.Events, amEvents...)
	out.Raw = append(out.Raw, amRaw...)

	mruEv, mruRaw := p.mruEvents(h, hiveType, host, user)
	out.Events = append(out.Events, mruEv...)
	out.Raw = append(out.Raw, mruRaw...)

	// Phase 18: Windows local accounts and their NTLM hashes. Gated on
	// the SAM account structures actually being present, not on the
	// filename or on classifyHive's answer, so a hive that merely got
	// called SAM contributes nothing here. See samaccount.go.
	samEv, samRaw := p.samAccountEvents(h, absPath, hiveType, ctx)
	out.Events = append(out.Events, samEv...)
	out.Raw = append(out.Raw, samRaw...)

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
			// Every service in a hive snapshot has an ImagePath; that is
			// configuration, not a modification. The event stays in the
			// timeline as evidence (a hive-only acquisition has nothing
			// else), and is marked so the detection rule raises a lead only
			// for a user-writable or non-standard location or an interpreter.
			if kind == regpersist.KindServiceImagePath {
				if ev.Extra == nil {
					ev.Extra = map[string]string{}
				}
				if !procclass.HasSuspiciousPath(data) && !runsInterpreter(data) {
					ev.Extra["persistence_lead"] = "false"
				}
			}
			out.Events = append(out.Events, ev)
			out.Raw = append(out.Raw, raw)
		}
		return nil
	})
	if walkErr != nil {
		return parsers.ParseResult{}, fmt.Errorf("registry: walking hive: %w", walkErr)
	}
	if hiveType == HiveSystem {
		cs, reason := selectedControlSet(h)
		for i := range out.Events {
			if out.Events[i].Extra == nil {
				out.Events[i].Extra = map[string]string{}
			}
			extra := out.Events[i].Extra
			if cs == "" {
				extra["control_set_status"] = "unknown"
				extra["control_set_reason"] = reason
			} else {
				extra["control_set_status"] = "selected"
				extra["control_set"] = cs
				extra["control_set_basis"] = `SYSTEM\Select\Current`
			}
		}
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
	cs, _ := selectedControlSet(h)
	relKey := cs + `\Control\ComputerName\ComputerName`
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
			"control_set":         cs,
			"control_set_basis":   `SYSTEM\Select\Current`,
			"registry_hive":       string(hiveType),
			"registry_hive_type":  string(hiveType),
			"registry_key":        keyPath,
			"registry_value_name": "ComputerName",
			"registry_value_data": host,
			"registry_last_write": ts.UTC().Format("2006-01-02T15:04:05Z"),
			"observation":         "Registry key last-write observed; machine hostname recorded in the SYSTEM hive",
		},
	}
	// What else the same hive says about who this machine is. Each value
	// carries its own caveat in the key that names it (ip_origin).
	for k, v := range systemIdentity(h) {
		ev.Extra[k] = v
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

// systemHostname reads only the hostname in Select\Current's control set.
// An unavailable selector is unknown, not permission to choose a stale set.
func systemHostname(h *regf.Hive) string {
	cs, _ := selectedControlSet(h)
	if cs == "" {
		return ""
	}
	k, err := h.OpenKey(cs + `\Control\ComputerName\ComputerName`)
	if err != nil {
		return ""
	}
	var found string
	for _, v := range k.Values {
		if !strings.EqualFold(v.Name, "ComputerName") {
			continue
		}
		name := strings.TrimSpace(v.String())
		if found != "" && !strings.EqualFold(found, name) {
			return ""
		}
		found = name
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// runsInterpreter reports whether a service image path starts a command or
// script interpreter, which a driver or service binary does not.
func runsInterpreter(imagePath string) bool {
	exe := strings.ToLower(normalize.ExecutableFromCommandLine(imagePath))
	return procclass.IsPowerShell(exe) || procclass.IsScriptHost(exe) || exe == "cmd.exe"
}
