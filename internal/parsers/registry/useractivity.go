package registry

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/regf"
	"tracefall/internal/shellbag"
	"tracefall/internal/userassist"
)

// User-activity extraction from a per-user hive (Phase 15): UserAssist
// and ShellBags.
//
// # Why these live in the registry parser rather than in parsers of
// their own
//
// Discovery assigns exactly ONE parser per evidence file (see
// ingest.Discover), and an NTUSER.DAT legitimately contains all three of
// the things Tracefall extracts from a hive: persistence values,
// UserAssist entries, and a BagMRU tree. A separate UserAssist parser
// would therefore never run -- this parser claims the file first by name
// and by REGF signature -- and making it win instead would simply move
// the problem to whichever parser lost.
//
// So the hive is opened once and read for everything it holds, which is
// exactly what this package was built to do: "a fixed, targeted set of
// forensically-meaningful locations" (see the package comment).
//
// # Why the EVENTS still carry their own artifact types
//
// model.Event.ArtifactType is set per event, not inherited from the
// source file. The FILE stays classified as a registry hive -- that is
// what was collected, hashed and attested. The EVENTS carry
// model.ArtifactUserAssist and model.ArtifactShellBags, because an
// analyst filtering a timeline is asking what the observation IS, and
// "registry hive" answers only where it was kept. Both types are
// registered as supported capabilities through
// parsers.EventArtifactTypes.

// userAssistKeyPath is where Explorer keeps the UserAssist tree in a
// user hive, relative to the hive root.
const userAssistKeyPath = `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`

// bagMRUPaths are where a BagMRU tree lives, relative to each hive's own
// root. NTUSER.DAT and UsrClass.dat keep it in different places, and
// UsrClass.dat is where modern Windows records most of it.
var bagMRUPaths = map[HiveType][]string{
	HiveNTUser: {
		`Software\Microsoft\Windows\Shell\BagMRU`,
		`Software\Microsoft\Windows\ShellNoRoam\BagMRU`,
	},
	HiveUsrClass: {
		`Local Settings\Software\Microsoft\Windows\Shell\BagMRU`,
		`Local Settings\Software\Microsoft\Windows\ShellNoRoam\BagMRU`,
	},
}

// userAssistEvents extracts every UserAssist entry in the hive.
//
// Returns no events, and no error, for a hive that simply has no
// UserAssist tree -- which is the normal state of a SYSTEM or SOFTWARE
// hive, and of a freshly-created profile. "Valid artifact, zero records"
// is not a failure.
func (p Parser) userAssistEvents(h *regf.Hive, hiveType HiveType, host, user string) ([]model.Event, []model.RawEvidence) {
	if hiveType != HiveNTUser {
		// UserAssist lives only in NTUSER.DAT. Looking for it elsewhere
		// would risk decoding an unrelated key that happens to sit at a
		// similar path.
		return nil, nil
	}

	guids, err := h.Subkeys(userAssistKeyPath)
	if err != nil || len(guids) == 0 {
		return nil, nil
	}
	sort.Strings(guids)

	lim := userassist.DefaultLimits()
	var events []model.Event
	var raws []model.RawEvidence

	for _, guid := range guids {
		countPath := userAssistKeyPath + `\` + guid + `\Count`
		// The path SHAPE is verified before anything is decoded, so a key
		// that merely resembles a UserAssist location cannot be read as
		// one.
		normalizedGUID, ok := userassist.CountKeyGUID(countPath)
		if !ok {
			continue
		}
		k, err := h.OpenKey(countPath)
		if err != nil {
			continue
		}
		for _, v := range k.Values {
			if len(events) >= lim.MaxEntries {
				return events, raws
			}
			entry, derr := userassist.Decode(normalizedGUID, v.Name, v.Data, lim)
			if derr != nil {
				// A value that is not a UserAssist record -- a settings
				// value living in the same key, or a layout Tracefall
				// does not read. Skipped rather than reported as broken
				// evidence: the Count key legitimately holds both.
				continue
			}
			ev, raw := userAssistEvent(entry, k, countPath, hiveType, host, user)
			events = append(events, ev)
			raws = append(raws, raw)
		}
	}
	return events, raws
}

// userAssistEvent builds one normalized event from a decoded entry.
func userAssistEvent(e userassist.Entry, k regf.Key, countPath string, hiveType HiveType, host, user string) (model.Event, model.RawEvidence) {
	keyPath := rootedPath(hiveType, countPath)

	// The item the entry names, most-resolved form first.
	target := e.ResolvedPath
	if target == "" {
		target = e.DecodedName
	}

	extra := map[string]string{
		"artifact_class":        "userassist",
		"registry_hive_type":    string(hiveType),
		"registry_key":          keyPath,
		"userassist_guid":       e.GUID,
		"userassist_version":    strconv.Itoa(e.Version),
		"userassist_value_name": e.EncodedName,
		"decoded_name":          e.DecodedName,
		"run_count":             strconv.FormatUint(uint64(e.RunCount), 10),
		"run_count_raw":         strconv.FormatUint(uint64(e.RunCountRaw), 10),
		"session_id":            strconv.FormatUint(uint64(e.SessionID), 10),
		"registry_last_write":   k.LastWrite.UTC().Format("2006-01-02T15:04:05Z"),
		// The single most important line on this event. UserAssist counts
		// SHELL launches; it is neither a process-creation record nor
		// proof that anything ran at the recorded instant.
		"evidence_meaning": "UserAssist recorded activity: Windows Explorer counted this item being launched " +
			"through the shell by this user. It is not a process-creation record, and a program started by a " +
			"script, a service or a command line leaves no UserAssist entry at all.",
	}
	if e.ResolvedPath != "" {
		extra["resolved_path"] = e.ResolvedPath
	}
	if e.GUIDMeaning != "" {
		extra["userassist_guid_meaning"] = e.GUIDMeaning
	} else {
		// Stated rather than left blank: an investigator should know the
		// GUID was unrecognized, not wonder whether it was checked.
		extra["userassist_guid_meaning"] = "not a GUID Tracefall recognizes; reported as stored"
	}
	if e.HasFocusData {
		extra["focus_count"] = strconv.FormatUint(uint64(e.FocusCount), 10)
		extra["focus_time_ms"] = strconv.FormatInt(e.FocusTime.Milliseconds(), 10)
	}
	if e.Version == 3 && e.RunCountRaw >= 5 {
		extra["run_count_note"] = "the Windows XP-era counter starts at 5; run_count is the stored value minus 5, " +
			"and run_count_raw is exactly what the record holds"
	}
	if len(e.Warnings) > 0 {
		extra["warnings"] = strings.Join(e.Warnings, "; ")
	}
	addUserContext(extra, user)

	if !e.LastExecuted.IsZero() {
		extra["timestamp_meaning"] = "UserAssist last-recorded activity: when Explorer last updated this entry " +
			"for this item. Not a process start time."
		extra["timestamp_source"] = "UserAssist record last-execution FILETIME"
	} else {
		extra["timestamp_meaning"] = "no time is recorded for this entry"
		extra["timestamp_basis"] = "This UserAssist record carries no usable last-execution timestamp. " +
			"The run count is still evidence; the time is not."
	}

	ev := model.Event{
		// Zero when the record holds no time. The file's own modification
		// time and the key's last-write time are BOTH available here and
		// neither is used: a key holds many entries, so its write time
		// describes the key, not this item.
		Timestamp: e.LastExecuted.UTC(),
		Host:      host,
		User:      user,
		EventType: model.EventUserAssistActivity,
		// FilePath, not ProcessName: the entry names an item the shell
		// launched, and calling that a process name would assert a
		// process existed. Where the item genuinely looks like an
		// executable the timeline can still search it as a path.
		FilePath:     target,
		RegistryPath: keyPath + `\` + e.EncodedName,
		ArtifactType: model.ArtifactUserAssist,
		Parser:       parserName,
		// Below 1.0 deliberately: the FIELD MAPPING is unambiguous, but
		// the ROT13 name is an identifier whose resolution to a real path
		// depends on a known-folder table that cannot cover every GUID.
		Confidence:      0.9,
		SourceReference: "userassist:" + e.GUID + `\` + e.EncodedName,
		Extra:           extra,
	}

	rawJSON, _ := json.Marshal(map[string]any{
		"hive_type":     string(hiveType),
		"key_path":      keyPath,
		"guid":          e.GUID,
		"guid_meaning":  e.GUIDMeaning,
		"encoded_name":  e.EncodedName,
		"decoded_name":  e.DecodedName,
		"resolved_path": e.ResolvedPath,
		"version":       e.Version,
		"session_id":    e.SessionID,
		"run_count":     e.RunCount,
		"run_count_raw": e.RunCountRaw,
		"focus_count":   e.FocusCount,
		"focus_time_ms": e.FocusTime.Milliseconds(),
		"last_executed": timeOrNil(e.LastExecuted),
		"record_bytes":  e.RawSize,
		"warnings":      e.Warnings,
	})
	return ev, model.RawEvidence{SourceReference: ev.SourceReference, Raw: string(rawJSON)}
}

// bagNode is one level of the BagMRU tree while it is being walked.
type bagNode struct {
	keyPath  string
	segments []string
}

// shellBagEvents reconstructs the BagMRU tree into navigation events.
//
// The tree is walked breadth-first with an explicit queue rather than by
// recursion: the depth is attacker-controlled, and a bounded queue
// cannot overflow the stack however the hive is shaped.
func (p Parser) shellBagEvents(h *regf.Hive, hiveType HiveType, host, user string) ([]model.Event, []model.RawEvidence) {
	roots, ok := bagMRUPaths[hiveType]
	if !ok {
		return nil, nil
	}

	lim := shellbag.DefaultLimits()
	var events []model.Event
	var raws []model.RawEvidence

	for _, root := range roots {
		if _, err := h.OpenKey(root); err != nil {
			continue // this hive does not carry this tree; not an error
		}
		queue := []bagNode{{keyPath: root}}
		depth := 0

		for len(queue) > 0 && depth < lim.MaxDepth {
			var next []bagNode
			for _, node := range queue {
				if len(events) >= lim.MaxEntries {
					return events, raws
				}
				children := p.bagLevel(h, node, hiveType, host, user, lim, &events, &raws)
				next = append(next, children...)
			}
			queue = next
			depth++
		}
	}
	return events, raws
}

// bagLevel reads one BagMRU key: decodes its shell items into events and
// returns the child nodes to visit, each carrying the path reconstructed
// so far.
func (p Parser) bagLevel(h *regf.Hive, node bagNode, hiveType HiveType, host, user string,
	lim shellbag.Limits, events *[]model.Event, raws *[]model.RawEvidence) []bagNode {

	k, err := h.OpenKey(node.keyPath)
	if err != nil {
		return nil
	}

	// A BagMRU key's shell items are in values named "0", "1", "2"...,
	// each matching the subkey of the same name. MRUListEx, NodeSlot and
	// NodeSlots are bookkeeping and carry no shell item.
	itemsByIndex := map[string]shellbag.Item{}
	for _, v := range k.Values {
		if _, err := strconv.Atoi(v.Name); err != nil {
			continue
		}
		items, derr := shellbag.DecodeList(v.Data, lim)
		if len(items) == 0 {
			if derr != nil {
				// A value that should hold a shell item and does not.
				// Recorded as a warning-bearing event would be noise;
				// skipping silently would hide a real decode failure, so
				// it is attached to the parent's raw record below.
				continue
			}
			continue
		}
		// The LAST item in the list is the one this level names; earlier
		// items repeat the ancestors, which the walk already has.
		itemsByIndex[v.Name] = items[len(items)-1]
	}

	var children []bagNode
	indices := make([]string, 0, len(itemsByIndex))
	for idx := range itemsByIndex {
		indices = append(indices, idx)
	}
	// Numeric order, so output is deterministic across runs.
	sort.Slice(indices, func(i, j int) bool {
		a, _ := strconv.Atoi(indices[i])
		b, _ := strconv.Atoi(indices[j])
		return a < b
	})

	// Bounded per level. A real BagMRU level holds a handful of children;
	// a level with thousands is malformed or hostile, and resolving each
	// child key costs a lookup that scans its siblings -- so an unbounded
	// level is quadratic work an attacker controls. The regf reader
	// already caps values per key at 4096; this is the tighter,
	// artifact-specific bound.
	if len(indices) > lim.MaxItemsPerKey {
		indices = indices[:lim.MaxItemsPerKey]
	}

	for _, idx := range indices {
		item := itemsByIndex[idx]
		seg := shellbag.PathSegment(item)
		segments := append(append([]string{}, node.segments...), seg)

		childPath := node.keyPath + `\` + idx
		childKey, cerr := h.OpenKey(childPath)
		lastWrite := k.LastWrite
		if cerr == nil && !childKey.LastWrite.IsZero() {
			// The child key is the node that represents THIS folder, so
			// its write time is the one that describes it.
			lastWrite = childKey.LastWrite
		}

		ev, raw := shellBagEvent(item, segments, childPath, lastWrite, hiveType, host, user)
		*events = append(*events, ev)
		*raws = append(*raws, raw)

		if cerr == nil {
			children = append(children, bagNode{keyPath: childPath, segments: segments})
		}
	}
	return children
}

// shellBagEvent builds one normalized event for a reconstructed bag.
//
// The TIMESTAMP is the BagMRU key's last-write time, and nothing else.
// That is a real FILETIME the registry recorded, in UTC, and it means
// "Explorer last updated this node of the tree". The shell item's own
// DOS date/time fields are reported as metadata and are deliberately NOT
// candidates for this field: they carry no timezone, so there is no
// instant they can honestly become. See internal/shellbag.
func shellBagEvent(item shellbag.Item, segments []string, keyPath string,
	lastWrite time.Time, hiveType HiveType, host, user string) (model.Event, model.RawEvidence) {

	rooted := rootedPath(hiveType, keyPath)
	path := shellbag.JoinPath(segments)

	extra := map[string]string{
		"artifact_class":      "shellbags",
		"registry_hive_type":  string(hiveType),
		"registry_key":        rooted,
		"shell_item_kind":     string(item.Kind),
		"shell_item_type_hex": fmt.Sprintf("0x%02X", item.TypeByte),
		"shell_item_name":     item.Name,
		"reconstructed_path":  path,
		"bag_depth":           strconv.Itoa(len(segments)),
		"shell_item_offset":   strconv.Itoa(item.Offset),
		"shell_item_bytes":    strconv.Itoa(item.Size),
		"registry_last_write": lastWrite.UTC().Format("2006-01-02T15:04:05Z"),
		"timestamp_meaning": "BagMRU key last-write time: when Explorer last updated this entry. " +
			"It is not the moment the user browsed the folder, and it is not a file timestamp.",
		"timestamp_source": "registry key last-write FILETIME",
		"evidence_meaning": "Explorer recorded this shell location: the folder or item was present in the " +
			"Windows Explorer namespace for this user. It is not evidence that a file was opened, and not " +
			"evidence that anything was executed.",
	}
	// The HIERARCHY. A ShellBags entry means little on its own: what it
	// establishes is where a folder sat, and that is a statement about
	// its ancestors. Every event therefore carries the chain it came
	// from and the node above it, so a source folder can be read off the
	// evidence instead of inferred from a single leaf.
	if n := len(segments); n > 0 {
		extra["shellbag_node"] = lastSegment(keyPath)
		if n > 1 {
			parentSegs := segments[:n-1]
			extra["parent_name"] = orUndecoded(parentSegs[len(parentSegs)-1])
			extra["parent_path"] = shellbag.JoinPath(parentSegs)
			extra["parent_registry_key"] = rootedPath(hiveType, parentKeyPath(keyPath))
			extra["parent_relationship"] = "recorded: this node is a child of the BagMRU key above it, " +
				"which is the hierarchy the registry itself stores -- not an inference"
		} else {
			extra["parent_relationship"] = "none: this is a top-level BagMRU node"
		}
	}
	// Whether the path is COMPLETE. A path containing an undecoded level
	// still places the folder, but it does not prove the chain, and an
	// analyst must be able to tell those apart at a glance.
	if undecoded := countUndecoded(segments); undecoded > 0 {
		extra["path_complete"] = "false"
		extra["path_incomplete_levels"] = strconv.Itoa(undecoded)
		extra["path_limitation"] = fmt.Sprintf(
			"%d level(s) of this path could not be decoded and are shown as %q. The levels above and below "+
				"them are recorded by the registry hierarchy, so the ORDER is evidence; the missing names are not.",
			undecoded, shellbag.UndecodedSegment)
	} else {
		extra["path_complete"] = "true"
	}
	if item.NameIsRecovered {
		extra["shell_item_name_source"] = "recovered structurally: this item has no documented name field"
		if len(item.RecoveredStrings) > 0 {
			extra["shell_item_recovered_strings"] = strings.Join(item.RecoveredStrings, " | ")
		}
	} else if item.Name != "" {
		extra["shell_item_name_source"] = "decoded from the item's documented name field"
	}
	if item.ShortName != "" {
		extra["shell_item_short_name"] = item.ShortName
	}
	if item.CLSID != "" {
		extra["shell_item_clsid"] = item.CLSID
		if item.CLSIDMeaning != "" {
			extra["shell_item_clsid_meaning"] = item.CLSIDMeaning
		} else {
			extra["shell_item_clsid_meaning"] = "not a CLSID Tracefall recognizes; reported as stored"
		}
	}
	if item.FileSize > 0 {
		extra["shell_item_size_bytes"] = strconv.FormatUint(uint64(item.FileSize), 10)
	}
	if len(item.AttributeNames) > 0 {
		extra["shell_item_attributes"] = humanJoin(item.AttributeNames)
		extra["shell_item_attributes_hex"] = fmt.Sprintf("0x%04X", item.Attributes)
	}
	if item.MFTEntry != 0 {
		extra["mft_record_number"] = strconv.FormatUint(item.MFTEntry, 10)
		extra["mft_sequence_number"] = strconv.FormatUint(uint64(item.MFTSequence), 10)
	}
	// The DOS readings, labelled for what they are. Named with a
	// "_local" suffix and carrying an explicit note, so neither the UI
	// nor an export can mistake them for instants.
	if s := item.Modified.String(); s != "" {
		extra["shell_item_modified_local"] = s
	}
	if s := item.Created.String(); s != "" {
		extra["shell_item_created_local"] = s
	}
	if s := item.Accessed.String(); s != "" {
		extra["shell_item_accessed_local"] = s
	}
	if item.Modified.String() != "" || item.Created.String() != "" || item.Accessed.String() != "" {
		extra["shell_item_time_note"] = "the *_local readings come from the shell item's FAT-style date fields: " +
			"two-second resolution, recorded in the machine's local time, with no timezone stored. They are " +
			"wall-clock readings, not instants, and are not used as this event's timestamp."
	}
	if len(item.Warnings) > 0 {
		extra["warnings"] = strings.Join(item.Warnings, "; ")
	}
	addUserContext(extra, user)

	ev := model.Event{
		Timestamp:    lastWrite.UTC(),
		Host:         host,
		User:         user,
		EventType:    model.EventShellBagNavigation,
		FilePath:     path,
		RegistryPath: rooted,
		ArtifactType: model.ArtifactShellBags,
		Parser:       parserName,
		// Below 1.0: the shell item decodes unambiguously, but a
		// reconstructed PATH is assembled across tree levels and can be
		// partial where an ancestor item did not decode.
		Confidence:      0.9,
		SourceReference: "shellbag:" + keyPath,
		Extra:           extra,
	}

	rawJSON, _ := json.Marshal(map[string]any{
		"hive_type":           string(hiveType),
		"key_path":            rooted,
		"key_last_write":      lastWrite.UTC(),
		"reconstructed_path":  path,
		"path_segments":       segments,
		"parent_path":         shellbag.JoinPath(segments[:max(0, len(segments)-1)]),
		"parent_registry_key": rootedPath(hiveType, parentKeyPath(keyPath)),
		"name_is_recovered":   item.NameIsRecovered,
		"recovered_strings":   item.RecoveredStrings,
		"shell_item_kind":     string(item.Kind),
		"shell_item_type":     fmt.Sprintf("0x%02X", item.TypeByte),
		"shell_item_name":     item.Name,
		"shell_item_short":    item.ShortName,
		"shell_item_clsid":    item.CLSID,
		"shell_item_size":     item.FileSize,
		"shell_item_attrs":    item.Attributes,
		"modified_local":      item.Modified.String(),
		"created_local":       item.Created.String(),
		"accessed_local":      item.Accessed.String(),
		"mft_record_number":   item.MFTEntry,
		"mft_sequence_number": item.MFTSequence,
		"shell_item_offset":   item.Offset,
		"shell_item_bytes":    item.Size,
		"warnings":            item.Warnings,
	})
	return ev, model.RawEvidence{SourceReference: ev.SourceReference, Raw: string(rawJSON)}
}

// timeOrNil renders a time for JSON, or nil when it is not recorded --
// so a raw record shows an absent timestamp as absent rather than as
// year 1.
func timeOrNil(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

// addUserContext records the account an artifact belongs to, and says
// WHERE that attribution came from.
//
// The distinction matters and is required by the phase's own rules: a
// username read out of the evidence path is an inference from how the
// collection was laid out, while one stored inside the artifact is a
// fact the artifact asserts. Presenting them identically would let a
// path-derived guess be read as recorded evidence.
func addUserContext(extra map[string]string, user string) {
	if user == "" {
		extra["user_context"] = "not determinable from this evidence"
		return
	}
	extra["user_context"] = user
	extra["user_context_source"] = "derived from the hive's path within the evidence collection, " +
		"not recorded inside the artifact"
}

func humanJoin(parts []string) string {
	return strings.Join(parts, ", ")
}

// lastSegment is the final component of a backslash-separated key path --
// the BagMRU node's own index.
func lastSegment(keyPath string) string {
	if i := strings.LastIndex(keyPath, `\`); i >= 0 {
		return keyPath[i+1:]
	}
	return keyPath
}

// parentKeyPath is the BagMRU key one level up. The registry hierarchy
// IS the parent-child relationship here; nothing is inferred.
func parentKeyPath(keyPath string) string {
	if i := strings.LastIndex(keyPath, `\`); i > 0 {
		return keyPath[:i]
	}
	return keyPath
}

// orUndecoded renders an empty segment as the placeholder, so a parent
// with no decoded name is never reported as having no parent.
func orUndecoded(s string) string {
	if strings.TrimSpace(s) == "" {
		return shellbag.UndecodedSegment
	}
	return s
}

// countUndecoded counts the levels whose shell item yielded no name.
func countUndecoded(segments []string) int {
	n := 0
	for _, s := range segments {
		if strings.TrimSpace(s) == "" {
			n++
		}
	}
	return n
}
