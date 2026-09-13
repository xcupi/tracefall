package registry

import (
	"encoding/binary"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/amcache"
	"tracefall/internal/model"
	"tracefall/internal/regf"
	"tracefall/internal/shellbag"
)

// Application and user-activity extraction (Phase 16): Amcache, and the
// per-user MRU structures Explorer maintains.
//
// # Why these live here
//
// The same reason UserAssist and ShellBags do (see useractivity.go):
// discovery assigns exactly ONE parser per evidence file, and every
// artifact below lives inside a hive this parser already claims.
// Amcache.hve in particular is claimed by REGF content detection, so
// before this it was classified "supported" and produced nothing --
// the worst of both answers for an analyst.
//
// # A shared rule for every artifact in this file
//
// None of them records an execution. Each records that Windows NOTICED
// something: catalogued a binary, listed a document, remembered a typed
// command. The event types, the evidence_meaning strings and the
// timestamp_meaning strings all say that, and the tests assert it.

// MRU key paths, relative to a user hive's root.
const (
	pathRecentDocs   = `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
	pathRunMRU       = `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
	pathTypedPaths   = `Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`
	pathOpenSavePidl = `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
	pathLastVisited  = `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
)

// muiCachePaths are where the shell caches application display names.
// Modern Windows keeps it in UsrClass.dat; older builds in NTUSER.DAT.
var muiCachePaths = map[HiveType][]string{
	HiveUsrClass: {`Local Settings\Software\Microsoft\Windows\Shell\MuiCache`},
	HiveNTUser: {
		`Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`,
		`Software\Microsoft\Windows\ShellNoRoam\MUICache`,
	},
}

// ---------------- Amcache ----------------

// amcacheEvents extracts every Amcache entry in the hive.
//
// Returns nothing for a hive with no Amcache tree, which is the normal
// state of every hive except Amcache.hve itself -- a valid artifact with
// zero records of this kind, not a failure.
func (p Parser) amcacheEvents(h *regf.Hive, host string) ([]model.Event, []model.RawEvidence) {
	lim := amcache.DefaultLimits()
	var events []model.Event
	var raws []model.RawEvidence

	add := func(e amcache.Entry) bool {
		if len(events) >= lim.MaxEntries {
			return false
		}
		ev, raw := amcacheEvent(e, host)
		events = append(events, ev)
		raws = append(raws, raw)
		return true
	}

	// Each tree is enumerated with ChildKeys, which reads a key's
	// children in ONE pass. Listing names and then opening each by path
	// is quadratic -- see regf.ChildKeys -- and an Amcache inventory is
	// exactly the wide key that makes that fatal.

	// Windows 10/11: InventoryApplicationFile, one subkey per binary.
	for _, k := range sortedChildren(h, amcache.PathInventoryFile) {
		if !add(amcache.DecodeInventoryFile(valueSource(k, k.Name, k.Path), lim)) {
			return events, raws
		}
	}

	// Windows 10/11: InventoryApplication, one subkey per installed
	// program. A different claim from a file entry, and kept distinct.
	for _, k := range sortedChildren(h, amcache.PathInventoryApplication) {
		if !add(amcache.DecodeInventoryApplication(valueSource(k, k.Name, k.Path), lim)) {
			return events, raws
		}
	}

	// Windows 8/8.1: Root\File\{VolumeGUID}\{FileID}, two levels deep.
	for _, vol := range sortedChildren(h, amcache.PathFile) {
		for _, k := range sortedChildren(h, vol.Path) {
			entry := amcache.DecodeFileEntry(valueSource(k, k.Name, k.Path), lim)
			entry.Extra["volume_guid"] = vol.Name
			if !add(entry) {
				return events, raws
			}
		}
	}

	return events, raws
}

// valueSource renders one registry key for the amcache decoder, keeping
// that package independent of the hive reader.
func valueSource(k regf.Key, name, path string) amcache.ValueSource {
	src := amcache.ValueSource{
		KeyName:   name,
		KeyPath:   path,
		LastWrite: k.LastWrite,
		Values:    map[string]string{},
		Numbers:   map[string]uint64{},
	}
	for _, v := range k.Values {
		src.Values[v.Name] = v.String()
		switch v.Type {
		case regf.RegDWord:
			if len(v.Data) >= 4 {
				src.Numbers[v.Name] = uint64(binary.LittleEndian.Uint32(v.Data[:4]))
			}
		case regf.RegQWord:
			if len(v.Data) >= 8 {
				src.Numbers[v.Name] = binary.LittleEndian.Uint64(v.Data[:8])
			}
		}
	}
	return src
}

// amcacheEvent builds one normalized event from a decoded Amcache entry.
func amcacheEvent(e amcache.Entry, host string) (model.Event, model.RawEvidence) {
	keyPath := `Amcache.hve\` + e.KeyPath

	extra := map[string]string{
		"artifact_class":      "amcache",
		"amcache_generation":  string(e.Generation),
		"registry_key":        keyPath,
		"registry_last_write": e.KeyLastWrite.UTC().Format("2006-01-02T15:04:05Z"),
		"evidence_meaning":    e.EvidenceMeaning(),
		"timestamp_meaning":   amcache.TimestampMeaning(),
		"timestamp_source":    "Amcache registry key last-write FILETIME",
	}
	setIf := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			extra[k] = v
		}
	}
	setIf("application_name", e.Name)
	setIf("application_path", e.Path)
	setIf("publisher", e.Publisher)
	setIf("product_name", e.ProductName)
	setIf("product_version", e.Version)
	setIf("program_id", e.ProgramID)
	setIf("amcache_source", e.Source)
	if e.SHA1 != "" {
		extra["sha1"] = e.SHA1
		extra["sha1_note"] = "recorded by Amcache for the binary at the path above. It identifies the FILE; " +
			"it is not evidence that the file ran."
	}
	if e.SizeBytes >= 0 {
		extra["file_size_bytes"] = strconv.FormatInt(e.SizeBytes, 10)
	}
	if !e.LinkDate.IsZero() {
		extra["pe_link_date"] = e.LinkDate.UTC().Format("2006-01-02T15:04:05Z")
		extra["pe_link_date_note"] = "the PE header's compilation timestamp. It describes when the BINARY was " +
			"built, not any activity on this machine, and it is trivially forgeable."
	}
	if !e.InstallDate.IsZero() {
		extra["install_date"] = e.InstallDate.UTC().Format("2006-01-02T15:04:05Z")
	}
	for k, v := range e.Extra {
		extra["amcache_"+k] = v
	}
	if len(e.Warnings) > 0 {
		extra["warnings"] = strings.Join(e.Warnings, "; ")
	}

	ev := model.Event{
		Timestamp: e.KeyLastWrite.UTC(),
		Host:      host,
		EventType: model.EventAmcacheApplication,
		// FilePath, never ProcessName: Amcache names a FILE it
		// catalogued. Putting it in ProcessName would assert a process
		// existed, which is the exact overstatement this artifact invites.
		FilePath:     e.Path,
		RegistryPath: keyPath,
		ArtifactType: model.ArtifactAmcache,
		Parser:       parserName,
		// 0.9: the fields decode unambiguously, but Amcache's own
		// semantics (which event caused the entry) are not recorded.
		Confidence:      0.9,
		SourceReference: "amcache:" + e.KeyPath,
		Extra:           extra,
	}

	rawJSON, _ := json.Marshal(map[string]any{
		"generation":     string(e.Generation),
		"key_path":       e.KeyPath,
		"key_last_write": e.KeyLastWrite.UTC(),
		"name":           e.Name,
		"path":           e.Path,
		"sha1":           e.SHA1,
		"size_bytes":     e.SizeBytes,
		"publisher":      e.Publisher,
		"product_name":   e.ProductName,
		"version":        e.Version,
		"program_id":     e.ProgramID,
		"source":         e.Source,
		"link_date":      timeOrNil(e.LinkDate),
		"install_date":   timeOrNil(e.InstallDate),
		"extra":          e.Extra,
		"warnings":       e.Warnings,
	})
	return ev, model.RawEvidence{SourceReference: ev.SourceReference, Raw: string(rawJSON)}
}

// ---------------- Per-user MRU structures ----------------

// mruEvents extracts RecentDocs, RunMRU, TypedPaths, OpenSavePidlMRU and
// MUICache from a user hive.
func (p Parser) mruEvents(h *regf.Hive, hiveType HiveType, host, user string) ([]model.Event, []model.RawEvidence) {
	if hiveType != HiveNTUser && hiveType != HiveUsrClass {
		return nil, nil
	}
	var events []model.Event
	var raws []model.RawEvidence
	collect := func(e []model.Event, r []model.RawEvidence) {
		events = append(events, e...)
		raws = append(raws, r...)
	}

	if hiveType == HiveNTUser {
		collect(p.recentDocsEvents(h, hiveType, host, user))
		collect(p.runMRUEvents(h, hiveType, host, user))
		collect(p.typedPathsEvents(h, hiveType, host, user))
		collect(p.openSaveEvents(h, hiveType, host, user))
	}
	collect(p.muiCacheEvents(h, hiveType, host, user))
	return events, raws
}

// mruOrder decodes an MRUListEx value: little-endian int32 indices in
// most-recently-used order, terminated by 0xFFFFFFFF.
//
// Returns the position of each index, so an entry can report WHERE it
// sits in the order rather than only that an order exists.
func mruOrder(values []regf.Value) map[string]int {
	out := map[string]int{}
	for _, v := range values {
		switch strings.ToLower(v.Name) {
		case "mrulistex":
			for i := 0; i+4 <= len(v.Data); i += 4 {
				n := binary.LittleEndian.Uint32(v.Data[i : i+4])
				if n == 0xFFFFFFFF {
					return out
				}
				out[strconv.FormatUint(uint64(n), 10)] = i / 4
			}
			return out
		case "mrulist":
			// The older form: a NUL-terminated UTF-16 string of letters,
			// each naming a value ("a", "b", ...).
			for i, r := range v.String() {
				if r == 0 {
					break
				}
				out[string(r)] = i
			}
			return out
		}
	}
	return out
}

// mruPosition renders an entry's place in the MRU order, or "" when the
// key records no order.
func mruPosition(order map[string]int, name string) string {
	if len(order) == 0 {
		return ""
	}
	pos, ok := order[name]
	if !ok {
		return ""
	}
	return strconv.Itoa(pos)
}

// recentDocsEvents reads the RecentDocs tree.
//
// The root key holds recent documents of every type; each `.ext` subkey
// holds the same list filtered to one extension. Both are read, and the
// extension is recorded, so an analyst can tell a general entry from an
// extension-scoped one.
func (p Parser) recentDocsEvents(h *regf.Hive, hiveType HiveType, host, user string) ([]model.Event, []model.RawEvidence) {
	var events []model.Event
	var raws []model.RawEvidence

	read := func(keyPath, ext string) {
		k, err := h.OpenKey(keyPath)
		if err != nil {
			return
		}
		order := mruOrder(k.Values)
		for _, v := range k.Values {
			if isMRUBookkeeping(v.Name) {
				continue
			}
			name, shellPath := decodeRecentDocValue(v)
			if name == "" {
				continue
			}
			ev, raw := mruEvent(mruSpec{
				eventType:     model.EventRecentDocument,
				artifactType:  model.ArtifactRecentDocs,
				artifactClass: "recent_docs",
				keyPath:       rootedPath(hiveType, keyPath),
				valueName:     v.Name,
				value:         name,
				filePath:      name,
				lastWrite:     k.LastWrite,
				position:      mruPosition(order, v.Name),
				host:          host, user: user,
				evidenceMeaning: "Explorer recorded this document in its recent-documents list. It is evidence " +
					"the document was OPENED THROUGH THE SHELL by this user; it is not a process-creation " +
					"record, and it does not say the document still exists.",
				timestampMeaning: "RecentDocs key last-write time. It dates the MOST RECENT change to this key -- " +
					"which is the top entry only. An older entry in the same key was added at some earlier, " +
					"unrecorded time.",
				extra: map[string]string{},
			})
			if ext != "" {
				ev.Extra["recentdocs_extension"] = ext
				ev.Extra["recentdocs_scope"] = "extension-specific list"
			} else {
				ev.Extra["recentdocs_scope"] = "all document types"
			}
			if shellPath != "" {
				ev.Extra["shell_item_path"] = shellPath
			}
			events = append(events, ev)
			raws = append(raws, raw)
		}
	}

	read(pathRecentDocs, "")
	for _, sub := range sortedSubkeys(h, pathRecentDocs) {
		read(pathRecentDocs+`\`+sub, sub)
	}
	return events, raws
}

// decodeRecentDocValue reads a RecentDocs value.
//
// The value is a UTF-16 name, then a shell item link. Only the leading
// name is relied on; the trailing shell item is decoded opportunistically
// and reported separately when it yields anything, rather than being
// merged into the name.
func decodeRecentDocValue(v regf.Value) (name, shellPath string) {
	data := v.Data
	if len(data) < 2 {
		return "", ""
	}
	name = firstUTF16(data, 4096)
	consumed := (len([]rune(name)) + 1) * 2
	if consumed < len(data) {
		if items, err := shellbag.DecodeList(data[consumed:], shellbag.DefaultLimits()); err == nil && len(items) > 0 {
			var segs []string
			for _, it := range items {
				if s := shellbag.PathSegment(it); s != "" {
					segs = append(segs, s)
				}
			}
			shellPath = shellbag.JoinPath(segs)
		}
	}
	return name, shellPath
}

// runMRUEvents reads the Run-dialog MRU.
func (p Parser) runMRUEvents(h *regf.Hive, hiveType HiveType, host, user string) ([]model.Event, []model.RawEvidence) {
	k, err := h.OpenKey(pathRunMRU)
	if err != nil {
		return nil, nil
	}
	order := mruOrder(k.Values)
	var events []model.Event
	var raws []model.RawEvidence
	for _, v := range k.Values {
		if isMRUBookkeeping(v.Name) {
			continue
		}
		cmd := strings.TrimSpace(v.String())
		// Windows appends "\1" to the stored command. Stripped so the
		// command reads as typed, with the raw form kept in the record.
		cmd = strings.TrimSuffix(cmd, "\\1")
		if cmd == "" {
			continue
		}
		ev, raw := mruEvent(mruSpec{
			eventType:     model.EventRunMRUCommand,
			artifactType:  model.ArtifactRunMRU,
			artifactClass: "run_mru",
			keyPath:       rootedPath(hiveType, pathRunMRU),
			valueName:     v.Name,
			value:         cmd,
			// The command text goes in CommandLine, which is honest: it
			// IS a command line the user typed. ProcessName stays empty
			// because no process is recorded.
			commandLine: cmd,
			lastWrite:   k.LastWrite,
			position:    mruPosition(order, v.Name),
			host:        host, user: user,
			evidenceMeaning: "Run dialog command recorded: this text was typed into the Windows Run dialog and " +
				"accepted by this user. It is not evidence that the command executed successfully, and it is " +
				"not a process-creation record.",
			timestampMeaning: "RunMRU key last-write time, which dates the most recent entry in this key only.",
			extra:            map[string]string{"raw_value": truncate(v.String(), 1024)},
		})
		events = append(events, ev)
		raws = append(raws, raw)
	}
	return events, raws
}

// typedPathsEvents reads the Explorer address-bar history.
func (p Parser) typedPathsEvents(h *regf.Hive, hiveType HiveType, host, user string) ([]model.Event, []model.RawEvidence) {
	k, err := h.OpenKey(pathTypedPaths)
	if err != nil {
		return nil, nil
	}
	var events []model.Event
	var raws []model.RawEvidence
	// Value names are url1, url2, ... with url1 the most recent.
	names := make([]regf.Value, 0, len(k.Values))
	names = append(names, k.Values...)
	sort.SliceStable(names, func(i, j int) bool { return names[i].Name < names[j].Name })

	for _, v := range names {
		path := strings.TrimSpace(v.String())
		if path == "" {
			continue
		}
		pos := ""
		if n := strings.TrimPrefix(strings.ToLower(v.Name), "url"); n != v.Name {
			if i, err := strconv.Atoi(n); err == nil {
				pos = strconv.Itoa(i - 1) // url1 is position 0
			}
		}
		ev, raw := mruEvent(mruSpec{
			eventType:     model.EventTypedPath,
			artifactType:  model.ArtifactTypedPaths,
			artifactClass: "typed_paths",
			keyPath:       rootedPath(hiveType, pathTypedPaths),
			valueName:     v.Name,
			value:         path,
			filePath:      path,
			lastWrite:     k.LastWrite,
			position:      pos,
			host:          host, user: user,
			evidenceMeaning: "Path entered into the Windows Explorer address bar by this user. It records what " +
				"was TYPED -- not that the path was opened, not that it existed, and certainly not that " +
				"anything was executed.",
			timestampMeaning: "TypedPaths key last-write time, which dates the most recent entry in this key only.",
			extra:            map[string]string{},
		})
		events = append(events, ev)
		raws = append(raws, raw)
	}
	return events, raws
}

// openSaveEvents reads the Open/Save common-dialog MRU.
//
// Its values are shell item lists, decoded by the SAME decoder ShellBags
// uses (internal/shellbag) rather than a second implementation.
func (p Parser) openSaveEvents(h *regf.Hive, hiveType HiveType, host, user string) ([]model.Event, []model.RawEvidence) {
	var events []model.Event
	var raws []model.RawEvidence

	read := func(keyPath, ext string) {
		k, err := h.OpenKey(keyPath)
		if err != nil {
			return
		}
		order := mruOrder(k.Values)
		for _, v := range k.Values {
			if isMRUBookkeeping(v.Name) {
				continue
			}
			items, derr := shellbag.DecodeList(v.Data, shellbag.DefaultLimits())
			if len(items) == 0 {
				continue
			}
			var segs []string
			for _, it := range items {
				if s := shellbag.PathSegment(it); s != "" {
					segs = append(segs, s)
				}
			}
			path := shellbag.JoinPath(segs)
			if path == "" {
				continue
			}
			last := items[len(items)-1]
			ev, raw := mruEvent(mruSpec{
				eventType:     model.EventOpenSaveMRU,
				artifactType:  model.ArtifactOpenSaveMRU,
				artifactClass: "opensave_mru",
				keyPath:       rootedPath(hiveType, keyPath),
				valueName:     v.Name,
				value:         path,
				filePath:      path,
				lastWrite:     k.LastWrite,
				position:      mruPosition(order, v.Name),
				host:          host, user: user,
				evidenceMeaning: "File selected in a Windows Open or Save dialog by this user. It records that " +
					"the file was CHOSEN in a dialog -- not that it was executed, and for a Save dialog not " +
					"that it previously existed.",
				timestampMeaning: "OpenSavePidlMRU key last-write time, which dates the most recent entry in " +
					"this key only.",
				extra: map[string]string{
					"shell_item_kind": string(last.Kind),
					"shell_item_name": last.Name,
				},
			})
			if ext != "" && !strings.EqualFold(ext, "*") {
				ev.Extra["opensave_extension"] = ext
			}
			if derr != nil {
				ev.Extra["warnings"] = derr.Error()
			}
			if s := last.Modified.String(); s != "" {
				ev.Extra["shell_item_modified_local"] = s
				ev.Extra["shell_item_time_note"] = "a FAT-style wall-clock reading from the shell item: no " +
					"timezone, two-second resolution. Not this event's timestamp."
			}
			events = append(events, ev)
			raws = append(raws, raw)
		}
	}

	for _, ext := range sortedSubkeys(h, pathOpenSavePidl) {
		read(pathOpenSavePidl+`\`+ext, ext)
	}
	read(pathOpenSavePidl, "")
	return events, raws
}

// muiCacheEvents reads the shell's cached application display names.
func (p Parser) muiCacheEvents(h *regf.Hive, hiveType HiveType, host, user string) ([]model.Event, []model.RawEvidence) {
	paths, ok := muiCachePaths[hiveType]
	if !ok {
		return nil, nil
	}
	var events []model.Event
	var raws []model.RawEvidence

	for _, keyPath := range paths {
		k, err := h.OpenKey(keyPath)
		if err != nil {
			continue
		}
		for _, v := range k.Values {
			// MUICache value names are executable paths, sometimes with a
			// ".FriendlyAppName" or ".ApplicationCompany" suffix.
			exe := v.Name
			field := "friendly_name"
			switch {
			case strings.HasSuffix(exe, ".FriendlyAppName"):
				exe = strings.TrimSuffix(exe, ".FriendlyAppName")
			case strings.HasSuffix(exe, ".ApplicationCompany"):
				exe = strings.TrimSuffix(exe, ".ApplicationCompany")
				field = "application_company"
			case strings.HasPrefix(exe, "@"):
				// A resource reference rather than a path.
				continue
			}
			display := strings.TrimSpace(v.String())
			if exe == "" || display == "" {
				continue
			}
			ev, raw := mruEvent(mruSpec{
				eventType:     model.EventMUICacheEntry,
				artifactType:  model.ArtifactMUICache,
				artifactClass: "muicache",
				keyPath:       rootedPath(hiveType, keyPath),
				valueName:     v.Name,
				value:         display,
				filePath:      exe,
				lastWrite:     k.LastWrite,
				host:          host, user: user,
				evidenceMeaning: "MUICache recorded a display name for this application. The shell caches these " +
					"when it ENUMERATES an executable -- browsing a folder is enough -- so this is " +
					"application-presence evidence and not evidence that the program ran.",
				timestampMeaning: "MUICache key last-write time. The key holds many entries, so it does not " +
					"date this one.",
				extra: map[string]string{
					"muicache_field": field,
					"display_name":   display,
				},
			})
			events = append(events, ev)
			raws = append(raws, raw)
		}
	}
	return events, raws
}

// ---------------- Shared MRU event construction ----------------

type mruSpec struct {
	eventType        string
	artifactType     string
	artifactClass    string
	keyPath          string
	valueName        string
	value            string
	filePath         string
	commandLine      string
	lastWrite        time.Time
	position         string
	host, user       string
	evidenceMeaning  string
	timestampMeaning string
	extra            map[string]string
}

// mruEvent builds one normalized event for an MRU-style artifact.
//
// Every one of these shares the same awkward timestamp property, and it
// is stated on every event rather than left for the reader to know: the
// key's last-write time dates the key, and a key holds many entries, so
// only the most recent entry is actually dated by it.
func mruEvent(s mruSpec) (model.Event, model.RawEvidence) {
	extra := map[string]string{
		"artifact_class":      s.artifactClass,
		"registry_key":        s.keyPath,
		"registry_value_name": s.valueName,
		"registry_last_write": s.lastWrite.UTC().Format("2006-01-02T15:04:05Z"),
		"evidence_meaning":    s.evidenceMeaning,
		"timestamp_meaning":   s.timestampMeaning,
		"timestamp_source":    "registry key last-write FILETIME",
	}
	for k, v := range s.extra {
		if strings.TrimSpace(v) != "" {
			extra[k] = v
		}
	}
	if s.position != "" {
		extra["mru_position"] = s.position
		extra["mru_position_note"] = "0 is the most recently used entry in this key"
	}
	addUserContext(extra, s.user)

	ev := model.Event{
		Timestamp:    s.lastWrite.UTC(),
		Host:         s.host,
		User:         s.user,
		EventType:    s.eventType,
		FilePath:     s.filePath,
		CommandLine:  s.commandLine,
		RegistryPath: s.keyPath + `\` + s.valueName,
		ArtifactType: s.artifactType,
		Parser:       parserName,
		// 0.8 across this family. The VALUE decodes unambiguously, but
		// the key's write time dates the key rather than the entry, so
		// the event's position in time is weaker than its content.
		Confidence:      0.8,
		SourceReference: s.artifactClass + ":" + s.keyPath + `\` + s.valueName,
		Extra:           extra,
	}

	rawJSON, _ := json.Marshal(map[string]any{
		"artifact_class": s.artifactClass,
		"key_path":       s.keyPath,
		"key_last_write": s.lastWrite.UTC(),
		"value_name":     s.valueName,
		"value":          s.value,
		"mru_position":   s.position,
		"extra":          s.extra,
	})
	return ev, model.RawEvidence{SourceReference: ev.SourceReference, Raw: string(rawJSON)}
}

// isMRUBookkeeping reports whether a value name is ordering/bookkeeping
// rather than an entry.
func isMRUBookkeeping(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "mrulistex", "mrulist", "nodeslot", "nodeslots", "":
		return true
	}
	return false
}

// sortedSubkeys lists a key's subkey NAMES in a deterministic order, or
// none when the key does not exist. For a key whose children must then
// be read, use sortedChildren instead -- opening each name separately is
// quadratic on a wide key.
func sortedSubkeys(h *regf.Hive, path string) []string {
	subs, err := h.Subkeys(path)
	if err != nil {
		return nil
	}
	sort.Strings(subs)
	return subs
}

// sortedChildren reads a key's children in one pass, in a deterministic
// order, or none when the key does not exist.
func sortedChildren(h *regf.Hive, path string) []regf.Key {
	kids, err := h.ChildKeys(path)
	if err != nil {
		return nil
	}
	sort.Slice(kids, func(i, j int) bool { return kids[i].Name < kids[j].Name })
	return kids
}

// firstUTF16 reads a NUL-terminated little-endian UTF-16 string.
func firstUTF16(b []byte, max int) string {
	var sb strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i:])
		if u == 0 {
			break
		}
		if u < 0x20 || u == 0x7F {
			return sb.String()
		}
		sb.WriteRune(rune(u))
		if sb.Len() >= max {
			break
		}
	}
	return sb.String()
}
