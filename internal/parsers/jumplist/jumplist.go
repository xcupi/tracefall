// Package jumplist turns Windows Jump Lists into normalized evidence.
//
// # What an entry asserts
//
// That an application HOLDS A REFERENCE to a target, and -- where the
// Jump List's own DestList recorded one -- that the reference was last
// touched at a given time and has been reached a given number of times.
//
// It is not proof of execution. Windows records items that were opened,
// saved, previewed, or merely reached through a file dialog, and an
// application may add entries of its own. So no event this parser emits
// is named for a run, no ProcessName or CommandLine is ever populated,
// and any arguments the embedded shortcut carried are recorded as
// shortcut metadata rather than as a command line that executed.
//
// # Two timestamps, never merged
//
// A Jump List can supply two quite different times, and conflating them
// would misdate a reconstruction:
//
//	jumplist_entry_access     the DestList's own last-recorded access.
//	                          The artifact's closest thing to a moment
//	                          of use.
//	jumplist_target_metadata  the TARGET FILE's creation/write/access
//	                          time, carried by the embedded shortcut.
//	                          A property of the file, not of any use.
//
// Every event states which it is, in timestamp_meaning.
//
// # Reuse
//
// Containers are read by internal/jumplist, compound files by
// internal/olecf, and embedded shortcuts by internal/shelllink -- the
// same shortcut parser that reads standalone .lnk files. Nothing about
// either format is reimplemented here.
package jumplist

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	jl "tracefall/internal/jumplist"
	"tracefall/internal/model"
	"tracefall/internal/ntfs"
	"tracefall/internal/parsers"
	"tracefall/internal/shelllink"
)

// Distinct names, one per parser. Import re-resolves a file's parser by
// NAME (see api.findParserFor), so two parsers sharing one name would
// send every file to whichever registered first -- which is exactly what
// happened here: custom lists were handed to the automatic parser and
// refused for having the wrong container.
const (
	automaticParserName = "jumplist@1"
	customParserName    = "jumplistcustom@1"
)

// Two parsers, because the registry maps one parser to one artifact
// type and the two containers ARE different artifacts: an automatic list
// carries a DestList with access times and an ordering, a custom list
// carries none of that. An analyst reading "Jump List" must be able to
// tell which they have.
//
// Both delegate to the same implementation below; only detection and the
// artifact type differ.

// AutomaticParser reads *.automaticDestinations-ms.
type AutomaticParser struct{ p base }

// NewAutomatic returns the Automatic Destinations parser.
func NewAutomatic() *AutomaticParser { return &AutomaticParser{base{jl.DefaultLimits()}} }

func (AutomaticParser) Name() string         { return automaticParserName }
func (AutomaticParser) ArtifactType() string { return model.ArtifactJumpListAutomatic }

// Detect claims the extension. Content detection is not offered for this
// container: an Automatic Destinations list is an OLE compound file, a
// format it shares with pre-2007 Office documents, MSI packages and
// Thumbs.db, and nothing in the first 512 bytes tells them apart. What
// distinguishes a Jump List -- a DestList stream beside numbered
// shortcut streams -- is visible only after the container's allocation
// tables have been walked, which discovery does not do.
//
// Claiming every compound file by content would classify every old .doc
// in a collection as a Jump List and then report each as a parse
// failure. The extension is claimed instead, and a file wearing it
// without the content is refused at parse time.
func (AutomaticParser) Detect(relPath string) bool {
	return strings.HasSuffix(strings.ToLower(filepath.Base(relPath)), ".automaticdestinations-ms")
}

// Parse reads one Automatic Destinations Jump List.
func (a AutomaticParser) Parse(absPath string) (parsers.ParseResult, error) {
	return a.p.parse(absPath, jl.KindAutomatic, automaticParserName)
}

// CustomParser reads *.customDestinations-ms.
type CustomParser struct{ p base }

// NewCustom returns the Custom Destinations parser.
func NewCustom() *CustomParser { return &CustomParser{base{jl.DefaultLimits()}} }

func (CustomParser) Name() string         { return customParserName }
func (CustomParser) ArtifactType() string { return model.ArtifactJumpListCustom }

// Detect claims the extension as a fast path.
func (CustomParser) Detect(relPath string) bool {
	return strings.HasSuffix(strings.ToLower(filepath.Base(relPath)), ".customdestinations-ms")
}

// DetectContent finds a RENAMED Custom Destinations list.
//
// Unlike the automatic container, this one is identifiable from its
// leading bytes: a shell link header is 20 bytes of fixed content, and a
// custom list places its first one AFTER a small header rather than at
// offset zero -- which is what separates it from a standalone .lnk. See
// internal/jumplist.SniffCustom.
func (CustomParser) DetectContent(header []byte) bool { return jl.SniffCustom(header) }

// Parse reads one Custom Destinations Jump List.
func (c CustomParser) Parse(absPath string) (parsers.ParseResult, error) {
	return c.p.parse(absPath, jl.KindCustom, customParserName)
}

// base holds the shared implementation.
type base struct {
	limits jl.Limits
}

// parse reads one Jump List and refuses a container that is not the one
// this parser claimed -- so a file with the wrong extension for its
// content is reported as what it is, not parsed as what it was named.
func (p base) parse(absPath string, want jl.Kind, name string) (parsers.ParseResult, error) {
	list, err := jl.ParseFile(absPath, p.limits)
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("jumplist: %w", err)
	}
	if list.Kind != want {
		return parsers.ParseResult{}, fmt.Errorf(
			"jumplist: %w: this file is named as a %s Jump List but its container is %s",
			jl.ErrNotJumpList, want, list.Kind)
	}
	sourceName := filepath.Base(absPath)

	artifactType := model.ArtifactJumpListAutomatic
	containerLabel := "Automatic Destinations (OLE compound file)"
	if list.Kind == jl.KindCustom {
		artifactType = model.ArtifactJumpListCustom
		containerLabel = "Custom Destinations (concatenated shell links)"
	}

	appLabel := jl.ApplicationLabel(list.AppID, list.Application)
	base := map[string]string{
		"jumplist_file":      sourceName,
		"source_file":        sourceName,
		"jumplist_kind":      string(list.Kind),
		"jumplist_container": containerLabel,
		"application":        appLabel,
		// The raw identifier is always present, resolved or not: it is
		// the thing an analyst can look up.
		"app_id": orNone(list.AppID, "(the filename carries no AppID)"),
		"evidence_meaning": "Jump List entry: the application named above holds a reference to this target. " +
			"This is NOT evidence that the target was executed -- Windows records items that were opened, saved, " +
			"previewed, or merely reached through a file dialog, and an application may add entries itself.",
		"artifact_class": "Jump List (application reference evidence)",
	}
	if list.Application == "" {
		base["app_id_resolved"] = "false"
	} else {
		base["app_id_resolved"] = "true"
	}
	if list.DestListVersion != 0 {
		base["destlist_version"] = strconv.FormatUint(uint64(list.DestListVersion), 10)
	}
	if len(list.Warnings) > 0 {
		base["parse_warnings"] = strings.Join(list.Warnings, "; ")
	}

	var out parsers.ParseResult
	for i, e := range list.Entries {
		extra, raw := p.entryFields(base, list, e, i)

		// Reference: where this entry lived inside the artifact.
		ref := fmt.Sprintf("jumplist:%s:%s", list.Kind, e.StreamName)
		emitted := 0

		// 1. The Jump List's OWN timestamp, where the DestList had one.
		if e.Dest != nil && !e.Dest.LastRecordedAccess.IsZero() {
			ev := p.event(artifactType, name, model.EventJumpListEntryAccess,
				e.Dest.LastRecordedAccess, extra, ref+":access")
			ev.Extra["timestamp_meaning"] = "Jump List last-recorded access: when the application last recorded " +
				"reaching this item. Not proof that the target was executed."
			ev.Extra["timestamp_source"] = "DestList entry for stream " + e.StreamName
			out.Events = append(out.Events, ev)
			out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ref + ":access", Raw: raw})
			emitted++
		}

		// 2. The TARGET FILE's own timestamps, from the embedded
		//    shortcut. Separate events, separately labelled.
		if e.LinkError == nil {
			for _, s := range targetStamps(e.Link) {
				if s.at.IsZero() {
					continue
				}
				r := ref + ":" + s.field
				ev := p.event(artifactType, name, model.EventJumpListTargetMetadata, s.at, extra, r)
				ev.Extra["timestamp_meaning"] = s.meaning
				ev.Extra["timestamp_source"] = "embedded shortcut ShellLinkHeader " + s.field
				out.Events = append(out.Events, ev)
				out.Raw = append(out.Raw, model.RawEvidence{SourceReference: r, Raw: raw})
				emitted++
			}
		}

		// An entry with no usable timestamp is still evidence: it names
		// an application and a target. It is kept as a record rather
		// than given a time it does not have.
		if emitted == 0 {
			out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ref + ":metadata", Raw: raw})
		}
	}

	if len(list.Entries) == 0 {
		report, _ := json.Marshal(map[string]any{
			"jumplist_file": sourceName,
			"kind":          string(list.Kind),
			"app_id":        list.AppID,
			"application":   appLabel,
			"entries":       0,
			"streams_seen":  list.StreamsSeen,
			"warnings":      list.Warnings,
			"note":          "the container was read and held no entries",
		})
		out.Raw = append(out.Raw, model.RawEvidence{
			SourceReference: "jumplist:parse-report", Raw: string(report),
		})
	}
	return out, nil
}

// event builds one normalized event with the shared fields.
func (p base) event(artifactType, parser, eventType string, at time.Time, extra map[string]string, ref string) model.Event {
	ev := model.Event{
		Timestamp:    at.UTC(),
		EventType:    eventType,
		ArtifactType: artifactType,
		Parser:       parser,
		// FilePath is the TARGET, not the Jump List.
		//
		// It is the subject of the event, it is what an investigator
		// searches for, and -- decisively -- FilePath is part of an
		// event's dedup identity (model.Event.ComputeDedupHash). Using
		// the Jump List's own name here made every entry in one list
		// share it, so two entries with the same timestamp collapsed
		// into one and a real target was lost. The artifact itself stays
		// in extra as jumplist_file and source_file.
		FilePath: extra["target_path"],
		// No User, no ProcessName, no CommandLine. A Jump List names an
		// APPLICATION, not a process that ran, and the embedded
		// shortcut's arguments are metadata rather than a command line
		// that was executed.
		//
		// 0.8, matching standalone shortcuts: the observation is solid,
		// but what it proves about activity is weaker than a recorded
		// execution or a logged event.
		Confidence:      0.8,
		SourceReference: ref,
		Extra:           make(map[string]string, len(extra)+2),
	}
	for k, v := range extra {
		ev.Extra[k] = v
	}
	return ev
}

// targetStamps lists an embedded shortcut's target timestamps in a fixed
// order, so output is deterministic.
func targetStamps(l shelllink.Link) []struct {
	at      time.Time
	field   string
	meaning string
} {
	return []struct {
		at      time.Time
		field   string
		meaning string
	}{
		{l.CreationTime, "CreationTime",
			"target file creation time, as the embedded shortcut recorded it. A property of the file, not a use of it."},
		{l.WriteTime, "WriteTime",
			"target file last-write time, as the embedded shortcut recorded it. A property of the file, not a use of it."},
		{l.AccessTime, "AccessTime",
			"target file last-access time, as the embedded shortcut recorded it. A property of the file, not a use of it."},
	}
}

// entryFields builds one entry's flat fields and its raw record.
func (p base) entryFields(base map[string]string, list jl.JumpList, e jl.Entry, index int) (map[string]string, string) {
	extra := make(map[string]string, len(base)+20)
	for k, v := range base {
		extra[k] = v
	}

	// Provenance: exactly where inside the artifact this came from.
	extra["jumplist_stream"] = e.StreamName
	extra["jumplist_entry_index"] = strconv.Itoa(index)
	if e.StreamIndex >= 0 {
		extra["jumplist_stream_directory_index"] = strconv.Itoa(e.StreamIndex)
	}
	if e.Bytes > 0 {
		extra["embedded_link_bytes"] = strconv.Itoa(e.Bytes)
	}
	if list.Kind == jl.KindCustom {
		extra["embedded_link_offset"] = strconv.Itoa(e.Offset)
	}

	target, source := e.TargetPath()
	if target != "" {
		extra["target_path"] = target
		extra["target_path_source"] = source
		extra["target_name"] = baseName(target)
	}
	if e.PathsDisagree() {
		extra["target_path_disagreement"] = "the embedded shortcut and the DestList record different targets; both are preserved"
	}

	if e.Dest != nil {
		d := e.Dest
		extra["mru_position"] = strconv.Itoa(d.MRUPosition)
		extra["access_count"] = strconv.FormatUint(uint64(d.AccessCount), 10)
		extra["pinned"] = strconv.FormatBool(d.Pinned)
		if d.Path != "" {
			extra["destlist_path"] = d.Path
		}
		if d.Hostname != "" {
			extra["destlist_hostname"] = d.Hostname
		}
		if !d.LastRecordedAccess.IsZero() {
			extra["jumplist_last_access"] = d.LastRecordedAccess.UTC().Format("2006-01-02T15:04:05Z")
		}
	}

	if e.LinkError != nil {
		extra["embedded_link_error"] = e.LinkError.Error()
	} else {
		l := e.Link
		if l.LinkInfoPath != "" {
			extra["link_info_path"] = l.LinkInfoPath
		}
		if l.IDListPath != "" {
			extra["id_list_path"] = l.IDListPath
		}
		if l.RelativePath != "" {
			extra["relative_path"] = l.RelativePath
		}
		if l.WorkingDir != "" {
			extra["working_directory"] = l.WorkingDir
		}
		if l.Arguments != "" {
			// Recorded as SHORTCUT METADATA. It is not a command line
			// that ran, and the field name says so.
			extra["shortcut_arguments"] = l.Arguments
		}
		if l.IconLocation != "" {
			extra["icon_location"] = l.IconLocation
		}
		if l.FileSize != 0 {
			extra["target_file_size"] = strconv.FormatUint(uint64(l.FileSize), 10)
		}
		if l.FileAttributes != 0 {
			extra["file_attributes"] = fmt.Sprintf("0x%08X", l.FileAttributes)
			extra["file_attribute_names"] = ntfs.JoinNames(ntfs.FileAttributeNames(l.FileAttributes))
		}
		if l.Volume.Present {
			extra["drive_type"] = shelllink.DriveTypeName(l.Volume.DriveType)
			extra["volume_serial"] = fmt.Sprintf("%08X", l.Volume.SerialNumber)
			if l.Volume.Label != "" {
				extra["volume_label"] = l.Volume.Label
			}
		}
		if l.Network.Present {
			extra["network_share"] = l.Network.NetName
		}
		if l.TrackerMachineID != "" {
			extra["tracker_machine_id"] = l.TrackerMachineID
		}
		if len(l.Warnings) > 0 {
			extra["embedded_link_warnings"] = strings.Join(l.Warnings, "; ")
		}
	}

	raw, _ := json.Marshal(map[string]any{
		"jumplist_file": base["jumplist_file"],
		"kind":          string(list.Kind),
		"container":     base["jumplist_container"],
		"application": map[string]any{
			"app_id":   orNil(list.AppID),
			"resolved": orNil(list.Application),
			"label":    base["application"],
		},
		// Where inside the artifact this entry lived.
		"location": map[string]any{
			"stream":                 e.StreamName,
			"stream_directory_index": nilIfNegative(e.StreamIndex),
			"offset":                 e.Offset,
			"bytes":                  e.Bytes,
			"entry_index":            index,
		},
		// The Jump List's own record of the item.
		"destlist": destListJSON(e),
		// The embedded shortcut.
		"embedded_link": linkJSON(e),
		"target": map[string]any{
			"path":        orNil(target),
			"path_source": orNil(source),
			"name":        orNil(baseName(target)),
		},
		"evidence_meaning": "an application holds a reference to this target; not evidence of execution",
	})
	return extra, string(raw)
}

func destListJSON(e jl.Entry) any {
	if e.Dest == nil {
		return nil
	}
	d := e.Dest
	return map[string]any{
		"entry_number":         d.EntryNumber,
		"mru_position":         d.MRUPosition,
		"access_count":         d.AccessCount,
		"last_recorded_access": timeOrNil(d.LastRecordedAccess),
		"pinned":               d.Pinned,
		"hostname":             orNil(d.Hostname),
		"recorded_path":        orNil(d.Path),
		"warnings":             d.Warnings,
	}
}

func linkJSON(e jl.Entry) any {
	if e.LinkError != nil {
		return map[string]any{"parsed": false, "error": e.LinkError.Error()}
	}
	l := e.Link
	return map[string]any{
		"parsed":               true,
		"target_path":          orNil(l.TargetPath()),
		"link_info_path":       orNil(l.LinkInfoPath),
		"id_list_path":         orNil(l.IDListPath),
		"relative_path":        orNil(l.RelativePath),
		"working_directory":    orNil(l.WorkingDir),
		"shortcut_arguments":   orNil(l.Arguments),
		"icon_location":        orNil(l.IconLocation),
		"target_file_size":     l.FileSize,
		"target_creation_time": timeOrNil(l.CreationTime),
		"target_write_time":    timeOrNil(l.WriteTime),
		"target_access_time":   timeOrNil(l.AccessTime),
		"file_attributes":      fmt.Sprintf("0x%08X", l.FileAttributes),
		"file_attribute_names": ntfs.FileAttributeNames(l.FileAttributes),
		"volume":               volumeJSON(l),
		"network_share":        orNil(l.Network.NetName),
		"tracker_machine_id":   orNil(l.TrackerMachineID),
		"string_encoding":      l.StringEncoding,
		"warnings":             l.Warnings,
	}
}

func volumeJSON(l shelllink.Link) any {
	if !l.Volume.Present {
		return nil
	}
	return map[string]any{
		"drive_type":    shelllink.DriveTypeName(l.Volume.DriveType),
		"serial_number": fmt.Sprintf("%08X", l.Volume.SerialNumber),
		"label":         orNil(l.Volume.Label),
	}
}

func baseName(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func orNone(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func orNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nilIfNegative(n int) any {
	if n < 0 {
		return nil
	}
	return n
}

func timeOrNil(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}
