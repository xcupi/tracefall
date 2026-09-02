// Package lnk turns Windows shortcuts (.lnk) into normalized evidence.
//
// # What this parser asserts
//
// That a shortcut existed which REFERENCED a target, and what that
// shortcut recorded about it. Nothing more. A .lnk is created when a
// file is opened, saved, or merely selected in a dialog, and an
// application may write one for a target the user never touched.
//
// So the events emitted are TARGET METADATA events, never execution
// events, and every record says so explicitly. The three timestamps
// belong to the target file as it stood when the shortcut was last
// written -- they are the target's MACE times, not the moment the
// shortcut was used.
//
// # One event per recorded timestamp
//
// A shortcut carries up to three target timestamps. Each is a separate
// observation, so each becomes its own event, exactly as the $MFT's
// timestamps do (see internal/parsers/mft). A shortcut that records none
// produces structured evidence and no timeline events rather than an
// invented time -- the .lnk file's own mtime is when the evidence was
// collected, not what the shortcut says.
package lnk

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/ntfs"
	"tracefall/internal/parsers"
	"tracefall/internal/shelllink"
)

const parserName = "lnk@1"

// Parser implements parsers.ArtifactParser and parsers.ContentDetector.
type Parser struct {
	limits shelllink.Limits
}

func New() *Parser { return &Parser{limits: shelllink.DefaultLimits()} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactLNK }

// Detect deliberately matches NOTHING by filename.
//
// A .lnk extension is not evidence that a file is a shortcut, and a
// shortcut carried out of a triage image may arrive under any name. More
// importantly, claiming a file by extension would classify a mislabelled
// file as a supported artifact and then fail to parse it, reporting a
// parse failure where the honest answer is "this is not a shortcut".
// Detection is therefore structural only; see DetectContent.
func (Parser) Detect(string) bool { return false }

// DetectContent identifies a shortcut by its fixed header size and class
// identifier, both of which sit inside the first 76 bytes.
func (Parser) DetectContent(header []byte) bool { return shelllink.Sniff(header) }

// Parse reads one shortcut.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	l, err := shelllink.ParseFile(absPath, p.limits)
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("lnk: %w", err)
	}
	sourceName := filepath.Base(absPath)

	extra := map[string]string{
		"lnk_path":         sourceName,
		"source_file":      sourceName,
		"link_flags":       fmt.Sprintf("0x%08X", l.LinkFlags),
		"link_flag_names":  strings.Join(shelllink.FlagNames(l.LinkFlags), ", "),
		"string_encoding":  l.StringEncoding,
		"show_command":     shelllink.ShowCommandName(l.ShowCommand),
		"target_file_size": strconv.FormatUint(uint64(l.FileSize), 10),
		// Stated on EVERY record. A shortcut is the artifact most often
		// misread as proof that something ran.
		"evidence_meaning": "shortcut metadata: a .lnk file referenced this target and recorded the target's own " +
			"timestamps, size and location. This is NOT evidence that the target was executed, opened by the user, " +
			"or ever present on this system.",
		"artifact_class": "shortcut (reference evidence)",
	}
	if l.FileAttributes != 0 {
		extra["file_attributes"] = fmt.Sprintf("0x%08X", l.FileAttributes)
		// The same Windows attribute bitmask the NTFS parsers decode --
		// one vocabulary across the codebase rather than a second table.
		extra["file_attribute_names"] = ntfs.JoinNames(ntfs.FileAttributeNames(l.FileAttributes))
	}
	if target := l.TargetPath(); target != "" {
		extra["target_path"] = target
	}
	// Every path representation the shortcut carried is kept. They can
	// legitimately disagree -- LinkInfo is what the writer recorded, the
	// ID list is what the shell resolved -- and a disagreement is itself
	// forensically interesting, so neither is dropped.
	if l.LinkInfoPath != "" {
		extra["link_info_path"] = l.LinkInfoPath
	}
	if l.LocalBasePath != "" {
		extra["local_base_path"] = l.LocalBasePath
	}
	if l.CommonPathSuffix != "" {
		extra["common_path_suffix"] = l.CommonPathSuffix
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
		extra["command_line_arguments"] = l.Arguments
	}
	if l.IconLocation != "" {
		extra["icon_location"] = l.IconLocation
	}
	if l.Name != "" {
		extra["shortcut_name"] = l.Name
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
		if l.Network.DeviceName != "" {
			extra["network_device"] = l.Network.DeviceName
		}
	}
	if l.TrackerMachineID != "" {
		extra["tracker_machine_id"] = l.TrackerMachineID
	}
	if l.HasIDList {
		extra["id_list_items"] = strconv.Itoa(len(l.IDListItems))
	}
	if len(l.ExtraBlocks) > 0 {
		extra["extra_data_blocks"] = strings.Join(l.ExtraBlocks, ", ")
	}
	if len(l.Warnings) > 0 {
		extra["parse_warnings"] = strings.Join(l.Warnings, "; ")
	}
	// Where each structure began, so a field can be traced to a byte
	// range in the evidence file.
	if off, ok := l.Offsets["link_info"]; ok {
		extra["link_info_offset"] = strconv.Itoa(off)
	}
	if off, ok := l.Offsets["link_target_id_list"]; ok {
		extra["id_list_offset"] = strconv.Itoa(off)
	}

	raw, _ := json.Marshal(map[string]any{
		"lnk_file":               sourceName,
		"link_flags":             fmt.Sprintf("0x%08X", l.LinkFlags),
		"link_flag_names":        shelllink.FlagNames(l.LinkFlags),
		"file_attributes":        fmt.Sprintf("0x%08X", l.FileAttributes),
		"file_attribute_names":   ntfs.FileAttributeNames(l.FileAttributes),
		"string_encoding":        l.StringEncoding,
		"show_command":           shelllink.ShowCommandName(l.ShowCommand),
		"icon_index":             l.IconIndex,
		"hotkey":                 fmt.Sprintf("0x%04X", l.HotKey),
		"target_creation_time":   timeOrNil(l.CreationTime),
		"target_access_time":     timeOrNil(l.AccessTime),
		"target_write_time":      timeOrNil(l.WriteTime),
		"target_file_size":       l.FileSize,
		"target_path":            l.TargetPath(),
		"link_info_path":         l.LinkInfoPath,
		"local_base_path":        l.LocalBasePath,
		"common_path_suffix":     l.CommonPathSuffix,
		"id_list_path":           l.IDListPath,
		"id_list_items":          shellItems(l),
		"relative_path":          l.RelativePath,
		"working_directory":      l.WorkingDir,
		"command_line_arguments": l.Arguments,
		"icon_location":          l.IconLocation,
		"shortcut_name":          l.Name,
		"volume":                 volumeJSON(l),
		"network":                networkJSON(l),
		"tracker_machine_id":     l.TrackerMachineID,
		"extra_data_blocks":      l.ExtraBlocks,
		"structure_offsets":      l.Offsets,
		"warnings":               l.Warnings,
		"evidence_meaning": "shortcut reference evidence; the timestamps describe the TARGET file, " +
			"not any execution of it",
	})

	// One event per timestamp the shortcut actually recorded, in a fixed
	// order so output is deterministic.
	stamps := []struct {
		at        time.Time
		eventType string
		field     string
		meaning   string
	}{
		{l.CreationTime, model.EventLnkTargetCreated, "CreationTime",
			"target file creation time, as the shortcut recorded it when it was last written"},
		{l.WriteTime, model.EventLnkTargetModified, "WriteTime",
			"target file last-write time, as the shortcut recorded it when it was last written"},
		{l.AccessTime, model.EventLnkTargetAccessed, "AccessTime",
			"target file last-access time, as the shortcut recorded it when it was last written"},
	}

	var out parsers.ParseResult
	for _, s := range stamps {
		if s.at.IsZero() {
			continue
		}
		evExtra := make(map[string]string, len(extra)+2)
		for k, v := range extra {
			evExtra[k] = v
		}
		evExtra["timestamp_meaning"] = s.meaning
		evExtra["timestamp_source"] = "ShellLinkHeader " + s.field
		ref := "lnk:" + strings.ToLower(s.field)
		out.Events = append(out.Events, model.Event{
			Timestamp:    s.at.UTC(),
			EventType:    s.eventType,
			ArtifactType: model.ArtifactLNK,
			Parser:       parserName,
			// FilePath is the shortcut itself, matching how every other
			// parser records the artifact an event came from.
			FilePath: sourceName,
			// No User and no ProcessName. A shortcut names neither the
			// account that created it nor any process, and deriving
			// either from a path would be a guess.
			//
			// 0.8: the observation is solid -- the shortcut says exactly
			// this -- but what it proves about activity is weaker than a
			// recorded execution or a logged event.
			Confidence:      0.8,
			SourceReference: ref,
			Extra:           evExtra,
		})
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ref, Raw: string(raw)})
	}

	if len(out.Events) == 0 {
		// A shortcut with no usable target timestamp is still evidence:
		// it names a path, a volume and a size. It simply cannot be
		// placed on a timeline, and no time is invented to put it there.
		out.Raw = append(out.Raw, model.RawEvidence{
			SourceReference: "lnk:metadata",
			Raw:             string(raw),
		})
	}
	return out, nil
}

func timeOrNil(t interface{ IsZero() bool }) any {
	type formatter interface{ Format(string) string }
	if t.IsZero() {
		return nil
	}
	if f, ok := t.(formatter); ok {
		return f.Format("2006-01-02T15:04:05Z")
	}
	return nil
}

func shellItems(l shelllink.Link) []map[string]any {
	out := make([]map[string]any, 0, len(l.IDListItems))
	for _, it := range l.IDListItems {
		m := map[string]any{
			"kind":      it.Kind,
			"type_byte": fmt.Sprintf("0x%02X", it.TypeByte),
			"offset":    it.Offset,
			"bytes":     it.RawBytes,
		}
		if it.Name != "" {
			m["name"] = it.Name
		}
		if it.GUID != "" {
			m["guid"] = it.GUID
		}
		if it.Kind == "file_entry" || it.Kind == "directory_entry" {
			m["size"] = it.Size
			m["dos_modified_time"] = timeOrNil(it.Modified)
			if it.HasAttrs {
				m["file_attributes"] = fmt.Sprintf("0x%04X", it.Attributes)
			}
		}
		out = append(out, m)
	}
	return out
}

func volumeJSON(l shelllink.Link) any {
	if !l.Volume.Present {
		return nil
	}
	return map[string]any{
		"drive_type":    shelllink.DriveTypeName(l.Volume.DriveType),
		"drive_type_id": l.Volume.DriveType,
		"serial_number": fmt.Sprintf("%08X", l.Volume.SerialNumber),
		"label":         l.Volume.Label,
	}
}

func networkJSON(l shelllink.Link) any {
	if !l.Network.Present {
		return nil
	}
	return map[string]any{
		"share":  l.Network.NetName,
		"device": l.Network.DeviceName,
	}
}
