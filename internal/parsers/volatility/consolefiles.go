package volatility

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/memory"
	"tracefall/internal/model"
	"tracefall/internal/payload"
)

const (
	maxFileEvents    = 20000
	maxScreenExtra   = 4000
	notFoundConsole  = "Console Information Not Found"
	consoleHostNote  = "Volatility 3 reads console history from conhost.exe. No conhost.exe is in this image's process list, so the operating system hosted its consoles somewhere this plugin cannot read; the absence of commands here does not mean none were typed."
	consoleEmptyNote = "The console plugins ran and found no commands. A console's history is lost when it closes, and a cleared or short history is not evidence that nothing was typed."
)

// A command row is named ..._Command_<n>, whichever plugin reported it.
var commandProp = regexp.MustCompile(`_Command_(\d+)$`)
var screenProp = regexp.MustCompile(`\.ScreenBuffer_(\d+)\.Dump$`)

type consoleKey struct {
	pid int64
	n   string
	cmd string
}

// consoleEvents turns cmdscan and consoles rows into events. Both plugins can
// report the same history; a command found by both is emitted once and says
// which plugins found it.
func consoleEvents(rowsOf map[string][]map[string]any, pluginName map[string]string, snapshot time.Time, add func(model.Event, string)) (commands, screens int, notFound int) {
	type found struct {
		ev      model.Event
		raw     string
		sources []string
	}
	var order []consoleKey
	byKey := map[consoleKey]*found{}
	titles := map[int64]string{}
	apps := map[int64]map[string]bool{}

	for _, logical := range []string{"cmdscan", "consoles"} {
		for _, r := range rowsOf[logical] {
			pid, _ := intv(r, "PID")
			prop, data := str(r, "Property"), str(r, "Data")
			switch {
			case strings.HasSuffix(prop, ".OriginalTitle") || strings.HasSuffix(prop, "_CONSOLE_INFORMATION.Title"):
				if data != "" && data != "None" {
					titles[pid] = data
				}
			case strings.HasSuffix(prop, "_Application") || strings.HasSuffix(prop, "COMMAND_HISTORY.Application"):
				if data != "" && data != "None" {
					if apps[pid] == nil {
						apps[pid] = map[string]bool{}
					}
					apps[pid][data] = true
				}
			}
		}
	}
	for _, logical := range []string{"cmdscan", "consoles"} {
		for i, r := range rowsOf[logical] {
			pid, _ := intv(r, "PID")
			prop, data := str(r, "Property"), str(r, "Data")
			if data == notFoundConsole {
				notFound++
				continue
			}
			if m := commandProp.FindStringSubmatch(prop); m != nil && data != "" && data != "None" {
				k := consoleKey{pid, m[1], data}
				if f := byKey[k]; f != nil {
					f.sources = append(f.sources, logical)
					continue
				}
				ev := model.Event{
					Timestamp: snapshot, EventType: model.EventMemoryConsole, PID: pid, ProcessName: str(r, "Process"),
					CommandLine: data, Confidence: 0.9,
					SourceReference: fmt.Sprintf("windows.%s row %d", logical, i),
					Extra: map[string]string{
						"timestamp_basis": "memory_snapshot", "command_index": m[1],
						"observation": "a command line the console still held at capture; the console keeps no time for it, so the event is stamped with the capture's time",
					},
				}
				byKey[k] = &found{ev: ev, raw: rawJSON(pluginName[logical], r), sources: []string{logical}}
				order = append(order, k)
				continue
			}
			if m := screenProp.FindStringSubmatch(prop); m != nil && strings.TrimSpace(data) != "" && data != "None" {
				text := strings.TrimRight(data, " \r\n\t")
				ev := model.Event{
					Timestamp: snapshot, EventType: model.EventMemoryConsoleScreen, PID: pid, ProcessName: str(r, "Process"),
					Confidence: 0.9, SourceReference: fmt.Sprintf("windows.%s row %d", logical, i),
					Extra: map[string]string{
						"timestamp_basis": "memory_snapshot", "screen_buffer": m[1], "screen_lines": strconv.Itoa(strings.Count(text, "\n") + 1),
						"screen_text": clip(text, maxScreenExtra),
						"observation": "the text of a console screen buffer at capture: commands and their output as displayed",
					},
				}
				if len(text) > maxScreenExtra {
					ev.Extra["screen_text_truncated"] = strconv.Itoa(len(text))
				}
				if t := titles[pid]; t != "" {
					ev.Extra["console_title"] = t
				}
				add(ev, rawJSON(pluginName[logical], r))
				screens++
			}
		}
	}
	for _, k := range order {
		f := byKey[k]
		f.ev.Extra["found_by"] = strings.Join(dedupStrings(f.sources), ",")
		if t := titles[k.pid]; t != "" {
			f.ev.Extra["console_title"] = t
		}
		if a := apps[k.pid]; len(a) == 1 {
			for name := range a {
				f.ev.Extra["console_application"] = name
			}
		}
		add(f.ev, f.raw)
		commands++
	}
	return commands, screens, notFound
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// hasConhost reports whether the process list holds a conhost.exe.
func hasConhost(rowsOf map[string][]map[string]any) bool {
	for _, logical := range []string{"pslist", "psscan"} {
		for _, r := range rowsOf[logical] {
			if strings.EqualFold(str(r, "ImageFileName"), "conhost.exe") {
				return true
			}
		}
	}
	return false
}

// fileEvents lists the file objects worth a reader's time: runnable, document,
// archive and data files outside the operating system's own locations. The
// rest are counted, not dropped silently.
func fileEvents(rows []map[string]any, plugin string, snapshot time.Time, add func(model.Event, string)) (listed, routine, junk, other int) {
	seen := map[string]bool{}
	for i, r := range rows {
		name := str(r, "Name")
		switch memory.ClassifyFile(name) {
		case memory.FileGarbage:
			junk++
			continue
		case memory.FileRoutine:
			routine++
			continue
		case memory.FileOther:
			other++
			continue
		}
		lower := strings.ToLower(name)
		if seen[lower] {
			continue
		}
		if listed >= maxFileEvents {
			other++
			continue
		}
		seen[lower] = true
		off, _ := intv(r, "Offset")
		add(model.Event{
			Timestamp: snapshot, EventType: model.EventMemoryFile, FilePath: name, Confidence: 0.8,
			SourceReference: fmt.Sprintf("windows.filescan row %d", i),
			Extra: map[string]string{
				"timestamp_basis": "memory_snapshot", "file_object_offset": fmt.Sprintf("0x%x", off),
				"observation": "a file object the kernel held at capture: the file was open or cached; this does not show it still exists on disk and carries no content hash",
			},
		}, rawJSON(plugin, r))
		listed++
	}
	return listed, routine, junk, other
}

// recoveredEvents turns files read back from memory into events: one per part
// (the cached data and the mapped image of a program are two different byte
// strings), and a count of what could not be recovered.
func recoveredEvents(files []memory.RecoveredFile, snapshot time.Time, add func(model.Event, string)) (summary string) {
	counts := map[string]int{}
	seen := map[string]bool{}
	for i, f := range files {
		counts[f.Status]++
		for j, part := range f.Parts {
			rep := part.Report
			if rep.SHA256 == "" && !rep.Truncated {
				continue // too large to read: counted, no content to describe
			}
			key := strings.ToLower(f.Name) + "|" + part.Cache + "|" + rep.SHA256
			if seen[key] {
				continue
			}
			seen[key] = true
			ex := map[string]string{
				"timestamp_basis": "memory_snapshot", "memory_cache": part.Cache, "recovered_bytes": strconv.FormatInt(part.Size, 10),
				"sha256": rep.SHA256, "md5": rep.MD5, "sha1": rep.SHA1, "file_signature": rep.Type, "entropy": strconv.FormatFloat(rep.Entropy, 'f', 2, 64),
				"file_object_offset": fmt.Sprintf("0x%x", f.FileObject),
				"observation": "bytes read back from memory and inspected without running them. They are the pages that were resident, laid out as the cache or the loader held them: " +
					"an image-section dump of a program is laid out as mapped, so this hash is not necessarily the hash of the file on disk",
			}
			if rep.Truncated {
				ex["inspection_truncated"] = "true"
			}
			if rep.Type == "" {
				ex["file_signature"] = "unknown"
				ex["file_signature_note"] = "the file's first bytes were not recognised; if the first page was not resident in memory they are zeros"
			}
			sparse := false
			if part.TotalPages > 0 {
				ex["zero_pages"] = fmt.Sprintf("%d of %d", part.ZeroPages, part.TotalPages)
				if part.ZeroPages*10 >= part.TotalPages { // a tenth or more of the pages are blank
					sparse = true
					ex["sparse"] = "true"
					ex["sparse_note"] = "pages that were not in memory come back as zeros, so imports, signatures and other structure that are absent here may only be absent from what was resident"
				}
			}
			if pe := rep.PE; pe != nil {
				ex["pe_machine"], ex["pe_subsystem"] = pe.Machine, pe.Subsystem
				ex["pe_dll"] = strconv.FormatBool(pe.DLL)
				ex["pe_sections"] = strconv.Itoa(len(pe.Sections))
				ex["pe_import_count"] = strconv.Itoa(pe.ImportCount)
				ex["pe_signature_directory"] = strconv.FormatBool(pe.HasSignature)
				ex["pe_overlay_bytes"] = strconv.FormatInt(pe.OverlayBytes, 10)
				if !pe.ClaimedBuild.IsZero() {
					ex["pe_claimed_build_time"] = pe.ClaimedBuild.UTC().Format(time.RFC3339)
					ex["pe_claimed_build_note"] = "written by whoever built the file; it can be set to anything"
				}
				if pe.ImpHash != "" {
					ex["pe_imphash"] = pe.ImpHash
				}
				if len(pe.ImportDLLs) > 0 {
					ex["pe_import_dlls"] = strings.Join(pe.ImportDLLs, ",")
				}
				if len(pe.InjectionAPIs) > 0 {
					ex["pe_injection_apis"] = strings.Join(pe.InjectionAPIs, ",")
				}
				if len(pe.Exports) > 0 {
					ex["pe_exports"] = strings.Join(pe.Exports, ",")
				}
			}
			inds := rep.Indicators
			if sparse {
				// An indicator that says something is missing cannot be
				// trusted when the missing part may simply not have been in
				// memory.
				var kept []payload.Indicator
				var withheld []string
				for _, ind := range inds {
					if ind.ID == "very_few_imports" || ind.ID == "no_signature_directory" || ind.ID == "malformed_pe" {
						withheld = append(withheld, ind.ID)
						continue
					}
					kept = append(kept, ind)
				}
				inds = kept
				if len(withheld) > 0 {
					ex["indicators_withheld"] = strings.Join(withheld, ",")
				}
			}
			if len(inds) > 0 {
				ids := make([]string, len(inds))
				details := make([]string, len(inds))
				for k, ind := range inds {
					ids[k], details[k] = ind.ID, ind.Detail
				}
				ex["indicators"] = strings.Join(ids, ",")
				ex["indicator_details"] = strings.Join(details, "; ")
				ex["indicator_meaning"] = "properties that are common in malware and in legitimate software alike; none is a verdict"
			}
			for k, v := range map[string][]string{"strings_urls": rep.Strings.URLs, "strings_ipv4": rep.Strings.IPv4, "strings_commands": rep.Strings.Commands,
				"strings_registry": rep.Strings.Registry, "strings_notable": rep.Strings.Notable} {
				if len(v) > 0 {
					ex[k] = strings.Join(v, " | ")
				}
			}
			add(model.Event{
				Timestamp: snapshot, EventType: model.EventMemoryFileContent, FilePath: f.Name, Confidence: 0.9,
				SourceReference: fmt.Sprintf("windows.dumpfiles file %d part %d", i, j), Extra: ex,
			}, rawFileJSON(f, j))
		}
	}
	if len(files) == 0 {
		return ""
	}
	return fmt.Sprintf("tried %d file(s): %d recovered, %d not in memory (not cached or already released), %d too large to read, %d failed",
		len(files), counts[memory.RecoveredOK], counts[memory.RecoveredNone], counts[memory.RecoveredTooLarge], counts[memory.RecoveredFailed])
}

// rawFileJSON is the raw record of one recovered part: what was asked and what
// came back, without the strings lists the event already carries.
func rawFileJSON(f memory.RecoveredFile, part int) string {
	p := f.Parts[part]
	return rawJSON("windows.dumpfiles", map[string]any{
		"Name": f.Name, "FileObject": f.FileObject, "Cache": p.Cache, "Size": p.Size, "SHA256": p.Report.SHA256, "Type": p.Report.Type,
	})
}
