package volatility

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"tracefall/internal/model"
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

// Locations whose contents are the operating system's or installed
// software's own, where a file object says nothing about what happened.
var routinePathPrefixes = []string{
	`\windows\system32\`, `\windows\syswow64\`, `\windows\winsxs\`, `\windows\assembly\`, `\windows\microsoft.net\`,
	`\windows\servicing\`, `\windows\fonts\`, `\windows\globalization\`, `\windows\systemapps\`, `\windows\immersivecontrolpanel\`,
	`\windows\inf\`, `\windows\branding\`, `\windows\resources\`, `\windows\media\`, `\windows\cursors\`,
	`\program files\`, `\program files (x86)\`, `\programdata\microsoft\windows defender\`, `\programdata\package cache\`,
}

// Extensions of things a person runs, opens as a document, or unpacks.
var interestingExt = map[string]bool{
	".exe": true, ".dll": true, ".scr": true, ".sys": true, ".bat": true, ".cmd": true, ".ps1": true, ".vbs": true, ".vbe": true,
	".js": true, ".jse": true, ".wsf": true, ".hta": true, ".jar": true, ".lnk": true, ".msi": true, ".com": true, ".cpl": true,
	".doc": true, ".docx": true, ".docm": true, ".xls": true, ".xlsx": true, ".xlsm": true, ".ppt": true, ".pptx": true, ".pdf": true,
	".rtf": true, ".zip": true, ".rar": true, ".7z": true, ".gz": true, ".tar": true, ".iso": true, ".img": true, ".vhd": true,
	".txt": true, ".csv": true, ".kdbx": true, ".pst": true, ".ost": true, ".dmp": true, ".mem": true, ".pcap": true, ".pcapng": true,
	".sql": true, ".bak": true, ".evtx": true, ".reg": true,
}

// plausibleName rejects the garbage the pool scan returns when it reads a
// freed or partly overwritten object: control characters, the replacement
// character and private-use code points.
func plausibleName(n string) bool {
	if !strings.HasPrefix(n, `\`) || len(n) < 3 {
		return false
	}
	for _, r := range n {
		if r == unicode.ReplacementChar || r == 0xFFFF || unicode.IsControl(r) || (r >= 0xE000 && r <= 0xF8FF) || r > 0xFFFF {
			return false
		}
	}
	return true
}

func routineFilePath(lower string) bool {
	for _, p := range routinePathPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func fileExt(lower string) string {
	if i := strings.LastIndexAny(lower, `\.`); i >= 0 && lower[i] == '.' {
		return lower[i:]
	}
	return ""
}

// fileEvents lists the file objects worth a reader's time: runnable, document,
// archive and data files outside the operating system's own locations. The
// rest are counted, not dropped silently.
func fileEvents(rows []map[string]any, plugin string, snapshot time.Time, add func(model.Event, string)) (listed, routine, junk, other int) {
	seen := map[string]bool{}
	for i, r := range rows {
		name := str(r, "Name")
		if !plausibleName(name) {
			junk++
			continue
		}
		lower := strings.ToLower(name)
		switch {
		case routineFilePath(lower):
			routine++
			continue
		case !interestingExt[fileExt(lower)]:
			other++
			continue
		}
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
