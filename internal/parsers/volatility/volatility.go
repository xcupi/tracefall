// Package volatility turns the combined output of Volatility 3 for one
// memory image (internal/memory.Analysis) into Tracefall events.
//
// # What a memory image can and cannot say about time
//
// A memory image is a photograph of the machine at one instant. Some of
// what is in it carries its own time (a process's create time, a socket's
// creation time) and those become ordinary events at that time. Much of it
// does not (a service in the service table, a suspicious memory region, a
// socket with no recorded creation): the only honest time for those is the
// moment of capture, "this was true when the image was taken". Those
// events are dated to the system clock value recorded in the image, and
// say so in Extra["timestamp_basis"], so nothing here is passed off as the
// time something HAPPENED when it is only the time it was OBSERVED.
//
// # Joining across plugins
//
// One file carries every plugin's output, so a process (pslist/psscan) can
// be joined with its command line (cmdline) deterministically, without
// depending on the order separate files were imported in. PIDs are reused,
// so rows are keyed by PID and create time, and a command line is only
// attached to a process that was still alive when the list was taken.
//
// # Reading hostile data
//
// Everything in the analysis came from parsing an attacker-influenced
// memory image. Process names, command lines and addresses are therefore
// treated as untrusted text: bounded in length, never executed or
// interpreted, and every numeric field is range-checked.
package volatility

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/memory"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const (
	parserName       = "volatility_memory@1"
	analysisFileName = "volatility-analysis.json"

	maxAnalysisBytes = 512 << 20
	maxEvents        = 200_000
	maxFieldLen      = 4096
	maxExtraLen      = 2048
	maxRawLen        = 64 << 10
)

// Parser implements parsers.ArtifactParser, ContentDetector and
// ContentConfirmer.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactMemoryAnalysis }

// Detect matches the fixed file name the extraction step writes.
func (Parser) Detect(relPath string) bool {
	return strings.EqualFold(filepath.Base(filepath.ToSlash(relPath)), analysisFileName)
}

// DetectContent recognises the schema marker, which is the first key.
func (Parser) DetectContent(header []byte) bool {
	return bytes.Contains(header, []byte(`"`+memory.AnalysisSchema+`"`))
}

// ConfirmContent keeps a file merely NAMED like the analysis from being
// claimed.
func (p Parser) ConfirmContent(header []byte) bool { return p.DetectContent(header) }

// ---- field helpers: everything is untrusted

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 { // do not split a UTF-8 sequence
		cut--
	}
	return s[:cut] + "..."
}

func str(r map[string]any, k string) string {
	switch v := r[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func intv(r map[string]any, k string) (int64, bool) {
	switch v := r[k].(type) {
	case float64:
		if v != v || v < -1e15 || v > 1e15 || v != float64(int64(v)) {
			return 0, false
		}
		return int64(v), true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(v), 0, 64)
		return n, err == nil
	}
	return 0, false
}

func timeLayouts() []string {
	return []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05-07:00", "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05"}
}

func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, l := range timeLayouts() {
		if t, err := time.Parse(l, s); err == nil {
			t = t.UTC()
			// A zero FILETIME shows up as 1601; that is "no time", not a time.
			if t.Year() < 1990 || t.Year() > 2100 {
				return time.Time{}, false
			}
			return t, true
		}
	}
	return time.Time{}, false
}

func timeOf(r map[string]any, k string) (time.Time, bool) {
	s, _ := r[k].(string)
	return parseTime(s)
}

func hexOf(r map[string]any, k string) string {
	switch v := r[k].(type) {
	case float64:
		if v >= 0 && v < 1e18 {
			return "0x" + strconv.FormatUint(uint64(v), 16)
		}
	case string:
		return clip(v, 40)
	}
	return ""
}

func rawJSON(plugin string, rows ...map[string]any) string {
	b, err := json.Marshal(map[string]any{"plugin": plugin, "rows": rows})
	if err != nil || len(b) > maxRawLen {
		return `{"plugin":"` + plugin + `","note":"row omitted: too large or not serializable"}`
	}
	return string(b)
}

// ---- the parser

type proc struct {
	pid, ppid        int64
	imageName        string
	create           time.Time
	createRaw        string
	exit             string
	inList, inScan   bool
	threads, handles string
	session, wow64   string
	listIdx, scanIdx int
	listRow, scanRow map[string]any
}

// Parse reads one analysis file.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	st, err := os.Stat(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if st.Size() > maxAnalysisBytes {
		return parsers.ParseResult{}, fmt.Errorf("volatility: analysis is %d bytes, over the %d limit", st.Size(), maxAnalysisBytes)
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	var a memory.Analysis
	if err := json.Unmarshal(data, &a); err != nil {
		return parsers.ParseResult{}, fmt.Errorf("volatility: not a memory analysis: %w", err)
	}
	if a.Schema != memory.AnalysisSchema {
		return parsers.ParseResult{}, errors.New("volatility: the file is not a Tracefall memory analysis (schema marker missing)")
	}

	snapshot, haveSnapshot := parseTime(a.Info["SystemTime"])
	rowsOf := map[string][]map[string]any{}
	pluginName := map[string]string{}
	var failed []string
	var statuses []string
	for _, pr := range a.Plugins {
		statuses = append(statuses, pr.Logical+":"+pr.Status)
		if pr.Status != memory.StatusOK {
			failed = append(failed, pr.Logical)
			continue
		}
		rowsOf[pr.Logical] = pr.Rows
		pluginName[pr.Logical] = pr.Plugin
	}

	var out parsers.ParseResult
	skipped := 0
	truncated := false
	add := func(ev model.Event, raw string) {
		if len(out.Events) >= maxEvents {
			truncated = true
			return
		}
		ev.ArtifactType, ev.Parser = model.ArtifactMemoryAnalysis, parserName
		if ev.Extra == nil {
			ev.Extra = map[string]string{}
		}
		ev.Extra["evidence_kind"] = "memory"
		for k, v := range ev.Extra {
			ev.Extra[k] = clip(v, maxExtraLen)
		}
		ev.ProcessName, ev.ProcessPath = clip(ev.ProcessName, maxFieldLen), clip(ev.ProcessPath, maxFieldLen)
		ev.ParentProcessName, ev.CommandLine = clip(ev.ParentProcessName, maxFieldLen), clip(ev.CommandLine, maxFieldLen)
		ev.NetworkSource, ev.NetworkDest, ev.FilePath = clip(ev.NetworkSource, 256), clip(ev.NetworkDest, 256), clip(ev.FilePath, maxFieldLen)
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ev.SourceReference, Raw: raw})
	}

	// ---- processes
	procs := map[string]*proc{}
	var order []string
	collect := func(logical string, scan bool) {
		for i, r := range rowsOf[logical] {
			pid, ok := intv(r, "PID")
			if !ok || pid < 0 || pid > 1<<32 {
				skipped++
				continue
			}
			created, _ := r["CreateTime"].(string)
			ct, hasTime := parseTime(created)
			if !hasTime {
				skipped++
				continue
			}
			key := strconv.FormatInt(pid, 10) + "|" + ct.Format(time.RFC3339Nano)
			pr := procs[key]
			if pr == nil {
				ppid, _ := intv(r, "PPID")
				pr = &proc{pid: pid, ppid: ppid, create: ct, createRaw: created, listIdx: -1, scanIdx: -1}
				procs[key] = pr
				order = append(order, key)
			}
			if pr.imageName == "" {
				pr.imageName = clip(str(r, "ImageFileName"), 256)
			}
			if s := str(r, "ExitTime"); s != "" && pr.exit == "" {
				if et, ok := parseTime(s); ok {
					pr.exit = et.Format(time.RFC3339)
				}
			}
			if scan {
				pr.inScan, pr.scanIdx, pr.scanRow = true, i, r
			} else {
				pr.inList, pr.listIdx, pr.listRow = true, i, r
				pr.threads, pr.handles, pr.session, pr.wow64 = str(r, "Threads"), str(r, "Handles"), str(r, "SessionId"), str(r, "Wow64")
			}
		}
	}
	collect("pslist", false)
	collect("psscan", true)

	cmdlines := map[int64]string{}
	unavailable := map[int64]string{}
	for _, r := range rowsOf["cmdline"] {
		pid, ok := intv(r, "PID")
		if !ok {
			continue
		}
		args := str(r, "Args")
		if args == "" || strings.HasPrefix(args, "Required memory at") || strings.Contains(args, "is inaccessible") || strings.Contains(args, "is not valid") {
			if _, seen := cmdlines[pid]; !seen {
				unavailable[pid] = clip(args, 200)
			}
			continue
		}
		if _, seen := cmdlines[pid]; !seen {
			cmdlines[pid] = args
		}
	}

	// parents by PID, latest create time not after the child's
	byPID := map[int64][]*proc{}
	for _, k := range order {
		pr := procs[k]
		byPID[pr.pid] = append(byPID[pr.pid], pr)
	}
	parentOf := func(child *proc) *proc {
		if child.ppid == child.pid {
			return nil
		}
		var best *proc
		for _, c := range byPID[child.ppid] {
			if c.create.After(child.create) {
				continue
			}
			if best == nil || c.create.After(best.create) {
				best = c
			}
		}
		return best
	}

	for _, k := range order {
		pr := procs[k]
		alive := pr.exit == ""
		ev := model.Event{
			Timestamp: pr.create, EventType: model.EventProcessCreate, PID: pr.pid, PPID: pr.ppid, ProcessName: pr.imageName,
			Extra: map[string]string{
				"image_file_name": pr.imageName, "create_time": pr.create.Format(time.RFC3339Nano), "timestamp_basis": "process_create_time",
			},
		}
		switch {
		case pr.inList && pr.inScan:
			ev.Extra["memory_source"], ev.Confidence = "pslist+psscan", 0.9
		case pr.inList:
			ev.Extra["memory_source"], ev.Confidence = "pslist", 0.9
		default:
			ev.Extra["memory_source"], ev.Confidence = "psscan", 0.7
			if alive {
				// Found by scanning pool memory, never exited, but absent
				// from the active process list: unlinked from it.
				ev.Extra["hidden_process"], ev.Confidence = "true", 0.6
			}
		}
		if pr.exit != "" {
			ev.Extra["exit_time"] = pr.exit
		}
		for k, v := range map[string]string{"threads": pr.threads, "handles": pr.handles, "session_id": pr.session, "wow64": pr.wow64} {
			if v != "" {
				ev.Extra[k] = v
			}
		}
		if pr.inList && alive {
			if c, ok := cmdlines[pr.pid]; ok {
				ev.CommandLine = c
				if tok := firstToken(c); strings.ContainsAny(tok, `\/:`) {
					ev.ProcessPath = tok
					ev.ProcessName = baseName(tok)
				}
			} else if why, ok := unavailable[pr.pid]; ok {
				ev.Extra["cmdline_unavailable"] = why
				if why == "" {
					ev.Extra["cmdline_unavailable"] = "no command line recorded"
				}
			}
		}
		if par := parentOf(pr); par != nil {
			ev.ParentProcessName = par.imageName
		}
		ev.SourceReference = fmt.Sprintf("windows.%s pid %d", ev.Extra["memory_source"], pr.pid)
		var raws []map[string]any
		if pr.listRow != nil {
			raws = append(raws, pr.listRow)
		}
		if pr.scanRow != nil {
			raws = append(raws, pr.scanRow)
		}
		add(ev, rawJSON(ev.Extra["memory_source"], raws...))
	}

	// ---- network
	for i, r := range rowsOf["netscan"] {
		pid, _ := intv(r, "PID")
		lport, _ := intv(r, "LocalPort")
		fport, _ := intv(r, "ForeignPort")
		foreign := strings.TrimSpace(str(r, "ForeignAddr"))
		ev := model.Event{
			PID: pid, ProcessName: clip(str(r, "Owner"), 256), NetworkSource: str(r, "LocalAddr"),
			Extra: map[string]string{
				"protocol": clip(str(r, "Proto"), 16), "state": clip(str(r, "State"), 32), "local_port": strconv.FormatInt(lport, 10),
			},
			SourceReference: fmt.Sprintf("windows.netscan row %d", i),
			Confidence:      0.8,
		}
		if t, ok := timeOf(r, "Created"); ok {
			ev.Timestamp = t
			ev.Extra["timestamp_basis"] = "socket_created"
		} else if haveSnapshot {
			ev.Timestamp = snapshot
			ev.Extra["timestamp_basis"] = "memory_snapshot"
		} else {
			skipped++
			continue
		}
		switch foreign {
		case "", "*", "0.0.0.0", "::", "N/A", "null":
			ev.EventType = model.EventNetworkListener
		default:
			if fport <= 0 || fport > 65535 {
				ev.EventType = model.EventNetworkListener
			} else {
				ev.EventType, ev.NetworkDest, ev.NetworkDestPort = model.EventNetworkConnection, foreign, int(fport)
			}
		}
		add(ev, rawJSON(pluginName["netscan"], r))
	}

	// ---- malfind
	seen := map[string]bool{}
	for i, r := range rowsOf["malfind"] {
		if !haveSnapshot {
			skipped++
			continue
		}
		pid, _ := intv(r, "PID")
		start, end := hexOf(r, "Start VPN"), hexOf(r, "End VPN")
		// Use the same region bounds that participate in event identity;
		// sharing a start address does not make different ranges identical.
		key := strconv.FormatInt(pid, 10) + "|" + start + "|" + end
		if seen[key] {
			continue
		}
		seen[key] = true
		hexdump := strings.TrimSpace(str(r, "Hexdump"))
		ev := model.Event{
			Timestamp: snapshot, EventType: model.EventMemoryInjection, PID: pid, ProcessName: clip(str(r, "Process"), 256),
			Confidence: 0.5, SourceReference: fmt.Sprintf("windows.malfind row %d", i),
			Extra: map[string]string{
				"timestamp_basis": "memory_snapshot", "start_vpn": start, "end_vpn": end,
				"protection": clip(str(r, "Protection"), 64), "tag": clip(str(r, "Tag"), 16), "notes": clip(str(r, "Notes"), 256),
				"commit_charge": str(r, "CommitCharge"), "private_memory": str(r, "PrivateMemory"),
				"hexdump_head": clip(hexdump, 200), "disasm_head": clip(str(r, "Disasm"), 400),
				"heuristic": "malfind reports private executable memory; JIT-compiled code produces the same signature",
			},
		}
		if strings.HasPrefix(strings.ToLower(hexdump), "4d 5a") {
			ev.Extra["pe_header"] = "true"
		}
		add(ev, rawJSON(pluginName["malfind"], r))
	}

	// ---- services
	for i, r := range rowsOf["svcscan"] {
		if !haveSnapshot {
			skipped++
			continue
		}
		pid, _ := intv(r, "PID")
		bin := str(r, "Binary")
		if bin == "" {
			bin = str(r, "Binary (Registry)")
		}
		ev := model.Event{
			Timestamp: snapshot, EventType: model.EventMemoryService, PID: pid, FilePath: bin, Confidence: 0.8,
			SourceReference: fmt.Sprintf("windows.svcscan row %d", i),
			Extra: map[string]string{
				"timestamp_basis": "memory_snapshot", "service_name": clip(str(r, "Name"), 256), "display_name": clip(str(r, "Display"), 256),
				"state": clip(str(r, "State"), 64), "start_type": clip(str(r, "Start"), 64), "service_type": clip(str(r, "Type"), 64),
				"binary_registry": clip(str(r, "Binary (Registry)"), 1024), "dll": clip(str(r, "Dll"), 1024),
			},
		}
		add(ev, rawJSON(pluginName["svcscan"], r))
	}

	// ---- consoles and file objects
	var consoleNote, filesNote string
	if haveSnapshot {
		cmds, screens, notFound := consoleEvents(rowsOf, pluginName, snapshot, add)
		_, ranCmd := rowsOf["cmdscan"]
		_, ranCons := rowsOf["consoles"]
		switch {
		case cmds+screens > 0:
		case (ranCmd || ranCons) && !hasConhost(rowsOf) && (rowsOf["pslist"] != nil || rowsOf["psscan"] != nil):
			consoleNote = consoleHostNote
		case ranCmd || ranCons:
			consoleNote = consoleEmptyNote
		}
		if notFound > 0 {
			consoleNote = strings.TrimSpace(consoleNote + fmt.Sprintf(" %d console(s) were found but their structures could not be read.", notFound))
		}
		if fr, ok := rowsOf["filescan"]; ok {
			l, routine, junk, other := fileEvents(fr, pluginName["filescan"], snapshot, add)
			filesNote = fmt.Sprintf("listed %d; not listed: %d in operating-system or installed-software locations, %d of other types, %d unreadable names", l, routine, other, junk)
		}
	} else if len(rowsOf["cmdscan"])+len(rowsOf["consoles"])+len(rowsOf["filescan"]) > 0 {
		skipped += len(rowsOf["cmdscan"]) + len(rowsOf["consoles"]) + len(rowsOf["filescan"])
	}

	// ---- the snapshot itself
	if haveSnapshot {
		extra := map[string]string{
			"timestamp_basis": "system_clock_in_image", "volatility_version": a.Volatility, "isolation": a.Isolation,
			"image_name": clip(a.ImageName, 256), "image_size": strconv.FormatInt(a.ImageSize, 10),
			"ntbuildlab": clip(a.Info["NTBuildLab"], 128), "os_version": clip(a.Info["Major/Minor"], 32), "is_64bit": clip(a.Info["Is64Bit"], 8),
			"kernel_base": clip(a.Info["Kernel Base"], 40), "plugins": strings.Join(statuses, ","),
			"skipped_rows": strconv.Itoa(skipped),
		}
		if len(failed) > 0 {
			sort.Strings(failed)
			extra["plugins_failed"] = strings.Join(failed, ",")
		}
		if consoleNote != "" {
			extra["console_note"] = consoleNote
		}
		if filesNote != "" {
			extra["file_objects"] = filesNote
		}
		if truncated {
			extra["truncated"] = fmt.Sprintf("event cap %d reached", maxEvents)
		}
		maxBefore := len(out.Events)
		out.Events = append(out.Events, model.Event{
			Timestamp: snapshot, EventType: model.EventMemorySnapshot, Confidence: 1.0, Extra: extra,
			ArtifactType: model.ArtifactMemoryAnalysis, Parser: parserName, SourceReference: "windows.info",
		})
		out.Events[maxBefore].Extra["evidence_kind"] = "memory"
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: "windows.info", Raw: rawJSON("windows.info", infoRow(a.Info))})
	}
	return out, nil
}

func infoRow(info map[string]string) map[string]any {
	m := map[string]any{}
	for k, v := range info {
		m[clip(k, 64)] = clip(v, 512)
	}
	return m
}

func firstToken(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if strings.HasPrefix(cmd, `"`) {
		if end := strings.Index(cmd[1:], `"`); end >= 0 {
			return cmd[1 : end+1]
		}
	}
	if i := strings.IndexAny(cmd, " \t"); i >= 0 {
		return cmd[:i]
	}
	return cmd
}

func baseName(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
