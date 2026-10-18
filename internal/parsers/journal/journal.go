// Package journal parses systemd journal files (*.journal).
//
// # Why this parser exists
//
// A journal holds the structured log of every service on a systemd host,
// with a real UTC timestamp on every entry. Unlike auth.log and syslog, it
// carries the year, so events from it are dated.
//
// # Format
//
// A journal file is a 240-byte header (or larger) followed by objects. Each
// object has a 16-byte header: type (1 byte), flags (1 byte), size (8
// bytes). Two object types matter here:
//
//   - DATA (type 1): one "NAME=value" field. The payload starts 64 bytes in.
//     Its flags say whether the payload is compressed. LZ4 is decoded here;
//     XZ and ZSTD are not, and fields stored that way are reported rather
//     than guessed.
//   - ENTRY (type 3): one log record. It holds the realtime timestamp (UTC
//     microseconds) and a list of references to its DATA objects.
//
// # What is emitted
//
// Every entry becomes a journal_entry event, except entries from the
// services the text-log parsers already cover (sshd, sudo, su, and cron).
// Those are excluded so the same action is not counted twice. The count of
// excluded entries is reported.
//
// # What is not interpreted
//
// Only a fixed set of fields is kept (see whitelist). Other fields are read
// past and dropped. The message is kept, truncated at maxMessageRunes.
package journal

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pierrec/lz4/v4"

	"tracefall/internal/model"
	"tracefall/internal/normalize"
	"tracefall/internal/parsers"
)

const parserName = "journal@1"

const (
	magic            = "LPKSHHRH"
	headerSizeOffset = 88
	minHeaderSize    = 240

	objectData  = 1
	objectEntry = 3

	objFlagXZ   = 1 << 0
	objFlagLZ4  = 1 << 1
	objFlagZSTD = 1 << 2

	dataPayloadOffset = 64
	entryItemsOffset  = 64
	entryItemSize     = 16
	maxFileBytes      = 512 << 20
	maxObjectBytes    = 64 << 20
	maxMessageRunes   = 4096
)

// whitelist is the set of fields kept from each DATA object. Everything else
// is read past.
var whitelist = map[string]bool{
	"MESSAGE":           true,
	"_HOSTNAME":         true,
	"_COMM":             true,
	"_EXE":              true,
	"_CMDLINE":          true,
	"_PID":              true,
	"_UID":              true,
	"_BOOT_ID":          true,
	"_SYSTEMD_UNIT":     true,
	"_TRANSPORT":        true,
	"_AUDIT_ID":         true,
	"SYSLOG_IDENTIFIER": true,
	"PRIORITY":          true,
}

// coveredByTextParsers are the services whose actions the auth.log, syslog
// and bash-history parsers already emit. Journal entries from them are
// excluded so one action is not counted twice.
var coveredByTextParsers = map[string]bool{
	"sshd": true,
	"sudo": true,
	"su":   true,
	"CRON": true,
	"cron": true,
}

// ErrNotJournal means the file does not start with the journal signature.
var ErrNotJournal = errors.New("journal: not a systemd journal file")

// ErrTooLarge means the file exceeds the size ceiling.
var ErrTooLarge = errors.New("journal: file exceeds the maximum size")

// Stats reports what was read, so a reviewer can see what the event count
// does and does not include.
type Stats struct {
	Entries            int // every entry in the file
	Excluded           int // entries left to the text-log parsers
	Emitted            int // entries that became events
	UnsupportedObjects int // DATA objects compressed with XZ or ZSTD, not decoded
	UndecodableObjects int // DATA objects whose LZ4 payload failed to decode
	Executions         int // audit-grouped execution events among Emitted
}

// Parser implements parsers.ArtifactParser.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactJournal }

// Detect matches the .journal extension. Rotated journals that journald set
// aside after corruption (system@....journal~) do not match by name; they are
// claimed by DetectContent instead, because their first bytes carry the same
// signature and they read correctly (the lab's MrGamer image has three).
func (Parser) Detect(relPath string) bool {
	return strings.EqualFold(filepath.Ext(strings.ReplaceAll(relPath, `\`, "/")), ".journal")
}

// DetectContent claims a file whose first bytes are the journal signature.
// The signature is at the start of the file, so a 512-byte header is enough
// to recognise it, and it does not depend on reading the tail.
func (Parser) DetectContent(header []byte) bool {
	return len(header) >= len(magic) && string(header[:len(magic)]) == magic
}

// Parse reads a journal with no evidence path.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	res, _, err := p.ParseDetailed(absPath, parsers.ParseContext{})
	return res, err
}

// ParseWithContext reads a journal and returns its events.
func (p Parser) ParseWithContext(absPath string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
	res, _, err := p.ParseDetailed(absPath, ctx)
	return res, err
}

// ParseDetailed is ParseWithContext with the reading statistics.
func (p Parser) ParseDetailed(absPath string, ctx parsers.ParseContext) (parsers.ParseResult, Stats, error) {
	var st Stats
	info, err := os.Stat(absPath)
	if err != nil {
		return parsers.ParseResult{}, st, err
	}
	if info.Size() > maxFileBytes {
		return parsers.ParseResult{}, st, fmt.Errorf("%w: %d bytes", ErrTooLarge, info.Size())
	}
	b, err := os.ReadFile(absPath)
	if err != nil {
		return parsers.ParseResult{}, st, err
	}
	if len(b) < minHeaderSize || string(b[:len(magic)]) != magic {
		return parsers.ParseResult{}, st, ErrNotJournal
	}
	hdrSize := binary.LittleEndian.Uint64(b[headerSizeOffset : headerSizeOffset+8])
	if hdrSize < minHeaderSize || hdrSize > uint64(len(b)) {
		return parsers.ParseResult{}, st, fmt.Errorf("journal: header size %d outside the file", hdrSize)
	}

	type field struct{ name, value string }
	data := map[uint64]field{}
	type entry struct {
		off      uint64
		seqnum   uint64
		realtime uint64
		bootID   []byte
		items    []uint64
	}
	var entries []entry

	off := hdrSize
	for off+16 <= uint64(len(b)) {
		typ, flags := b[off], b[off+1]
		size := binary.LittleEndian.Uint64(b[off+8 : off+16])
		if size < 16 || off+size > uint64(len(b)) {
			break // the used region ends here; the rest is preallocated or padding
		}
		switch typ {
		case objectData:
			if flags&(objFlagXZ|objFlagZSTD) != 0 {
				st.UnsupportedObjects++
				break
			}
			payload, err := dataPayload(b[off+dataPayloadOffset:off+size], flags)
			if err != nil {
				st.UndecodableObjects++
				break
			}
			if k := bytes.IndexByte(payload, '='); k > 0 {
				name := string(payload[:k])
				if whitelist[name] {
					data[off] = field{name: name, value: strings.ToValidUTF8(string(payload[k+1:]), "\uFFFD")}
				}
			}
		case objectEntry:
			if size < entryItemsOffset {
				break
			}
			n := (size - entryItemsOffset) / entryItemSize
			e := entry{
				off:      off,
				seqnum:   binary.LittleEndian.Uint64(b[off+16 : off+24]),
				realtime: binary.LittleEndian.Uint64(b[off+24 : off+32]),
				bootID:   b[off+40 : off+56],
			}
			for i := uint64(0); i < n; i++ {
				base := off + entryItemsOffset + i*entryItemSize
				e.items = append(e.items, binary.LittleEndian.Uint64(b[base:base+8]))
			}
			entries = append(entries, e)
		}
		off += (size + 7) &^ 7
	}

	sourceName := filepath.Base(absPath)
	var out parsers.ParseResult

	emitPlain := func(r rec) {
		if excludedService(r.fields) {
			st.Excluded++
			return
		}
		st.Emitted++
		ev := entryEvent(r.seqnum, r.realtime, r.bootID, r.fields, sourceName)
		ref := "seqnum:" + strconv.FormatUint(r.seqnum, 10)
		ev.SourceReference = ref
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ref, Raw: rawText(r.seqnum, r.realtime, r.fields)})
	}

	// audit records are grouped by their serial, so one execution is one event.
	audit := map[string][]rec{}
	var auditOrder []string
	for _, e := range entries {
		st.Entries++
		fields := map[string]string{}
		for _, ref := range e.items {
			if f, ok := data[ref]; ok {
				fields[f.name] = f.value
			}
		}
		r := rec{seqnum: e.seqnum, realtime: e.realtime, bootID: bytesHex(e.bootID), fields: fields}
		if fields["_TRANSPORT"] == "audit" && fields["_AUDIT_ID"] != "" {
			id := fields["_AUDIT_ID"]
			if _, seen := audit[id]; !seen {
				auditOrder = append(auditOrder, id)
			}
			audit[id] = append(audit[id], r)
			continue
		}
		emitPlain(r)
	}

	for _, id := range auditOrder {
		recs := audit[id]
		sys := execSyscall(recs)
		if sys == nil {
			// Not an execution (login, credential or backlog records): keep
			// each record as its own entry, as for any other journal entry.
			for _, r := range recs {
				emitPlain(r)
			}
			continue
		}
		if excludedService(sys.fields) {
			st.Excluded++
			continue
		}
		st.Emitted++
		st.Executions++
		ev, raw := executionEvent(id, recs, sys, sourceName)
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: "audit:" + id, Raw: raw})
	}
	return out, st, nil
}

// dataPayload returns the "NAME=value" bytes of a DATA object, decompressing
// LZ4 when the flags say so. An LZ4 payload starts with the uncompressed
// size as an 8-byte little-endian integer, then the LZ4 block.
func dataPayload(payload []byte, flags byte) ([]byte, error) {
	if flags&objFlagLZ4 == 0 {
		return payload, nil
	}
	if len(payload) < 8 {
		return nil, errors.New("lz4 payload shorter than its size prefix")
	}
	usz := binary.LittleEndian.Uint64(payload[:8])
	if usz == 0 || usz > maxObjectBytes {
		return nil, fmt.Errorf("lz4 uncompressed size %d outside the allowed range", usz)
	}
	dst := make([]byte, usz)
	n, err := lz4.UncompressBlock(payload[8:], dst)
	if err != nil {
		return nil, err
	}
	if uint64(n) != usz {
		return nil, fmt.Errorf("lz4 decoded %d bytes, size prefix says %d", n, usz)
	}
	return dst, nil
}

func entryEvent(seqnum, realtime uint64, bootID string, f map[string]string, sourceName string) model.Event {
	var ts time.Time
	if realtime != 0 {
		ts = time.UnixMicro(int64(realtime)).UTC()
	}
	pid, _ := strconv.ParseInt(f["_PID"], 10, 64)
	msg := f["MESSAGE"]
	if utf8.RuneCountInString(msg) > maxMessageRunes {
		msg = string([]rune(msg)[:maxMessageRunes]) + "..."
	}
	extra := map[string]string{
		"timestamp_known": strconv.FormatBool(!ts.IsZero()),
		"seqnum":          strconv.FormatUint(seqnum, 10),
		"realtime_usec":   strconv.FormatUint(realtime, 10),
		"boot_id":         bootID,
		"journal_file":    sourceName,
	}
	if msg != "" {
		extra["message"] = msg
	}
	for _, k := range []string{"_UID", "_SYSTEMD_UNIT", "_TRANSPORT", "PRIORITY"} {
		if v := f[k]; v != "" {
			extra[strings.TrimPrefix(strings.ToLower(k), "_")] = v
		}
	}
	return model.Event{
		Timestamp:    ts,
		EventType:    model.EventJournalEntry,
		Host:         normalize.Host(f["_HOSTNAME"]),
		Provider:     f["SYSLOG_IDENTIFIER"],
		PID:          pid,
		ProcessName:  f["_COMM"],
		ProcessPath:  f["_EXE"],
		CommandLine:  f["_CMDLINE"],
		FilePath:     sourceName,
		ArtifactType: model.ArtifactJournal,
		Parser:       parserName,
		Confidence:   0.7,
		Extra:        extra,
	}
}

func rawText(seqnum, realtime uint64, f map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "seqnum=%d realtime_usec=%d\n", seqnum, realtime)
	for _, k := range []string{"_HOSTNAME", "_PID", "_COMM", "_EXE", "_CMDLINE", "_UID", "SYSLOG_IDENTIFIER", "MESSAGE"} {
		if v, ok := f[k]; ok {
			fmt.Fprintf(&b, "%s=%s\n", k, v)
		}
	}
	return b.String()
}

func bytesHex(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hex[c>>4], hex[c&0x0f])
	}
	return string(out)
}

// rec is one journal entry, reduced to the whitelisted fields.
type rec struct {
	seqnum, realtime uint64
	bootID           string
	fields           map[string]string
}

// excludedService reports whether a record belongs to a service the text-log
// parsers already cover.
func excludedService(f map[string]string) bool {
	return coveredByTextParsers[f["SYSLOG_IDENTIFIER"]] || coveredByTextParsers[f["_COMM"]]
}

// auditKV matches auditd's "key=value" pairs. A value is either quoted text
// or a bare token; a list split across records appears as key[0], key[1]...
var auditKV = regexp.MustCompile(`([A-Za-z0-9_]+(?:\[[0-9]+\])?)=("[^"]*"|[^\s]+)`)

// parseKV returns the first value for each key in an audit message, unquoted.
func parseKV(msg string) map[string]string {
	out := map[string]string{}
	for _, m := range auditKV.FindAllStringSubmatch(msg, -1) {
		if _, seen := out[m[1]]; !seen {
			out[m[1]] = unquote(m[2])
		}
	}
	return out
}

func unquote(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	return v
}

// decodeArg turns one EXECVE argument into text. auditd quotes plain text and
// writes arguments with special characters as bare hex.
func decodeArg(v string) string {
	if len(v) >= 2 && v[0] == '"' {
		return unquote(v)
	}
	if b, err := hex.DecodeString(v); err == nil {
		return string(b)
	}
	return v
}

// execArgs rebuilds argv from an EXECVE message, joining chunked arguments
// (a0[0], a0[1], ...) in order.
func execArgs(msg string) []string {
	argRe := regexp.MustCompile(`\ba([0-9]+)(?:\[([0-9]+)\])?=("[^"]*"|[^\s]+)`)
	parts := map[int][]string{}
	for _, m := range argRe.FindAllStringSubmatch(msg, -1) {
		idx, _ := strconv.Atoi(m[1])
		parts[idx] = append(parts[idx], decodeArg(m[3]))
	}
	idxs := make([]int, 0, len(parts))
	for i := range parts {
		idxs = append(idxs, i)
	}
	sort.Ints(idxs)
	args := make([]string, 0, len(idxs))
	for _, i := range idxs {
		args = append(args, strings.Join(parts[i], ""))
	}
	return args
}

// execSyscall returns the SYSCALL record of an audit group when it is an
// execve (59) or execveat (322), or nil for any other group.
func execSyscall(recs []rec) *rec {
	for i := range recs {
		msg := recs[i].fields["MESSAGE"]
		if !strings.HasPrefix(msg, "SYSCALL ") {
			continue
		}
		kv := parseKV(msg)
		if isExecSyscall(kv["arch"], kv["syscall"]) {
			return &recs[i]
		}
	}
	return nil
}

// execSyscalls maps audit arch (hex) to the syscall numbers that start a
// program: execve and execveat. The number alone is not enough: 11 is execve
// on 32-bit x86 but munmap on x86_64, so the arch decides.
var execSyscalls = map[string]map[string]bool{
	"c000003e": {"59": true, "322": true},  // x86_64
	"40000003": {"11": true, "358": true},  // i386, also 32-bit processes on an x86_64 kernel
	"c00000b7": {"221": true, "281": true}, // aarch64
}

func isExecSyscall(arch, nr string) bool {
	return execSyscalls[strings.ToLower(arch)][nr]
}

const (
	maxPathsPerExecution = 20
	maxCommandRunes      = 8192
)

// executionEvent turns one audit group that is an execve into one
// process_create event. The SYSCALL record gives the process, the EXECVE
// record its arguments, CWD its directory, PATH the files it touched, and
// PROCTITLE its title. Everything is kept; nothing is dropped.
func executionEvent(id string, recs []rec, sys *rec, sourceName string) (model.Event, string) {
	sk := parseKV(sys.fields["MESSAGE"])
	var args, paths []string
	var cwd, proctitle string
	var raw []string
	for _, r := range recs {
		msg := r.fields["MESSAGE"]
		raw = append(raw, msg)
		switch {
		case strings.HasPrefix(msg, "EXECVE "):
			args = execArgs(msg)
		case strings.HasPrefix(msg, "CWD "):
			cwd = parseKV(msg)["cwd"]
		case strings.HasPrefix(msg, "PATH "):
			if n := parseKV(msg)["name"]; n != "" {
				paths = append(paths, n)
			}
		case strings.HasPrefix(msg, "PROCTITLE "):
			proctitle = titleText(parseKV(msg)["proctitle"])
		}
	}

	cmd := strings.Join(args, " ")
	cmdSource := "execve arguments"
	if cmd == "" && proctitle != "" {
		cmd, cmdSource = proctitle, "proctitle (no EXECVE record)"
	}
	truncated := false
	if utf8.RuneCountInString(cmd) > maxCommandRunes {
		cmd = string([]rune(cmd)[:maxCommandRunes]) + "..."
		truncated = true
	}

	var ts time.Time
	if sys.realtime != 0 {
		ts = time.UnixMicro(int64(sys.realtime)).UTC()
	}
	pid, _ := strconv.ParseInt(sys.fields["_PID"], 10, 64)
	ppid, _ := strconv.ParseInt(sk["ppid"], 10, 64)
	comm := sys.fields["_COMM"]
	if comm == "" {
		comm = sk["comm"]
	}

	shown := paths
	if len(shown) > maxPathsPerExecution {
		shown = shown[:maxPathsPerExecution]
	}
	extra := map[string]string{
		"timestamp_known": strconv.FormatBool(!ts.IsZero()),
		"source":          "auditd execve syscall",
		"audit_id":        id,
		"syscall":         sk["syscall"],
		"syscall_success": sk["success"],
		"exit":            sk["exit"],
		"uid":             sk["uid"],
		"auid":            sk["auid"],
		"euid":            sk["euid"],
		"gid":             sk["gid"],
		"argc":            strconv.Itoa(len(args)),
		"command_source":  cmdSource,
		"path_count":      strconv.Itoa(len(paths)),
		"record_count":    strconv.Itoa(len(recs)),
		"realtime_usec":   strconv.FormatUint(sys.realtime, 10),
		"seqnum":          strconv.FormatUint(sys.seqnum, 10),
		"boot_id":         sys.bootID,
		"journal_file":    sourceName,
	}
	if cwd != "" {
		extra["cwd"] = cwd
	}
	if len(shown) > 0 {
		extra["paths"] = strings.Join(shown, "; ")
	}
	if proctitle != "" {
		extra["proctitle"] = proctitle
	}
	if truncated {
		extra["command_truncated"] = "true"
	}
	ev := model.Event{
		Timestamp:       ts,
		EventType:       model.EventProcessCreate,
		Host:            normalize.Host(sys.fields["_HOSTNAME"]),
		Provider:        "audit",
		PID:             pid,
		PPID:            ppid,
		ProcessName:     comm,
		ProcessPath:     sk["exe"],
		CommandLine:     cmd,
		FilePath:        sourceName,
		ArtifactType:    model.ArtifactJournal,
		Parser:          parserName,
		Confidence:      0.8,
		SourceReference: "audit:" + id,
		Extra:           extra,
	}
	return ev, strings.Join(raw, "\n")
}

// titleText decodes a PROCTITLE value: bare hex with NUL separators, or
// quoted text.
func titleText(v string) string {
	if len(v) >= 2 && v[0] == '"' {
		return unquote(v)
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return v
	}
	return strings.ReplaceAll(string(b), "\x00", " ")
}
