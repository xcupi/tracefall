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
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	for _, e := range entries {
		st.Entries++
		fields := map[string]string{}
		for _, ref := range e.items {
			if f, ok := data[ref]; ok {
				fields[f.name] = f.value
			}
		}
		ident := fields["SYSLOG_IDENTIFIER"]
		comm := fields["_COMM"]
		if coveredByTextParsers[ident] || coveredByTextParsers[comm] {
			st.Excluded++
			continue
		}
		st.Emitted++
		ev := entryEvent(e.seqnum, e.realtime, bytesHex(e.bootID), fields, sourceName)
		ref := "seqnum:" + strconv.FormatUint(e.seqnum, 10)
		ev.SourceReference = ref
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ref, Raw: rawText(e.seqnum, e.realtime, fields)})
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
