// Package pshistory parses PowerShell console history files
// (ConsoleHost_history.txt), written by the PSReadLine module.
//
// # What this artifact is, and is not
//
// PSReadLine appends every command line an interactive PowerShell
// session accepts, one per line, in order. That is genuinely valuable:
// it survives the session, it is per-user, and attackers routinely
// forget it exists.
//
// It records NO timestamps. Not per command, not per session. Events
// produced here therefore carry a ZERO Timestamp, and say so explicitly
// in Extra. The file's own modification time is deliberately NOT used:
// that is when the file was last written or collected, not when any
// particular command ran, and presenting it as an execution time would
// be fabricating evidence.
//
// It also does not record whether a command SUCCEEDED, or even ran --
// PSReadLine writes the line when it is accepted at the prompt. The
// event type (model.EventPowerShellHistoryCommand) is named for what the
// evidence supports: a command was entered.
//
// See Event.ComputeDedupHash's zero-time rule for how N timestamp-less
// commands keep distinct identities.
package pshistory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "pshistory@1"

var (
	// ErrTooLarge means the history file exceeds the size ceiling.
	ErrTooLarge = errors.New("pshistory: file exceeds the maximum size")
	// ErrEncoding means the file's bytes are not decodable as any
	// encoding PowerShell writes.
	ErrEncoding = errors.New("pshistory: file is not valid UTF-8 or UTF-16 text")
)

const (
	maxFileBytes   = 32 << 20 // 32 MiB: a console history is normally a few KB
	maxCommands    = 200_000
	maxCommandRune = 8192 // one absurdly long line cannot become an unbounded field
)

// Parser implements parsers.ArtifactParser and parsers.ContentDetector.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactPowerShellHistory }

// Detect matches the filename PSReadLine uses. The path is not required
// to be the canonical AppData location, because triage collections
// flatten and rename directories constantly -- but the filename itself
// is distinctive enough to be a reliable fast path.
func (Parser) Detect(relPath string) bool {
	return strings.EqualFold(filepath.Base(relPath), "ConsoleHost_history.txt")
}

// DetectContent deliberately returns false.
//
// A console history is plain text with no signature, so there is nothing
// to sniff: claiming any text file that "looks like commands" is a
// PowerShell history would misclassify every script, log and note in a
// collection. Recognition is by filename only, and that limitation is
// stated rather than papered over with a guess.
func (Parser) DetectContent(header []byte) bool { return false }

// Parse reads a console history file and emits one event per command.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if info.Size() > maxFileBytes {
		return parsers.ParseResult{}, fmt.Errorf("%w: %d bytes", ErrTooLarge, info.Size())
	}
	raw, err := os.ReadFile(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}

	text, encoding, err := decodeText(raw)
	if err != nil {
		return parsers.ParseResult{}, err
	}

	sourceName := filepath.Base(absPath)
	user := userFromPath(absPath)

	var out parsers.ParseResult
	// Line numbers count EVERY line including blanks, so a reference
	// points at the same line an investigator sees opening the file.
	for i, line := range splitLines(text) {
		cmd := strings.TrimRight(line, " \t")
		if strings.TrimSpace(cmd) == "" {
			continue
		}
		if len(out.Events) >= maxCommands {
			break
		}
		if utf8.RuneCountInString(cmd) > maxCommandRune {
			cmd = string([]rune(cmd)[:maxCommandRune]) + "..."
		}

		ev := model.Event{
			// ZERO. The artifact records no time, and the file's mtime is
			// not an execution time. See this package's doc comment.
			EventType:    model.EventPowerShellHistoryCommand,
			User:         user,
			ProcessName:  "powershell.exe",
			CommandLine:  cmd,
			FilePath:     sourceName,
			ArtifactType: model.ArtifactPowerShellHistory,
			Parser:       parserName,
			// Not a confidence in the COMMAND -- that is recorded exactly
			// as written. It reflects that the artifact cannot say when,
			// or whether, the command executed.
			Confidence:      0.5,
			SourceReference: "line:" + strconv.Itoa(i+1),
			Extra: map[string]string{
				"timestamp_known":   "false",
				"timestamp_basis":   "PowerShell console history records no timestamps; the file's modification time is not an execution time and is deliberately not used",
				"history_file":      sourceName,
				"line_number":       strconv.Itoa(i + 1),
				"text_encoding":     encoding,
				"records_execution": "false: PSReadLine writes a line when it is accepted at the prompt, which does not prove it ran or succeeded",
			},
		}
		if user != "" {
			ev.Extra["user_from_path"] = user
		}

		rawJSON, _ := json.Marshal(map[string]any{
			"history_file": sourceName,
			"line_number":  i + 1,
			"command":      cmd,
			"encoding":     encoding,
		})
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ev.SourceReference, Raw: string(rawJSON)})
	}
	return out, nil
}

// decodeText decodes the file as the encodings PowerShell actually
// writes, reporting which one was used so the choice is auditable.
//
// PSReadLine writes UTF-8 by default, but a history file copied or
// re-saved through Windows tooling can arrive as UTF-16, with or without
// a byte-order mark. Guessing wrong turns every command into mojibake,
// so the BOM is honored when present and UTF-16 is detected structurally
// when it is not.
func decodeText(raw []byte) (text, encoding string, err error) {
	switch {
	case bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}):
		body := raw[3:]
		if !utf8.Valid(body) {
			return "", "", fmt.Errorf("%w: UTF-8 BOM present but the content is not valid UTF-8", ErrEncoding)
		}
		return string(body), "utf-8-bom", nil

	case bytes.HasPrefix(raw, []byte{0xFF, 0xFE}):
		return decodeUTF16(raw[2:], false), "utf-16le-bom", nil

	case bytes.HasPrefix(raw, []byte{0xFE, 0xFF}):
		return decodeUTF16(raw[2:], true), "utf-16be-bom", nil
	}

	// The UTF-16 structural check MUST come before the UTF-8 one.
	// BOM-less UTF-16LE ASCII is byte-for-byte *valid UTF-8* -- NUL is a
	// legal UTF-8 byte -- so testing UTF-8 first silently accepts it and
	// turns every command into NUL-separated mojibake. Real text does not
	// contain NULs, so the NUL-every-other-byte pattern is decisive.
	if looksUTF16(raw, false) {
		return decodeUTF16(raw, false), "utf-16le", nil
	}
	if looksUTF16(raw, true) {
		return decodeUTF16(raw, true), "utf-16be", nil
	}
	if utf8.Valid(raw) {
		return string(raw), "utf-8", nil
	}
	return "", "", fmt.Errorf("%w: no byte-order mark, and the content decodes as neither UTF-8 nor UTF-16", ErrEncoding)
}

// looksUTF16 reports whether raw has the NUL-every-other-byte pattern of
// UTF-16-encoded ASCII in the given byte order.
func looksUTF16(raw []byte, bigEndian bool) bool {
	if len(raw) < 4 || len(raw)%2 != 0 {
		return false
	}
	sample := raw
	if len(sample) > 512 {
		sample = sample[:512]
	}
	nulAt, total := 0, 0
	for i := 0; i+1 < len(sample); i += 2 {
		idx := i + 1 // low byte holds the NUL for big-endian ASCII
		if bigEndian {
			idx = i
		}
		if sample[idx] == 0 {
			nulAt++
		}
		total++
	}
	return total > 0 && nulAt*10 >= total*9 // at least 90% of pairs
}

func decodeUTF16(b []byte, bigEndian bool) string {
	n := len(b) &^ 1
	u := make([]uint16, 0, n/2)
	for i := 0; i < n; i += 2 {
		if bigEndian {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		} else {
			u = append(u, uint16(b[i+1])<<8|uint16(b[i]))
		}
	}
	return string(utf16.Decode(u))
}

// splitLines handles CRLF and LF (and a stray CR) identically.
func splitLines(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return strings.Split(text, "\n")
}

// userFromPath recovers the owning username from the evidence path, when
// it genuinely contains one (".../Users/jdoe/AppData/Roaming/..."). An
// unknown user stays unknown -- never guessed from the filename.
func userFromPath(path string) string {
	parts := strings.Split(strings.ReplaceAll(path, `\`, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "Users") || strings.EqualFold(parts[i], "Documents and Settings") {
			name := parts[i+1]
			if name != "" && !strings.EqualFold(name, "Public") && !strings.EqualFold(name, "Default") {
				return name
			}
		}
	}
	return ""
}
