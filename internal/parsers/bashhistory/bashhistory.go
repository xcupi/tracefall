// Package bashhistory parses POSIX shell history files (~/.bash_history).
//
// # What this artifact is, and is not
//
// bash writes each command line to its history file when the session
// accepts it. That survives the session, is per-user, and is often the
// only record of what an operator typed on a Linux host after the logs
// were rotated.
//
// The file has no timestamps by default. When the shell runs with
// HISTTIMEFORMAT set, bash writes a "#<epoch-seconds>" line immediately
// before each command. This parser honours that line when it is present
// and leaves the event undated when it is not. The file's modification
// time is never used as an execution time, for the same reason
// pshistory refuses it: it is when the file was last written, not when
// any command ran.
//
// Like PSReadLine, bash records a line when it is accepted at the
// prompt. It does not prove the command ran or succeeded, and an
// unfinished or cleared session can leave gaps.
package bashhistory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "bashhistory@1"

// ErrTooLarge means the history file exceeds the size ceiling.
var ErrTooLarge = errors.New("bashhistory: file exceeds the maximum size")

const (
	maxFileBytes   = 32 << 20 // 32 MiB: a shell history is normally a few KB
	maxCommands    = 200_000
	maxCommandRune = 8192
)

// epochLine matches the "#<epoch>" marker bash writes under HISTTIMEFORMAT.
// Anchored and digits-only, so a real command that starts with "#" (a
// comment someone typed) is never mistaken for a timestamp.
var epochLine = regexp.MustCompile(`^#([0-9]{1,12})$`)

// Parser implements parsers.ArtifactParser.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactBashHistory }

// Detect matches the file name bash uses. Triage collections flatten and
// rename directories, so the name is the reliable fast path.
func (Parser) Detect(relPath string) bool {
	return strings.EqualFold(filepath.Base(strings.ReplaceAll(relPath, `\`, "/")), ".bash_history")
}

// DetectContent returns false: a history file is plain text with no
// signature, so claiming any text file that looks like commands would
// misclassify scripts and notes. Recognition is by file name only.
func (Parser) DetectContent(header []byte) bool { return false }

// Parse reads a history file with no evidence path, so no user is
// attributed from location.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	return p.ParseWithContext(absPath, parsers.ParseContext{})
}

// ParseWithContext uses the evidence-relative path for user attribution.
func (p Parser) ParseWithContext(absPath string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
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

	// Commands are kept as the bytes the file holds. Invalid UTF-8 is
	// replaced rather than dropped, so a line is never silently lost.
	text := strings.ToValidUTF8(string(raw), "\uFFFD")

	sourceName := filepath.Base(absPath)
	user := linuxUserFromEvidencePath(ctx.EvidencePath)

	var out parsers.ParseResult
	var pending time.Time // timestamp from the "#<epoch>" line above, if any
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, " \t\r")
		if m := epochLine.FindStringSubmatch(line); m != nil {
			sec, _ := strconv.ParseInt(m[1], 10, 64)
			pending = time.Unix(sec, 0).UTC()
			continue
		}
		if strings.TrimSpace(line) == "" {
			pending = time.Time{}
			continue
		}
		if len(out.Events) >= maxCommands {
			break
		}
		if utf8.RuneCountInString(line) > maxCommandRune {
			line = string([]rune(line)[:maxCommandRune]) + "..."
		}

		ts := pending
		pending = time.Time{}
		known := "false"
		basis := "bash history records no timestamps by default; the file's modification time is not an execution time and is deliberately not used"
		if !ts.IsZero() {
			known = "true"
			basis = "epoch from the '#<epoch>' line bash writes under HISTTIMEFORMAT, immediately before this command"
		}

		ev := model.Event{
			// Zero unless the history carried a '#<epoch>' line. An unknown
			// time stays zero, never the file's mtime.
			Timestamp:    ts,
			EventType:    model.EventBashHistoryCommand,
			User:         user,
			ProcessName:  "bash",
			CommandLine:  line,
			FilePath:     sourceName,
			ArtifactType: model.ArtifactBashHistory,
			Parser:       parserName,
			// Not a confidence in the command text, which is kept exactly.
			// It reflects that the artifact cannot prove execution.
			Confidence:      0.5,
			SourceReference: "line:" + strconv.Itoa(i+1),
			Extra: map[string]string{
				"timestamp_known":   known,
				"timestamp_basis":   basis,
				"history_file":      sourceName,
				"line_number":       strconv.Itoa(i + 1),
				"records_execution": "false: bash writes a line when it is accepted at the prompt, which does not prove it ran or succeeded",
			},
		}
		if user != "" {
			ev.Extra["user_from_path"] = user
		}
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, model.RawEvidence{
			SourceReference: ev.SourceReference,
			Raw:             line,
		})
	}
	return out, nil
}

// linuxUserFromEvidencePath attributes a history file to an account from
// where it sits: "<...>/home/<name>/..." or "<...>/root/...". The shared
// normalize.UserFromEvidencePath only recognises a "home" in the first
// segment and knows nothing about /root, so Linux paths need their own
// rule; it is kept here so the Windows rule is not changed.
func linuxUserFromEvidencePath(evidencePath string) string {
	p := strings.ReplaceAll(strings.TrimSpace(evidencePath), `\`, "/")
	if p == "" || strings.HasPrefix(p, "/") {
		return ""
	}
	parts := strings.Split(p, "/")
	last := len(parts) - 1 // the file name itself is never a directory
	for i := 0; i < last; i++ {
		switch {
		case parts[i] == "home" && i+2 <= last:
			if name := strings.TrimSpace(parts[i+1]); name != "" {
				return name
			}
		case parts[i] == "root":
			return "root"
		}
	}
	return ""
}
