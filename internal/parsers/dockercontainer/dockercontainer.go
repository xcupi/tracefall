// Package dockercontainer reads the files a Docker (or containerd based)
// container engine keeps about one container:
//
//   - <id>-json.log (also the rotated <id>-json.log.N): the json-file log
//     driver's record of what the container wrote to stdout and stderr;
//   - config.v2.json: the container's recorded configuration and state;
//   - hostconfig.json: the privileges and isolation it was started with.
//
// Linux keeps them under /var/lib/docker/containers/<id>/, Windows under
// C:\ProgramData\docker\containers\<id>\. <id> is the 64 hex character
// container id.
//
// The Windows layout is built from the documented format only (the same
// Docker code writes the same JSON). It is NOT verified against a real
// Windows engine. The Linux layout was checked against a real engine (see the
// env-gated test).
//
// # What the files are, and are not
//
// They are what the engine recorded. They are not a view inside the
// container: a process that wrote nowhere the engine captured is invisible
// here, and config.v2.json and hostconfig.json are a snapshot taken when the
// engine last saved them, not a record of what ran. Each emitted config event
// says so in Extra["records_outcome"].
//
// # Time
//
// A json-file record has its own UTC time (nanoseconds), the moment the engine
// received the line. That is the event time. A Grafana line inside the log is
// dated by the application's own t=, the engine time is kept in
// Extra["container_received"]. config.v2.json and hostconfig.json are
// snapshots: the event has NO timestamp, and the instants the file records
// (created, started, finished) are kept as written in Extra. A state time of
// 0001-01-01T00:00:00Z is the engine's zero value for "never happened" and is
// omitted.
//
// # Secrets
//
// Environment variable VALUES are never read into output: only names. The
// raw record kept for config.v2.json has every Env value replaced, so it is
// NOT the untouched file; the file itself stays in the evidence store. Log
// messages and command text go through cmdsem.Redact (best effort). The raw
// record of a log line is kept as written.
//
// # Limits
//
// A log is streamed. A line longer than 1 MiB is counted, not parsed. After
// 250000 records the parser stops and says so in the coverage notes.
package dockercontainer

import (
	"bytes"
	"errors"
	"path"
	"regexp"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "dockercontainer@1"

var (
	idRe  = regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)
	logRe = regexp.MustCompile(`^([0-9A-Fa-f]{64})-json\.log(?:\.[0-9]+)?$`)
)

type kind int

const (
	kindNone kind = iota
	kindLog
	kindConfig
	kindHostConfig
)

// Parser implements parsers.ArtifactParser and ContextualParser.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactContainerLog }

// EventArtifactTypes: config.v2.json and hostconfig.json events are
// container_config; the primary type is the log.
func (Parser) EventArtifactTypes() []string { return []string{model.ArtifactContainerConfig} }

// classify decides the kind from the path alone and returns the container id.
func classify(relPath string) (kind, string) {
	p := strings.ReplaceAll(relPath, `\`, "/")
	base := path.Base(p)
	if m := logRe.FindStringSubmatch(base); m != nil {
		return kindLog, strings.ToLower(m[1])
	}
	lower := strings.ToLower(base)
	if lower != "config.v2.json" && lower != "hostconfig.json" {
		return kindNone, ""
	}
	dir := path.Base(path.Dir(p))
	if !idRe.MatchString(dir) {
		return kindNone, ""
	}
	if lower == "config.v2.json" {
		return kindConfig, strings.ToLower(dir)
	}
	return kindHostConfig, strings.ToLower(dir)
}

// Detect is name-driven: the id in a log name, or the id directory above
// config.v2.json / hostconfig.json. A config.v2.json elsewhere is not claimed.
func (Parser) Detect(relPath string) bool {
	k, _ := classify(relPath)
	return k != kindNone
}

// DetectPath: content is never used to claim a file, so a location outside a
// name match is not worth asking the bytes about.
func (p Parser) DetectPath(relPath string) bool { return p.Detect(relPath) }

// DetectContent is false on purpose. A JSON object is not enough to call a
// file a container artifact; the name and the id directory decide, and
// ConfirmContent checks the bytes agree.
func (Parser) DetectContent(header []byte) bool { return false }

// ConfirmContent checks that a name match looks like one of the three formats.
// The sniff window (512 bytes) cannot hold every key of config.v2.json, so
// this is a head check; Parse then requires the keys in full.
func (Parser) ConfirmContent(header []byte) bool {
	h := bytes.TrimLeft(header, "\xef\xbb\xbf \t\r\n")
	if len(h) == 0 || h[0] != '{' {
		return false
	}
	s := string(h)
	switch {
	case strings.HasPrefix(s, `{"log":`):
		return true
	case strings.Contains(s, `"NetworkMode"`) && (strings.Contains(s, `"PortBindings"`) || strings.Contains(s, `"Privileged"`) || strings.Contains(s, `"Binds"`)):
		return true
	case strings.Contains(s, `"State"`) || strings.Contains(s, `"StreamConfig"`) || strings.Contains(s, `"ID"`):
		return true
	}
	return false
}

// Parse reads a file with no evidence path (its own name decides the kind).
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	return p.ParseWithContext(absPath, parsers.ParseContext{})
}

// ParseWithContext dispatches on the file kind. The evidence path, when
// given, decides the kind and the container id (a stored copy may carry a
// different name).
func (p Parser) ParseWithContext(absPath string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
	name := absPath
	if ctx.EvidencePath != "" {
		name = ctx.EvidencePath
	}
	k, id := classify(name)
	switch k {
	case kindLog:
		return parseLog(absPath, id, path.Base(strings.ReplaceAll(name, `\`, "/")))
	case kindConfig:
		return parseConfig(absPath, id)
	case kindHostConfig:
		return parseHostConfig(absPath, id)
	}
	return parsers.ParseResult{}, errors.New("dockercontainer: not a container engine file name")
}
