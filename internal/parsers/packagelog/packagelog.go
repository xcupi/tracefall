// Package packagelog parses the Debian package manager's transaction log
// (/var/log/dpkg.log and its plain rotations).
//
//	2010-04-19 12:00:30 install python-tz <none> 2007k-0ubuntu2
//	2010-04-19 12:05:11 upgrade openssl 0.9.8g-4 0.9.8g-10
//	2010-04-19 12:06:02 remove telnet 0.17-35 0.17-35
//
// # What is emitted
//
// One package_change event for each install, upgrade, remove and purge
// line, with the package, the architecture if the name carries one, and the
// old and new versions. The other lines (status, configure, trigproc,
// startup) describe the steps of a transaction, not a change a person asked
// for, and are not emitted.
//
// # Time
//
// Each line begins with a date and time but names no time zone: dpkg writes
// local time. The zone is not in the file and is not guessed, so the event's
// Timestamp stays zero and the text is kept as written in
// Extra["timestamp_local"]. The date has a year, so it can be compared with
// other dated artifacts once the zone is established from the host.
//
// # What it proves
//
// That the package database changed. It does not show that anything in the
// package ran, or who asked for the change.
package packagelog

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "packagelog@1"

const maxFileBytes = 64 << 20

var lineRe = regexp.MustCompile(`^([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}) (install|upgrade|remove|purge) (\S+) (\S+) (\S+)$`)

var rotationRe = regexp.MustCompile(`(?i)^dpkg\.log\.[0-9]+$`)

// Parser implements parsers.ArtifactParser.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactPackageLog }

// Detect matches dpkg.log and its numbered plain rotations.
func (Parser) Detect(relPath string) bool {
	base := filepath.Base(strings.ReplaceAll(relPath, `\`, "/"))
	return strings.EqualFold(base, "dpkg.log") || rotationRe.MatchString(base)
}

// DetectContent returns false: the format has no signature to sniff.
func (Parser) DetectContent(header []byte) bool { return false }

// Parse reads a dpkg log with no evidence path.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	return p.ParseWithContext(absPath, parsers.ParseContext{})
}

// ParseWithContext reads the file in file order.
func (p Parser) ParseWithContext(absPath string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if info.Size() > maxFileBytes {
		return parsers.ParseResult{}, fmt.Errorf("packagelog: file exceeds %d bytes", maxFileBytes)
	}
	raw, err := os.ReadFile(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	text := strings.ToValidUTF8(string(raw), "\uFFFD")

	sourceName := filepath.Base(absPath)
	var out parsers.ParseResult
	for i, l := range strings.Split(text, "\n") {
		l = strings.TrimRight(l, "\r")
		m := lineRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		stamp, action, pkg, oldV, newV := m[1], m[2], m[3], m[4], m[5]
		arch := ""
		if j := strings.LastIndexByte(pkg, ':'); j > 0 {
			pkg, arch = pkg[:j], pkg[j+1:]
		}
		ref := "line:" + strconv.Itoa(i+1)
		extra := map[string]string{
			"action":            action,
			"package":           pkg,
			"version_before":    noneToEmpty(oldV),
			"version_after":     noneToEmpty(newV),
			"timestamp_known":   "false",
			"timestamp_local":   stamp,
			"timestamp_basis":   "dpkg writes local time and does not record the time zone; the zone is not assumed, so the date is kept as written",
			"line_number":       strconv.Itoa(i + 1),
			"history_file":      sourceName,
			"records_execution": "false: the package database changed; nothing in the package is shown to have run",
		}
		if arch != "" {
			extra["architecture"] = arch
		}
		out.Events = append(out.Events, model.Event{
			EventType:       model.EventPackageChange,
			ProcessName:     "dpkg",
			ArtifactType:    model.ArtifactPackageLog,
			Parser:          parserName,
			FilePath:        sourceName,
			SourceReference: ref,
			Confidence:      0.95,
			Extra:           extra,
		})
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ref, Raw: l})
	}
	return out, nil
}

func noneToEmpty(v string) string {
	if v == "<none>" {
		return ""
	}
	return v
}
