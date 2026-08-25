// Package normalize holds normalization logic shared by every artifact
// parser: timestamp parsing, host/user canonicalization, and process path
// splitting. Centralizing it here means every parser produces events on
// the same conventions (UTC timestamps, "DOMAIN\user" casing, etc.)
// instead of each parser inventing its own.
package normalize

import (
	"path"
	"strconv"
	"strings"
	"time"
)

// Timestamp layouts accepted from KAPE/EZ Tools CSV output and raw XML.
// EZ Tools consistently emit "2006-01-02T15:04:05.0000000Z" (round-trip
// UTC); we also accept a plain space-separated form defensively since
// some tool versions/locales differ.
var timeLayouts = []string{
	"2006-01-02T15:04:05.0000000Z",
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05.999999999", // Task Scheduler RegistrationInfo/Date (no offset)
	"2006-01-02T15:04:05",
}

// Timestamp parses a KAPE/EZ-Tools-style timestamp string and normalizes
// it to UTC. Returns the zero time and false if none of the known layouts
// match, so callers can decide how to handle an unparseable timestamp
// (skip the record, flag low confidence, etc.) rather than silently
// inventing a time.
func Timestamp(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// User canonicalizes a username string. KAPE/EZ Tools sometimes render
// "-" or empty for unavailable data; both normalize to "".
func User(s string) string {
	s = strings.TrimSpace(s)
	if s == "-" {
		return ""
	}
	return s
}

// Host canonicalizes a hostname, uppercased to match Windows' own
// case-insensitive convention so entity correlation (internal/correlate)
// can compare hosts with a plain string match.
func Host(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

// ProcessName returns the base executable name from a full file path,
// lowercased for stable comparison (Windows paths are case-insensitive).
// "C:\Windows\System32\cmd.exe" -> "cmd.exe". Unlike a command line, a
// path has no arguments to strip, so this is a plain basename -- it must
// NOT be used on a raw command line, since splitting an unquoted path
// containing spaces (e.g. "C:\Program Files\...") on whitespace would
// truncate it. Use ExecutableFromCommandLine for that case.
func ProcessName(fullPath string) string {
	fullPath = strings.TrimSpace(fullPath)
	if fullPath == "" {
		return ""
	}
	base := path.Base(strings.ReplaceAll(fullPath, `\`, "/"))
	return strings.ToLower(base)
}

// ExecutableFromCommandLine extracts the executable's base name from a
// full command line, honoring a leading quoted path (e.g.
// `"C:\Program Files\x\y.exe" /arg`). Use this for fields that may
// include arguments (e.g. a registry Run key's value data); use
// ProcessName directly for fields that are known to be a bare path.
func ExecutableFromCommandLine(cmd string) string {
	return ProcessName(firstToken(cmd))
}

// firstToken extracts the executable token from a command line, honoring
// a leading quoted path (e.g. `"C:\Program Files\x\y.exe" /arg`).
func firstToken(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if strings.HasPrefix(cmd, `"`) {
		if end := strings.Index(cmd[1:], `"`); end >= 0 {
			return cmd[1 : end+1]
		}
	}
	if idx := strings.IndexAny(cmd, " \t"); idx >= 0 {
		return cmd[:idx]
	}
	return cmd
}

// Int64 parses s as a base-10 integer, returning 0 if it isn't one. Used
// for PID/PPID columns that are sometimes blank or "-" in EZ Tools CSV.
func Int64(s string) int64 {
	s = strings.TrimSpace(s)
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// Int parses s as a base-10 integer, returning 0 if it isn't one.
func Int(s string) int {
	return int(Int64(s))
}
