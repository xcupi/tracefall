// Package userassist decodes Windows UserAssist entries out of an
// NTUSER.DAT registry hive.
//
// # What this artifact is
//
// Explorer maintains a per-user tally under
//
//	HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
//
// recording programs and shortcuts the user launched THROUGH THE SHELL --
// from the Start menu, the desktop, Explorer, the taskbar. Each value's
// NAME is the item, obfuscated with ROT13; each value's DATA is a small
// fixed-size record holding a run count and, on most Windows versions, a
// last-execution FILETIME.
//
// # What it proves, and what it does not
//
// It is USER-ATTRIBUTED activity evidence, which is its real value: the
// hive belongs to one account, so an entry says this user's shell
// launched this item. It is NOT process-execution evidence in the sense
// a Security 4688 record is:
//
//   - Only shell-initiated launches are counted. A program started by a
//     script, a service, another process, or from a command prompt
//     leaves no UserAssist entry at all. Absence proves nothing.
//   - The counter is a tally maintained by Explorer, not a log. It can
//     be reset, and the entry survives deletion of the program.
//   - The recorded time is when Explorer last updated the entry.
//
// So events built from this carry an event type and a timestamp meaning
// that say "UserAssist recorded activity", never "process executed".
// See internal/parsers/registry, which is where those events are made.
//
// # Versions
//
// Two record layouts exist in the wild and both are read here:
//
//	16 bytes  Windows 2000/XP/2003 era ("version 3")
//	72 bytes  Windows 7 and later ("version 5"), also seen on Vista
//
// A value whose data is neither length is reported as an unsupported
// structure rather than being decoded on a guess -- see ErrUnknownLayout.
// That distinction matters: "Tracefall does not read this layout" and
// "this entry is corrupt" are different answers for an investigator.
package userassist

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Errors returned by Decode. They are distinguished so a caller can tell
// an unreadable entry from an entry in a layout Tracefall does not know
// -- see the package comment.
var (
	// ErrUnknownLayout means the data length matches no known UserAssist
	// record layout.
	ErrUnknownLayout = errors.New("userassist: unrecognized record layout")
	// ErrEmptyValue means the value carries no data at all.
	ErrEmptyValue = errors.New("userassist: value has no data")
)

// Record layout sizes. Named rather than inlined because the length IS
// the version discriminator -- there is no version field in the record.
const (
	sizeV3 = 16 // Windows 2000 / XP / 2003
	sizeV5 = 72 // Windows Vista / 7 / 8 / 10 / 11
)

// Field offsets within the version 5 (72-byte) record. Only the fields
// with a settled, documented meaning are read; the ten single-precision
// floats between the focus fields and the timestamp are session
// telemetry whose interpretation is not agreed on, and are deliberately
// left alone rather than exposed under an invented name.
const (
	v5OffSessionID  = 0
	v5OffRunCount   = 4
	v5OffFocusCount = 8
	v5OffFocusTime  = 12
	v5OffLastRun    = 60
)

// Field offsets within the version 3 (16-byte) record.
const (
	v3OffSessionID = 0
	v3OffRunCount  = 4
	v3OffLastRun   = 8
)

// v3CounterBase is where the version 3 run counter starts.
//
// On Windows 2000/XP the counter is initialized to 5 rather than 0, so
// the raw value overstates the number of launches by five. Decode
// reports BOTH numbers -- RunCountRaw exactly as stored, and RunCount
// adjusted -- because the adjustment is a documented convention rather
// than something the record states, and an examiner asked to justify a
// figure needs the stored one.
const v3CounterBase = 5

// Limits bound what Decode will accept, so a hostile hive cannot turn a
// value name into an unbounded allocation.
type Limits struct {
	// MaxNameBytes caps the decoded value name.
	MaxNameBytes int
	// MaxEntries caps how many entries a caller should collect. Decode
	// handles one entry and does not enforce it; it lives here so the
	// bound is stated in one place with the others.
	MaxEntries int
}

// DefaultLimits are sized for real evidence, not for a synthetic worst
// case. A UserAssist path is a filesystem path and a known-folder GUID;
// 4 KiB is far beyond any legitimate one, and a populated Count key
// holds hundreds of entries, not tens of thousands.
func DefaultLimits() Limits {
	return Limits{MaxNameBytes: 4096, MaxEntries: 20000}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxNameBytes <= 0 {
		l.MaxNameBytes = d.MaxNameBytes
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = d.MaxEntries
	}
	return l
}

// Entry is one decoded UserAssist value.
type Entry struct {
	// GUID is the Count key's parent GUID, and GUIDMeaning is what that
	// GUID is known to signify. GUIDMeaning is EMPTY for a GUID not in
	// the documented table -- never a guess. See KnownGUID.
	GUID        string
	GUIDMeaning string

	// EncodedName is the value name exactly as stored (ROT13), and
	// DecodedName is it after decoding. Both are kept: the stored form is
	// what an examiner would see in any other tool, and showing only the
	// decoded form would hide a transformation Tracefall performed.
	EncodedName string
	DecodedName string

	// ResolvedPath is DecodedName with a leading known-folder GUID
	// replaced by its documented name. Empty when the name carries no
	// recognized folder GUID, in which case DecodedName is already the
	// most resolved form available.
	ResolvedPath string

	// Version is 3 or 5 -- the record layout, inferred from its length.
	Version int

	SessionID uint32

	// RunCountRaw is the counter exactly as stored. RunCount is the
	// interpreted number of launches, which differs from RunCountRaw
	// only for version 3 -- see v3CounterBase.
	RunCountRaw uint32
	RunCount    uint32

	// FocusCount and FocusTime are version 5 only: how many times the
	// item's window was focused, and for how long in total. Zero and
	// absent are indistinguishable in the record, so a zero here means
	// "recorded as zero", not "not recorded" -- HasFocusData says which
	// applies.
	FocusCount   uint32
	FocusTime    time.Duration
	HasFocusData bool

	// LastExecuted is when Explorer last updated this entry, in UTC.
	// Zero when the record stores no time or stores an implausible one;
	// callers must treat a zero here as "not recorded" and must not
	// substitute another time. See the package comment on what this
	// timestamp does and does not establish.
	LastExecuted time.Time

	// RawSize is the stored data length, retained so an unusual record
	// can be described precisely.
	RawSize int

	// Warnings describe anything recovered but questionable. An entry
	// with warnings is still returned: partial evidence, clearly
	// labelled, beats discarding a record because one field is odd.
	Warnings []string
}

// knownGUIDs maps the UserAssist subkey GUIDs whose meaning is
// documented.
//
// A GUID that is not in this table yields an EMPTY GUIDMeaning. That is
// deliberate and matches how Tracefall handles Jump List AppIDs: naming
// an unknown identifier from a guess would put an invented fact in front
// of an investigator, and "unknown" is a true and useful answer.
var knownGUIDs = map[string]string{
	"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "executables launched through the shell (Windows 7+)",
	"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "shortcut (.lnk) files launched through the shell (Windows 7+)",
	"{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}": "Windows 7 taskbar/Start menu items",
	"{B267E3AD-A825-4A09-82B9-EEC22AA3B847}": "Windows 7 taskbar/Start menu items",
	"{5E6AB780-7743-11CF-A12B-00AA004AE837}": "Internet Explorer toolbar items (Windows XP era)",
	"{75048700-EF1F-11D0-9888-006097DEACF9}": "applications launched through the shell (Windows XP era)",
	"{0D6D4F41-2994-4BA0-8FEF-620E43CD2812}": "Windows 8 shell items",
	"{A3D53349-6E61-4557-8FC7-0028EDCEEBF6}": "Windows 8 shell items",
	"{BCB48336-4DDD-48FF-BB0B-D3190DACB3E2}": "Windows 8 shell items",
}

// KnownGUID returns the documented meaning of a UserAssist subkey GUID,
// and whether it is known at all.
func KnownGUID(guid string) (string, bool) {
	m, ok := knownGUIDs[strings.ToUpper(strings.TrimSpace(guid))]
	return m, ok
}

// knownFolders maps the KNOWNFOLDERID GUIDs that appear as a prefix on
// UserAssist value names to their documented folder.
//
// Only folders that actually turn up in UserAssist names are listed. As
// with knownGUIDs, an unrecognized GUID is left exactly as decoded
// rather than being expanded on a guess.
var knownFolders = map[string]string{
	"{6D809377-6AF0-444B-8957-A3773F02200E}": `C:\Program Files (x86)`,
	"{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": `C:\Program Files (x86)`,
	"{905E63B6-C1BF-494E-B29C-65B732D3D21A}": `C:\Program Files`,
	"{F38BF404-1D43-42F2-9305-67DE0B28FC23}": `C:\Windows`,
	"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": `C:\Windows\System32`,
	"{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": `C:\Windows\System32`,
	"{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "Desktop",
	"{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": "Documents",
	"{374DE290-123F-4565-9164-39C4925E467B}": "Downloads",
	"{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": "Start Menu Programs",
	"{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": "Common Start Menu Programs",
	"{9E3995AB-1F9C-4F13-B827-48B24B6C7174}": "Taskbar pinned items",
	"{DE61D971-5EBC-4F02-A3A9-6C82895E5C04}": "Add or Remove Programs (Get Programs)",
	"{D0384E7D-BAC3-4797-8F14-CBA229B392B5}": "Common Administrative Tools",
	"{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}": "Public Desktop",
	"{F3CE0F7C-4901-4ACC-8648-D5D44B04EF8F}": "User Profile",
}

// KnownFolder returns the documented folder for a KNOWNFOLDERID.
func KnownFolder(guid string) (string, bool) {
	f, ok := knownFolders[strings.ToUpper(strings.TrimSpace(guid))]
	return f, ok
}

// ROT13 decodes (and, being its own inverse, encodes) a UserAssist value
// name.
//
// Only ASCII letters are transformed. Digits, punctuation, path
// separators, braces and every non-ASCII rune pass through untouched,
// which is what keeps a GUID prefix and a Unicode filename intact.
func ROT13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		default:
			return r
		}
	}, s)
}

// resolveFolder expands a leading "{GUID}\..." known-folder prefix.
//
// Returns "" when the name has no recognized prefix, so the caller can
// tell "resolved to this" from "nothing to resolve" instead of comparing
// strings.
func resolveFolder(decoded string) string {
	if !strings.HasPrefix(decoded, "{") {
		return ""
	}
	end := strings.Index(decoded, "}")
	if end < 0 {
		return ""
	}
	guid := decoded[:end+1]
	folder, ok := KnownFolder(guid)
	if !ok {
		return ""
	}
	rest := decoded[end+1:]
	rest = strings.TrimPrefix(rest, `\`)
	if rest == "" {
		return folder
	}
	return folder + `\` + rest
}

// Decode reads one UserAssist Count value.
//
// name is the value name as stored (still ROT13); data is the value's
// raw bytes; guid is the Count key's parent GUID, used only to describe
// the entry.
func Decode(guid, name string, data []byte, lim Limits) (Entry, error) {
	lim = lim.withDefaults()

	if len(data) == 0 {
		return Entry{}, ErrEmptyValue
	}

	decoded := ROT13(name)
	if len(decoded) > lim.MaxNameBytes {
		decoded = decoded[:lim.MaxNameBytes]
	}
	if len(name) > lim.MaxNameBytes {
		name = name[:lim.MaxNameBytes]
	}

	e := Entry{
		GUID:         strings.ToUpper(strings.TrimSpace(guid)),
		EncodedName:  name,
		DecodedName:  decoded,
		ResolvedPath: resolveFolder(decoded),
		RawSize:      len(data),
	}
	if m, ok := KnownGUID(e.GUID); ok {
		e.GUIDMeaning = m
	}

	switch len(data) {
	case sizeV5:
		e.Version = 5
		e.SessionID = binary.LittleEndian.Uint32(data[v5OffSessionID:])
		e.RunCountRaw = binary.LittleEndian.Uint32(data[v5OffRunCount:])
		e.RunCount = e.RunCountRaw
		e.FocusCount = binary.LittleEndian.Uint32(data[v5OffFocusCount:])
		focusMS := binary.LittleEndian.Uint32(data[v5OffFocusTime:])
		e.FocusTime = time.Duration(focusMS) * time.Millisecond
		e.HasFocusData = true
		e.LastExecuted = fileTime(binary.LittleEndian.Uint64(data[v5OffLastRun:]))

	case sizeV3:
		e.Version = 3
		e.SessionID = binary.LittleEndian.Uint32(data[v3OffSessionID:])
		e.RunCountRaw = binary.LittleEndian.Uint32(data[v3OffRunCount:])
		// The version 3 counter starts at 5. Below that the stored value
		// cannot be a launch tally at all, so it is reported raw with a
		// warning instead of being turned into a negative number by
		// subtraction.
		if e.RunCountRaw >= v3CounterBase {
			e.RunCount = e.RunCountRaw - v3CounterBase
		} else {
			e.RunCount = e.RunCountRaw
			e.Warnings = append(e.Warnings, fmt.Sprintf(
				"run counter is %d, below the version 3 base of %d; reported as stored without adjustment",
				e.RunCountRaw, v3CounterBase))
		}
		e.LastExecuted = fileTime(binary.LittleEndian.Uint64(data[v3OffLastRun:]))

	default:
		return Entry{}, fmt.Errorf("%w: %d bytes (known layouts are %d and %d)",
			ErrUnknownLayout, len(data), sizeV3, sizeV5)
	}

	if e.LastExecuted.IsZero() {
		e.Warnings = append(e.Warnings,
			"no usable last-execution timestamp is recorded in this entry")
	}
	if e.DecodedName == "" {
		e.Warnings = append(e.Warnings, "value name is empty")
	}
	return e, nil
}

// CountKeyGUID extracts the "{GUID}" component from a UserAssist Count
// key path, and reports whether the path is shaped like one at all.
//
// The path is expected to end "...\UserAssist\{GUID}\Count", which is
// the only place these values live. Matching the SHAPE rather than
// merely looking for the word "UserAssist" is what stops an unrelated
// key that happens to contain the string from being decoded as one.
func CountKeyGUID(keyPath string) (string, bool) {
	parts := strings.Split(strings.ReplaceAll(keyPath, "/", `\`), `\`)
	if len(parts) < 3 {
		return "", false
	}
	if !strings.EqualFold(parts[len(parts)-1], "Count") {
		return "", false
	}
	guid := parts[len(parts)-2]
	if !strings.EqualFold(parts[len(parts)-3], "UserAssist") {
		return "", false
	}
	if !looksLikeGUID(guid) {
		return "", false
	}
	return strings.ToUpper(guid), true
}

// looksLikeGUID checks the braced 8-4-4-4-12 shape.
func looksLikeGUID(s string) bool {
	if len(s) != 38 || s[0] != '{' || s[37] != '}' {
		return false
	}
	for i, r := range s[1:37] {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}

// fileTime converts a Windows FILETIME to UTC.
//
// Zero means "not recorded", and a value outside a plausible window is
// treated the same way rather than being surfaced as a date in year 1601
// or 30828 -- the same rule every other Tracefall parser applies.
func fileTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ticksPerSecond = 10_000_000
	const epochDelta = 11644473600 // seconds between 1601-01-01 and 1970-01-01
	secs := int64(ft/ticksPerSecond) - epochDelta
	nsec := int64(ft%ticksPerSecond) * 100
	t := time.Unix(secs, nsec).UTC()
	if t.Year() < 1990 || t.Year() > 2200 {
		return time.Time{}
	}
	return t
}
