// Package amcache decodes Windows Amcache entries out of an Amcache.hve
// registry hive.
//
// # What this artifact is
//
// Amcache.hve is written by the Application Experience / compatibility
// machinery. It catalogues binaries the system has encountered, and it
// is unusually rich for a registry artifact: a full path, a SHA-1 of the
// file, a size, a publisher and a version, all in one place, and all
// surviving the deletion of the binary itself.
//
// # What it proves, and what it does not
//
// It records that Windows CATALOGUED a binary. That happens on
// installation, during inventory scans, and on execution alike -- so an
// entry is APPLICATION-PRESENCE evidence with strong identifying
// metadata, not a process-creation record.
//
// This distinction is the single most misread thing about Amcache.
// Older write-ups treated the "last modified" time on a File key as an
// execution time; it is not, and Tracefall does not present it as one.
// Security 4688 records process creation. Prefetch records that Windows
// prefetched a binary. Amcache records that Windows knew about it.
//
// The value for an investigator is the OPPOSITE of a timeline entry: a
// SHA-1 and a full path for a binary that may no longer exist on disk.
//
// # Formats
//
// Two generations, both read here and distinguished in the output:
//
//	Windows 8 / 8.1     Root\File\{VolumeGUID}\{FileID}  and Root\Programs
//	Windows 10 / 11     Root\InventoryApplicationFile    and
//	                    Root\InventoryApplication
//
// The Windows 10 layout uses named values ("LowerCaseLongPath",
// "FileId", "Publisher"); the Windows 8 layout uses NUMBERED value names
// whose meanings are a documented but undocumented-by-Microsoft mapping.
// Only the numbered fields with a settled meaning are decoded; the rest
// are preserved raw rather than guessed at.
package amcache

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// ErrNotAmcache means the hive carries no Amcache tree at all.
var ErrNotAmcache = errors.New("amcache: no Amcache structure found in this hive")

// Generation names which Amcache layout an entry came from. It is
// reported on every entry, because the two generations record different
// fields and an analyst comparing entries needs to know which they are
// looking at.
type Generation string

const (
	// GenInventory is the Windows 10/11 layout (InventoryApplicationFile).
	GenInventory Generation = "windows10_inventory"
	// GenFile is the Windows 8/8.1 layout (Root\File).
	GenFile Generation = "windows8_file"
	// GenApplication is the Windows 10/11 installed-application layout
	// (InventoryApplication), which describes a PROGRAM rather than a
	// single binary.
	GenApplication Generation = "windows10_application"
)

// Key paths, relative to the hive root.
const (
	PathInventoryFile        = `Root\InventoryApplicationFile`
	PathInventoryApplication = `Root\InventoryApplication`
	PathFile                 = `Root\File`
	PathPrograms             = `Root\Programs`
)

// Limits bound decoding against a hostile or merely enormous hive.
type Limits struct {
	// MaxEntries caps how many entries a caller collects.
	MaxEntries int
	// MaxStringBytes caps any single recovered string.
	MaxStringBytes int
}

// DefaultLimits are sized for real evidence: a populated Amcache holds
// thousands of entries, not millions, and no legitimate field is
// megabytes long.
func DefaultLimits() Limits {
	return Limits{MaxEntries: 100000, MaxStringBytes: 8192}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxEntries <= 0 {
		l.MaxEntries = d.MaxEntries
	}
	if l.MaxStringBytes <= 0 {
		l.MaxStringBytes = d.MaxStringBytes
	}
	return l
}

// Entry is one decoded Amcache record.
//
// Every field is optional. An Amcache entry legitimately carries only
// some of them, and an absent field is left EMPTY rather than filled
// with a placeholder -- "" means the artifact did not record it.
type Entry struct {
	Generation Generation
	// KeyName is the subkey this entry came from, and KeyPath is its
	// full path. Both are retained for provenance.
	KeyName string
	KeyPath string
	// KeyLastWrite is when the registry key was last written. This is a
	// real FILETIME and the only defensible timestamp on most entries --
	// see the package comment for what it does NOT mean.
	KeyLastWrite time.Time

	// Name is the binary's filename; Path its full path.
	Name string
	Path string
	// SHA1 is the file hash Amcache stores, normalized to lowercase hex
	// with the leading "0000" padding Windows writes stripped. Empty
	// when not recorded.
	SHA1 string
	// SizeBytes is the file size; -1 when not recorded, so "zero bytes"
	// and "not recorded" stay distinguishable.
	SizeBytes int64

	Publisher   string
	ProductName string
	Version     string
	// ProgramID links a file entry to an installed-program entry.
	ProgramID string

	// LinkDate is the PE header's compilation timestamp, when recorded.
	// It describes the BINARY, not any activity on this machine, and is
	// labelled as such wherever it is shown.
	LinkDate time.Time
	// InstallDate is when an application was installed, for
	// InventoryApplication entries.
	InstallDate time.Time

	// Source records where Amcache says it learned about the binary
	// (e.g. an inventory source name). Preserved verbatim.
	Source string

	// Extra holds recovered values whose meaning Tracefall does not
	// assert -- particularly the numbered fields of the Windows 8
	// layout. Preserved so nothing is silently discarded.
	Extra map[string]string

	// Warnings describe anything recovered but questionable.
	Warnings []string
}

// win8FieldNames maps the Windows 8 numbered value names whose meaning
// is settled.
//
// The Windows 8 Root\File layout names its values "0", "1", "2"... and
// Microsoft never documented them. The mapping below is the subset that
// independent research agrees on; every other number is preserved under
// its own name in Extra rather than being given a label Tracefall cannot
// stand behind.
var win8FieldNames = map[string]string{
	"0":   "product_name",
	"1":   "company_name",
	"6":   "file_size",
	"c":   "file_description",
	"15":  "full_path",
	"100": "program_id",
	"101": "sha1",
}

// KnownWin8Field reports the settled meaning of a numbered value.
func KnownWin8Field(name string) (string, bool) {
	f, ok := win8FieldNames[strings.ToLower(strings.TrimSpace(name))]
	return f, ok
}

// NormalizeSHA1 turns the hash Amcache stores into plain lowercase hex.
//
// Windows writes it as a 4-zero prefix followed by the 40-character
// digest ("0000" + 40 hex). The prefix is stripped only when the result
// is exactly a 40-character hex string; anything else is returned
// unchanged with ok=false, because a half-recognized hash presented as a
// hash is worse than a raw value an examiner can inspect.
func NormalizeSHA1(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if len(s) == 44 && strings.HasPrefix(s, "0000") {
		s = s[4:]
	}
	if len(s) != 40 || !isHex(s) {
		return raw, false
	}
	return s, true
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// ValueSource supplies one registry key's values to the decoder, so this
// package stays independent of the hive reader.
type ValueSource struct {
	// KeyName and KeyPath identify the key.
	KeyName string
	KeyPath string
	// LastWrite is the key's last-write time.
	LastWrite time.Time
	// Values maps value name to its string form. The caller is
	// responsible for rendering registry types to strings.
	Values map[string]string
	// Numbers maps value name to its integer form, for values stored as
	// DWORD/QWORD. Absent when the value is not numeric.
	Numbers map[string]uint64
}

// DecodeInventoryFile decodes a Windows 10 InventoryApplicationFile key.
func DecodeInventoryFile(src ValueSource, lim Limits) Entry {
	lim = lim.withDefaults()
	e := newEntry(GenInventory, src, lim)

	e.Path = get(src, lim, "LowerCaseLongPath", "LongPathHash", "Path")
	e.Name = get(src, lim, "Name", "FileName")
	if e.Name == "" && e.Path != "" {
		e.Name = baseName(e.Path)
	}
	e.Publisher = get(src, lim, "Publisher", "PublisherName", "CompanyName")
	e.ProductName = get(src, lim, "ProductName", "Product")
	e.Version = get(src, lim, "Version", "ProductVersion", "FileVersion")
	e.ProgramID = get(src, lim, "ProgramId", "ProgramID")
	e.Source = get(src, lim, "Source")

	if raw := get(src, lim, "FileId", "FileID"); raw != "" {
		if h, ok := NormalizeSHA1(raw); ok {
			e.SHA1 = h
		} else {
			e.Extra["file_id_raw"] = truncate(raw, lim.MaxStringBytes)
			e.Warnings = append(e.Warnings,
				"FileId is not a recognizable SHA-1; preserved raw rather than reported as a hash")
		}
	}
	e.SizeBytes = number(src, "Size", "FileSize")
	e.LinkDate = parseAmcacheTime(get(src, lim, "LinkDate"))
	return e
}

// DecodeInventoryApplication decodes a Windows 10 InventoryApplication
// key, which describes an installed PROGRAM rather than one binary.
func DecodeInventoryApplication(src ValueSource, lim Limits) Entry {
	lim = lim.withDefaults()
	e := newEntry(GenApplication, src, lim)

	e.Name = get(src, lim, "Name")
	e.Publisher = get(src, lim, "Publisher")
	e.Version = get(src, lim, "Version")
	e.ProgramID = get(src, lim, "ProgramId", "ProgramID")
	e.Source = get(src, lim, "Source", "InstallDateSource")
	e.Path = get(src, lim, "RootDirPath", "InstallLocation")
	e.InstallDate = parseAmcacheTime(get(src, lim, "InstallDate"))
	e.SizeBytes = -1
	return e
}

// DecodeFileEntry decodes a Windows 8 Root\File key, whose values are
// numbered.
func DecodeFileEntry(src ValueSource, lim Limits) Entry {
	lim = lim.withDefaults()
	e := newEntry(GenFile, src, lim)

	for name, raw := range src.Values {
		field, known := KnownWin8Field(name)
		if !known {
			// Preserved under its own numeric name. Not discarded, and
			// not labelled with a meaning Tracefall cannot justify.
			e.Extra["value_"+strings.ToLower(name)] = truncate(raw, lim.MaxStringBytes)
			continue
		}
		v := truncate(raw, lim.MaxStringBytes)
		switch field {
		case "full_path":
			e.Path = v
			if e.Name == "" {
				e.Name = baseName(v)
			}
		case "product_name":
			e.ProductName = v
		case "company_name":
			e.Publisher = v
		case "sha1":
			if h, ok := NormalizeSHA1(v); ok {
				e.SHA1 = h
			} else {
				e.Extra["sha1_raw"] = v
				e.Warnings = append(e.Warnings,
					"the SHA-1 value is not a recognizable digest; preserved raw")
			}
		case "file_description":
			e.Extra["file_description"] = v
		case "file_size":
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 0, 64); err == nil {
				e.SizeBytes = n
			}
		case "program_id":
			e.ProgramID = v
		}
	}
	if e.SizeBytes == 0 {
		if n := number(src, "6"); n >= 0 {
			e.SizeBytes = n
		}
	}
	return e
}

func newEntry(gen Generation, src ValueSource, lim Limits) Entry {
	return Entry{
		Generation:   gen,
		KeyName:      truncate(src.KeyName, lim.MaxStringBytes),
		KeyPath:      truncate(src.KeyPath, lim.MaxStringBytes),
		KeyLastWrite: src.LastWrite,
		SizeBytes:    -1,
		Extra:        map[string]string{},
	}
}

// get returns the first non-empty value among names, bounded.
func get(src ValueSource, lim Limits, names ...string) string {
	for _, n := range names {
		for have, v := range src.Values {
			if strings.EqualFold(have, n) && strings.TrimSpace(v) != "" {
				return truncate(strings.TrimSpace(v), lim.MaxStringBytes)
			}
		}
	}
	return ""
}

// number returns the first numeric value among names, or -1.
func number(src ValueSource, names ...string) int64 {
	for _, n := range names {
		for have, v := range src.Numbers {
			if strings.EqualFold(have, n) {
				if v > 1<<62 {
					return -1
				}
				return int64(v)
			}
		}
		// Some builds store the size as a string.
		for have, v := range src.Values {
			if strings.EqualFold(have, n) {
				if parsed, err := strconv.ParseInt(strings.TrimSpace(v), 0, 64); err == nil && parsed >= 0 {
					return parsed
				}
			}
		}
	}
	return -1
}

// parseAmcacheTime reads the date forms Amcache writes for LinkDate and
// InstallDate.
//
// These are TEXT values in a locale-ish format, not FILETIMEs. Only
// unambiguous forms are accepted; anything else yields the zero time,
// which the caller reports as "not recorded" rather than guessing at a
// date. A wrong compile date on a binary is a fact an examiner might
// build an argument on.
func parseAmcacheTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	layouts := []string{
		"01/02/2006 15:04:05",
		"1/2/2006 15:04:05",
		"01/02/2006 3:04:05 PM",
		"2006-01-02 15:04:05",
		time.RFC3339,
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			if t.Year() < 1990 || t.Year() > 2200 {
				return time.Time{}
			}
			return t.UTC()
		}
	}
	return time.Time{}
}

func baseName(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	if i := strings.LastIndex(p, `\`); i >= 0 && i+1 < len(p) {
		return p[i+1:]
	}
	return p
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Describe renders a one-line summary of what an entry names, for a
// timeline detail cell.
func (e Entry) Describe() string {
	switch {
	case e.Path != "":
		return e.Path
	case e.Name != "":
		return e.Name
	default:
		return e.KeyName
	}
}

// EvidenceMeaning is the sentence every Amcache event carries. It is a
// function rather than a constant so the wording stays attached to the
// generation it describes.
func (e Entry) EvidenceMeaning() string {
	base := "Amcache recorded this binary: Windows' application-compatibility inventory catalogued it. " +
		"That happens on installation, during inventory scans and on execution alike, so this is " +
		"application-presence evidence, not a process-creation record."
	if e.Generation == GenApplication {
		return "Amcache recorded this installed application. It describes a program that was present on the " +
			"system, not an execution."
	}
	if e.SHA1 != "" {
		return base + " Its value here is the recorded path and SHA-1, which survive deletion of the binary."
	}
	return base
}

// TimestampMeaning describes what an event's timestamp is.
func TimestampMeaning() string {
	return "Amcache key last-write time: when Windows last updated this entry. It is NOT an execution time, " +
		"and older guidance that treated it as one was mistaken."
}
