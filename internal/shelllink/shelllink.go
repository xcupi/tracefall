// Package shelllink reads the Windows Shell Link Binary File Format
// (.LNK) for forensic triage.
//
// # What a shortcut proves, and what it does not
//
// A .LNK records a REFERENCE to a target: where it was, how big it was,
// and the target's own MACE timestamps as they stood when the shortcut
// was last written. That is often the only surviving description of a
// file that has since been deleted, and it is why shortcuts matter.
//
// It is not execution evidence. Windows creates shortcuts for files that
// were merely opened, saved, or listed in a dialog, and an application
// may write one for a target the user never touched. The three
// timestamps in the header belong to the TARGET FILE, not to any launch
// of it. This package therefore never names a field "execution", and the
// parser above it emits target-metadata events, not run events.
//
// # Structure
//
// A shortcut is a fixed 76-byte header followed by optional structures,
// each present only if its LinkFlags bit is set, in this order:
//
//	ShellLinkHeader        always, 0x4C bytes, fixed CLSID
//	LinkTargetIDList       if HasLinkTargetIDList
//	LinkInfo               if HasLinkInfo
//	StringData             Name, RelativePath, WorkingDir, Arguments,
//	                       IconLocation -- each if its flag is set
//	ExtraData              a chain of typed blocks, terminated by 0
//
// Nothing here assumes a structure is present. Every offset is read from
// the file, bounds-checked against it, and a structure that does not fit
// is reported as a warning rather than being decoded out of adjacent
// bytes.
//
// # Hostile input
//
// Sizes and counts come from the file. All are capped, every read is
// bounds-checked, and a malformed shortcut returns an error or a partial
// result with warnings -- never a panic, and never a field invented to
// fill a gap.
package shelllink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	// ErrNotShellLink means the file is not a shortcut: the header size
	// or the class identifier did not match.
	ErrNotShellLink = errors.New("shelllink: not a Windows shortcut (.lnk)")
	// ErrCorrupt means the shortcut is structurally invalid or truncated
	// beyond what can be read.
	ErrCorrupt = errors.New("shelllink: shortcut is corrupt or truncated")
	// ErrLimitExceeded means a declared size exceeded a safety ceiling.
	ErrLimitExceeded = errors.New("shelllink: shortcut exceeds a safety limit")
)

const (
	// headerSize is the only valid ShellLinkHeader size, per the format.
	headerSize = 0x4C
)

// linkCLSID is the shell link class identifier,
// 00021401-0000-0000-C000-000000000046, in its on-disk byte order:
// the first three fields are little-endian, the last eight are bytes.
var linkCLSID = [16]byte{
	0x01, 0x14, 0x02, 0x00,
	0x00, 0x00,
	0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

// LinkFlags bits. Only the ones this reader acts on are named; the raw
// value is preserved in full on the parsed result.
const (
	FlagHasLinkTargetIDList = 1 << 0
	FlagHasLinkInfo         = 1 << 1
	FlagHasName             = 1 << 2
	FlagHasRelativePath     = 1 << 3
	FlagHasWorkingDir       = 1 << 4
	FlagHasArguments        = 1 << 5
	FlagHasIconLocation     = 1 << 6
	FlagIsUnicode           = 1 << 7
	FlagForceNoLinkInfo     = 1 << 8
	FlagHasExpString        = 1 << 9
	FlagRunInSeparateProc   = 1 << 10
	FlagHasDarwinID         = 1 << 12
	FlagRunAsUser           = 1 << 13
	FlagHasExpIcon          = 1 << 14
	FlagNoPidlAlias         = 1 << 15
	FlagRunWithShimLayer    = 1 << 17
	FlagForceNoLinkTrack    = 1 << 18
	FlagEnableTargetMeta    = 1 << 19
	FlagDisableLinkPathTrk  = 1 << 20
)

// flagNames maps the documented LinkFlags bits to their spec names, so
// an analyst reads what the file declared rather than a hex value.
var flagNames = []struct {
	bit  uint32
	name string
}{
	{FlagHasLinkTargetIDList, "HasLinkTargetIDList"},
	{FlagHasLinkInfo, "HasLinkInfo"},
	{FlagHasName, "HasName"},
	{FlagHasRelativePath, "HasRelativePath"},
	{FlagHasWorkingDir, "HasWorkingDir"},
	{FlagHasArguments, "HasArguments"},
	{FlagHasIconLocation, "HasIconLocation"},
	{FlagIsUnicode, "IsUnicode"},
	{FlagForceNoLinkInfo, "ForceNoLinkInfo"},
	{FlagHasExpString, "HasExpString"},
	{FlagRunInSeparateProc, "RunInSeparateProcess"},
	{FlagHasDarwinID, "HasDarwinID"},
	{FlagRunAsUser, "RunAsUser"},
	{FlagHasExpIcon, "HasExpIcon"},
	{FlagNoPidlAlias, "NoPidlAlias"},
	{FlagRunWithShimLayer, "RunWithShimLayer"},
	{FlagForceNoLinkTrack, "ForceNoLinkTrack"},
	{FlagEnableTargetMeta, "EnableTargetMetadata"},
	{FlagDisableLinkPathTrk, "DisableLinkPathTracking"},
}

// FlagNames returns the set LinkFlags by name, in bit order.
func FlagNames(flags uint32) []string {
	var out []string
	for _, f := range flagNames {
		if flags&f.bit != 0 {
			out = append(out, f.name)
		}
	}
	return out
}

// ShowCommandName renders the window state the shortcut requests.
// Anything outside the three documented values is reported as its raw
// number rather than mapped to a guess.
func ShowCommandName(v uint32) string {
	switch v {
	case 1:
		return "SW_SHOWNORMAL"
	case 3:
		return "SW_SHOWMAXIMIZED"
	case 7:
		return "SW_SHOWMINNOACTIVE"
	default:
		return fmt.Sprintf("unrecognized(0x%X)", v)
	}
}

// DriveTypeName renders a LinkInfo VolumeID drive type.
func DriveTypeName(v uint32) string {
	switch v {
	case 0:
		return "DRIVE_UNKNOWN"
	case 1:
		return "DRIVE_NO_ROOT_DIR"
	case 2:
		return "DRIVE_REMOVABLE"
	case 3:
		return "DRIVE_FIXED"
	case 4:
		return "DRIVE_REMOTE"
	case 5:
		return "DRIVE_CDROM"
	case 6:
		return "DRIVE_RAMDISK"
	default:
		return fmt.Sprintf("unrecognized(%d)", v)
	}
}

// Limits bounds what one shortcut may consume.
type Limits struct {
	MaxFileBytes   int64
	MaxStringChars int
	MaxIDListItems int
}

// DefaultLimits comfortably fit any real shortcut: they are a few
// kilobytes and reference a path, not a payload.
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:   16 << 20, // 16 MiB
		MaxStringChars: 32 << 10,
		MaxIDListItems: 512,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxStringChars <= 0 {
		l.MaxStringChars = d.MaxStringChars
	}
	if l.MaxIDListItems <= 0 {
		l.MaxIDListItems = d.MaxIDListItems
	}
	return l
}

// VolumeInfo is the LinkInfo VolumeID: which volume the target was on.
type VolumeInfo struct {
	DriveType    uint32
	SerialNumber uint32
	Label        string
	// Present distinguishes "the shortcut recorded no volume" from "the
	// volume it recorded had a zero serial", which are different facts.
	Present bool
}

// NetworkInfo is the LinkInfo CommonNetworkRelativeLink: the share the
// target lived on, when it was a network target.
type NetworkInfo struct {
	NetName     string
	DeviceName  string
	ProviderRaw uint32
	Present     bool
}

// ShellItem is one entry from the LinkTargetIDList.
//
// Only the documented, version-stable subset is decoded. Everything else
// is recorded by its type byte and size and left alone -- see Parse's
// comment on the BEEF extension blocks for why that boundary is where it
// is.
type ShellItem struct {
	// TypeByte is the item's leading classification byte, kept raw
	// because the shell item taxonomy is only partially documented.
	TypeByte byte
	Kind     string
	// Name is the item's primary name where the item type defines one.
	Name string
	// Size and Modified come from file-entry items only.
	Size     uint32
	Modified time.Time
	// Attributes is the DOS/NTFS attribute word from a file-entry item.
	Attributes uint16
	HasAttrs   bool
	// GUID is the class identifier from a root-folder item.
	GUID string
	// RawBytes is the item's declared size, for provenance.
	RawBytes int
	// Offset is where this item began, relative to the start of the file.
	Offset int
}

// Link is one parsed shortcut.
//
// Fields a shortcut does not record are left zero. Nothing is inferred
// from another field, and nothing is filled in from the .lnk file's own
// filesystem metadata -- that would record when the evidence was
// collected, not what the shortcut says.
type Link struct {
	// Header.
	LinkFlags      uint32
	FileAttributes uint32
	CreationTime   time.Time
	AccessTime     time.Time
	WriteTime      time.Time
	FileSize       uint32
	IconIndex      int32
	ShowCommand    uint32
	HotKey         uint16

	// LinkInfo.
	LocalBasePath    string
	CommonPathSuffix string
	// LinkInfoPath is LocalBasePath joined with CommonPathSuffix: the
	// path LinkInfo describes, assembled the way the format defines.
	LinkInfoPath string
	Volume       VolumeInfo
	Network      NetworkInfo
	HasLinkInfo  bool

	// StringData. Each is present only when its flag was set.
	Name         string
	RelativePath string
	WorkingDir   string
	Arguments    string
	IconLocation string

	// LinkTargetIDList.
	IDListItems []ShellItem
	// IDListPath is the path reconstructed from the ID list's named
	// items, which is a SEPARATE representation from LinkInfoPath and is
	// kept even when it agrees with it.
	IDListPath  string
	HasIDList   bool
	IDListBytes int

	// TrackerMachineID is the NetBIOS name of the machine that created
	// the shortcut, from the ExtraData TrackerDataBlock when present.
	TrackerMachineID string
	// ExtraBlocks lists the ExtraData block signatures found, in order.
	ExtraBlocks []string

	// StringEncoding is "unicode" or "ansi", as declared by LinkFlags.
	StringEncoding string
	// Offsets records where each structure began in the file, so a
	// finding can be traced back to a byte range in the evidence.
	Offsets  map[string]int
	Warnings []string
}

// TargetPath returns the single best path representation available,
// preferring the one the format defines most precisely.
//
// LinkInfo's local base path is preferred because it is an explicit,
// fully-qualified path the writer recorded. The ID list path is a
// reconstruction from shell items and is used only when LinkInfo carried
// none. Both are always retained on the Link; this only chooses which to
// show first.
func (l Link) TargetPath() string {
	switch {
	case l.LinkInfoPath != "":
		return l.LinkInfoPath
	case l.Network.Present && l.Network.NetName != "":
		if l.CommonPathSuffix != "" {
			return strings.TrimRight(l.Network.NetName, `\`) + `\` + l.CommonPathSuffix
		}
		return l.Network.NetName
	case l.IDListPath != "":
		return l.IDListPath
	default:
		return ""
	}
}

// HasAnyTimestamp reports whether the shortcut recorded at least one
// target timestamp that can be placed on a timeline.
func (l Link) HasAnyTimestamp() bool {
	return !l.CreationTime.IsZero() || !l.AccessTime.IsZero() || !l.WriteTime.IsZero()
}

// Sniff reports whether header begins a shell link.
//
// Both the declared header size and the class identifier must match.
// Requiring both is what makes content detection safe: the CLSID alone
// is 16 fixed bytes, but checking the size too rejects a file that
// merely embeds the GUID at offset 4.
func Sniff(header []byte) bool {
	if len(header) < headerSize {
		return false
	}
	if binary.LittleEndian.Uint32(header[0:4]) != headerSize {
		return false
	}
	for i := 0; i < 16; i++ {
		if header[4+i] != linkCLSID[i] {
			return false
		}
	}
	return true
}

// ParseFile reads one .lnk file.
func ParseFile(path string, lim Limits) (Link, error) {
	lim = lim.withDefaults()
	info, err := os.Stat(path)
	if err != nil {
		return Link{}, err
	}
	if info.Size() > lim.MaxFileBytes {
		return Link{}, fmt.Errorf("%w: file is %d bytes", ErrLimitExceeded, info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Link{}, err
	}
	return Parse(data, lim)
}

// Parse reads a shortcut from memory.
//
// A structure that does not fit the file is skipped with a warning and
// parsing continues: a truncated shortcut still yields the header, and
// the header is where the target's timestamps live. Returning nothing
// for a file that lost its tail would discard the evidence that
// survived.
func Parse(data []byte, lim Limits) (link Link, err error) {
	lim = lim.withDefaults()
	defer func() {
		if r := recover(); r != nil {
			link, err = Link{}, fmt.Errorf("%w: recovered from %v", ErrCorrupt, r)
		}
	}()

	if !Sniff(data) {
		return Link{}, ErrNotShellLink
	}

	l := Link{Offsets: map[string]int{"header": 0}}
	l.LinkFlags = binary.LittleEndian.Uint32(data[20:24])
	l.FileAttributes = binary.LittleEndian.Uint32(data[24:28])
	l.CreationTime = fileTime(binary.LittleEndian.Uint64(data[28:36]))
	l.AccessTime = fileTime(binary.LittleEndian.Uint64(data[36:44]))
	l.WriteTime = fileTime(binary.LittleEndian.Uint64(data[44:52]))
	l.FileSize = binary.LittleEndian.Uint32(data[52:56])
	l.IconIndex = int32(binary.LittleEndian.Uint32(data[56:60]))
	l.ShowCommand = binary.LittleEndian.Uint32(data[60:64])
	l.HotKey = binary.LittleEndian.Uint16(data[64:66])

	unicode := l.LinkFlags&FlagIsUnicode != 0
	l.StringEncoding = "ansi"
	if unicode {
		l.StringEncoding = "unicode"
	}

	off := headerSize

	// ---- LinkTargetIDList ----
	if l.LinkFlags&FlagHasLinkTargetIDList != 0 {
		l.HasIDList = true
		l.Offsets["link_target_id_list"] = off
		if off+2 > len(data) {
			l.Warnings = append(l.Warnings, "LinkTargetIDList is declared but the file ends before it")
			return l, nil
		}
		size := int(binary.LittleEndian.Uint16(data[off : off+2]))
		l.IDListBytes = size
		end := off + 2 + size
		if end > len(data) {
			l.Warnings = append(l.Warnings, fmt.Sprintf(
				"LinkTargetIDList declares %d bytes but only %d remain; the list was not read", size, len(data)-off-2))
			return l, nil
		}
		l.IDListItems = parseIDList(data[off+2:end], off+2, lim, &l)
		l.IDListPath = idListPath(l.IDListItems)
		off = end
	}

	// ---- LinkInfo ----
	if l.LinkFlags&FlagHasLinkInfo != 0 && l.LinkFlags&FlagForceNoLinkInfo == 0 {
		l.Offsets["link_info"] = off
		if off+4 > len(data) {
			l.Warnings = append(l.Warnings, "LinkInfo is declared but the file ends before it")
			return l, nil
		}
		size := int(binary.LittleEndian.Uint32(data[off : off+4]))
		if size < 4 || off+size > len(data) {
			l.Warnings = append(l.Warnings, fmt.Sprintf(
				"LinkInfo declares %d bytes, which does not fit the file; it was not read", size))
			return l, nil
		}
		parseLinkInfo(data[off:off+size], &l, lim)
		l.HasLinkInfo = true
		off += size
	}

	// ---- StringData ----
	// Ordered, and each present only if its flag is set. A short read
	// stops the chain: continuing would decode the next string out of
	// whatever bytes followed.
	strs := []struct {
		flag uint32
		name string
		dst  *string
	}{
		{FlagHasName, "name_string", &l.Name},
		{FlagHasRelativePath, "relative_path", &l.RelativePath},
		{FlagHasWorkingDir, "working_dir", &l.WorkingDir},
		{FlagHasArguments, "command_line_arguments", &l.Arguments},
		{FlagHasIconLocation, "icon_location", &l.IconLocation},
	}
	for _, s := range strs {
		if l.LinkFlags&s.flag == 0 {
			continue
		}
		l.Offsets[s.name] = off
		v, n, ok := readStringData(data, off, unicode, lim)
		if !ok {
			l.Warnings = append(l.Warnings, fmt.Sprintf(
				"StringData %q is declared but does not fit the file; it and any later strings were not read", s.name))
			return l, nil
		}
		*s.dst = v
		off += n
	}

	// ---- ExtraData ----
	if off < len(data) {
		l.Offsets["extra_data"] = off
		parseExtraData(data[off:], off, &l)
	}
	return l, nil
}

// parseLinkInfo decodes the LinkInfo structure.
//
// Every offset inside it is relative to the START of LinkInfo, which is
// why the caller passes the exact slice: an offset that walks outside it
// is a corrupt file, not a pointer into the rest of the shortcut.
func parseLinkInfo(b []byte, l *Link, lim Limits) {
	if len(b) < 0x1C {
		l.Warnings = append(l.Warnings, "LinkInfo is shorter than its own fixed header")
		return
	}
	hdrSize := int(binary.LittleEndian.Uint32(b[4:8]))
	flags := binary.LittleEndian.Uint32(b[8:12])
	volIDOff := int(binary.LittleEndian.Uint32(b[12:16]))
	localBaseOff := int(binary.LittleEndian.Uint32(b[16:20]))
	netRelOff := int(binary.LittleEndian.Uint32(b[20:24]))
	suffixOff := int(binary.LittleEndian.Uint32(b[24:28]))

	// The optional unicode offsets exist only in the larger header form.
	var localBaseUniOff, suffixUniOff int
	if hdrSize >= 0x24 && len(b) >= 0x24 {
		localBaseUniOff = int(binary.LittleEndian.Uint32(b[28:32]))
		suffixUniOff = int(binary.LittleEndian.Uint32(b[32:36]))
	}

	const (
		volumeIDAndLocalBasePath           = 1 << 0
		commonNetworkRelativeLinkAndSuffix = 1 << 1
	)

	if flags&volumeIDAndLocalBasePath != 0 {
		if v, ok := parseVolumeID(b, volIDOff, lim); ok {
			l.Volume = v
		} else if volIDOff != 0 {
			l.Warnings = append(l.Warnings, "LinkInfo VolumeID does not fit the structure")
		}
		// Unicode form preferred when present: it is the same path
		// without the codepage ambiguity.
		if localBaseUniOff > 0 {
			l.LocalBasePath = readUTF16At(b, localBaseUniOff, lim)
		}
		if l.LocalBasePath == "" && localBaseOff > 0 {
			l.LocalBasePath = readANSIAt(b, localBaseOff, lim)
		}
	}
	if flags&commonNetworkRelativeLinkAndSuffix != 0 {
		if n, ok := parseNetworkLink(b, netRelOff, lim); ok {
			l.Network = n
		} else if netRelOff != 0 {
			l.Warnings = append(l.Warnings, "LinkInfo CommonNetworkRelativeLink does not fit the structure")
		}
	}
	if suffixUniOff > 0 {
		l.CommonPathSuffix = readUTF16At(b, suffixUniOff, lim)
	}
	if l.CommonPathSuffix == "" && suffixOff > 0 {
		l.CommonPathSuffix = readANSIAt(b, suffixOff, lim)
	}

	if l.LocalBasePath != "" {
		l.LinkInfoPath = l.LocalBasePath
		if l.CommonPathSuffix != "" {
			l.LinkInfoPath = strings.TrimRight(l.LocalBasePath, `\`) + `\` + l.CommonPathSuffix
		}
	}
}

func parseVolumeID(b []byte, off int, lim Limits) (VolumeInfo, bool) {
	if off <= 0 || off+16 > len(b) {
		return VolumeInfo{}, false
	}
	size := int(binary.LittleEndian.Uint32(b[off : off+4]))
	if size < 16 || off+size > len(b) {
		return VolumeInfo{}, false
	}
	v := VolumeInfo{
		Present:      true,
		DriveType:    binary.LittleEndian.Uint32(b[off+4 : off+8]),
		SerialNumber: binary.LittleEndian.Uint32(b[off+8 : off+12]),
	}
	labelOff := int(binary.LittleEndian.Uint32(b[off+12 : off+16]))
	// 0x14 is the sentinel meaning "the label is unicode, at the offset
	// in the next field" -- the format's own escape hatch.
	if labelOff == 0x14 && off+20 <= len(b) {
		uniOff := int(binary.LittleEndian.Uint32(b[off+16 : off+20]))
		v.Label = readUTF16At(b, off+uniOff, lim)
	} else if labelOff > 0 {
		v.Label = readANSIAt(b, off+labelOff, lim)
	}
	return v, true
}

func parseNetworkLink(b []byte, off int, lim Limits) (NetworkInfo, bool) {
	if off <= 0 || off+20 > len(b) {
		return NetworkInfo{}, false
	}
	size := int(binary.LittleEndian.Uint32(b[off : off+4]))
	if size < 20 || off+size > len(b) {
		return NetworkInfo{}, false
	}
	flags := binary.LittleEndian.Uint32(b[off+4 : off+8])
	netNameOff := int(binary.LittleEndian.Uint32(b[off+8 : off+12]))
	deviceNameOff := int(binary.LittleEndian.Uint32(b[off+12 : off+16]))
	n := NetworkInfo{Present: true, ProviderRaw: binary.LittleEndian.Uint32(b[off+16 : off+20])}

	// A NetNameOffset above 0x14 signals the extended form, which adds
	// unicode offsets after the fixed fields.
	if netNameOff > 0x14 && off+28 <= len(b) {
		uniNet := int(binary.LittleEndian.Uint32(b[off+20 : off+24]))
		uniDev := int(binary.LittleEndian.Uint32(b[off+24 : off+28]))
		if uniNet > 0 {
			n.NetName = readUTF16At(b, off+uniNet, lim)
		}
		if uniDev > 0 {
			n.DeviceName = readUTF16At(b, off+uniDev, lim)
		}
	}
	if n.NetName == "" && netNameOff > 0 {
		n.NetName = readANSIAt(b, off+netNameOff, lim)
	}
	const validDevice = 1 << 0
	if n.DeviceName == "" && flags&validDevice != 0 && deviceNameOff > 0 {
		n.DeviceName = readANSIAt(b, off+deviceNameOff, lim)
	}
	return n, true
}

// parseIDList walks the shell item list.
//
// # Why only part of each item is decoded
//
// The shell item taxonomy is large and only partly documented, and the
// long-name extension block (signature 0xBEEF0004) places its strings at
// version-dependent offsets. Decoding those offsets by guesswork would
// produce a path that LOOKS authoritative and may be wrong, which is
// worse than not producing one.
//
// So the documented, version-stable subset is decoded -- root folder
// GUIDs, volume names, and the ANSI primary name plus size, DOS
// timestamp and attributes of file entries -- and everything else is
// recorded by type and size. The presence of an extension block is noted
// so an analyst knows a long name exists that this reader did not take.
func parseIDList(b []byte, baseOffset int, lim Limits, l *Link) []ShellItem {
	var items []ShellItem
	pos := 0
	for pos+2 <= len(b) {
		size := int(binary.LittleEndian.Uint16(b[pos : pos+2]))
		if size == 0 {
			break // terminal ID
		}
		if size < 3 || pos+size > len(b) {
			l.Warnings = append(l.Warnings, fmt.Sprintf(
				"shell item at list offset %d declares %d bytes and does not fit; the list was truncated there", pos, size))
			break
		}
		if len(items) >= lim.MaxIDListItems {
			l.Warnings = append(l.Warnings, fmt.Sprintf("shell item list stopped at the %d-item limit", lim.MaxIDListItems))
			break
		}
		items = append(items, parseShellItem(b[pos:pos+size], baseOffset+pos))
		pos += size
	}
	return items
}

func parseShellItem(b []byte, offset int) ShellItem {
	it := ShellItem{RawBytes: len(b), Offset: offset, Kind: "other"}
	if len(b) < 3 {
		return it
	}
	it.TypeByte = b[2]

	switch {
	case it.TypeByte == 0x1F:
		// Root folder: a class identifier, no name.
		it.Kind = "root_folder"
		if len(b) >= 20 {
			it.GUID = formatGUID(b[4:20])
		}
	case it.TypeByte == 0x2E:
		it.Kind = "device"
	case it.TypeByte&0x70 == 0x20:
		// Volume: an ANSI drive string such as "C:\".
		it.Kind = "volume"
		it.Name = trimNulANSI(b[3:])
	case it.TypeByte&0x70 == 0x30:
		// File entry. The fixed prefix is documented and stable:
		// size(2) type(1) unknown(1) filesize(4) dosdate(4) attrs(2),
		// then the ANSI primary name.
		it.Kind = "file_entry"
		if it.TypeByte&0x01 != 0 {
			it.Kind = "directory_entry"
		}
		if len(b) >= 14 {
			it.Size = binary.LittleEndian.Uint32(b[4:8])
			it.Modified = dosDateTime(binary.LittleEndian.Uint32(b[8:12]))
			it.Attributes = binary.LittleEndian.Uint16(b[12:14])
			it.HasAttrs = true
			it.Name = trimNulANSI(b[14:])
		}
	case it.TypeByte&0x70 == 0x40:
		it.Kind = "network_location"
		if len(b) > 5 {
			it.Name = trimNulANSI(b[5:])
		}
	case it.TypeByte == 0x00:
		it.Kind = "unknown"
	}
	return it
}

// idListPath reconstructs a path from the named items.
//
// Only items that actually carry a name contribute. An item this reader
// did not decode contributes nothing rather than a placeholder, so the
// result is always a real prefix of the target path -- possibly shorter
// than the truth, never invented.
func idListPath(items []ShellItem) string {
	var parts []string
	for _, it := range items {
		if it.Name == "" {
			continue
		}
		parts = append(parts, strings.TrimRight(it.Name, `\`))
	}
	if len(parts) == 0 {
		return ""
	}
	joined := strings.Join(parts, `\`)
	// A volume item already ends in a backslash ("C:\"), which the trim
	// above removed; a single-part result is that volume alone.
	return joined
}

// parseExtraData walks the ExtraData block chain, recording which blocks
// are present and decoding only the tracker block.
func parseExtraData(b []byte, baseOffset int, l *Link) {
	pos := 0
	for pos+8 <= len(b) {
		size := int(binary.LittleEndian.Uint32(b[pos : pos+4]))
		if size < 8 {
			break // terminal block, or corrupt
		}
		if pos+size > len(b) {
			l.Warnings = append(l.Warnings, "an ExtraData block extends past the end of the file")
			break
		}
		sig := binary.LittleEndian.Uint32(b[pos+4 : pos+8])
		l.ExtraBlocks = append(l.ExtraBlocks, extraBlockName(sig))
		// TrackerDataBlock: the only one decoded here. Its MachineID is
		// the NetBIOS name of the machine that CREATED the shortcut,
		// which attributes the artifact to a host.
		if sig == 0xA0000003 && size >= 0x60 && pos+0x20 <= len(b) {
			l.TrackerMachineID = trimNulANSI(b[pos+16 : pos+32])
			l.Offsets["tracker_data_block"] = baseOffset + pos
		}
		pos += size
	}
}

func extraBlockName(sig uint32) string {
	switch sig {
	case 0xA0000001:
		return "EnvironmentVariableDataBlock"
	case 0xA0000002:
		return "ConsoleDataBlock"
	case 0xA0000003:
		return "TrackerDataBlock"
	case 0xA0000004:
		return "ConsoleFEDataBlock"
	case 0xA0000005:
		return "SpecialFolderDataBlock"
	case 0xA0000006:
		return "DarwinDataBlock"
	case 0xA0000007:
		return "IconEnvironmentDataBlock"
	case 0xA0000008:
		return "ShimDataBlock"
	case 0xA0000009:
		return "PropertyStoreDataBlock"
	case 0xA000000B:
		return "KnownFolderDataBlock"
	case 0xA000000C:
		return "VistaAndAboveIDListDataBlock"
	default:
		return fmt.Sprintf("unrecognized(0x%08X)", sig)
	}
}

// readStringData reads one CountCharacters-prefixed StringData entry,
// returning the value and the total bytes consumed.
func readStringData(data []byte, off int, unicode bool, lim Limits) (string, int, bool) {
	if off+2 > len(data) {
		return "", 0, false
	}
	count := int(binary.LittleEndian.Uint16(data[off : off+2]))
	if count > lim.MaxStringChars {
		return "", 0, false
	}
	width := 1
	if unicode {
		width = 2
	}
	end := off + 2 + count*width
	if end > len(data) {
		return "", 0, false
	}
	raw := data[off+2 : end]
	if unicode {
		return safeString(decodeUTF16(raw)), 2 + count*width, true
	}
	return safeString(string(raw)), 2 + count, true
}

// readUTF16At reads a NUL-terminated UTF-16 string at a bounded offset.
func readUTF16At(b []byte, off int, lim Limits) string {
	if off <= 0 || off >= len(b) {
		return ""
	}
	rest := b[off:]
	limit := len(rest) - len(rest)%2
	for i := 0; i+1 < limit; i += 2 {
		if rest[i] == 0 && rest[i+1] == 0 {
			limit = i
			break
		}
		if i/2 >= lim.MaxStringChars {
			limit = i
			break
		}
	}
	return safeString(decodeUTF16(rest[:limit]))
}

// readANSIAt reads a NUL-terminated single-byte string at a bounded
// offset. The codepage is not known from the file, so bytes above ASCII
// are preserved through the UTF-8 sanitizer rather than transcoded from
// an assumed codepage.
func readANSIAt(b []byte, off int, lim Limits) string {
	if off <= 0 || off >= len(b) {
		return ""
	}
	rest := b[off:]
	if len(rest) > lim.MaxStringChars {
		rest = rest[:lim.MaxStringChars]
	}
	return safeString(trimNulANSI(rest))
}

func trimNulANSI(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func decodeUTF16(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	return string(utf16.Decode(u))
}

// safeString bounds what evidence-derived text may contain. It reaches
// JSON, SQLite and the UI, so invalid UTF-8 is replaced rather than
// propagated, and control characters are dropped.
func safeString(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return -1
		}
		return r
	}, s)
}

func formatGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// fileTime converts a Windows FILETIME to UTC.
//
// Zero means "not recorded" and stays zero -- a shortcut routinely
// leaves a target timestamp unset, and 1601-01-01 is not a date to put
// on a timeline. The plausibility window matches internal/prefetch and
// internal/ntfs, so one rule holds across the codebase.
func fileTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ticksPerSecond = 10_000_000
	const epochDelta = 11644473600
	t := time.Unix(int64(ft/ticksPerSecond)-epochDelta, int64(ft%ticksPerSecond)*100).UTC()
	if t.Year() < 1990 || t.Year() > 2200 {
		return time.Time{}
	}
	return t
}

// dosDateTime converts a packed DOS date/time, as shell items carry.
// It has 2-second resolution and no timezone; it is treated as UTC
// because nothing in the artifact records an offset, and that is stated
// wherever the value is surfaced.
func dosDateTime(v uint32) time.Time {
	if v == 0 {
		return time.Time{}
	}
	date := uint16(v & 0xFFFF)
	tm := uint16(v >> 16)
	year := int(date>>9) + 1980
	month := time.Month((date >> 5) & 0x0F)
	day := int(date & 0x1F)
	hour := int(tm >> 11)
	minute := int((tm >> 5) & 0x3F)
	sec := int(tm&0x1F) * 2
	if month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || sec > 59 {
		return time.Time{}
	}
	t := time.Date(year, month, day, hour, minute, sec, 0, time.UTC)
	if t.Year() < 1990 || t.Year() > 2200 {
		return time.Time{}
	}
	return t
}
