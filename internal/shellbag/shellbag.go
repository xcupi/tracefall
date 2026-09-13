// Package shellbag decodes Windows ShellBags -- the BagMRU tree Explorer
// keeps in a user's NTUSER.DAT and UsrClass.dat hives.
//
// # What this artifact is
//
// Every time a user browses a folder in Explorer, Windows records the
// view settings for it. The FOLDER IDENTITY half of that record lives in
// a tree under BagMRU, one registry key per level of the path, each
// holding one or more binary shell items (SHITEMID structures) naming
// the child it leads to. Reassembling the tree reconstructs the paths a
// user navigated, including onto removable media and network shares that
// are long gone -- and the entries outlive the folders themselves.
//
// # What it proves, and what it does not
//
// A ShellBag is evidence that EXPLORER RECORDED A FOLDER. That is
// genuinely user-attributed navigation evidence, and it is the reason
// the artifact matters. It is not:
//
//   - evidence a file was opened. BagMRU records folders and shell
//     namespace locations, not documents being read.
//   - evidence anything was executed. Nothing here records execution.
//   - evidence of WHEN the user browsed, in the way a log would. See the
//     timestamp discussion below, which is the subtlest part of this
//     artifact and the easiest to overstate.
//
// # Timestamps, and why this package does not turn them into instants
//
// Two unrelated kinds of time appear here, and conflating them would
// fabricate precision:
//
//  1. The BagMRU registry key's LAST-WRITE time. A real FILETIME, in
//     UTC, recorded by the registry. It says when Explorer last updated
//     that node of the tree. This is the defensible one, and it belongs
//     to the KEY, not to any individual shell item inside it.
//
//  2. The DOS date/time fields inside a file-entry shell item
//     (modified, and created/accessed in the extension block). These are
//     FAT-style timestamps: two-second granularity, and recorded in the
//     LOCAL TIME OF THE MACHINE with no timezone stored anywhere. They
//     cannot be converted to an instant without knowing that machine's
//     timezone, which the artifact does not record.
//
// So this package returns the DOS fields as WALL-CLOCK READINGS, in a
// type that says so (DOSTime), and never as time.Time in UTC. The caller
// places the key's last-write time on the timeline and reports the DOS
// readings as metadata. See internal/parsers/registry.
//
// # Scope
//
// The common shell item types are decoded: root/known-folder items,
// volume items, file and directory entries, and the 0xBEEF0004 extension
// block that carries the long name. Undocumented extension blocks are
// skipped by their own length rather than guessed at -- an unrecognized
// block makes the item partially decoded, never invalid.
package shellbag

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

var (
	// ErrTooShort means a shell item claims a size that cannot hold its
	// own header.
	ErrTooShort = errors.New("shellbag: shell item is too short to be valid")
	// ErrBadSize means a shell item's declared size does not fit the
	// buffer it was read from.
	ErrBadSize = errors.New("shellbag: shell item size exceeds the available data")
)

// Limits bound decoding so a hostile hive cannot exhaust memory or time.
type Limits struct {
	// MaxDepth caps BagMRU tree recursion. Real paths are shallow; a
	// tree deeper than this is malformed or hostile.
	MaxDepth int
	// MaxEntries caps how many bags a caller collects in total.
	MaxEntries int
	// MaxItemsPerKey caps the shell items read from one BagMRU key.
	MaxItemsPerKey int
	// MaxNameBytes caps a decoded name.
	MaxNameBytes int
	// MaxRecoveredStrings bounds how many strings are kept from an item
	// with no documented name field.
	MaxRecoveredStrings int
	// MaxItemBytes caps one shell item's declared size.
	MaxItemBytes int
}

// DefaultLimits are sized against real evidence. A browsed path is rarely
// more than 20 levels deep, and a BagMRU key holds a handful of items.
func DefaultLimits() Limits {
	return Limits{
		MaxDepth:       64,
		MaxEntries:     50000,
		MaxItemsPerKey: 512,
		MaxNameBytes:   4096,
		MaxItemBytes:   64 * 1024,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = d.MaxEntries
	}
	if l.MaxItemsPerKey <= 0 {
		l.MaxItemsPerKey = d.MaxItemsPerKey
	}
	if l.MaxRecoveredStrings <= 0 {
		l.MaxRecoveredStrings = DefaultLimits().MaxRecoveredStrings
	}
	if l.MaxNameBytes <= 0 {
		l.MaxNameBytes = d.MaxNameBytes
	}
	if l.MaxItemBytes <= 0 {
		l.MaxItemBytes = d.MaxItemBytes
	}
	return l
}

// ItemKind classifies a decoded shell item.
type ItemKind string

const (
	// KindRoot is a shell namespace root: My Computer, Network, Control
	// Panel, or a known folder, identified by a CLSID.
	KindRoot ItemKind = "root"
	// KindVolume is a drive or volume, e.g. "C:\".
	KindVolume ItemKind = "volume"
	// KindDirectory is a folder entry.
	KindDirectory ItemKind = "directory"
	// KindFile is a file entry. Rare in BagMRU, which records folders,
	// but the structure permits it and it is reported honestly when
	// present rather than relabelled as a folder.
	KindFile ItemKind = "file"
	// KindNetwork is a network share or workgroup location.
	KindNetwork ItemKind = "network"
	// KindURI is a URI-form shell location.
	KindURI ItemKind = "uri"
	// KindKnownFolder is a shell item identified by a folder GUID rather
	// than a name -- "This PC\\Pictures" and its siblings. The GUID is
	// resolved from a documented table; an unlisted one is reported as
	// the GUID itself.
	KindKnownFolder ItemKind = "known_folder"
	// KindDevice is a portable device or its contents: a phone or camera
	// attached over MTP, and the folders inside it. These items carry no
	// filesystem path -- the device is not mounted as a drive -- so the
	// name is the only identity they have.
	KindDevice ItemKind = "device"
	// KindUnknown is a well-formed shell item whose type byte Tracefall
	// does not decode. Its raw type is still reported -- an unrecognized
	// item is a gap in coverage, not corruption, and the two must stay
	// distinguishable.
	KindUnknown ItemKind = "unknown"
)

// DOSTime is a FAT-style date/time as stored in a shell item.
//
// It is deliberately NOT a time.Time. These fields carry no timezone,
// have two-second granularity, and are written in the local time of the
// machine that recorded them -- so there is no instant they can honestly
// be converted to. Formatting one produces a wall-clock reading that an
// analyst can interpret against the machine's known timezone; converting
// it to UTC here would invent a fact.
type DOSTime struct {
	Year   int
	Month  time.Month
	Day    int
	Hour   int
	Minute int
	Second int
	// Valid is false when the field was absent or held an impossible
	// date, which is common: an unset DOS timestamp is all zero bits.
	Valid bool
}

// String renders the reading, or "" when there is none.
func (d DOSTime) String() string {
	if !d.Valid {
		return ""
	}
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d",
		d.Year, int(d.Month), d.Day, d.Hour, d.Minute, d.Second)
}

// Item is one decoded shell item.
type Item struct {
	Kind ItemKind
	// TypeByte is the raw shell item type, kept so an item Tracefall
	// classifies as unknown can still be described precisely.
	TypeByte byte
	// Name is the item's display name: a drive letter, a folder name, a
	// known-folder name, or the long name from the extension block when
	// one is present.
	Name string
	// ShortName is the 8.3 name a file entry carries, when it differs
	// from Name. Kept because it is what appears in some other tooling.
	ShortName string
	// CLSID is set for root items, and CLSIDMeaning is its documented
	// meaning -- empty for a CLSID not in the table, never a guess.
	CLSID        string
	CLSIDMeaning string
	// FileSize is the size a file entry records. Meaningless for other
	// kinds and left zero.
	FileSize uint32
	// Attributes is the FILE_ATTRIBUTE_* mask a file/directory entry
	// records, with AttributeNames its decoded form.
	Attributes     uint16
	AttributeNames []string
	// Modified, Created and Accessed are the item's DOS wall-clock
	// readings. See DOSTime for why they are not instants.
	Modified DOSTime
	Created  DOSTime
	Accessed DOSTime
	// MFTEntry and MFTSequence come from a version 7+ extension block,
	// linking this shell item to an $MFT record. Zero when absent.
	MFTEntry    uint64
	MFTSequence uint16
	// Size is the item's declared byte length, and Offset is where it
	// began within the value data -- both retained for provenance.
	Size   int
	Offset int
	// NameIsRecovered marks a Name that was located structurally rather
	// than read from a documented field. It is still evidence; it is a
	// weaker claim than a decoded name, and presenting the two alike
	// would overstate what is known.
	NameIsRecovered bool
	// RecoveredStrings are every readable string the item holds, kept so
	// a structurally recovered name can be checked rather than trusted.
	RecoveredStrings []string
	// Warnings describe what could not be decoded within an item that
	// was otherwise readable.
	Warnings []string
}

// rootCLSIDs are the shell namespace roots whose meaning is documented.
// An unlisted CLSID yields an empty CLSIDMeaning rather than a guess.
var rootCLSIDs = map[string]string{
	"{20D04FE0-3AEA-1069-A2D8-08002B30309D}": "This PC / My Computer",
	"{208D2C60-3AEA-1069-A2D7-08002B30309D}": "Network",
	"{871C5380-42A0-1069-A2EA-08002B30309D}": "Internet Explorer",
	"{645FF040-5081-101B-9F08-00AA002F954E}": "Recycle Bin",
	"{21EC2020-3AEA-1069-A2DD-08002B30309D}": "Control Panel",
	"{031E4825-7B94-4DC3-B131-E946B44C8DD5}": "Libraries",
	"{59031A47-3F72-44A7-89C5-5595FE6B30EE}": "User Profiles",
	"{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "Desktop",
	"{450D8FBA-AD25-11D0-98A8-0800361B1103}": "My Documents",
	"{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}": "Network Places",
	"{5E6AB780-7743-11CF-A12B-00AA004AE837}": "Internet Explorer toolbar",
	"{679F85CB-0220-4080-B29B-5540CC05AAB6}": "Quick Access / Home",
}

// RootCLSID returns a documented shell root's meaning.
func RootCLSID(clsid string) (string, bool) {
	m, ok := rootCLSIDs[strings.ToUpper(strings.TrimSpace(clsid))]
	return m, ok
}

// Shell item type codes. Only the high nibble is meaningful for most
// entries, which is why classification masks rather than compares.
const (
	typeRootFolder = 0x1F
	typeVolume     = 0x2F
	typeFileEntry  = 0x30 // 0x30-0x3F: file/directory entries
	typeNetwork    = 0x40 // 0x40-0x4F: network locations
	typeURI        = 0x60 // 0x60-0x6F: URI
	typeControl    = 0x70
)

// File-entry sub-flags within the 0x30 family.
const (
	fileEntryIsDirectory = 0x01
	fileEntryIsFile      = 0x02
)

// beefSignature marks the extension block carrying the long name.
const (
	// typeDelegate (0x2E) is a delegate shell item. Two shapes appear in
	// practice, told apart by the byte after the type: 0x80 introduces a
	// 16-byte folder GUID, anything else a device item whose identity is
	// carried as text.
	typeDelegate = 0x2E
	// typeProperty (0x00) is a property-store / MTP item: the folders
	// INSIDE a portable device. It has no documented fixed layout that
	// Tracefall relies on -- see decodeProperty.
	typeProperty = 0x00
	// delegateGUIDFlag marks the 0x2E variant that carries a GUID.
	delegateGUIDFlag = 0x80
)

// knownFolderGUIDs are the "This PC" folder GUIDs, which appear in
// BagMRU as delegate items with no name of their own. Documented values
// only: an unlisted GUID is reported AS the GUID, never guessed at.
var knownFolderGUIDs = map[string]string{
	"{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "Desktop",
	"{D3162B92-9365-467A-956B-92703ACA08AF}": "Documents",
	"{A8CDFF1C-4878-43BE-B5FD-F8091C1C60D0}": "Documents",
	"{088E3905-0323-4B02-9826-5D99428E115F}": "Downloads",
	"{374DE290-123F-4565-9164-39C4925E467B}": "Downloads",
	"{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}": "Music",
	"{1CF1260C-4DD0-4EBB-811F-33C572699FDE}": "Music",
	"{24AD3AD4-A569-4530-98E1-AB02F9417AA8}": "Pictures",
	"{33E28130-4E1E-4676-835A-98395C3BC3BB}": "Pictures",
	"{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}": "Videos",
	"{A0953C92-50DC-43BF-BE83-3742FED03C9C}": "Videos",
	"{5E6C858F-0E22-4760-9AFE-EA3317B67173}": "User profile",
	"{59031A47-3F72-44A7-89C5-5595FE6B30EE}": "Users",
}

// KnownFolder resolves a folder GUID to its documented name.
func KnownFolder(guid string) (string, bool) {
	n, ok := knownFolderGUIDs[strings.ToUpper(guid)]
	return n, ok
}

const beefSignature = 0xBEEF0004

// DecodeItem decodes one shell item from the start of data.
//
// The first two bytes are the item's own declared size, INCLUDING those
// two bytes. A size of zero terminates an item list and is reported as
// (zero Item, 0, nil) so a caller can stop cleanly.
func DecodeItem(data []byte, offset int, lim Limits) (Item, int, error) {
	lim = lim.withDefaults()

	if len(data) < 2 {
		return Item{}, 0, ErrTooShort
	}
	size := int(binary.LittleEndian.Uint16(data[0:2]))
	if size == 0 {
		// The documented list terminator.
		return Item{}, 0, nil
	}
	if size < 3 {
		return Item{}, 0, fmt.Errorf("%w: declared size %d", ErrTooShort, size)
	}
	if size > len(data) {
		return Item{}, 0, fmt.Errorf("%w: declared size %d, %d bytes available", ErrBadSize, size, len(data))
	}
	if size > lim.MaxItemBytes {
		return Item{}, 0, fmt.Errorf("%w: declared size %d exceeds the %d-byte limit",
			ErrBadSize, size, lim.MaxItemBytes)
	}

	body := data[:size]
	it := Item{TypeByte: body[2], Size: size, Offset: offset}

	switch {
	case it.TypeByte == typeRootFolder:
		decodeRoot(&it, body, lim)
	case it.TypeByte == typeVolume:
		decodeVolume(&it, body, lim)
	case it.TypeByte&0xF0 == typeFileEntry:
		decodeFileEntry(&it, body, lim)
	case it.TypeByte&0xF0 == typeNetwork:
		decodeNetwork(&it, body, lim)
	case it.TypeByte&0xF0 == typeURI:
		it.Kind = KindURI
		it.Name = firstASCIIString(body[3:], lim.MaxNameBytes)
	case it.TypeByte == typeDelegate:
		decodeDelegate(&it, body, lim)
	case it.TypeByte == typeProperty:
		decodeProperty(&it, body, lim)
	case it.TypeByte&0xF0 == typeControl:
		it.Kind = KindRoot
		decodeRoot(&it, body, lim)
	default:
		it.Kind = KindUnknown
		it.Warnings = append(it.Warnings, fmt.Sprintf(
			"shell item type 0x%02X is not decoded by Tracefall; the item is well-formed but its contents are not interpreted",
			it.TypeByte))
	}

	return it, size, nil
}

// decodeRoot reads a root/known-folder item: a sort index byte followed
// by a 16-byte CLSID.
func decodeRoot(it *Item, body []byte, lim Limits) {
	it.Kind = KindRoot
	// 2 size + 1 type + 1 sort index, then the CLSID.
	const clsidOff = 4
	if len(body) < clsidOff+16 {
		it.Warnings = append(it.Warnings, "root item is too short to carry a CLSID")
		return
	}
	it.CLSID = formatGUID(body[clsidOff : clsidOff+16])
	if m, ok := RootCLSID(it.CLSID); ok {
		it.CLSIDMeaning = m
		it.Name = m
	} else {
		// Named by its CLSID rather than by a guess. An investigator can
		// look the GUID up; an invented label they cannot check is worse
		// than a raw one they can.
		it.Name = it.CLSID
	}
}

// decodeVolume reads a volume item, whose name is usually an ASCII drive
// path such as "C:\".
func decodeVolume(it *Item, body []byte, lim Limits) {
	it.Kind = KindVolume
	if len(body) < 4 {
		it.Warnings = append(it.Warnings, "volume item is too short")
		return
	}
	name := firstASCIIString(body[3:], lim.MaxNameBytes)
	if name == "" {
		// Some volume items carry a CLSID instead of a drive string.
		if len(body) >= 20 {
			it.CLSID = formatGUID(body[4:20])
			if m, ok := RootCLSID(it.CLSID); ok {
				it.CLSIDMeaning = m
				name = m
			} else {
				name = it.CLSID
			}
		}
	}
	it.Name = name
}

// decodeNetwork reads a network-location item.
func decodeNetwork(it *Item, body []byte, lim Limits) {
	it.Kind = KindNetwork
	if len(body) < 6 {
		it.Warnings = append(it.Warnings, "network item is too short")
		return
	}
	// 2 size + 1 type + 1 flags + 2 unknown, then a NUL-terminated name.
	it.Name = firstASCIIString(body[5:], lim.MaxNameBytes)
}

// File-entry field offsets, from the start of the item.
const (
	feOffFlags    = 3
	feOffFileSize = 4
	feOffModDate  = 8
	feOffModTime  = 10
	feOffAttrs    = 12
	feOffName     = 14
)

// decodeFileEntry reads a file or directory entry, then its extension
// block if one is present.
func decodeFileEntry(it *Item, body []byte, lim Limits) {
	// Checked before the flags byte is read, not after: a three-byte
	// item is long enough to carry a type but not a flags field, and
	// reading one anyway is an out-of-range panic on evidence an
	// attacker controls.
	if len(body) <= feOffFlags {
		it.Kind = KindUnknown
		it.Warnings = append(it.Warnings, "file entry is too short to carry its flags byte")
		return
	}
	flags := body[feOffFlags]
	switch {
	case flags&fileEntryIsDirectory != 0:
		it.Kind = KindDirectory
	case flags&fileEntryIsFile != 0:
		it.Kind = KindFile
	default:
		// Neither bit set. Treated as a directory because BagMRU records
		// folders, but the ambiguity is reported rather than hidden.
		it.Kind = KindDirectory
		it.Warnings = append(it.Warnings, fmt.Sprintf(
			"file entry flags 0x%02X mark it as neither file nor directory; recorded as a directory because BagMRU stores folders", flags))
	}

	if len(body) < feOffName {
		it.Warnings = append(it.Warnings, "file entry is too short to carry its fields")
		return
	}
	it.FileSize = binary.LittleEndian.Uint32(body[feOffFileSize:])
	it.Modified = dosDateTime(
		binary.LittleEndian.Uint16(body[feOffModDate:]),
		binary.LittleEndian.Uint16(body[feOffModTime:]))
	it.Attributes = binary.LittleEndian.Uint16(body[feOffAttrs:])
	it.AttributeNames = attributeNames(it.Attributes)

	// The primary (short) name is an ASCII, NUL-terminated string.
	shortName := firstASCIIString(body[feOffName:], lim.MaxNameBytes)
	it.Name = shortName

	// The extension block follows the name, aligned to a 2-byte
	// boundary. Its own first two bytes are its size.
	extStart := feOffName + len(shortName) + 1
	if extStart%2 != 0 {
		extStart++
	}
	if extStart+8 > len(body) {
		// No extension block. Common on older items, and not an error.
		return
	}
	decodeExtensionBlock(it, body[extStart:], shortName, lim)
}

// decodeDelegate reads a 0x2E delegate item.
//
// Two shapes appear in real BagMRU trees and they are told apart by the
// byte after the type, not guessed at:
//
//   - 0x80: a 16-byte folder GUID follows. These are the "This PC"
//     folders -- Pictures, Downloads, Desktop -- which BagMRU records by
//     identity rather than by name. Resolved from the documented table;
//     an unlisted GUID is reported AS the GUID.
//   - anything else: a portable device (a phone or camera attached over
//     MTP). Its identity is carried as text inside the item, so the name
//     is recovered by the same structural scan decodeProperty uses, and
//     is labelled as recovered that way.
//
// Before this, every 0x2E item decoded to an EMPTY name. That was worse
// than it sounds: an unnamed level was then dropped from the
// reconstructed path entirely, so "This PC\Pictures\Contact" was
// reported as "This PC\Contact" -- a parent-child relationship that the
// evidence does not contain.
func decodeDelegate(it *Item, body []byte, lim Limits) {
	if len(body) > 4 && body[3] == delegateGUIDFlag {
		it.Kind = KindKnownFolder
		it.CLSID = formatGUID(body[4:20])
		if name, ok := KnownFolder(it.CLSID); ok {
			it.Name = name
			it.CLSIDMeaning = name
			return
		}
		// Not in the table. The GUID IS the honest identity here.
		it.Name = it.CLSID
		it.Warnings = append(it.Warnings,
			"this folder is recorded by GUID and the GUID is not one Tracefall has a documented name for; "+
				"the GUID is reported in place of a name rather than guessed at")
		return
	}

	it.Kind = KindDevice
	names := recoverStrings(body, lim)
	if len(names) == 0 {
		it.Warnings = append(it.Warnings,
			"this delegate item carries no readable name; it is reported as an unnamed device item")
		return
	}
	it.Name = names[0]
	it.RecoveredStrings = names
	it.NameIsRecovered = true
	it.Warnings = append(it.Warnings, deviceNameWarning)
}

// decodeProperty reads a 0x00 property-store item -- the folders INSIDE
// a portable device, which is where a phone's DCIM and Camera folders
// appear.
//
// There is no fixed offset here that Tracefall is willing to rely on.
// The item is a serialized property store whose layout varies with what
// the device reported, so the name is located STRUCTURALLY: the first
// well-formed, NUL-terminated UTF-16 string in the item. On real
// evidence that is consistently the display name, and every other string
// the item holds is kept alongside it so an analyst can check that
// judgement rather than take it on trust.
//
// The result is marked NameIsRecovered, and events built from it say so.
// A recovered name is evidence; it is not the same claim as a name read
// from a documented field, and the two must not be presented alike.
func decodeProperty(it *Item, body []byte, lim Limits) {
	it.Kind = KindDevice
	names := recoverStrings(body, lim)
	if len(names) == 0 {
		it.Warnings = append(it.Warnings,
			"this property-store item carries no readable name; its contents are not interpreted")
		return
	}
	it.Name = names[0]
	it.RecoveredStrings = names
	it.NameIsRecovered = true
	it.Warnings = append(it.Warnings, deviceNameWarning)
}

const deviceNameWarning = "this item has no documented name field; the name shown is the first readable text " +
	"in the item and every string it holds is preserved alongside it, so the reading can be checked"

// recoverStrings returns the named strings inside an item that carries
// no documented name field, in order.
//
// The rule is SELF-VALIDATING rather than a scan for anything printable.
// A string is accepted only where a 32-bit length immediately precedes
// it AND that length equals the number of UTF-16 code units actually
// present up to the terminator. Binary padding that happens to decode as
// text will not carry a matching length in front of it, so it is not
// mistaken for a name.
//
// The first accepted string is the display name on every real item
// examined; the rest are returned so that judgement can be checked
// rather than trusted. A device item that yields nothing here keeps an
// empty name and says so, which is the honest outcome.
func recoverStrings(body []byte, lim Limits) []string {
	const (
		minChars = 2
		// How far back to look for the length that describes a string.
		// These items carry a small table of lengths ahead of the
		// strings themselves, so the length is near but not adjacent.
		lengthWindow = 10
	)
	maxChars := lim.MaxNameBytes / 2
	var out []string
	seen := map[string]bool{}

	for off := 4; off+4 <= len(body); off += 2 {
		end, ok, _ := scanUTF16Name(body[off:], lim.MaxNameBytes)
		if !ok {
			continue
		}
		units := end / 2 // characters plus the terminator
		if units < minChars+1 || units > maxChars {
			continue
		}
		// A string is accepted only when a 32-bit field shortly before
		// it DECLARES exactly this many code units. Binary padding that
		// happens to decode as text is not described by a length, so it
		// is not mistaken for a name -- which is what an unvalidated
		// scan did, reporting a phone's folders as "\uffff\u5058\u4d54".
		declared := false
		for back := 4; back <= lengthWindow*4 && off-back >= 0; back += 4 {
			if int(binary.LittleEndian.Uint32(body[off-back:])) == units {
				declared = true
				break
			}
		}
		if !declared {
			continue
		}
		// A validated candidate may still start LATE: the same terminator
		// is reached from several earlier offsets, and the length table
		// can describe either. "LG Q7" and "Q7" end at the same NUL, and
		// taking the first match found reports the device as "Q7".
		// Extending backwards while the longer form is ALSO declared
		// keeps the full recorded name.
		for back := off - 2; back >= 4; back -= 2 {
			e2, ok2, _ := scanUTF16Name(body[back:], lim.MaxNameBytes)
			if !ok2 || back+e2 != off+end {
				break
			}
			u2 := e2 / 2
			found := false
			for b := 4; b <= lengthWindow*4 && back-b >= 0; b += 4 {
				if int(binary.LittleEndian.Uint32(body[back-b:])) == u2 {
					found = true
					break
				}
			}
			if !found {
				break
			}
			off, end, units = back, e2, u2
		}

		str := sanitize(firstUTF16String(body[off:], lim.MaxNameBytes))
		if len([]rune(str)) < minChars {
			continue
		}
		if !seen[str] {
			seen[str] = true
			out = append(out, str)
			if len(out) >= lim.MaxRecoveredStrings {
				break
			}
		}
		off += end - 2
	}
	return out
}

// decodeExtensionBlock reads the 0xBEEF0004 block, which carries the
// long name and the created/accessed readings.
//
// A block with a different signature is SKIPPED rather than interpreted.
// Windows defines several, most undocumented, and decoding one on a
// guess would attach invented metadata to a real item.
func decodeExtensionBlock(it *Item, ext []byte, shortName string, lim Limits) {
	if len(ext) < 8 {
		return
	}
	blockSize := int(binary.LittleEndian.Uint16(ext[0:2]))
	if blockSize < 8 || blockSize > len(ext) {
		it.Warnings = append(it.Warnings, "extension block size is inconsistent with the item; long name not recovered")
		return
	}
	version := binary.LittleEndian.Uint16(ext[2:4])
	signature := binary.LittleEndian.Uint32(ext[4:8])
	if signature != beefSignature {
		it.Warnings = append(it.Warnings, fmt.Sprintf(
			"extension block signature 0x%08X is not the 0xBEEF0004 long-name block; skipped rather than interpreted", signature))
		return
	}

	block := ext[:blockSize]
	// 8 header, then created (4) and accessed (4) DOS date/time.
	const offCreated = 8
	const offAccessed = 12
	if len(block) >= offAccessed+4 {
		it.Created = dosDateTime(
			binary.LittleEndian.Uint16(block[offCreated:]),
			binary.LittleEndian.Uint16(block[offCreated+2:]))
		it.Accessed = dosDateTime(
			binary.LittleEndian.Uint16(block[offAccessed:]),
			binary.LittleEndian.Uint16(block[offAccessed+2:]))
	}

	// The MFT reference is present from version 7 and is worth keeping:
	// it ties a ShellBag entry to an $MFT record Tracefall may also hold.
	// The file reference sits at 0x14, after the 2-byte unknown at 0x12
	// that version 7 introduces -- not at 0x12 itself. Confirmed against
	// a real Windows 10 UsrClass.dat, where reading it two bytes early
	// produced entry numbers in the hundreds of millions for files whose
	// real $MFT entries are in the thousands.
	const offFileReference = 20
	if version >= 7 && len(block) >= offFileReference+8 {
		ref := binary.LittleEndian.Uint64(block[offFileReference : offFileReference+8])
		it.MFTEntry = ref & 0x0000FFFFFFFFFFFF
		it.MFTSequence = uint16(ref >> 48)
	}

	// The long name is located from the block's DOCUMENTED field layout,
	// with the structural scan kept only as a fallback.
	//
	// This is the reverse of an earlier decision here, and the reversal
	// was forced by real evidence. The scan looked safer -- published
	// offset tables disagree, and an offset wrong by two bytes yields a
	// plausible but WRONG filename. In practice the scan is what produced
	// the wrong names: it starts at the earliest two-byte-aligned
	// position that decodes as printable text and terminates near the
	// block's end, and the version-8 "unknown" field immediately before
	// the name frequently decodes as printable. On one real UsrClass.dat
	// it prepended two junk characters to 25 of 35 names -- "usr" read as
	// "\u1471\u00C6usr", "System32" as "\u8DCD)System32" -- and the
	// documented offset produced the correct name in every one of those
	// cases and agreed in the rest.
	//
	// The offsets are computed CUMULATIVELY from the version, which is
	// where the published tables actually agree; they disagree only when
	// read as a flat per-version list. And the result is validated the
	// same way the scan's was: it must be a well-formed, NUL-terminated
	// UTF-16 string inside the block. If it is not, the scan runs and
	// says so -- so a version this layout does not cover degrades to the
	// old behaviour with a warning rather than to a wrong name.
	nameOff := documentedLongNameOffset(version)
	if _, ok, _ := scanUTF16Name(sliceFrom(block, nameOff), lim.MaxNameBytes); !ok {
		var skippedBinary bool
		nameOff, skippedBinary = findLongName(block, minLongNameOffset(version), lim)
		if nameOff < 0 {
			it.Warnings = append(it.Warnings,
				"the extension block carries no readable long name; the short name is reported instead")
			return
		}
		it.Warnings = append(it.Warnings, fmt.Sprintf(
			"the long name was not at the documented offset for a version %d extension block; it was located "+
				"by scanning the block, so it may begin earlier or later than the recorded name does", version))
		if skippedBinary {
			it.Warnings = append(it.Warnings,
				"the recorded long name contains characters that are not valid in a Windows name; "+
					"the value reported may be a fragment of it")
		}
	}
	long := firstUTF16String(block[nameOff:], lim.MaxNameBytes)
	if long != "" {
		if shortName != "" && !strings.EqualFold(long, shortName) {
			it.ShortName = shortName
		}
		it.Name = long
	}
}

// documentedLongNameOffset is where the long name begins in a
// 0xBEEF0004 extension block, from the block's documented field layout.
//
// The fields are CUMULATIVE: a version 9 block carries every field
// introduced at version 3, 7, 8 and 9. Reading the published tables as a
// flat per-version list is what makes them look contradictory.
//
//	0x00 size (2), version (2), signature (4)
//	0x08 creation DOS date/time (4)
//	0x0C access DOS date/time (4)
//	0x10 unknown (2)
//	version >= 7: unknown (2), file reference (8), unknown (8)
//	version >= 3: long string size (2)
//	version >= 9: unknown (4)
//	version >= 8: unknown (4)
//	then the long name, UTF-16, NUL-terminated
func documentedLongNameOffset(version uint16) int {
	off := 18 // through the 2-byte unknown at 0x10
	if version >= 7 {
		off = 36 // plus unknown(2), file reference(8), unknown(8)
	}
	if version >= 3 {
		off += 2 // long string size
	}
	if version >= 9 {
		off += 4
	}
	if version >= 8 {
		off += 4
	}
	return off
}

// sliceFrom returns b[off:], or nil when off is outside b -- so a
// computed offset can be validated without a bounds panic.
func sliceFrom(b []byte, off int) []byte {
	if off < 0 || off >= len(b) {
		return nil
	}
	return b[off:]
}

// minLongNameOffset is the earliest offset a long name can begin at, by
// block version. These are lower BOUNDS on where the fixed fields end,
// not claims about the exact name offset -- findLongName does the
// locating. Being a bound rather than a position is what makes an
// imprecise version mapping harmless here.
func minLongNameOffset(version uint16) int {
	switch {
	case version >= 7:
		// 18 bytes of header and timestamps, plus the 8-byte MFT
		// reference and 8 further bytes.
		return 34
	case version >= 3:
		return 18
	default:
		return 18
	}
}

// findLongName returns the offset of the block's long name, and whether
// the scan had to pass over control-character data to reach it.
//
// "Well-formed" means: begins on a two-byte boundary, decodes to at
// least one printable character, is NUL-terminated inside the block, and
// terminates close to the block's end -- which is where a real long name
// sits, since it is the block's last variable-length field. That last
// condition is what stops the scan from latching onto a short run of
// text in the middle of binary fields and reporting it as a folder name.
func findLongName(block []byte, start int, lim Limits) (offset int, skippedBinary bool) {
	if start < 0 {
		start = 0
	}
	if start%2 != 0 {
		start++
	}
	// How much may follow the name's terminator. Real blocks carry a
	// small trailing field after it; anything more means the candidate
	// is not the block's final string.
	const maxTrailingBytes = 8

	for off := start; off+4 <= len(block); off += 2 {
		end, ok, sawControl := scanUTF16Name(block[off:], lim.MaxNameBytes)
		if sawControl {
			skippedBinary = true
		}
		if !ok {
			continue
		}
		if len(block)-(off+end) > maxTrailingBytes {
			continue
		}
		return off, skippedBinary
	}
	return -1, skippedBinary
}

// scanUTF16Name examines a candidate name.
//
// end is the byte length including the terminator; ok reports whether it
// is a well-formed name; sawControl reports that a control character was
// encountered, which marks the region as binary rather than text.
func scanUTF16Name(b []byte, max int) (end int, ok bool, sawControl bool) {
	chars := 0
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i:])
		if u == 0 {
			return i + 2, chars > 0, sawControl
		}
		if u < 0x20 || u == 0x7F {
			return 0, false, true
		}
		chars++
		if chars*2 > max {
			return 0, false, sawControl
		}
	}
	return 0, false, sawControl
}

// dosDateTime decodes a FAT date/time pair into a wall-clock reading.
//
// Returns an invalid DOSTime for the all-zero encoding, which is how an
// unset field appears, and for any combination that is not a real date.
func dosDateTime(date, dosTime uint16) DOSTime {
	if date == 0 && dosTime == 0 {
		return DOSTime{}
	}
	d := DOSTime{
		Year:   1980 + int(date>>9),
		Month:  time.Month((date >> 5) & 0x0F),
		Day:    int(date & 0x1F),
		Hour:   int(dosTime >> 11),
		Minute: int((dosTime >> 5) & 0x3F),
		Second: int(dosTime&0x1F) * 2,
	}
	if d.Month < 1 || d.Month > 12 || d.Day < 1 || d.Day > 31 ||
		d.Hour > 23 || d.Minute > 59 || d.Second > 59 {
		return DOSTime{}
	}
	d.Valid = true
	return d
}

// fileAttributes names the FILE_ATTRIBUTE_* bits worth reporting.
var fileAttributes = []struct {
	mask uint16
	name string
}{
	{0x0001, "read_only"},
	{0x0002, "hidden"},
	{0x0004, "system"},
	{0x0010, "directory"},
	{0x0020, "archive"},
	{0x0040, "device"},
	{0x0080, "normal"},
	{0x0100, "temporary"},
	{0x0200, "sparse_file"},
	{0x0400, "reparse_point"},
	{0x0800, "compressed"},
	{0x1000, "offline"},
	{0x2000, "not_content_indexed"},
	{0x4000, "encrypted"},
}

func attributeNames(mask uint16) []string {
	var out []string
	for _, a := range fileAttributes {
		if mask&a.mask != 0 {
			out = append(out, a.name)
		}
	}
	return out
}

// firstASCIIString reads a NUL-terminated single-byte string.
func firstASCIIString(b []byte, max int) string {
	end := len(b)
	if end > max {
		end = max
	}
	for i := 0; i < end; i++ {
		if b[i] == 0 {
			return sanitize(string(b[:i]))
		}
	}
	return sanitize(string(b[:end]))
}

// firstUTF16String reads a NUL-terminated little-endian UTF-16 string.
func firstUTF16String(b []byte, max int) string {
	var units []uint16
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i:])
		if u == 0 {
			break
		}
		units = append(units, u)
		if len(units)*2 >= max {
			break
		}
	}
	if len(units) == 0 {
		return ""
	}
	return sanitize(string(utf16.Decode(units)))
}

// sanitize strips control characters, which have no place in a name and
// would corrupt any view that renders one.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F {
			return -1
		}
		return r
	}, s)
}

// formatGUID renders a 16-byte little-endian GUID in the braced form.
func formatGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return strings.ToUpper(fmt.Sprintf("{%08X-%04X-%04X-%04X-%012X}",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16]))
}

// DecodeList decodes every shell item in one BagMRU value's data.
//
// A value normally holds exactly one item, but the structure permits a
// list, and reading them all costs nothing. Decoding stops at the
// terminator, at the limit, or at the first item that cannot be read --
// with everything decoded so far returned alongside the error, because a
// truncated list still contains real evidence.
func DecodeList(data []byte, lim Limits) ([]Item, error) {
	lim = lim.withDefaults()
	var out []Item
	offset := 0
	for offset < len(data) && len(out) < lim.MaxItemsPerKey {
		it, size, err := DecodeItem(data[offset:], offset, lim)
		if err != nil {
			return out, err
		}
		if size == 0 {
			break
		}
		out = append(out, it)
		offset += size
	}
	return out, nil
}

// PathSegment is the string an item contributes to a reconstructed path.
//
// Empty when the item names nothing, so a caller can skip it rather than
// insert a blank level and produce "C:\\\Users".
func PathSegment(it Item) string {
	name := strings.TrimSpace(it.Name)
	if name == "" {
		return ""
	}
	// A volume item already carries its trailing separator ("C:\"), and
	// keeping it would double up when segments are joined.
	return strings.TrimSuffix(name, `\`)
}

// UndecodedSegment stands in for a BagMRU level whose shell item yielded
// no name. It is a placeholder in the PATH, never a folder name.
const UndecodedSegment = "(undecoded)"

// JoinPath assembles a reconstructed path from root to leaf.
//
// An undecoded level becomes a PLACEHOLDER rather than disappearing.
// Dropping it silently was a forensic misstatement, not merely missing
// detail: with segments ["This PC", "", "Contact"] the result read
// "This PC\Contact", which asserts that Contact is a direct child of
// This PC. It is not -- there is a level between them, and on the
// evidence that produced this it was "Pictures". A path that shows the
// gap is incomplete; a path that hides it is wrong.
func JoinPath(segments []string) string {
	var kept []string
	for _, s := range segments {
		s = strings.TrimSpace(s)
		if s == "" {
			s = UndecodedSegment
		}
		kept = append(kept, s)
	}
	// Trailing placeholders carry no information about the leaf, but a
	// path that is ONLY placeholders is still evidence of depth.
	for len(kept) > 0 && kept[len(kept)-1] == UndecodedSegment {
		kept = kept[:len(kept)-1]
	}
	if len(kept) == 0 {
		return ""
	}
	// A drive-letter root joins with a separator directly ("C:" + "\" +
	// "Users"); a namespace root reads better with one too, so the rule
	// is uniform and the result is always unambiguous.
	return strings.Join(kept, `\`)
}
