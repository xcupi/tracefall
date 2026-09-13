// Package sbgen builds synthetic shell items and BagMRU structures for
// tests and browser-verification fixtures.
//
// Entirely invented values; nothing here comes from real evidence.
//
// As with the other *gen packages, this is the writer counterpart to the
// reader in internal/shellbag, built against the same offsets so a
// layout error surfaces as a failing round-trip instead of as quietly
// wrong evidence.
package sbgen

import (
	"encoding/binary"
	"strings"
	"time"
	"unicode/utf16"
)

// Root builds a shell-namespace root item (type 0x1F) for a CLSID such
// as "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" (This PC).
func Root(clsid string) []byte {
	body := make([]byte, 0, 20)
	body = append(body, 0, 0) // size, filled at the end
	body = append(body, 0x1F) // type
	body = append(body, 0x50) // sort index
	body = append(body, guidBytes(clsid)...)
	return withSize(body)
}

// Volume builds a volume item (type 0x2F), e.g. name "C:\".
func Volume(name string) []byte {
	body := make([]byte, 0, 8+len(name))
	body = append(body, 0, 0)
	body = append(body, 0x2F)
	body = append(body, []byte(name)...)
	body = append(body, 0)
	// Real volume items are padded out; the reader stops at the NUL, so
	// the padding only proves it does.
	for len(body)%2 != 0 {
		body = append(body, 0)
	}
	return withSize(body)
}

// FileEntry describes a synthetic file or directory shell item.
type FileEntry struct {
	// ShortName is the primary ASCII name (classically an 8.3 name).
	ShortName string
	// LongName goes in the 0xBEEF0004 extension block. Leave empty to
	// omit the block entirely, which is what an older item looks like.
	LongName string
	// IsDirectory sets the directory flag; false marks a file.
	IsDirectory bool
	FileSize    uint32
	// Attributes is the FILE_ATTRIBUTE_* mask.
	Attributes uint16
	// Modified, Created and Accessed are written as DOS date/time pairs.
	// They are WALL-CLOCK readings with no timezone -- exactly as the
	// real format stores them. A zero time writes the all-zero encoding,
	// which is how an unset field appears.
	Modified time.Time
	Created  time.Time
	Accessed time.Time
	// ExtVersion is the extension block version. 3, 7, 8 and 9 place the
	// long name at different offsets; 9 is what modern Windows writes.
	ExtVersion uint16
	// MFTEntry/MFTSequence are written when ExtVersion >= 7.
	MFTEntry    uint64
	MFTSequence uint16
}

// File builds a file/directory shell item (type 0x31 or 0x32).
func File(f FileEntry) []byte {
	typeByte := byte(0x32) // file
	flags := byte(0x02)
	if f.IsDirectory {
		typeByte = 0x31
		flags = 0x01
	}

	body := make([]byte, 14)
	// body[0:2] size, filled at the end
	body[2] = typeByte
	body[3] = flags
	binary.LittleEndian.PutUint32(body[4:], f.FileSize)
	d, t := dosDateTime(f.Modified)
	binary.LittleEndian.PutUint16(body[8:], d)
	binary.LittleEndian.PutUint16(body[10:], t)
	binary.LittleEndian.PutUint16(body[12:], f.Attributes)

	body = append(body, []byte(f.ShortName)...)
	body = append(body, 0)
	if len(body)%2 != 0 {
		body = append(body, 0)
	}

	if f.LongName != "" {
		body = append(body, extensionBlock(f)...)
	}
	// The documented terminator for the item's extension area.
	body = append(body, 0, 0)
	return withSize(body)
}

// extensionBlock builds the 0xBEEF0004 long-name block.
func extensionBlock(f FileEntry) []byte {
	version := f.ExtVersion
	if version == 0 {
		version = 9
	}

	blk := make([]byte, 8)
	// blk[0:2] size, filled at the end
	binary.LittleEndian.PutUint16(blk[2:], version)
	binary.LittleEndian.PutUint32(blk[4:], 0xBEEF0004)

	cd, ct := dosDateTime(f.Created)
	ad, at := dosDateTime(f.Accessed)
	blk = binary.LittleEndian.AppendUint16(blk, cd)
	blk = binary.LittleEndian.AppendUint16(blk, ct)
	blk = binary.LittleEndian.AppendUint16(blk, ad)
	blk = binary.LittleEndian.AppendUint16(blk, at)
	// The field layout below is CUMULATIVE, matching what Windows
	// actually writes -- verified against a real Windows 10 UsrClass.dat.
	//
	// This generator previously omitted two of these fields, which made
	// its blocks shorter than real ones and put the long name at an
	// offset no Windows version uses. The reader located the name by
	// scanning, so reader and generator agreed with each other and both
	// disagreed with Windows: the round trip passed while 25 of 35 real
	// folder names came back with two junk characters prepended. A
	// fixture that encodes the reader's own misunderstanding proves
	// nothing, so this now writes the documented layout.
	//
	// 0x10 unknown (2), taking the block to offset 18.
	blk = binary.LittleEndian.AppendUint16(blk, 0x0014)

	if version >= 7 {
		// unknown (2), 8-byte MFT file reference, unknown (8).
		blk = binary.LittleEndian.AppendUint16(blk, 0)
		ref := (f.MFTEntry & 0x0000FFFFFFFFFFFF) | (uint64(f.MFTSequence) << 48)
		blk = binary.LittleEndian.AppendUint64(blk, ref)
		blk = binary.LittleEndian.AppendUint64(blk, 0)
	}
	if version >= 3 {
		// Long string size. Windows writes 0 here for these blocks.
		blk = binary.LittleEndian.AppendUint16(blk, 0)
	}
	if version >= 9 {
		blk = binary.LittleEndian.AppendUint32(blk, 0)
	}
	if version >= 8 {
		blk = binary.LittleEndian.AppendUint32(blk, 0)
	}

	blk = append(blk, utf16Bytes(f.LongName)...)
	blk = append(blk, 0, 0) // NUL terminator

	binary.LittleEndian.PutUint16(blk[0:2], uint16(len(blk)))
	return blk
}

// KnownFolder builds a 0x2E delegate item carrying a folder GUID -- how
// BagMRU records "This PC\\Pictures" and its siblings, which have no name
// of their own.
func KnownFolder(guid string) []byte {
	body := make([]byte, 0, 24)
	body = append(body, 0, 0) // size, filled at the end
	body = append(body, 0x2E, 0x80)
	body = append(body, guidBytes(guid)...)
	body = append(body, 0, 0)
	return withSize(body)
}

// Device builds a property-store item (type 0x00) naming one folder
// inside a portable device -- a phone's DCIM or Camera folder.
//
// It writes the shape real devices produce: a small table of string
// LENGTHS ahead of the strings themselves. The reader validates a
// candidate name against one of those lengths, so a fixture that omitted
// them would not exercise the check that stops binary padding being
// reported as a folder name.
func Device(name string, extra ...string) []byte {
	strs := append([]string{name}, extra...)

	var lengths []byte
	// A leading total, then one length per string, as observed.
	lengths = binary.LittleEndian.AppendUint32(lengths, uint32(len(strs)))
	for _, s := range strs {
		lengths = binary.LittleEndian.AppendUint32(lengths, uint32(len([]rune(s))+1))
	}

	body := make([]byte, 0, 32)
	body = append(body, 0, 0) // size
	body = append(body, 0x00, 0x00)
	body = append(body, lengths...)
	for _, s := range strs {
		body = append(body, utf16Bytes(s)...)
		body = append(body, 0, 0)
	}
	body = append(body, 0, 0)
	return withSize(body)
}

// Unknown builds a well-formed shell item of a type Tracefall does not
// decode, for testing that an unrecognized item is reported as such
// rather than as corruption.
func Unknown(typeByte byte, payload []byte) []byte {
	body := make([]byte, 0, 3+len(payload))
	body = append(body, 0, 0)
	body = append(body, typeByte)
	body = append(body, payload...)
	return withSize(body)
}

// List concatenates items and appends the two-byte terminator, which is
// how a BagMRU value's data is laid out.
func List(items ...[]byte) []byte {
	var out []byte
	for _, it := range items {
		out = append(out, it...)
	}
	return append(out, 0, 0)
}

// CorruptSize rewrites an item's declared size, for testing that a size
// inconsistent with the buffer is rejected rather than followed.
func CorruptSize(item []byte, size uint16) []byte {
	out := make([]byte, len(item))
	copy(out, item)
	if len(out) >= 2 {
		binary.LittleEndian.PutUint16(out[0:2], size)
	}
	return out
}

// Truncate shortens an item.
func Truncate(item []byte, keep int) []byte {
	if keep < 0 {
		keep = 0
	}
	if keep > len(item) {
		keep = len(item)
	}
	out := make([]byte, keep)
	copy(out, item[:keep])
	return out
}

// MRUListEx builds the value of that name: little-endian int32 indices
// in most-recently-used order, terminated by 0xFFFFFFFF.
func MRUListEx(order ...uint32) []byte {
	out := make([]byte, 0, 4*(len(order)+1))
	for _, i := range order {
		out = binary.LittleEndian.AppendUint32(out, i)
	}
	return binary.LittleEndian.AppendUint32(out, 0xFFFFFFFF)
}

// withSize writes the item's total length into its first two bytes.
func withSize(body []byte) []byte {
	binary.LittleEndian.PutUint16(body[0:2], uint16(len(body)))
	return body
}

// dosDateTime encodes a wall-clock reading as a FAT date/time pair. A
// zero time encodes as all zeros -- an unset field.
func dosDateTime(t time.Time) (date, dosTime uint16) {
	if t.IsZero() {
		return 0, 0
	}
	date = uint16((t.Year()-1980)<<9) | uint16(int(t.Month())<<5) | uint16(t.Day())
	dosTime = uint16(t.Hour()<<11) | uint16(t.Minute()<<5) | uint16(t.Second()/2)
	return date, dosTime
}

func utf16Bytes(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	return out
}

// guidBytes converts "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" to its
// 16-byte little-endian form.
func guidBytes(s string) []byte {
	hex := strings.NewReplacer("{", "", "}", "", "-", "").Replace(s)
	raw := make([]byte, 16)
	for i := 0; i < 16 && i*2+1 < len(hex); i++ {
		raw[i] = hexByte(hex[i*2])<<4 | hexByte(hex[i*2+1])
	}
	out := make([]byte, 16)
	// First three components are little-endian, the last two are not.
	out[0], out[1], out[2], out[3] = raw[3], raw[2], raw[1], raw[0]
	out[4], out[5] = raw[5], raw[4]
	out[6], out[7] = raw[7], raw[6]
	copy(out[8:], raw[8:])
	return out
}

func hexByte(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}
