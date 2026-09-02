// Package lnkgen builds synthetic Windows shortcuts in memory, for TEST
// FIXTURES ONLY.
//
// A real .lnk carries a real person's paths and a real machine name, so
// one cannot be committed. This emits the same on-disk structures
// Windows writes -- the fixed header and CLSID, the ID list, LinkInfo
// with its internal offsets, and the CountCharacters string chain -- so
// a fixture exercises the offset arithmetic the reader has to survive.
//
// It lives outside internal/shelllink so no production code can import a
// shortcut writer by accident.
package lnkgen

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

const headerSize = 0x4C

var clsid = []byte{
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

// Link describes a shortcut to build.
type Link struct {
	// Flags is the LinkFlags word. Build sets the presence bits for the
	// structures actually requested, so callers normally leave this zero
	// and set Unicode instead.
	Flags          uint32
	Unicode        bool
	FileAttributes uint32
	Creation       time.Time
	Access         time.Time
	Write          time.Time
	FileSize       uint32
	IconIndex      int32
	ShowCommand    uint32
	HotKey         uint16

	// StringData. Empty means the flag is not set and the string is not
	// written -- which is how a real shortcut omits one.
	Name         string
	RelativePath string
	WorkingDir   string
	Arguments    string
	IconLocation string

	// LinkInfo.
	LocalBasePath    string
	CommonPathSuffix string
	DriveType        uint32
	VolumeSerial     uint32
	VolumeLabel      string
	NetName          string
	OmitLinkInfo     bool

	// LinkTargetIDList.
	IDList []Item

	// TrackerMachineID writes an ExtraData TrackerDataBlock.
	TrackerMachineID string
}

// Item is one shell item for the ID list.
type Item struct {
	// Kind is "volume", "file", "dir" or "root".
	Kind     string
	Name     string
	Size     uint32
	Modified time.Time
	Attrs    uint16
	GUID     []byte
}

// Build assembles a complete shortcut.
func Build(l Link) []byte {
	flags := l.Flags
	if l.Unicode {
		flags |= 1 << 7
	}
	if len(l.IDList) > 0 {
		flags |= 1 << 0
	}
	if !l.OmitLinkInfo && (l.LocalBasePath != "" || l.NetName != "") {
		flags |= 1 << 1
	}
	for i, s := range []string{l.Name, l.RelativePath, l.WorkingDir, l.Arguments, l.IconLocation} {
		if s != "" {
			flags |= 1 << uint(2+i)
		}
	}

	out := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(out[0:4], headerSize)
	copy(out[4:20], clsid)
	binary.LittleEndian.PutUint32(out[20:24], flags)
	binary.LittleEndian.PutUint32(out[24:28], l.FileAttributes)
	binary.LittleEndian.PutUint64(out[28:36], toFileTime(l.Creation))
	binary.LittleEndian.PutUint64(out[36:44], toFileTime(l.Access))
	binary.LittleEndian.PutUint64(out[44:52], toFileTime(l.Write))
	binary.LittleEndian.PutUint32(out[52:56], l.FileSize)
	binary.LittleEndian.PutUint32(out[56:60], uint32(l.IconIndex))
	show := l.ShowCommand
	if show == 0 {
		show = 1
	}
	binary.LittleEndian.PutUint32(out[60:64], show)
	binary.LittleEndian.PutUint16(out[64:66], l.HotKey)

	if len(l.IDList) > 0 {
		out = append(out, buildIDList(l.IDList)...)
	}
	if flags&(1<<1) != 0 {
		out = append(out, buildLinkInfo(l)...)
	}
	for _, s := range []string{l.Name, l.RelativePath, l.WorkingDir, l.Arguments, l.IconLocation} {
		if s == "" {
			continue
		}
		out = append(out, buildStringData(s, l.Unicode)...)
	}
	if l.TrackerMachineID != "" {
		out = append(out, buildTrackerBlock(l.TrackerMachineID)...)
	}
	// Terminal ExtraData block.
	out = append(out, 0, 0, 0, 0)
	return out
}

func buildStringData(s string, unicode bool) []byte {
	if unicode {
		u := utf16.Encode([]rune(s))
		b := make([]byte, 2+len(u)*2)
		binary.LittleEndian.PutUint16(b[0:2], uint16(len(u)))
		for i, c := range u {
			binary.LittleEndian.PutUint16(b[2+i*2:4+i*2], c)
		}
		return b
	}
	b := make([]byte, 2+len(s))
	binary.LittleEndian.PutUint16(b[0:2], uint16(len(s)))
	copy(b[2:], s)
	return b
}

func buildIDList(items []Item) []byte {
	var body []byte
	for _, it := range items {
		body = append(body, buildShellItem(it)...)
	}
	body = append(body, 0, 0) // terminal ID
	out := make([]byte, 2)
	binary.LittleEndian.PutUint16(out[0:2], uint16(len(body)))
	return append(out, body...)
}

func buildShellItem(it Item) []byte {
	var b []byte
	switch it.Kind {
	case "root":
		b = make([]byte, 20)
		b[2] = 0x1F
		if len(it.GUID) == 16 {
			copy(b[4:20], it.GUID)
		}
	case "volume":
		b = make([]byte, 3+len(it.Name)+1)
		b[2] = 0x2F
		copy(b[3:], it.Name)
	default: // file / dir
		b = make([]byte, 14+len(it.Name)+1)
		b[2] = 0x32
		if it.Kind == "dir" {
			b[2] = 0x31
		}
		binary.LittleEndian.PutUint32(b[4:8], it.Size)
		binary.LittleEndian.PutUint32(b[8:12], toDOSDateTime(it.Modified))
		binary.LittleEndian.PutUint16(b[12:14], it.Attrs)
		copy(b[14:], it.Name)
	}
	binary.LittleEndian.PutUint16(b[0:2], uint16(len(b)))
	return b
}

// buildLinkInfo writes the structure with the extended (0x24) header, so
// both the ANSI and the unicode offset fields are exercised.
func buildLinkInfo(l Link) []byte {
	const hdr = 0x24
	var tail []byte
	addANSI := func(s string) int {
		off := hdr + len(tail)
		tail = append(tail, []byte(s)...)
		tail = append(tail, 0)
		return off
	}

	var volOff, localOff, netOff, suffixOff int
	var flags uint32
	if l.LocalBasePath != "" {
		flags |= 1 << 0
		// VolumeID first, then the local base path.
		label := l.VolumeLabel
		vol := make([]byte, 16+len(label)+1)
		binary.LittleEndian.PutUint32(vol[0:4], uint32(len(vol)))
		binary.LittleEndian.PutUint32(vol[4:8], l.DriveType)
		binary.LittleEndian.PutUint32(vol[8:12], l.VolumeSerial)
		binary.LittleEndian.PutUint32(vol[12:16], 16)
		copy(vol[16:], label)
		volOff = hdr + len(tail)
		tail = append(tail, vol...)
		localOff = addANSI(l.LocalBasePath)
	}
	if l.NetName != "" {
		flags |= 1 << 1
		net := make([]byte, 20+len(l.NetName)+1)
		binary.LittleEndian.PutUint32(net[0:4], uint32(len(net)))
		binary.LittleEndian.PutUint32(net[8:12], 20) // NetNameOffset
		copy(net[20:], l.NetName)
		netOff = hdr + len(tail)
		tail = append(tail, net...)
	}
	suffixOff = addANSI(l.CommonPathSuffix)

	out := make([]byte, hdr)
	binary.LittleEndian.PutUint32(out[0:4], uint32(hdr+len(tail)))
	binary.LittleEndian.PutUint32(out[4:8], hdr)
	binary.LittleEndian.PutUint32(out[8:12], flags)
	binary.LittleEndian.PutUint32(out[12:16], uint32(volOff))
	binary.LittleEndian.PutUint32(out[16:20], uint32(localOff))
	binary.LittleEndian.PutUint32(out[20:24], uint32(netOff))
	binary.LittleEndian.PutUint32(out[24:28], uint32(suffixOff))
	return append(out, tail...)
}

func buildTrackerBlock(machineID string) []byte {
	b := make([]byte, 0x60)
	binary.LittleEndian.PutUint32(b[0:4], 0x60)
	binary.LittleEndian.PutUint32(b[4:8], 0xA0000003)
	binary.LittleEndian.PutUint32(b[8:12], 0x58) // length
	binary.LittleEndian.PutUint32(b[12:16], 0)   // version
	copy(b[16:32], machineID)
	return b
}

// Truncate cuts a shortcut short, as a partially recovered file would be.
func Truncate(data []byte, n int) []byte {
	if n >= len(data) {
		return data
	}
	return append([]byte(nil), data[:n]...)
}

// Corrupt damages a shortcut in a named way.
func Corrupt(data []byte, how string) []byte {
	out := append([]byte(nil), data...)
	if len(out) < headerSize {
		return out
	}
	switch how {
	case "header-size":
		binary.LittleEndian.PutUint32(out[0:4], 0x50)
	case "clsid":
		out[10] ^= 0xFF
	case "huge-idlist":
		if len(out) > headerSize+2 {
			binary.LittleEndian.PutUint16(out[headerSize:headerSize+2], 0xFFFF)
		}
	case "huge-string-count":
		// The first StringData count. Only meaningful for a shortcut
		// built WITHOUT an ID list or LinkInfo, where StringData begins
		// immediately after the header -- writing at a fixed offset into
		// a shortcut that has them would land in an unrelated structure
		// and corrupt nothing the reader would notice.
		if len(out) > headerSize+2 {
			binary.LittleEndian.PutUint16(out[headerSize:headerSize+2], 0xFFFF)
		}
	}
	return out
}

func toFileTime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	const epochDelta = 11644473600
	return uint64((t.UTC().Unix()+epochDelta))*10_000_000 + uint64(t.Nanosecond()/100)
}

func toDOSDateTime(t time.Time) uint32 {
	if t.IsZero() {
		return 0
	}
	t = t.UTC()
	date := uint16((t.Year()-1980)<<9) | uint16(int(t.Month())<<5) | uint16(t.Day())
	tm := uint16(t.Hour()<<11) | uint16(t.Minute()<<5) | uint16(t.Second()/2)
	return uint32(date) | uint32(tm)<<16
}
