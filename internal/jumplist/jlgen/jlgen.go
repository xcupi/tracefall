// Package jlgen builds synthetic Jump Lists in memory, for TEST
// FIXTURES ONLY.
//
// A real Jump List names a real person's documents and the applications
// they use, so one cannot be committed. This writes both containers as
// Windows writes them -- a compound file whose numbered streams hold
// embedded shortcuts beside a DestList, and a Custom Destinations file
// of shortcuts written back to back -- so the fixtures exercise the
// container handling rather than a simplified stand-in.
//
// It lives outside internal/jumplist so no production code can import a
// Jump List writer by accident.
package jlgen

import (
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"

	"tracefall/internal/olecf/olegen"
	"tracefall/internal/shelllink/lnkgen"
)

// Item is one Jump List entry to build.
type Item struct {
	// Link describes the embedded shortcut.
	Link lnkgen.Link
	// EntryNumber names the stream the shortcut goes in. Zero means
	// "use the item's position".
	EntryNumber uint32
	// AccessCount and LastAccess become the DestList row's own fields.
	AccessCount uint32
	LastAccess  time.Time
	Pinned      bool
	Hostname    string
	// DestPath is the path the DestList records. Empty copies the
	// shortcut's local base path, which is what Windows does.
	DestPath string
	// RawLink replaces the generated shortcut with these bytes, for
	// building a malformed embedded entry.
	RawLink []byte
	// OmitStream writes the DestList row without its shortcut stream.
	OmitStream bool
	// OmitDestList writes the shortcut stream without a DestList row.
	OmitDestList bool
}

// Automatic describes an Automatic Destinations file to build.
type Automatic struct {
	// DestListVersion is 1 (Windows 7) or 3/4 (Windows 10). Zero means 3.
	DestListVersion uint32
	Items           []Item
	// DeclaredEntries overrides the count written in the DestList
	// header, for testing a header that disagrees with its rows.
	DeclaredEntries int
	// OmitDestList writes no DestList stream at all.
	OmitDestList bool
}

// BuildAutomatic assembles an Automatic Destinations compound file.
func BuildAutomatic(a Automatic) []byte {
	version := a.DestListVersion
	if version == 0 {
		version = 3
	}

	var streams []olegen.Stream
	var rows []Item
	for i, it := range a.Items {
		n := it.EntryNumber
		if n == 0 {
			n = uint32(i + 1)
		}
		it.EntryNumber = n
		if !it.OmitStream {
			data := it.RawLink
			if data == nil {
				data = lnkgen.Build(it.Link)
			}
			streams = append(streams, olegen.Stream{Name: fmt.Sprintf("%x", n), Data: data})
		}
		if !it.OmitDestList {
			rows = append(rows, it)
		}
	}
	if !a.OmitDestList {
		streams = append(streams, olegen.Stream{Name: "DestList", Data: buildDestList(version, rows, a.DeclaredEntries)})
	}
	return olegen.Build(streams)
}

// buildDestList writes the DestList stream for the given rows.
func buildDestList(version uint32, items []Item, declaredOverride int) []byte {
	declared := len(items)
	if declaredOverride != 0 {
		declared = declaredOverride
	}
	pinned := 0
	for _, it := range items {
		if it.Pinned {
			pinned++
		}
	}

	out := make([]byte, 32)
	binary.LittleEndian.PutUint32(out[0:4], version)
	binary.LittleEndian.PutUint32(out[4:8], uint32(declared))
	binary.LittleEndian.PutUint32(out[8:12], uint32(pinned))
	binary.LittleEndian.PutUint32(out[16:20], uint32(len(items)))

	fixed, trailing := 0x70, 0
	if version >= 3 {
		fixed, trailing = 0x80, 4
	}
	for _, it := range items {
		path := it.DestPath
		if path == "" {
			path = it.Link.LocalBasePath
		}
		u := utf16.Encode([]rune(path))
		row := make([]byte, fixed+2+len(u)*2+trailing)
		copy(row[0x48:0x58], it.Hostname)
		binary.LittleEndian.PutUint32(row[0x58:0x5C], it.EntryNumber)
		binary.LittleEndian.PutUint32(row[0x60:0x64], it.AccessCount)
		binary.LittleEndian.PutUint64(row[0x64:0x6C], toFileTime(it.LastAccess))
		if it.Pinned {
			binary.LittleEndian.PutUint32(row[0x6C:0x70], 0)
		} else {
			binary.LittleEndian.PutUint32(row[0x6C:0x70], 0xFFFFFFFF)
		}
		binary.LittleEndian.PutUint16(row[fixed:fixed+2], uint16(len(u)))
		for i, c := range u {
			binary.LittleEndian.PutUint16(row[fixed+2+i*2:], c)
		}
		out = append(out, row...)
	}
	return out
}

// BuildCustom assembles a Custom Destinations file: a short header
// followed by embedded shortcuts written back to back, which is how the
// real format is laid out.
func BuildCustom(links []lnkgen.Link) []byte {
	// The real header is a version word plus counts. Its exact meaning
	// is not decoded by the reader, so the fixture writes a plausible
	// one rather than pretending to more precision than that.
	out := make([]byte, 24)
	binary.LittleEndian.PutUint32(out[0:4], 2) // version
	binary.LittleEndian.PutUint32(out[16:20], uint32(len(links)))
	for _, l := range links {
		out = append(out, lnkgen.Build(l)...)
	}
	// The format's trailing marker.
	out = append(out, 0xAB, 0xFB, 0xBF, 0xBA)
	return out
}

// BuildCustomRaw assembles a Custom Destinations file from pre-built
// shortcut bytes, so a malformed entry can be placed among valid ones.
func BuildCustomRaw(blobs [][]byte) []byte {
	out := make([]byte, 24)
	binary.LittleEndian.PutUint32(out[0:4], 2)
	binary.LittleEndian.PutUint32(out[16:20], uint32(len(blobs)))
	for _, b := range blobs {
		out = append(out, b...)
	}
	out = append(out, 0xAB, 0xFB, 0xBF, 0xBA)
	return out
}

// CorruptDestList rewrites the DestList version in a built Automatic
// Destinations file. The stream is located by its content rather than by
// a fixed offset, since the layout depends on how many items were built.
func CorruptDestListVersion(data []byte, version uint32) []byte {
	out := append([]byte(nil), data...)
	// The DestList stream begins with its version word followed by an
	// entry count; find the one this fixture wrote.
	for i := 512; i+8 <= len(out); i += 64 {
		v := binary.LittleEndian.Uint32(out[i : i+4])
		if v == 1 || v == 3 || v == 4 {
			binary.LittleEndian.PutUint32(out[i:i+4], version)
			return out
		}
	}
	return out
}

func toFileTime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	const epochDelta = 11644473600
	return uint64(t.UTC().Unix()+epochDelta)*10_000_000 + uint64(t.Nanosecond()/100)
}
