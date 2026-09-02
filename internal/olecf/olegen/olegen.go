// Package olegen builds synthetic Compound File containers in memory,
// for TEST FIXTURES ONLY.
//
// A real Jump List names a real person's documents, so one cannot be
// committed. This writes the same structures Windows writes -- a 512-byte
// header, a FAT, a directory, and a mini FAT with the small streams
// packed into the root entry's mini stream -- because the mini stream is
// exactly where a Jump List keeps its LNK records, and a fixture that
// skipped it would leave that code path untested.
//
// It lives outside internal/olecf so no production code can import a
// compound-file writer by accident.
package olegen

import (
	"encoding/binary"
	"unicode/utf16"
)

const (
	sectorSize        = 512
	miniSectorSize    = 64
	dirEntryBytes     = 128
	miniCutoff        = 4096
	endOfChain        = 0xFFFFFFFE
	freeSect          = 0xFFFFFFFF
	fatSect           = 0xFFFFFFFD
	entriesPerSect    = sectorSize / dirEntryBytes
	fatEntriesPerSect = sectorSize / 4
)

// Stream is one named stream to place in the container.
type Stream struct {
	Name string
	Data []byte
}

// Build assembles a version-3 compound file holding the given streams.
//
// Every stream is written into the MINI stream, which is what Windows
// does for anything under 4096 bytes and therefore what a real Jump List
// looks like.
func Build(streams []Stream) []byte {
	// --- lay the mini stream out first ---
	var mini []byte
	miniStarts := make([]uint32, len(streams))
	miniChains := make([][]uint32, len(streams))
	next := uint32(0)
	for i, s := range streams {
		miniStarts[i] = next
		n := (len(s.Data) + miniSectorSize - 1) / miniSectorSize
		if n == 0 {
			n = 1
		}
		chain := make([]uint32, 0, n)
		for j := 0; j < n; j++ {
			chain = append(chain, next)
			next++
		}
		miniChains[i] = chain
		padded := make([]byte, n*miniSectorSize)
		copy(padded, s.Data)
		mini = append(mini, padded...)
	}

	// --- the mini FAT ---
	miniFAT := make([]uint32, next)
	for i := range miniFAT {
		miniFAT[i] = endOfChain
	}
	for _, chain := range miniChains {
		for j := 0; j < len(chain)-1; j++ {
			miniFAT[chain[j]] = chain[j+1]
		}
		miniFAT[chain[len(chain)-1]] = endOfChain
	}

	// --- sector layout: mini stream, mini FAT, directory, FAT ---
	miniSectors := sectorsFor(len(mini))
	miniFATBytes := make([]byte, len(miniFAT)*4)
	for i, v := range miniFAT {
		binary.LittleEndian.PutUint32(miniFATBytes[i*4:], v)
	}
	miniFATSectors := sectorsFor(len(miniFATBytes))

	dir := buildDirectory(streams, miniStarts, uint32(len(mini)))
	dirSectors := sectorsFor(len(dir))

	miniStart := uint32(0)
	miniFATStart := miniStart + uint32(miniSectors)
	dirStart := miniFATStart + uint32(miniFATSectors)
	fatStart := dirStart + uint32(dirSectors)
	total := int(fatStart) + 1

	// --- the FAT ---
	fat := make([]uint32, fatEntriesPerSect)
	for i := range fat {
		fat[i] = freeSect
	}
	link := func(start uint32, count int) {
		for i := 0; i < count; i++ {
			if int(start)+i >= len(fat) {
				return
			}
			if i == count-1 {
				fat[int(start)+i] = endOfChain
			} else {
				fat[int(start)+i] = start + uint32(i) + 1
			}
		}
	}
	link(miniStart, miniSectors)
	link(miniFATStart, miniFATSectors)
	link(dirStart, dirSectors)
	fat[fatStart] = fatSect

	// --- assemble ---
	out := make([]byte, sectorSize+total*sectorSize)
	h := out[:sectorSize]
	copy(h[0:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(h[0x18:], 0x003E) // minor version
	binary.LittleEndian.PutUint16(h[0x1A:], 3)      // major version
	binary.LittleEndian.PutUint16(h[0x1C:], 0xFFFE) // little-endian
	binary.LittleEndian.PutUint16(h[0x1E:], 9)      // 512-byte sectors
	binary.LittleEndian.PutUint16(h[0x20:], 6)      // 64-byte mini sectors
	binary.LittleEndian.PutUint32(h[0x28:], 0)      // directory sector count (v3: 0)
	binary.LittleEndian.PutUint32(h[0x2C:], 1)      // FAT sector count
	binary.LittleEndian.PutUint32(h[0x30:], dirStart)
	binary.LittleEndian.PutUint32(h[0x38:], miniCutoff)
	binary.LittleEndian.PutUint32(h[0x3C:], miniFATStart)
	binary.LittleEndian.PutUint32(h[0x40:], uint32(miniFATSectors))
	binary.LittleEndian.PutUint32(h[0x44:], endOfChain) // no DIFAT sectors
	binary.LittleEndian.PutUint32(h[0x48:], 0)
	// DIFAT: 109 entries at 0x4C, ending exactly at the 512-byte header
	// boundary. The first names the single FAT sector.
	binary.LittleEndian.PutUint32(h[0x4C:], fatStart)
	for i := 1; i < 109; i++ {
		binary.LittleEndian.PutUint32(h[0x4C+i*4:], freeSect)
	}

	put := func(startSector uint32, data []byte) {
		off := sectorSize + int(startSector)*sectorSize
		copy(out[off:], data)
	}
	put(miniStart, mini)
	put(miniFATStart, miniFATBytes)
	put(dirStart, dir)

	fatBytes := make([]byte, sectorSize)
	for i, v := range fat {
		binary.LittleEndian.PutUint32(fatBytes[i*4:], v)
	}
	put(fatStart, fatBytes)
	return out
}

// buildDirectory writes the root entry plus one stream entry each.
//
// The entries are chained as a flat right-leaning list under the root,
// which is a valid red-black tree shape for a reader that walks
// siblings, and is what keeps the fixture simple without being
// unrealistic.
func buildDirectory(streams []Stream, miniStarts []uint32, miniSize uint32) []byte {
	count := len(streams) + 1
	sectors := sectorsFor(count * dirEntryBytes)
	out := make([]byte, sectors*sectorSize)
	for i := range out {
		out[i] = 0
	}
	// Unallocated entries must declare type 0, which zeroing already
	// gives, but their sibling pointers must be -1.
	for i := 0; i < len(out)/dirEntryBytes; i++ {
		e := out[i*dirEntryBytes:]
		binary.LittleEndian.PutUint32(e[0x44:], 0xFFFFFFFF)
		binary.LittleEndian.PutUint32(e[0x48:], 0xFFFFFFFF)
		binary.LittleEndian.PutUint32(e[0x4C:], 0xFFFFFFFF)
	}

	writeEntry := func(index int, name string, objType byte, child, right int32, start uint32, size uint64) {
		e := out[index*dirEntryBytes : (index+1)*dirEntryBytes]
		u := utf16.Encode([]rune(name))
		if len(u) > 31 {
			u = u[:31]
		}
		for i, c := range u {
			binary.LittleEndian.PutUint16(e[i*2:], c)
		}
		binary.LittleEndian.PutUint16(e[0x40:], uint16((len(u)+1)*2))
		e[0x42] = objType
		e[0x43] = 1 // black
		binary.LittleEndian.PutUint32(e[0x44:], 0xFFFFFFFF)
		binary.LittleEndian.PutUint32(e[0x48:], uint32(right))
		binary.LittleEndian.PutUint32(e[0x4C:], uint32(child))
		binary.LittleEndian.PutUint32(e[0x74:], start)
		binary.LittleEndian.PutUint64(e[0x78:], size)
	}

	firstChild := int32(-1)
	if len(streams) > 0 {
		firstChild = 1
	}
	writeEntry(0, "Root Entry", 5, firstChild, -1, 0, uint64(miniSize))
	for i, s := range streams {
		right := int32(-1)
		if i+2 <= len(streams) {
			right = int32(i + 2)
		}
		writeEntry(i+1, s.Name, 2, -1, right, miniStarts[i], uint64(len(s.Data)))
	}
	return out
}

func sectorsFor(n int) int {
	if n == 0 {
		return 1
	}
	return (n + sectorSize - 1) / sectorSize
}

// Truncate cuts a container short, as a partially recovered file is.
func Truncate(data []byte, n int) []byte {
	if n >= len(data) {
		return data
	}
	return append([]byte(nil), data[:n]...)
}

// Corrupt damages a container in a named way.
func Corrupt(data []byte, how string) []byte {
	out := append([]byte(nil), data...)
	if len(out) < sectorSize {
		return out
	}
	switch how {
	case "signature":
		out[3] ^= 0xFF
	case "byte-order":
		binary.LittleEndian.PutUint16(out[0x1C:], 0x1234)
	case "version":
		binary.LittleEndian.PutUint16(out[0x1A:], 9)
	case "sector-shift":
		binary.LittleEndian.PutUint16(out[0x1E:], 20)
	case "mini-shift":
		binary.LittleEndian.PutUint16(out[0x20:], 11)
	case "fat-count":
		binary.LittleEndian.PutUint32(out[0x2C:], 0x7FFFFFFF)
	case "dir-start":
		binary.LittleEndian.PutUint32(out[0x30:], 0x00FFFFF0)
	case "minifat-start":
		binary.LittleEndian.PutUint32(out[0x3C:], 0x00FFFFF0)
	}
	return out
}
