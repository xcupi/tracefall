// Package prefetchgen builds synthetic Windows Prefetch (.pf) files in
// memory, for TEST FIXTURES ONLY.
//
// Real Prefetch files carry the names and paths of software actually run
// on a real machine, so they cannot be committed. Every file produced
// here is invented -- see testdata/native_samples/README.md.
//
// It emits the same structures a real file uses (SCCA header,
// version-specific file information, NUL-separated UTF-16 filename
// strings, volume information), because a fixture that avoided them
// would not test the reader that has to handle them.
//
// It lives outside internal/prefetch so no production code can import a
// Prefetch writer by accident.
package prefetchgen

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// File describes the synthetic Prefetch file to build.
type File struct {
	// Version selects the format: 17, 23, 26, 30 or 31.
	Version        uint32
	ExecutableName string // e.g. "CMD.EXE"
	PrefetchHash   uint32
	RunCount       uint32
	// LastRunTimes are written most-recent-first. Versions 17 and 23
	// record only the first; 26 and later record up to eight.
	LastRunTimes []time.Time
	// Filenames are the referenced full paths.
	Filenames []string
	// VolumeDevicePath and VolumeSerial describe a single volume entry.
	VolumeDevicePath string
	VolumeSerial     uint32
	VolumeCreated    time.Time
}

const headerSize = 84

// fileInfoSize is the file-information section size per version, and
// runCountOffset / runTimeOffset mirror internal/prefetch's layout table.
func layout(version uint32) (size, runTimeOffset, runTimeCount, runCountOffset int) {
	switch version {
	case 17:
		return 68, 36, 1, 60
	case 23:
		return 156, 44, 1, 68
	default: // 26, 30, 31
		return 212, 44, 8, 124
	}
}

func volumeEntrySize(version uint32) int {
	switch version {
	case 17:
		return 40
	case 23, 26:
		return 104
	default:
		return 96
	}
}

// Build serializes a complete Prefetch file.
func Build(f File) []byte {
	if f.Version == 0 {
		f.Version = 30
	}
	fiSize, runTimeOffset, runTimeCount, runCountOffset := layout(f.Version)

	// Layout: header | file information | filename strings | volume info.
	fiStart := headerSize
	stringsStart := fiStart + fiSize

	var strings []byte
	for _, name := range f.Filenames {
		strings = append(strings, encodeUTF16(name)...)
		strings = append(strings, 0x00, 0x00) // NUL terminator
	}
	volumesStart := stringsStart + len(strings)

	// One volume entry, followed by its device path string.
	vSize := volumeEntrySize(f.Version)
	volume := make([]byte, vSize)
	devicePath := encodeUTF16(f.VolumeDevicePath)
	binary.LittleEndian.PutUint32(volume[0:4], uint32(vSize)) // path offset, relative to the volume section
	binary.LittleEndian.PutUint32(volume[4:8], uint32(len([]rune(f.VolumeDevicePath))))
	binary.LittleEndian.PutUint64(volume[8:16], toFileTime(f.VolumeCreated))
	binary.LittleEndian.PutUint32(volume[16:20], f.VolumeSerial)
	volumeSection := append(volume, devicePath...)

	total := volumesStart + len(volumeSection)
	out := make([]byte, total)

	// Header.
	binary.LittleEndian.PutUint32(out[0:4], f.Version)
	copy(out[4:8], "SCCA")
	binary.LittleEndian.PutUint32(out[8:12], 0x11)
	binary.LittleEndian.PutUint32(out[12:16], uint32(total))
	copy(out[16:76], encodeUTF16(f.ExecutableName))
	binary.LittleEndian.PutUint32(out[76:80], f.PrefetchHash)

	// File information.
	fi := out[fiStart : fiStart+fiSize]
	binary.LittleEndian.PutUint32(fi[0:4], uint32(stringsStart)) // metrics array offset (unused by the reader)
	binary.LittleEndian.PutUint32(fi[4:8], uint32(len(f.Filenames)))
	binary.LittleEndian.PutUint32(fi[16:20], uint32(stringsStart))
	binary.LittleEndian.PutUint32(fi[20:24], uint32(len(strings)))
	binary.LittleEndian.PutUint32(fi[24:28], uint32(volumesStart))
	if f.VolumeDevicePath != "" {
		binary.LittleEndian.PutUint32(fi[28:32], 1)
	}
	binary.LittleEndian.PutUint32(fi[32:36], uint32(len(volumeSection)))
	for i := 0; i < runTimeCount && i < len(f.LastRunTimes); i++ {
		binary.LittleEndian.PutUint64(fi[runTimeOffset+i*8:runTimeOffset+i*8+8], toFileTime(f.LastRunTimes[i]))
	}
	binary.LittleEndian.PutUint32(fi[runCountOffset:runCountOffset+4], f.RunCount)

	copy(out[stringsStart:], strings)
	copy(out[volumesStart:], volumeSection)
	return out
}

// ---------- deliberately broken fixtures ----------

// Truncate cuts a file short, simulating an incomplete collection.
func Truncate(pf []byte, keep int) []byte {
	if keep > len(pf) {
		keep = len(pf)
	}
	out := make([]byte, keep)
	copy(out, pf)
	return out
}

// CorruptSignature replaces the SCCA magic.
func CorruptSignature(pf []byte) []byte {
	out := append([]byte(nil), pf...)
	copy(out[4:8], "XXXX")
	return out
}

// SetVersion rewrites the format version, for the unsupported-version path.
func SetVersion(pf []byte, version uint32) []byte {
	out := append([]byte(nil), pf...)
	binary.LittleEndian.PutUint32(out[0:4], version)
	return out
}

// CorruptFilenameOffset points the filename strings section outside the
// file -- the canonical "never trust an offset from the evidence" case.
func CorruptFilenameOffset(pf []byte) []byte {
	out := append([]byte(nil), pf...)
	version := binary.LittleEndian.Uint32(out[0:4])
	_, _, _, _ = layout(version)
	binary.LittleEndian.PutUint32(out[headerSize+16:headerSize+20], 0x7fffffff)
	return out
}

// Compressed wraps arbitrary bytes in a MAM header, producing the
// Windows 10/11 compressed form this reader deliberately refuses.
func Compressed(uncompressedSize uint32) []byte {
	out := make([]byte, 8, 64)
	copy(out[0:4], "MAM\x04")
	binary.LittleEndian.PutUint32(out[4:8], uncompressedSize)
	return append(out, make([]byte, 32)...)
}

// ---------- helpers ----------

func encodeUTF16(s string) []byte {
	var out []byte
	for _, r := range utf16.Encode([]rune(s)) {
		var t [2]byte
		binary.LittleEndian.PutUint16(t[:], r)
		out = append(out, t[:]...)
	}
	return out
}

func toFileTime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	const epochDelta = 11644473600
	return uint64((t.UTC().Unix()+epochDelta)*10_000_000) + uint64(t.Nanosecond()/100)
}
