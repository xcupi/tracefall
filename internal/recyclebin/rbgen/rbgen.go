// Package rbgen builds synthetic Recycle Bin $I records in memory, for
// TEST FIXTURES ONLY.
//
// A real $I names a real person's deleted file, so one cannot be
// committed. This emits both record versions exactly as Windows lays
// them out -- version 1's fixed 260-character path field and version 2's
// length-prefixed one -- because the difference between them is the
// thing the reader has to get right.
//
// It lives outside internal/recyclebin so no production code can import
// a record writer by accident.
package rbgen

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// Record describes an $I record to build.
type Record struct {
	// Version is 1 (Vista-8.1) or 2 (Windows 10+). Zero means 2.
	Version uint64
	// Size is the deleted file's original size.
	Size uint64
	// Deleted is the deletion time. Zero writes a zero FILETIME.
	Deleted time.Time
	// Path is the original full path.
	Path string
	// PathCharsOverride writes a different character count than the path
	// actually has, for testing a corrupt length field. Version 2 only.
	PathCharsOverride uint32
	// RawFileTime overrides the deletion timestamp with a raw value, for
	// testing implausible dates.
	RawFileTime uint64
	HasRawTime  bool
}

// Build assembles one $I record.
func Build(r Record) []byte {
	version := r.Version
	if version == 0 {
		version = 2
	}
	out := make([]byte, 24)
	binary.LittleEndian.PutUint64(out[0:8], version)
	binary.LittleEndian.PutUint64(out[8:16], r.Size)
	ft := toFileTime(r.Deleted)
	if r.HasRawTime {
		ft = r.RawFileTime
	}
	binary.LittleEndian.PutUint64(out[16:24], ft)

	u := utf16.Encode([]rune(r.Path))
	switch version {
	case 1:
		// A fixed 260-character field, NUL-terminated and zero-padded.
		field := make([]byte, 260*2)
		for i, c := range u {
			if i >= 259 {
				break
			}
			binary.LittleEndian.PutUint16(field[i*2:i*2+2], c)
		}
		return append(out, field...)
	default:
		n := uint32(len(u) + 1) // the count includes the terminator
		if r.PathCharsOverride != 0 {
			n = r.PathCharsOverride
		}
		lenField := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenField, n)
		out = append(out, lenField...)
		body := make([]byte, (len(u)+1)*2)
		for i, c := range u {
			binary.LittleEndian.PutUint16(body[i*2:i*2+2], c)
		}
		return append(out, body...)
	}
}

// Truncate cuts a record short, as a partially recovered file would be.
func Truncate(data []byte, n int) []byte {
	if n >= len(data) {
		return data
	}
	return append([]byte(nil), data[:n]...)
}

// WithVersion rewrites the version word, for testing an unsupported one.
func WithVersion(data []byte, version uint64) []byte {
	out := append([]byte(nil), data...)
	if len(out) >= 8 {
		binary.LittleEndian.PutUint64(out[0:8], version)
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
