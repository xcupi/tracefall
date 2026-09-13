// Package uagen builds synthetic UserAssist value data for tests and for
// browser-verification fixtures.
//
// Entirely invented values. Nothing here is derived from real evidence,
// and no output should ever be presented as a real artifact.
//
// It is the WRITER counterpart to internal/userassist's reader: the two
// were built against the same field offsets, so a layout mistake shows
// up as a failing round-trip rather than as silently wrong evidence.
package uagen

import (
	"encoding/binary"
	"time"

	"tracefall/internal/userassist"
)

// Entry describes one synthetic UserAssist record.
type Entry struct {
	// SessionID, RunCount and LastExecuted are written as given.
	// RunCount is the RAW stored counter -- for a version 3 record the
	// reader subtracts the base of 5, so a test that wants "3 launches"
	// writes 8 here.
	SessionID    uint32
	RunCount     uint32
	LastExecuted time.Time

	// FocusCount and FocusTime are version 5 only and ignored otherwise.
	FocusCount uint32
	FocusTime  time.Duration
}

// BuildV5 writes the 72-byte Windows 7+ record.
func BuildV5(e Entry) []byte {
	b := make([]byte, 72)
	binary.LittleEndian.PutUint32(b[0:], e.SessionID)
	binary.LittleEndian.PutUint32(b[4:], e.RunCount)
	binary.LittleEndian.PutUint32(b[8:], e.FocusCount)
	binary.LittleEndian.PutUint32(b[12:], uint32(e.FocusTime.Milliseconds()))
	// The ten single-precision floats between the focus fields and the
	// timestamp are session telemetry the reader deliberately ignores.
	// Left as the 0xFFFFFFFF filler Windows commonly writes, so a reader
	// that started interpreting them would see the same thing real
	// evidence shows.
	for off := 16; off+4 <= 56; off += 4 {
		binary.LittleEndian.PutUint32(b[off:], 0xFFFFFFFF)
	}
	binary.LittleEndian.PutUint64(b[60:], toFileTime(e.LastExecuted))
	return b
}

// BuildV3 writes the 16-byte Windows XP-era record.
func BuildV3(e Entry) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:], e.SessionID)
	binary.LittleEndian.PutUint32(b[4:], e.RunCount)
	binary.LittleEndian.PutUint64(b[8:], toFileTime(e.LastExecuted))
	return b
}

// Name ROT13-encodes a path into the form a value name is stored in, so
// a fixture can be written in readable terms.
func Name(plain string) string { return userassist.ROT13(plain) }

// Truncate shortens a record, for testing a value that cannot be a
// complete record of any known layout.
func Truncate(data []byte, keep int) []byte {
	if keep < 0 {
		keep = 0
	}
	if keep > len(data) {
		keep = len(data)
	}
	out := make([]byte, keep)
	copy(out, data[:keep])
	return out
}

// toFileTime converts to a Windows FILETIME. A zero time writes a zero
// FILETIME, which is how "not recorded" appears in real evidence.
func toFileTime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	const epochDelta = 11644473600
	return uint64((t.UTC().Unix() + epochDelta)) * 10_000_000
}
