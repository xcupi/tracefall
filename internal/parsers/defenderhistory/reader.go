// Package defenderhistory reads the bounded modern DetectionHistory LTV subset.
// Positional field names describe reverse-engineered evidence, not execution.
package defenderhistory

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

const MaxFileBytes = 1 << 20
const MaxEntries = 4096
const MaxResources = 128
const MaxNestedValues = 4096

type Entry struct {
	Offset  int
	End     int
	Type    uint32
	Raw     []byte
	Padding []byte
	Text    string
	Bits    uint64
}

// ReadEntries consumes the entire source, including final zero padding. On any
// error no partial entries are returned. Raw and Padding alias the input bytes.
func ReadEntries(data []byte) ([]Entry, error) {
	if len(data) == 0 || len(data) > MaxFileBytes {
		return nil, fmt.Errorf("history: size outside 1..%d bytes", MaxFileBytes)
	}
	var out []Entry
	for pos := 0; pos < len(data); {
		start := pos
		if len(out) >= MaxEntries || len(data)-pos < 8 {
			return nil, fmt.Errorf("history: entry cap or short header at %d", pos)
		}
		n := uint64(binary.LittleEndian.Uint32(data[pos:]))
		typ := binary.LittleEndian.Uint32(data[pos+4:])
		pos += 8
		padded := (n + 7) &^ uint64(7)
		if padded > uint64(len(data)-pos) {
			return nil, fmt.Errorf("history: payload/padding bounds at %d", start)
		}
		raw := data[pos : pos+int(n)]
		padding := data[pos+int(n) : pos+int(padded)]
		for _, v := range padding {
			if v != 0 {
				return nil, fmt.Errorf("history: nonzero padding at %d", start)
			}
		}
		e := Entry{Offset: start, End: pos + int(padded), Type: typ, Raw: raw, Padding: padding}
		width := 0
		switch typ {
		case 0, 5, 6:
			width = 4
		case 8, 10:
			width = 8
		case 30:
			width = 16
		case 21:
			s, err := decodeWide(raw)
			if err != nil {
				return nil, fmt.Errorf("history: UTF16 at %d: %w", start, err)
			}
			e.Text = s
		case 40:
		default:
			return nil, fmt.Errorf("history: unsupported type %d at %d", typ, start)
		}
		if width != 0 && len(raw) != width {
			return nil, fmt.Errorf("history: type %d width at %d", typ, start)
		}
		if width == 4 {
			e.Bits = uint64(binary.LittleEndian.Uint32(raw))
		}
		if width == 8 {
			e.Bits = binary.LittleEndian.Uint64(raw)
		}
		out = append(out, e)
		pos = e.End
	}
	return out, nil
}

func decodeWide(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("odd byte length")
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u >= 0xd800 && u <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", fmt.Errorf("unpaired surrogate")
			}
			i++
		} else if u >= 0xdc00 && u <= 0xdfff {
			return "", fmt.Errorf("unpaired surrogate")
		}
	}
	if len(units) > 0 && units[len(units)-1] == 0 {
		units = units[:len(units)-1]
	}
	return string(utf16.Decode(units)), nil
}
