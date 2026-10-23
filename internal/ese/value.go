package ese

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
	"unicode/utf16"
)

// Int returns an integer column as int64 (unsigned types are zero-extended).
func (v Value) Int() int64 {
	if v.Null || v.Col == nil {
		return 0
	}
	b := v.Raw
	switch len(b) {
	case 1:
		return int64(b[0])
	case 2:
		if v.Col.Type == TypeInt16 {
			return int64(int16(binary.LittleEndian.Uint16(b)))
		}
		return int64(binary.LittleEndian.Uint16(b))
	case 4:
		if v.Col.Type == TypeInt32 {
			return int64(int32(binary.LittleEndian.Uint32(b)))
		}
		return int64(binary.LittleEndian.Uint32(b))
	case 8:
		return int64(binary.LittleEndian.Uint64(b))
	}
	return 0
}

// Float returns a float column.
func (v Value) Float() float64 {
	switch len(v.Raw) {
	case 4:
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(v.Raw)))
	case 8:
		return math.Float64frombits(binary.LittleEndian.Uint64(v.Raw))
	}
	return 0
}

// Text decodes a text column by its code page: 1200 is UTF-16LE, everything else
// (1252 and 20127) is read byte for byte as Latin-1, which is what both are for
// the characters Windows uses in them.
func (v Value) Text() string { return decodeText(v.Raw, v.Col) }

// DecodeText decodes b as the text of column c.
func DecodeText(b []byte, c *Column) string { return decodeText(b, c) }

func decodeText(b []byte, c *Column) string {
	if c != nil && c.Codepage == 1200 {
		u := make([]uint16, 0, len(b)/2)
		for i := 0; i+1 < len(b); i += 2 {
			u = append(u, binary.LittleEndian.Uint16(b[i:]))
		}
		return string(utf16.Decode(u))
	}
	return latin1(b)
}

// Time returns a DateTime column. A JET date-time is an 8-byte float of days
// since 1899-12-30 (the OLE Automation date). SRUM stores its timestamps this
// way; WebCache uses FILETIME in 64-bit integers instead, which Int gives.
// ok is false when the value is null or not a representable date.
func (v Value) Time() (time.Time, bool) {
	if v.Null || v.Col == nil || v.Col.Type != TypeDateTime || len(v.Raw) != 8 {
		return time.Time{}, false
	}
	d := v.Float()
	if math.IsNaN(d) || d < 1 || d > 2958465 {
		return time.Time{}, false
	}
	ms := math.Round(d * 86400 * 1000)
	return time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC).Add(time.Duration(ms) * time.Millisecond), true
}

// FileTime converts a Windows FILETIME to UTC; ok is false for zero or a value
// outside 1601..9999.
func FileTime(ft int64) (time.Time, bool) {
	if ft <= 0 {
		return time.Time{}, false
	}
	const epochDiff = 11644473600
	sec := ft/10000000 - epochDiff
	if sec < -62135596800 || sec > 253402300799 {
		return time.Time{}, false
	}
	return time.Unix(sec, (ft%10000000)*100).UTC(), true
}

const (
	compNone     = 0
	comp7ASCII   = 1
	comp7Uni     = 2
	compXpress   = 3
	compScrub    = 4
	compXpress9  = 5
	compXpress10 = 6
)

// decompress undoes ESE column compression. The first byte holds the scheme in
// its high five bits.
func decompress(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return b, nil
	}
	switch b[0] >> 3 {
	case compNone:
		return b, nil
	case comp7ASCII:
		return sevenBit(b[1:], false), nil
	case comp7Uni:
		return sevenBit(b[1:], true), nil
	case compXpress:
		if len(b) < 3 {
			return nil, fmt.Errorf("%w: xpress data is cut", ErrCorrupt)
		}
		return lzxpress(b[3:], int(binary.LittleEndian.Uint16(b[1:3])))
	case compXpress9, compXpress10:
		return nil, fmt.Errorf("%w: XPRESS9/XPRESS10 column compression", ErrUnsupported)
	}
	return nil, fmt.Errorf("%w: compression scheme %d", ErrUnsupported, b[0]>>3)
}

func sevenBit(src []byte, wide bool) []byte {
	dst := make([]byte, 0, len(src)*8/7+2)
	var val uint
	shift := 0
	put := func(c byte) {
		dst = append(dst, c)
		if wide {
			dst = append(dst, 0)
		}
	}
	for _, c := range src {
		val |= uint(c) << shift
		put(byte(val & 0x7F))
		val >>= 7
		shift++
		if shift == 7 {
			put(byte(val & 0x7F))
			val >>= 7
			shift = 0
		}
	}
	return dst
}

// lzxpress decodes the plain LZ77 variant Windows calls XPRESS (MS-XCA 2.3).
// hint is the size recorded in the compressed header and only bounds the output.
func lzxpress(src []byte, hint int) ([]byte, error) {
	const limit = maxValueBytes
	dst := make([]byte, 0, hint)
	bad := func(what string) ([]byte, error) { return nil, fmt.Errorf("%w: xpress %s", ErrCorrupt, what) }
	pos := 0
	var flags uint32
	flagCount := 0
	nibbleAt := -1
	for pos < len(src) {
		if flagCount == 0 {
			if pos+4 > len(src) {
				return bad("flags are cut")
			}
			flags = binary.LittleEndian.Uint32(src[pos:])
			pos += 4
			flagCount = 32
		}
		flagCount--
		if flags&(1<<uint(flagCount)) == 0 {
			if pos >= len(src) {
				return bad("literal is cut")
			}
			dst = append(dst, src[pos])
			pos++
			if len(dst) > limit {
				return bad("output is too large")
			}
			continue
		}
		if pos == len(src) {
			break
		}
		if pos+2 > len(src) {
			return bad("match is cut")
		}
		m := int(binary.LittleEndian.Uint16(src[pos:]))
		pos += 2
		off, length := m/8+1, m%8
		if length == 7 {
			if nibbleAt < 0 {
				if pos >= len(src) {
					return bad("length is cut")
				}
				nibbleAt = pos
				length = int(src[pos] % 16)
				pos++
			} else {
				length = int(src[nibbleAt] / 16)
				nibbleAt = -1
			}
			if length == 15 {
				if pos >= len(src) {
					return bad("length is cut")
				}
				length = int(src[pos])
				pos++
				if length == 255 {
					if pos+2 > len(src) {
						return bad("length is cut")
					}
					length = int(binary.LittleEndian.Uint16(src[pos:]))
					pos += 2
					if length == 0 {
						if pos+4 > len(src) {
							return bad("length is cut")
						}
						length = int(binary.LittleEndian.Uint32(src[pos:]))
						pos += 4
					}
					if length < 15+7 {
						return bad("match length is wrong")
					}
					length -= 15 + 7
				}
				length += 15
			}
			length += 7
		}
		length += 3
		if off > len(dst) {
			return bad("match reaches before the start")
		}
		if len(dst)+length > limit {
			return bad("output is too large")
		}
		for i := 0; i < length; i++ {
			dst = append(dst, dst[len(dst)-off])
		}
	}
	return dst, nil
}
