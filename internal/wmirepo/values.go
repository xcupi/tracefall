package wmirepo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf8"
)

// CIMType preserves the declared scalar type and array flag.
type CIMType struct {
	Code  uint8
	Array bool
}
type Value struct {
	Value        any
	ValueOffsets []struct{ Offset, Length int }
}

func scalarWidth(code uint8) (int, error) {
	switch code {
	case 16, 17:
		return 1, nil
	case 2, 11, 18:
		return 2, nil
	case 3, 4, 8, 19, 101, 102:
		return 4, nil
	case 5, 20, 21:
		return 8, nil
	default:
		return 0, fmt.Errorf("%w: CIM scalar type %d", ErrUnsupported, code)
	}
}
func DecodeValue(region, slot []byte, typ CIMType) (Value, error) {
	out := Value{}
	decodedBytes := 0
	width, err := scalarWidth(typ.Code)
	if err != nil {
		return out, err
	}
	offsets := func(offset, length int) {
		out.ValueOffsets = append(out.ValueOffsets, struct{ Offset, Length int }{offset, length})
	}
	var scalar func([]byte) (any, error)
	scalar = func(raw []byte) (any, error) {
		if len(raw) != width {
			return nil, fmt.Errorf("%w: CIM slot width", ErrCorrupt)
		}
		switch typ.Code {
		case 16:
			return int8(raw[0]), nil
		case 17:
			return raw[0], nil
		case 2:
			return int16(binary.LittleEndian.Uint16(raw)), nil
		case 18:
			return binary.LittleEndian.Uint16(raw), nil
		case 3:
			return int32(binary.LittleEndian.Uint32(raw)), nil
		case 19:
			return binary.LittleEndian.Uint32(raw), nil
		case 20:
			return int64(binary.LittleEndian.Uint64(raw)), nil
		case 21:
			return binary.LittleEndian.Uint64(raw), nil
		case 11:
			n := binary.LittleEndian.Uint16(raw)
			if n != 0 && n != 0xffff {
				return nil, fmt.Errorf("%w: noncanonical boolean", ErrUnsupported)
			}
			return n == 0xffff, nil
		case 4, 5:
			var f float64
			if typ.Code == 4 {
				f = float64(math.Float32frombits(binary.LittleEndian.Uint32(raw)))
			} else {
				f = math.Float64frombits(binary.LittleEndian.Uint64(raw))
			}
			if math.IsNaN(f) || math.IsInf(f, 0) {
				return nil, fmt.Errorf("%w: nonfinite CIM value", ErrUnsupported)
			}
			return f, nil
		case 8, 101, 102:
			ref := uint64(binary.LittleEndian.Uint32(raw))
			if ref >= uint64(len(region)) {
				return nil, fmt.Errorf("%w: string offset", ErrCorrupt)
			}
			start := int(ref)
			if region[start] != 0 {
				return nil, fmt.Errorf("%w: WMI string encoding", ErrUnsupported)
			}
			end := bytes.IndexByte(region[start+1:], 0)
			if end < 0 || !utf8.Valid(region[start+1:start+1+end]) {
				return nil, fmt.Errorf("%w: WMI string terminator/UTF8", ErrCorrupt)
			}
			if end > 4<<20-decodedBytes {
				return nil, fmt.Errorf("%w: decoded value byte budget", ErrUnsupported)
			}
			decodedBytes += end
			offsets(start, end+2)
			return string(region[start+1 : start+1+end]), nil
		}
		return nil, fmt.Errorf("%w: CIM scalar", ErrUnsupported)
	}
	if !typ.Array {
		out.Value, err = scalar(slot)
		return out, err
	}
	if len(slot) != 4 {
		return out, fmt.Errorf("%w: array reference width", ErrCorrupt)
	}
	ref := uint64(binary.LittleEndian.Uint32(slot))
	if ref > uint64(len(region)) || uint64(len(region))-ref < 4 {
		return out, fmt.Errorf("%w: array offset", ErrCorrupt)
	}
	start := int(ref)
	count := uint64(binary.LittleEndian.Uint32(region[start:]))
	if count > 65536 || count > uint64((len(region)-start-4)/width) {
		return out, fmt.Errorf("%w: array count/region", ErrCorrupt)
	}
	offsets(start, 4+int(count)*width)
	values := make([]any, 0, int(count))
	for i := 0; i < int(count); i++ {
		at := start + 4 + i*width
		value, e := scalar(region[at : at+width])
		if e != nil {
			return Value{}, e
		}
		values = append(values, value)
	}
	out.Value = values
	return out, nil
}
