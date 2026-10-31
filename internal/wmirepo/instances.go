// Modified native Go adaptation of mandiant/flare-wmi python-cim/cim,
// revision b0a5a094ff9ca7d7a1c4fc711dc00c74dec4b6b1 (Apache-2.0).
// Changes include bounded readers, strict validation and physical provenance.
// See NOTICE.txt and LICENSE.apache-2.0.txt in this directory.
package wmirepo

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// Layout is a root-to-leaf chain with validated dense packed properties.
type Layout struct {
	Classes    []ClassDefinition
	Properties []PropertyDefinition
	SlotLength int
}

func BuildLayout(name string, load func(string) (ClassDefinition, error)) (Layout, error) {
	out := Layout{}
	seen := map[string]bool{}
	for current := name; current != ""; {
		id := strings.ToLower(current)
		if seen[id] || len(seen) >= 64 {
			return out, fmt.Errorf("%w: inheritance cycle/depth", ErrCorrupt)
		}
		seen[id] = true
		c, err := load(current)
		if err != nil {
			return out, err
		}
		if c.Name != current {
			return out, fmt.Errorf("%w: class identity mismatch", ErrCorrupt)
		}
		out.Classes = append(out.Classes, c)
		current = c.Super
	}
	if len(out.Classes) == 0 {
		return out, fmt.Errorf("%w: empty layout", ErrCorrupt)
	}
	for i, j := 0, len(out.Classes)-1; i < j; i, j = i+1, j-1 {
		out.Classes[i], out.Classes[j] = out.Classes[j], out.Classes[i]
	}
	props := map[int]PropertyDefinition{}
	for _, c := range out.Classes {
		for _, p := range c.Properties {
			if old, ok := props[p.Index]; ok {
				if old.Name != p.Name || old.Type != p.Type || old.Offset != p.Offset {
					return out, fmt.Errorf("%w: incompatible property override", ErrUnsupported)
				}
				p.Key = p.Key || old.Key
			}
			props[p.Index] = p
		}
		if len(props) > 4096 {
			return out, fmt.Errorf("%w: layout property cap", ErrUnsupported)
		}
		ordered := make([]PropertyDefinition, 0, len(props))
		for _, p := range props {
			ordered = append(ordered, p)
		}
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].Index < ordered[j].Index })
		length := 0
		names := map[string]bool{}
		for i, p := range ordered {
			if p.Index != i || p.Offset != length {
				return out, fmt.Errorf("%w: non-dense or non-packed layout", ErrUnsupported)
			}
			lower := strings.ToLower(p.Name)
			if names[lower] {
				return out, fmt.Errorf("%w: duplicate inherited name", ErrCorrupt)
			}
			names[lower] = true
			w, err := slotWidth(p.Type)
			if err != nil {
				return out, err
			}
			length += w
		}
		if len(c.Defaults) != (len(ordered)+3)/4+length {
			return out, fmt.Errorf("%w: class defaults layout length", ErrCorrupt)
		}
		out.Properties = ordered
		out.SlotLength = length
	}
	return out, nil
}

type PropertyValue struct {
	Type                                                 CIMType
	Index, LayoutOffset                                  int
	StateBits                                            byte
	Presence                                             string
	Value                                                any
	RawSlot                                              []byte
	StateSpans, SlotSpans, ValueSpans, DefaultStateSpans []Span
	DefaultClassNativeKey                                string
}
type Instance struct {
	Class, NativeKey, NameHash string
	TimestampTicks             [2]uint64
	Properties                 map[string]PropertyValue
	KeyProperties              map[string]any
	Record                     Record
}

func DecodeInstance(record Record, nativeKey string, layout Layout) (Instance, error) {
	out := Instance{NativeKey: nativeKey, Record: record, Properties: map[string]PropertyValue{}, KeyProperties: map[string]any{}}
	if len(layout.Classes) == 0 || len(layout.Properties) > 4096 || layout.SlotLength < 0 || layout.SlotLength > 32768 {
		return out, fmt.Errorf("%w: invalid instance layout", ErrCorrupt)
	}
	if len(record.Bytes) > MaxRecord {
		return out, fmt.Errorf("%w: instance record size", ErrUnsupported)
	}
	c := cursor{b: record.Bytes}
	hash := c.take(128)
	if c.err != nil {
		return out, c.err
	}
	var err error
	out.NameHash, err = unicodeName(hash)
	if err != nil {
		return out, fmt.Errorf("%w: non-Win7 instance hash", ErrUnsupported)
	}
	if len(out.NameHash) != 64 || strings.IndexFunc(out.NameHash, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'A' && r <= 'F') }) >= 0 {
		return out, fmt.Errorf("%w: instance hash encoding", ErrUnsupported)
	}
	ticks := c.take(16)
	if c.err != nil {
		return out, c.err
	}
	out.TimestampTicks = [2]uint64{binary.LittleEndian.Uint64(ticks), binary.LittleEndian.Uint64(ticks[8:])}
	size := c.u32()
	classRef := c.u32()
	c.take(1)
	if c.err != nil {
		return out, c.err
	}
	if uint64(size) != uint64(len(c.b)-144) {
		return out, fmt.Errorf("%w: instance length mismatch", ErrCorrupt)
	}
	stateBase := c.at
	states := c.take((len(layout.Properties) + 3) / 4)
	slotBase := c.at
	slots := c.take(layout.SlotLength)
	if c.err != nil {
		return out, c.err
	}
	if _, err = readQualifiers(&c); err != nil {
		return out, err
	}
	dyn := c.take(1)
	if c.err != nil {
		return out, c.err
	}
	if dyn[0] != 1 {
		return out, fmt.Errorf("%w: dynamic instance properties", ErrUnsupported)
	}
	region, regionBase := c.region()
	if c.err != nil {
		return out, c.err
	}
	if c.at != len(c.b) {
		return out, fmt.Errorf("%w: instance trailing layout", ErrUnsupported)
	}
	out.Class, _, err = wmiString(region, int(classRef))
	if err != nil {
		return out, err
	}
	if out.Class != layout.Classes[len(layout.Classes)-1].Name {
		return out, fmt.Errorf("%w: instance class identity", ErrCorrupt)
	}
	decodedBytes := 0
	for _, p := range layout.Properties {
		if p.Index < 0 || p.Index >= len(layout.Properties) {
			return out, fmt.Errorf("%w: property state index", ErrCorrupt)
		}
		state := states[p.Index/4] >> uint(2*(p.Index%4)) & 3
		v := PropertyValue{Type: p.Type, Index: p.Index, LayoutOffset: p.Offset, StateBits: state, Presence: "uninitialized"}
		v.StateSpans, err = Project(record.Spans, stateBase+p.Index/4, 1)
		if err != nil {
			return out, err
		}
		if state&1 == 0 {
			w, e := slotWidth(p.Type)
			if e != nil {
				return out, e
			}
			origin := record
			valueRegion, valueBase := region, regionBase
			at := slotBase + p.Offset
			if p.Offset < 0 || p.Offset > len(slots)-w {
				return out, fmt.Errorf("%w: instance property slot", ErrCorrupt)
			}
			raw := slots[p.Offset : p.Offset+w]
			v.Presence = "explicit"
			if state&2 != 0 {
				v.Presence = "default"
				found := false
				for i := len(layout.Classes) - 1; i >= 0; i-- {
					ancestor := layout.Classes[i]
					count := 0
					for j := 0; j <= i; j++ {
						for _, decl := range layout.Classes[j].Properties {
							count = max(count, decl.Index+1)
						}
					}
					if p.Index >= count {
						continue
					}
					stateLength := (count + 3) / 4
					if len(ancestor.Defaults) < stateLength {
						return out, fmt.Errorf("%w: default state vector", ErrCorrupt)
					}
					ds := ancestor.Defaults[p.Index/4] >> uint(2*(p.Index%4)) & 3
					if ds&1 != 0 {
						return out, fmt.Errorf("%w: requested default unavailable", ErrCorrupt)
					}
					if ds&2 != 0 {
						continue
					}
					off := stateLength + p.Offset
					if off < 0 || off > len(ancestor.Defaults)-w {
						return out, fmt.Errorf("%w: default slot bounds", ErrCorrupt)
					}
					raw = ancestor.Defaults[off : off+w]
					origin = ancestor.Record
					valueRegion, valueBase = ancestor.Region, ancestor.RegionOffset
					at = ancestor.DefaultsOffset + off
					v.DefaultClassNativeKey = ancestor.NativeKey
					v.DefaultStateSpans, err = Project(origin.Spans, ancestor.DefaultsOffset+p.Index/4, 1)
					if err != nil {
						return out, err
					}
					found = true
					break
				}
				if !found {
					return out, fmt.Errorf("%w: default origin unavailable", ErrCorrupt)
				}
			}
			decoded, e := DecodeValue(valueRegion, raw, p.Type)
			if e != nil {
				return out, e
			}
			decodedBytes += w + 48*len(decoded.ValueOffsets)
			for _, span := range decoded.ValueOffsets {
				decodedBytes += span.Length
			}
			if decodedBytes > 16<<20 {
				return out, fmt.Errorf("%w: decoded instance value byte budget", ErrUnsupported)
			}
			v.Value = decoded.Value
			v.RawSlot = append([]byte(nil), raw...)
			v.SlotSpans, err = Project(origin.Spans, at, w)
			if err != nil {
				return out, err
			}
			for _, s := range decoded.ValueOffsets {
				spans, e := Project(origin.Spans, valueBase+s.Offset, s.Length)
				if e != nil {
					return out, e
				}
				v.ValueSpans = append(v.ValueSpans, spans...)
			}
		}
		out.Properties[p.Name] = v
		if p.Key {
			if v.Presence == "uninitialized" {
				return out, fmt.Errorf("%w: uninitialized instance key", ErrCorrupt)
			}
			out.KeyProperties[p.Name] = v.Value
		}
	}
	return out, nil
}
