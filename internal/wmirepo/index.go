// Modified native Go adaptation of mandiant/flare-wmi python-cim/cim,
// revision b0a5a094ff9ca7d7a1c4fc711dc00c74dec4b6b1 (Apache-2.0).
// Changes include bounded readers, strict validation and physical provenance.
// See NOTICE.txt and LICENSE.apache-2.0.txt in this directory.
package wmirepo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"
)

// IndexKey retains the literal native identity and its source fragments.
type IndexKey struct {
	Key       string
	Fragments []Span
	Logical   uint32
}

func (p *Physical) ReadIndex() ([]IndexKey, error) {
	if len(p.IndexMap.Entries) == 0 {
		return nil, fmt.Errorf("%w: missing index mapping", ErrCorrupt)
	}
	out := []IndexKey{}
	budget := byteBudget{limit: 64 << 20}
	visited := map[uint32]bool{}
	keys := map[string]bool{}
	var walk func(uint32, int, string, string) error
	walk = func(logical uint32, depth int, low, high string) error {
		if logical == 0 || logical == 0xffffffff {
			return nil
		}
		if depth > 64 || visited[logical] || len(visited) >= len(p.IndexMap.Entries) || len(visited) >= 65536 {
			return fmt.Errorf("%w: index cycle/depth/count", ErrCorrupt)
		}
		visited[logical] = true
		b, physical, err := page(p.Index, p.IndexMap, logical)
		if err != nil {
			return err
		}
		u := func(off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
		n := int(u(16))
		if u(0) != 0xaccc || u(4) != logical || n > (PageSize-24)/10 {
			return fmt.Errorf("%w: active index header", ErrCorrupt)
		}
		pos := 20 + 4*n
		children := make([]uint32, n+1)
		for i := range children {
			children[i] = u(pos)
			pos += 4
		}
		take16 := func(count int) ([]uint16, error) {
			if count < 0 || count > (len(b)-pos)/2 {
				return nil, fmt.Errorf("%w: index table bounds", ErrCorrupt)
			}
			v := make([]uint16, count)
			for i := range v {
				v[i] = binary.LittleEndian.Uint16(b[pos:])
				pos += 2
			}
			return v, nil
		}
		ko, err := take16(n)
		if err != nil {
			return err
		}
		dc, err := take16(1)
		if err != nil {
			return err
		}
		defs, err := take16(int(dc[0]))
		if err != nil {
			return err
		}
		sc, err := take16(1)
		if err != nil {
			return err
		}
		so, err := take16(int(sc[0]) + 1)
		if err != nil {
			return err
		}
		node := make([]IndexKey, n)
		for i, di := range ko {
			d := int(di)
			if d >= len(defs) || int(defs[d]) > len(defs)-d-1 || defs[d] == 0 {
				return fmt.Errorf("%w: index key definition", ErrCorrupt)
			}
			parts := []string{}
			fragments := []Span{}
			for _, si := range defs[d+1 : d+1+int(defs[d])] {
				if int(si) >= len(so) {
					return fmt.Errorf("%w: index string ID", ErrCorrupt)
				}
				start := pos + int(so[si])
				if start < pos || start >= len(b) {
					return fmt.Errorf("%w: index string bounds", ErrCorrupt)
				}
				z := bytes.IndexByte(b[start:], 0)
				if z < 0 || !utf8.Valid(b[start:start+z]) {
					return fmt.Errorf("%w: index string encoding", ErrCorrupt)
				}
				parts = append(parts, string(b[start:start+z]))
				fragments = append(fragments, Span{File: "INDEX.BTR", Offset: physical + int64(start), Length: z + 1})
			}
			key := strings.Join(parts, "/")
			if keys[key] || (i > 0 && node[i-1].Key >= key) || (low != "" && key <= low) || (high != "" && key >= high) {
				return fmt.Errorf("%w: index duplicate/order", ErrCorrupt)
			}
			if len(keys) >= 250000 || len(key) > PageSize {
				return fmt.Errorf("%w: index key cap", ErrUnsupported)
			}
			if err := budget.charge(len(key) + 48*len(fragments)); err != nil {
				return err
			}
			keys[key] = true
			node[i] = IndexKey{Key: key, Fragments: fragments, Logical: logical}
		}
		for i, c := range children {
			l, h := low, high
			if i > 0 {
				l = node[i-1].Key
			}
			if i < n {
				h = node[i].Key
			}
			if err := walk(c, depth+1, l, h); err != nil {
				return err
			}
			if i < n {
				out = append(out, node[i])
			}
		}
		return nil
	}
	if err := walk(p.IndexMap.Entries[0][3], 0, "", ""); err != nil {
		return nil, err
	}
	return out, nil
}
