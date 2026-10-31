// Package wmitest builds small neutral repository bundles for integration tests.
// Bytes follow the documented Win7 layout and contain no external sample data.
package wmitest

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
)

const page = 8192

func u32(b []byte, vs ...uint32) []byte {
	for _, v := range vs {
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	return b
}
func id(prefix, name string) string {
	var b []byte
	for _, v := range utf16.Encode([]rune(strings.ToUpper(name))) {
		b = binary.LittleEndian.AppendUint16(b, v)
	}
	return fmt.Sprintf("%s%X", prefix, sha256.Sum256(b))
}
func text(b []byte, s string) ([]byte, uint32) {
	at := uint32(len(b))
	b = append(b, 0)
	b = append(b, s...)
	return append(b, 0), at
}

type prop struct {
	name, value string
	typ         uint32
	key         bool
}

func class(name string, props []prop) []byte {
	region, nameRef := text(nil, name)
	refs := []byte{}
	for i, p := range props {
		var nr uint32
		region, nr = text(region, p.name)
		mr := uint32(len(region))
		region = u32(region, p.typ)
		region = binary.LittleEndian.AppendUint16(region, uint16(i))
		region = u32(region, uint32(i*4), 0)
		if p.key {
			region = u32(region, 15, 0x80000001)
			region = append(region, 0)
			region = u32(region, 11)
			region = binary.LittleEndian.AppendUint16(region, 0xffff)
		} else {
			region = u32(region, 4)
		}
		refs = u32(refs, nr, mr)
	}
	states := (len(props) + 3) / 4
	defaults := make([]byte, states+len(props)*4)
	for i := range props {
		defaults[i/4] |= 1 << uint(2*(i%4))
	}
	b := u32(nil, 0, 0, 0, 0)
	b = append(b, 0)
	b = u32(b, nameRef, uint32(len(defaults)), 4, 4, uint32(len(props)))
	b = append(b, refs...)
	b = append(b, defaults...)
	b = u32(b, uint32(len(region)))
	b = append(b, region...)
	b = u32(b, 12, 0, 0x80000000)
	binary.LittleEndian.PutUint32(b[12:], uint32(len(b)-12))
	return b
}
func instance(name string, props []prop) []byte {
	b := make([]byte, 128)
	hash := id("", name)
	for i := range hash {
		b[i*2] = hash[i]
	}
	b = u32(b, 0, 0, 0, 0, 0, 0)
	b = append(b, 0)
	b = append(b, make([]byte, (len(props)+3)/4)...)
	region, _ := text(nil, name)
	for _, p := range props {
		var ref uint32
		region, ref = text(region, p.value)
		b = u32(b, ref)
	}
	b = u32(b, 4)
	b = append(b, 1)
	b = u32(b, uint32(len(region)))
	b = append(b, region...)
	binary.LittleEndian.PutUint32(b[144:], uint32(len(b)-144))
	return b
}

// Bundle contains exactly three configured objects, all undated. Marker is
// literal evidence used only to test raw retention and default privacy.
func Bundle(marker string) map[string][]byte {
	ns := id("NS_", `root\branch`)
	objects := []struct {
		name  string
		props []prop
	}{
		{"__EventFilter", []prop{{"Name", "filter01", 8, true}, {"Query", marker, 8, false}}},
		{"CommandLineEventConsumer", []prop{{"Name", "consumer01", 8, true}, {"CommandLineTemplate", marker, 8, false}}},
		{"__FilterToConsumerBinding", []prop{{"Filter", `__EventFilter.Name="filter01"`, 102, true}, {"Consumer", `CommandLineEventConsumer.Name="consumer01"`, 102, true}}},
	}
	records := map[string][]byte{}
	rid := uint32(1)
	for _, o := range objects {
		cd := class(o.name, o.props)
		records[fmt.Sprintf("%s/%s.0.%d.%d", ns, id("CD_", o.name), rid, len(cd))] = cd
		rid++
		ci := instance(o.name, o.props)
		records[fmt.Sprintf("%s/%s/%s.0.%d.%d", ns, id("CI_", o.name), id("IL_", o.name), rid, len(ci))] = ci
		rid++
	}
	keys := make([]string, 0, len(records))
	for k := range records {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	data := make([]byte, page)
	pos := (len(keys) + 1) * 16
	for i, k := range keys {
		parts := strings.Split(k, ".")
		var recID uint32
		fmt.Sscan(parts[2], &recID)
		r := records[k]
		copy(data[i*16:], u32(nil, recID, uint32(pos), uint32(len(r)), 0))
		copy(data[pos:], r)
		pos += len(r)
	}
	if pos > page {
		panic("neutral fixture exceeds one data page")
	}
	n := len(keys)
	node := u32(nil, 0xaccc, 1, 0, 0, uint32(n))
	for i := 0; i < n; i++ {
		node = u32(node, 0)
	}
	for i := 0; i <= n; i++ {
		node = u32(node, 0xffffffff)
	}
	for i := 0; i < n; i++ {
		node = binary.LittleEndian.AppendUint16(node, uint16(i*2))
	}
	node = binary.LittleEndian.AppendUint16(node, uint16(n*2))
	for i := 0; i < n; i++ {
		node = binary.LittleEndian.AppendUint16(node, 1)
		node = binary.LittleEndian.AppendUint16(node, uint16(i))
	}
	node = binary.LittleEndian.AppendUint16(node, uint16(n))
	off := 0
	for _, k := range keys {
		node = binary.LittleEndian.AppendUint16(node, uint16(off))
		off += len(k) + 1
	}
	node = binary.LittleEndian.AppendUint16(node, uint16(off))
	for _, k := range keys {
		node = append(node, k...)
		node = append(node, 0)
	}
	index := make([]byte, page*2)
	copy(index[page:], node)
	dm := u32(nil, 0xabcd, 1, 1, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0xdcba)
	im := u32(nil, 0xabcd, 1, 1, 2, 2, 2, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xdcba)
	return map[string][]byte{"OBJECTS.DATA": data, "INDEX.BTR": index, "MAPPING1.MAP": append(dm, im...)}
}
