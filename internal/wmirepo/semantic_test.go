package wmirepo

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"
)

func fixtureID(prefix, name string) string {
	var b []byte
	for _, u := range utf16.Encode([]rune(strings.ToUpper(name))) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return fmt.Sprintf("%s%X", prefix, sha256.Sum256(b))
}
func renamedClass(name string) Record {
	r := neutralClass()
	delta := len(name) - len("NeutralClass")
	regionBase := 66
	b := append([]byte(nil), r.Bytes[:regionBase+1]...)
	b = append(b, []byte(name)...)
	b = append(b, r.Bytes[regionBase+1+len("NeutralClass"):]...)
	for _, at := range []int{37, 41, 45, 49} {
		binary.LittleEndian.PutUint32(b[at:], uint32(int(binary.LittleEndian.Uint32(b[at:]))+delta))
	}
	binary.LittleEndian.PutUint32(b[regionBase-4:], uint32(int(binary.LittleEndian.Uint32(b[regionBase-4:]))+delta))
	binary.LittleEndian.PutUint32(b[12:], uint32(len(b)-12))
	r.Bytes = b
	r.Spans[0].Length = len(b)
	return r
}
func renamedInstance(name string) Record {
	r := neutralInstance(8)
	regionBase := 171
	delta := len(name) - len("NeutralClass")
	b := append([]byte(nil), r.Bytes[:regionBase+1]...)
	b = append(b, []byte(name)...)
	b = append(b, r.Bytes[regionBase+1+len("NeutralClass"):]...)
	binary.LittleEndian.PutUint32(b[154:], uint32(14+delta))
	binary.LittleEndian.PutUint32(b[regionBase-4:], uint32(int(binary.LittleEndian.Uint32(b[regionBase-4:]))+delta))
	binary.LittleEndian.PutUint32(b[144:], uint32(len(b)-144))
	r.Bytes = b
	r.Spans[0].Length = len(b)
	return r
}
func semanticFixture() (SemanticReader, map[string]Record) {
	records := map[string]Record{}
	keys := []IndexKey{}
	for _, ns := range []string{fixtureID("NS_", "root\\branch01"), fixtureID("NS_", "root\\branch02")} {
		cd := ns + "/" + fixtureID("CD_", "__EventFilter") + ".0.1.200"
		ci := ns + "/" + fixtureID("CI_", "__EventFilter") + "/IL_" + strings.Repeat("A", 64) + ".0.2.200"
		records[cd] = renamedClass("__EventFilter")
		records[ci] = renamedInstance("__EventFilter")
		keys = append(keys, IndexKey{Key: cd}, IndexKey{Key: ci})
	}
	return SemanticReader{Keys: keys, ReadRecord: func(key string) (Record, error) {
		r, ok := records[key]
		if !ok {
			return Record{}, ErrCorrupt
		}
		return r, nil
	}}, records
}
func TestSelectedClassesEnumerateNamespaceIDsWithoutGuesses(t *testing.T) {
	s, _ := semanticFixture()
	out, err := s.ReadSelected()
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Objects) != 2 || len(out.NamespaceIDs) != 2 || len(out.Coverage) != 14 {
		t.Fatalf("selected census: objects=%d namespaces=%d coverage=%d", len(out.Objects), len(out.NamespaceIDs), len(out.Coverage))
	}
	if out.Objects[0].NativeKey == out.Objects[1].NativeKey {
		t.Fatal("namespace identity collapsed")
	}
	decoded := 0
	unsupported := 0
	for _, c := range out.Coverage {
		if c.Decoded == 1 && c.Indexed == 1 && c.Class == "__EventFilter" {
			decoded++
		}
		if c.Status == "schema_unavailable" {
			unsupported++
		}
	}
	if decoded != 2 || unsupported != 12 {
		t.Fatalf("coverage: %+v", out.Coverage)
	}
}
func TestSelectedMissingAmbiguousSchemaAndIdentityFailClosed(t *testing.T) {
	for _, mode := range []string{"missing", "ambiguous", "wrongclass", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			s, records := semanticFixture()
			key := s.Keys[0].Key
			switch mode {
			case "missing":
				s.Keys = s.Keys[1:]
			case "ambiguous":
				s.Keys = append(s.Keys, IndexKey{Key: strings.TrimSuffix(key, ".0.1.200") + ".1.2.200"})
			case "wrongclass":
				records[key] = neutralClass()
			case "malformed":
				s.Keys[1].Key = strings.Replace(s.Keys[1].Key, "IL_A", "IL_Z", 1)
			}
			if _, err := s.ReadSelected(); err == nil {
				t.Fatal("invalid selected schema/identity silently accepted")
			}
		})
	}
}
