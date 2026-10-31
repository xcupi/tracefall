package wmirepo

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
)

// ClassCoverage distinguishes absence of indexed instances from missing schema.
type ClassCoverage struct {
	NamespaceID, Class, Status string
	Indexed, Decoded           int
}
type Snapshot struct {
	Objects      []Instance
	Coverage     []ClassCoverage
	NamespaceIDs []string
}

// SemanticReader uses only active literal index identities and mapped records.
type SemanticReader struct {
	Keys       []IndexKey
	ReadRecord func(string) (Record, error)
}

func nameID(prefix, name string) string {
	var b []byte
	for _, u := range utf16.Encode([]rune(strings.ToUpper(name))) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return fmt.Sprintf("%s%X", prefix, sha256.Sum256(b))
}
func hashID(id, prefix string) bool {
	if !strings.HasPrefix(id, prefix) || len(id) != len(prefix)+64 {
		return false
	}
	return strings.IndexFunc(id[len(prefix):], func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'A' && r <= 'F') }) < 0
}
func selectedClasses() []string {
	return []string{"__EventFilter", "__FilterToConsumerBinding", "CommandLineEventConsumer", "ActiveScriptEventConsumer", "NTEventLogEventConsumer", "LogFileEventConsumer", "SMTPEventConsumer"}
}
func (s SemanticReader) ReadSelected() (Snapshot, error) {
	out := Snapshot{}
	if s.ReadRecord == nil || len(s.Keys) > 250000 {
		return out, fmt.Errorf("%w: semantic index input", ErrUnsupported)
	}
	namespaces := map[string]bool{}
	definitions := map[string][]string{}
	instances := map[string][]string{}
	seen := map[string]bool{}
	selected := map[string]bool{}
	for _, cls := range selectedClasses() {
		selected[nameID("CI_", cls)] = true
	}
	keyBytes := 0
	for _, key := range s.Keys {
		keyBytes += len(key.Key)
		if keyBytes > 32<<20 {
			return out, fmt.Errorf("%w: semantic key byte cap", ErrUnsupported)
		}
		if seen[key.Key] {
			return out, fmt.Errorf("%w: duplicate semantic index key", ErrCorrupt)
		}
		seen[key.Key] = true
		parts := strings.Split(key.Key, "/")
		if len(parts) < 2 || !strings.HasPrefix(parts[0], "NS_") {
			continue
		}
		if !hashID(parts[0], "NS_") {
			return out, fmt.Errorf("%w: namespace identity", ErrCorrupt)
		}
		namespaces[parts[0]] = true
		if len(namespaces) > 4096 {
			return out, fmt.Errorf("%w: namespace count cap", ErrUnsupported)
		}
		if len(parts) == 2 {
			id := strings.Split(parts[1], ".")[0]
			if strings.HasPrefix(id, "CD_") {
				if !hashID(id, "CD_") {
					return out, fmt.Errorf("%w: class identity", ErrCorrupt)
				}
				definitions[parts[0]+"/"+id] = append(definitions[parts[0]+"/"+id], key.Key)
			}
		}
		if selected[parts[1]] {
			if len(parts) != 3 || !hashID(strings.Split(parts[2], ".")[0], "IL_") {
				return out, fmt.Errorf("%w: selected instance identity", ErrCorrupt)
			}
			instances[parts[0]+"/"+parts[1]] = append(instances[parts[0]+"/"+parts[1]], key.Key)
		}
	}
	for ns := range namespaces {
		out.NamespaceIDs = append(out.NamespaceIDs, ns)
	}
	sort.Strings(out.NamespaceIDs)
	totalBytes := 0
	valueBudget := byteBudget{limit: 64 << 20}
	// Unlike the per-layout cache, these limits cover the entire snapshot,
	// including repeated inherited/schema reads across namespaces/classes.
	schemaBudget := byteBudget{limit: 32 << 20}
	schemaReads := 0
	for _, ns := range out.NamespaceIDs {
		for _, cls := range selectedClasses() {
			keys := instances[ns+"/"+nameID("CI_", cls)]
			sort.Strings(keys)
			coverage := ClassCoverage{NamespaceID: ns, Class: cls, Indexed: len(keys), Status: "schema_unavailable"}
			cache := map[string]ClassDefinition{}
			cacheBytes := 0
			load := func(name string) (ClassDefinition, error) {
				if c, ok := cache[name]; ok {
					return c, nil
				}
				candidates := definitions[ns+"/"+nameID("CD_", name)]
				if len(candidates) == 0 {
					candidates = definitions[nameID("NS_", "__SystemClass")+"/"+nameID("CD_", name)]
				}
				if len(candidates) != 1 {
					return ClassDefinition{}, fmt.Errorf("%w: selected class schema missing or ambiguous", ErrUnsupported)
				}
				if schemaReads >= 4096 {
					return ClassDefinition{}, fmt.Errorf("%w: aggregate schema read count cap", ErrUnsupported)
				}
				schemaReads++
				r, err := s.ReadRecord(candidates[0])
				if err != nil {
					return ClassDefinition{}, err
				}
				if err := schemaBudget.charge(len(r.Bytes)); err != nil {
					return ClassDefinition{}, fmt.Errorf("%w: aggregate schema read byte cap", err)
				}
				cacheBytes += len(r.Bytes)
				if cacheBytes > 32<<20 || len(cache) >= 64 {
					return ClassDefinition{}, fmt.Errorf("%w: class schema byte/count cap", ErrUnsupported)
				}
				c, err := DecodeClass(r, candidates[0])
				if err != nil {
					return c, err
				}
				if c.Name != name {
					return c, fmt.Errorf("%w: indexed class identity disagreement", ErrCorrupt)
				}
				cache[name] = c
				return c, nil
			}
			defs := definitions[ns+"/"+nameID("CD_", cls)]
			systemDefs := definitions[nameID("NS_", "__SystemClass")+"/"+nameID("CD_", cls)]
			if len(defs) == 0 && len(systemDefs) == 0 && len(keys) == 0 {
				out.Coverage = append(out.Coverage, coverage)
				continue
			}
			layout, err := BuildLayout(cls, load)
			if err != nil {
				out.Coverage = append(out.Coverage, coverage)
				return out, err
			}
			coverage.Status = "no_indexed_instances"
			for _, key := range keys {
				if len(out.Objects) >= 10000 {
					return out, fmt.Errorf("%w: selected object count cap", ErrUnsupported)
				}
				r, err := s.ReadRecord(key)
				if err != nil {
					return out, err
				}
				totalBytes += len(r.Bytes)
				if totalBytes > 32<<20 {
					return out, fmt.Errorf("%w: selected record byte cap", ErrUnsupported)
				}
				o, err := DecodeInstance(r, key, layout)
				if err != nil {
					return out, err
				}
				for _, prop := range o.Properties {
					if err := valueBudget.charge(128 + len(prop.RawSlot)); err != nil {
						return out, err
					}
					for _, span := range prop.ValueSpans {
						if err := valueBudget.charge(48 + span.Length); err != nil {
							return out, err
						}
					}
				}
				out.Objects = append(out.Objects, o)
				coverage.Decoded++
				coverage.Status = "decoded"
			}
			out.Coverage = append(out.Coverage, coverage)
		}
	}
	if len(out.NamespaceIDs) == 0 {
		return out, fmt.Errorf("%w: no recognized indexed namespace", ErrUnsupported)
	}
	for _, coverage := range out.Coverage {
		if coverage.Status != "schema_unavailable" {
			return out, nil
		}
	}
	return out, fmt.Errorf("%w: no recognized selected class schema", ErrUnsupported)
}
