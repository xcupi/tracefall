package wmirepo

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func publicPhysical(t *testing.T) (Physical, []IndexKey) {
	t.Helper()
	dir := os.Getenv("TRACEFALL_REAL_WMI_REPOSITORY")
	proof := os.Getenv("TRACEFALL_REAL_WMI_PROTOTYPE")
	if dir == "" || proof == "" {
		t.Skip("set TRACEFALL_REAL_WMI_REPOSITORY and TRACEFALL_REAL_WMI_PROTOTYPE for pinned public parity")
	}
	hashes := map[string]string{
		"INDEX.BTR":    "e8ead6077adef0f76a396fd67ac927904488332cac21aa4b4f938ed3d31466c7",
		"OBJECTS.DATA": "00e69cf03327b57a8ab39c6807c2c51f168881d899487e0567b0652318caf232",
		"MAPPING1.MAP": "979bfbab082cacb7b55d5f8f5141ed4f3bd3235905f3afe246293e07c9742f1d",
		"MAPPING2.MAP": "8cb1d364b1291cb38ef5275fbda5fb79e2e237b33057009fcc95207571148d36",
		"MAPPING3.MAP": "d4df3f53fc230ff7d57d865d6f8d97233dcce97d64bf034969bcbed883f6088d",
	}
	files := map[string]File{}
	for name, want := range hashes {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		h := sha256.New()
		size, err := io.Copy(h, f)
		if err != nil || fmt.Sprintf("%x", h.Sum(nil)) != want {
			t.Fatalf("public hash mismatch: %s", name)
		}
		files[name] = File{f, size}
	}
	candidates := []MappingCandidate{}
	for _, name := range []string{"MAPPING1.MAP", "MAPPING2.MAP", "MAPPING3.MAP"} {
		dm, end, err := ReadMapping(files[name], 0)
		if err != nil {
			t.Fatal(err)
		}
		im, _, err := ReadMapping(files[name], end)
		if err != nil {
			t.Fatal(err)
		}
		candidates = append(candidates, MappingCandidate{Name: name, Data: dm, Index: im})
	}
	chosen, err := SelectMapping(candidates)
	if err != nil {
		t.Fatal(err)
	}
	p := Physical{Data: files["OBJECTS.DATA"], Index: files["INDEX.BTR"], DataMap: chosen.Data, IndexMap: chosen.Index, MapName: chosen.Name}
	keys, err := p.ReadIndex()
	if err != nil {
		t.Fatal(err)
	}
	return p, keys
}

func TestPublicPhysicalParity(t *testing.T) {
	p, keys := publicPhysical(t)
	proof := os.Getenv("TRACEFALL_REAL_WMI_PROTOTYPE")
	b, err := os.ReadFile(proof)
	if err != nil {
		t.Fatal(err)
	}
	var expected struct {
		IndexKeys int `json:"index_keys"`
		Objects   []struct {
			NativeKey string `json:"native_key"`
			SHA256    string `json:"record_sha256"`
			Spans     []Span `json:"record_spans"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(b, &expected); err != nil {
		t.Fatal(err)
	}
	if len(keys) != expected.IndexKeys || len(expected.Objects) != 3 {
		t.Fatalf("public census mismatch: keys=%d expected=%d objects=%d", len(keys), expected.IndexKeys, len(expected.Objects))
	}
	indexed := map[string]bool{}
	for _, k := range keys {
		indexed[k.Key] = true
	}
	for _, o := range expected.Objects {
		if !indexed[o.NativeKey] {
			t.Fatal("prototype native identity missing from active index")
		}
		r, err := p.ReadRecord(o.NativeKey)
		if err != nil {
			t.Fatal(err)
		}
		if r.SHA256 != o.SHA256 || len(r.Spans) != len(o.Spans) {
			t.Fatal("prototype record digest/extent mismatch")
		}
		for i, s := range o.Spans {
			if r.Spans[i] != s {
				t.Fatal("prototype physical span mismatch")
			}
		}
	}
	t.Logf("native active keys=%d selected public objects=%d mapping=%s", len(keys), len(expected.Objects), p.MapName)
}
