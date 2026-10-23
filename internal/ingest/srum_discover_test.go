package ingest

import (
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/ese/esegen"
	"tracefall/internal/model"
)

func TestDiscover_SRUDBIsReadOnlyWhenItIsAnESEDatabase(t *testing.T) {
	root := t.TempDir()
	ese := esegen.Build([]esegen.Table{{Name: "SruDbIdMapTable", Columns: []esegen.Column{{ID: 1, Name: "IdType", Type: esegen.Uint8}}}}, esegen.Options{})
	put := func(rel string, b []byte) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put("Windows/System32/sru/SRUDB.dat", ese)
	put("Other/sru/SRUDB.dat", []byte("this is not a database"))
	put("Users/a/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat", ese)
	files, err := Discover(root, Registry())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]DiscoveredFile{}
	for _, f := range files {
		by[filepath.ToSlash(f.Path)] = f
	}
	if f := by["Windows/System32/sru/SRUDB.dat"]; !f.Supported || f.Parser != "srum@1" || f.ArtifactType != model.ArtifactSRUM {
		t.Errorf("SRUDB.dat that is an ESE database: %+v", f)
	}
	if f := by["Other/sru/SRUDB.dat"]; f.Parser == "srum@1" || f.Supported {
		t.Errorf("a file named SRUDB.dat that is not ESE was claimed: %+v", f)
	}
	if f := by["Users/a/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat"]; f.Parser == "srum@1" || f.Supported {
		t.Errorf("another ESE database was read as SRUM: %+v", f)
	}
}
