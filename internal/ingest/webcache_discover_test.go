package ingest

import (
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/ese/esegen"
	"tracefall/internal/model"
)

func TestDiscover_WebCacheIsReadOnlyWhenItIsAnESEDatabase(t *testing.T) {
	root := t.TempDir()
	ese := esegen.Build([]esegen.Table{{Name: "Containers", Columns: []esegen.Column{{ID: 1, Name: "ContainerId", Type: esegen.Int64}}}}, esegen.Options{})
	put := func(rel string, b []byte) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put("Users/a/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat", ese)
	put("Users/b/AppData/Local/Microsoft/Windows/WebCache/WebCacheV24.dat", ese)
	put("Users/c/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat", []byte("this is not a database"))
	put("Users/d/Local Settings/History/index.dat", []byte("Client UrlCache MMF Ver 5.2"))
	files, err := Discover(root, Registry())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]DiscoveredFile{}
	for _, f := range files {
		by[filepath.ToSlash(f.Path)] = f
	}
	for _, p := range []string{"Users/a/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat", "Users/b/AppData/Local/Microsoft/Windows/WebCache/WebCacheV24.dat"} {
		if f := by[p]; !f.Supported || f.Parser != "webcache@1" || f.ArtifactType != model.ArtifactWebCache {
			t.Errorf("%s: %+v", p, f)
		}
	}
	if f := by["Users/c/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat"]; f.Parser == "webcache@1" || f.Supported {
		t.Errorf("a WebCacheV01.dat that is not ESE was claimed: %+v", f)
	}
	if f := by["Users/d/Local Settings/History/index.dat"]; f.Parser == "webcache@1" || f.Supported {
		t.Errorf("the old index.dat format was claimed: %+v", f)
	}
}
