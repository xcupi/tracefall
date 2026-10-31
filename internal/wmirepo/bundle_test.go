package wmirepo

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"tracefall/internal/wmitest"
)

func TestBundleNativeSyntheticSnapshotAndIntegrity(t *testing.T) {
	source := wmitest.Bundle("neutral-private-marker")
	files := map[string]File{}
	for name, b := range source {
		files[name] = file(b)
	}
	got, err := ReadBundle(files)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Snapshot.Objects) != 3 || len(got.Files) != 3 || got.MappingName != "MAPPING1.MAP" || got.MappingGeneration != 1 {
		t.Fatalf("bundle census/integrity: %+v", got)
	}
	for _, f := range got.Files {
		if f.SHA256 != fmt.Sprintf("%x", sha256.Sum256(source[f.Name])) || f.Size != int64(len(source[f.Name])) {
			t.Fatal("source digest mismatch")
		}
	}
	for _, o := range got.Snapshot.Objects {
		if len(o.Record.Spans) == 0 || o.Record.SHA256 == "" || o.TimestampTicks != ([2]uint64{}) {
			t.Fatal("native identity/span/ticks lost")
		}
	}
}
func TestBundleMissingOrUnsupportedIsNotSuccessfulZero(t *testing.T) {
	for _, missing := range []string{"OBJECTS.DATA", "INDEX.BTR", "MAPPING1.MAP"} {
		files := map[string]File{}
		for name, b := range wmitest.Bundle("") {
			if name != missing {
				files[name] = file(b)
			}
		}
		if _, err := ReadBundle(files); !errors.Is(err, ErrMissingBundle) {
			t.Fatalf("missing %s: %v", missing, err)
		}
	}
	files := map[string]File{}
	for name, b := range wmitest.Bundle("") {
		files[name] = file(b)
	}
	files["MAPPING4.MAP"] = file(nil)
	if _, err := ReadBundle(files); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unexpected file role: %v", err)
	}
}
