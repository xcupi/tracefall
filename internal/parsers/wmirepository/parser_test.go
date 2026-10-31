package wmirepository

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/wmirepo"
	"tracefall/internal/wmitest"
)

func materializedBundle(t *testing.T) (string, parsers.ParseContext) {
	t.Helper()
	root := t.TempDir()
	ctx := parsers.ParseContext{EvidenceRoot: root, EvidencePath: "stored-primary"}
	for role, b := range wmitest.Bundle("neutral-private-canary") {
		name := "stored-" + role
		if role == "OBJECTS.DATA" {
			name = "stored-primary"
		}
		if err := os.WriteFile(filepath.Join(root, name), b, 0600); err != nil {
			t.Fatal(err)
		}
		ctx.BundleFiles = append(ctx.BundleFiles, parsers.BundleFile{Role: role, Path: name, SourceFileID: "source-" + role})
	}
	return filepath.Join(root, "stored-primary"), ctx
}
func TestParserAdmittedStoredBundleKeepsPrivateRawUndated(t *testing.T) {
	abs, ctx := materializedBundle(t)
	got, err := New().ParseWithContext(abs, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Events) != 3 || len(got.Raw) != 3 || got.Coverage == nil || got.Coverage.Mapped != 3 || got.Coverage.Undated != 3 {
		t.Fatalf("census: %+v", got.Coverage)
	}
	refs := map[string]bool{}
	bindings := 0
	for i, e := range got.Events {
		if !e.Timestamp.IsZero() || e.EventType != model.EventWMISnapshot || e.ArtifactType != model.ArtifactWMIRepository || e.CommandLine != "" || e.ProcessPath != "" || e.FilePath != "" || e.Host != "" || e.User != "" {
			t.Fatal("configuration became execution/path/actor event")
		}
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), "neutral-private-canary") || strings.Contains(string(b), "filter01") || strings.Contains(string(b), "consumer01") || strings.Contains(string(b), ctx.EvidenceRoot) {
			t.Fatal("private literal or server root leaked")
		}
		if e.SourceReference == "" || refs[e.SourceReference] || got.Raw[i].SourceReference != e.SourceReference {
			t.Fatal("object identity/reference collapsed")
		}
		refs[e.SourceReference] = true
		if !strings.Contains(got.Raw[i].Raw, "source-INDEX.BTR") || !strings.Contains(got.Raw[i].Raw, "MAPPING1.MAP") {
			t.Fatal("registered companion provenance lost")
		}
		if e.Extra["wmi_class"] == "__FilterToConsumerBinding" {
			bindings++
			if e.Extra["filter_reference_status"] != "resolved" || e.Extra["consumer_reference_status"] != "resolved" {
				t.Fatal("decoded binding not persisted structurally")
			}
		}
	}
	raw, _ := json.Marshal(got.Raw)
	if !strings.Contains(string(raw), "neutral-private-canary") {
		t.Fatal("native private properties lost")
	}
	if bindings != 1 {
		t.Fatal("binding missing")
	}
}
func TestParserNoAdjacentFallbackAndContainedNoSymlinks(t *testing.T) {
	for _, mode := range []string{"nocontext", "missing", "duplicate", "escape", "symlink", "parentsymlink", "wrongprimary", "mismatchedhash"} {
		t.Run(mode, func(t *testing.T) {
			abs, ctx := materializedBundle(t)
			switch mode {
			case "nocontext":
				ctx = parsers.ParseContext{}
			case "missing":
				ctx.BundleFiles = ctx.BundleFiles[:1]
			case "duplicate":
				ctx.BundleFiles = append(ctx.BundleFiles, ctx.BundleFiles[0])
			case "escape":
				ctx.BundleFiles[0].Path = "../outside"
			case "symlink":
				member := ctx.BundleFiles[0]
				old := filepath.Join(ctx.EvidenceRoot, member.Path)
				other := filepath.Join(t.TempDir(), "source")
				if err := os.Rename(old, other); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, old); err != nil {
					t.Fatal(err)
				}
			case "parentsymlink":
				if err := os.Symlink(ctx.EvidenceRoot, filepath.Join(ctx.EvidenceRoot, "link")); err != nil {
					t.Fatal(err)
				}
				ctx.BundleFiles[0].Path = "link/" + ctx.BundleFiles[0].Path
			case "wrongprimary":
				abs = filepath.Join(ctx.EvidenceRoot, "other")
			case "mismatchedhash":
				ctx.BundleFiles[0].SHA256 = strings.Repeat("0", 64)
			}
			if got, err := New().ParseWithContext(abs, ctx); err == nil || len(got.Events) != 0 {
				t.Fatalf("unsafe/unadmitted bundle accepted mode=%s", mode)
			}
		})
	}
	if _, err := New().Parse("OBJECTS.DATA"); !errors.Is(err, wmirepo.ErrMissingBundle) {
		t.Fatalf("standalone parser falsely supports adjacency: %v", err)
	}
	p := New()
	if !p.Detect(`folder\objects.data`) || p.Detect("INDEX.BTR") || p.Detect("MAPPING1.MAP") {
		t.Fatal("bundle members claimed as independent repositories")
	}
}
