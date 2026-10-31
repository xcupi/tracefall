package api

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"tracefall/internal/model"
	"tracefall/internal/wmitest"
)

func TestWMIRepositoryMissingAmbiguousAndSymlinkBundleFailExplicitly(t *testing.T) {
	for _, mode := range []string{"missing", "ambiguous", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			svc := newTestService(t)
			c := mustCreateCase(t, routerFor(svc), "Neutral bundle admission")
			root := t.TempDir()
			files := wmitest.Bundle("")
			for name, b := range files {
				if name == "INDEX.BTR" && mode != "ambiguous" {
					continue
				}
				if err := os.WriteFile(filepath.Join(root, name), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "ambiguous" {
				if err := os.WriteFile(filepath.Join(root, "index.btr"), files["INDEX.BTR"], 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "symlink" {
				outside := filepath.Join(t.TempDir(), "index-source")
				if err := os.WriteFile(outside, files["INDEX.BTR"], 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(root, "INDEX.BTR")); err != nil {
					t.Fatal(err)
				}
			}
			d, err := svc.DiscoverEvidenceFromPath(c.ID, root)
			if mode == "symlink" {
				// The service rejects an escaping link before catalog admission. This
				// stronger boundary is distinct from a missing companion at parse time.
				if !errors.Is(err, ErrEvidenceTreeEscapes) {
					t.Fatalf("external link not refused at source admission: %v", err)
				}
				events, e := svc.store.ListEvents(c.ID)
				if e != nil || len(events) != 0 {
					t.Fatal("unsafe discovery admitted evidence")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			rows, err := svc.store.ListSourceFilesByCollection(d.Collection.ID)
			if err != nil {
				t.Fatal(err)
			}
			id := ""
			for _, sf := range rows {
				if sf.ArtifactType == model.ArtifactWMIRepository {
					id = sf.ID
				}
			}
			r, err := svc.ImportEvidence(c.ID, d.Collection.ID, []string{id})
			if err != nil || len(r.ParseFailures) != 1 || r.ParseFailures[0].Category != ParseFailureUnsupported || r.EventCount != 0 {
				t.Fatalf("unsafe/missing bundle not explicit: %+v err=%v", r, err)
			}
			sf, err := svc.store.GetSourceFile(id)
			if err != nil || sf.ImportStatus != model.SourceFileFailed {
				t.Fatal("failed repository silently marked successful")
			}
			events, err := svc.store.ListEvents(c.ID)
			if err != nil || len(events) != 0 {
				t.Fatal("partial repository import escaped failed admission")
			}
		})
	}
}
