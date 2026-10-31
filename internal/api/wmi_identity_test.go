package api

import (
	"os"
	"path/filepath"
	"testing"
	"tracefall/internal/model"
	"tracefall/internal/wmitest"
)

func TestWMIRepositoryBundleIdentitySurvivesSourceDedup(t *testing.T) {
	svc := newTestService(t)
	c := mustCreateCase(t, routerFor(svc), "Neutral repository state")
	root := t.TempDir()
	for _, dir := range []string{"a", "b"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
		for name, b := range wmitest.Bundle("state01") {
			if name == "INDEX.BTR" && dir == "b" {
				b[8192+8] = 1
			}
			if err := os.WriteFile(filepath.Join(root, dir, name), b, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	d, err := svc.DiscoverEvidenceFromPath(c.ID, root)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := svc.store.ListSourceFilesByCollection(d.Collection.ID)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, sf := range rows {
		if sf.ArtifactType == model.ArtifactWMIRepository {
			if sf.ImportStatus != model.SourceFileDiscovered {
				t.Fatal("same primary bytes hid different bundle state")
			}
			ids = append(ids, sf.ID)
		}
	}
	r, err := svc.ImportEvidence(c.ID, d.Collection.ID, ids)
	if err != nil || r.EventCount != 6 || len(r.Errors) > 0 {
		t.Fatalf("bundle-aware source admission result=%+v err=%v", r, err)
	}
	for _, changed := range []bool{false, true} {
		dir := t.TempDir()
		value := "state01"
		if changed {
			value = "state02"
		}
		for name, b := range wmitest.Bundle(value) {
			if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "collection-note"), []byte("new collection"), 0600); err != nil {
			t.Fatal(err)
		}
		d, err := svc.DiscoverEvidenceFromPath(c.ID, dir)
		if err != nil {
			t.Fatal(err)
		}
		rows, _ := svc.store.ListSourceFilesByCollection(d.Collection.ID)
		id := ""
		for _, sf := range rows {
			if sf.ArtifactType == model.ArtifactWMIRepository {
				id = sf.ID
			}
		}
		r, err := svc.ImportEvidence(c.ID, d.Collection.ID, []string{id})
		want := 0
		if changed {
			want = 3
		}
		// Import reports parsed observations separately from newly inserted events.
		if err != nil || r.EventCount != 3 || r.NewEventCount != want || len(r.Errors) > 0 {
			t.Fatalf("recollection changed=%v result=%+v err=%v", changed, r, err)
		}
	}
	events, err := svc.store.ListEvents(c.ID)
	if err != nil || len(events) != 9 {
		t.Fatalf("persisted state census=%d err=%v", len(events), err)
	}
	observations := 0
	for _, e := range events {
		seen, err := svc.store.ListEventObservations(e.ID)
		if err != nil {
			t.Fatal(err)
		}
		observations += len(seen)
	}
	if observations != 12 {
		t.Fatalf("recollection observations=%d want12", observations)
	}
}
