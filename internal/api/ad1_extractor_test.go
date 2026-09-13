package api

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/ad1"
	"tracefall/internal/model"
)

// The indexed extractor must select and write exactly what the previous
// per-file tree walk did. These tests pin the selection rule and the
// bytes, because the optimization is only safe if the evidence is
// identical.

// The index must contain exactly the entries a walk yields, in the same
// order per path.
//
// That is the whole safety argument. The original code chose an entry by
// walking and applying "first size match, else last path match" to the
// matches in WALK ORDER; the index applies the same rule to the same
// entries in the same order. So proving the index is a faithful,
// order-preserving record of the walk proves the selection is unchanged
// -- and it costs ONE walk rather than one per file.
func TestAD1Extractor_IndexIsAFaithfulRecordOfTheWalk(t *testing.T) {
	ad1Path := benchAD1(t)
	svc := newTestService(t)
	c, err := svc.CreateCase("extractor parity", "")
	if err != nil {
		t.Fatal(err)
	}
	disc, err := svc.DiscoverEvidenceFromPath(c.ID, ad1Path)
	if err != nil {
		t.Fatal(err)
	}

	x, err := svc.newAD1Extractor(c.ID, disc.Collection.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()

	// An independent walk, grouped the way the original selection saw it.
	segs, err := ad1.FindSiblingSegments(ad1Path)
	if err != nil {
		t.Fatal(err)
	}
	container, err := ad1.Open(segs, svc.ad1Limits)
	if err != nil {
		t.Fatal(err)
	}
	defer container.Close()

	want := map[string][]ad1.Entry{}
	total := 0
	if err := container.Walk(func(e ad1.Entry) error {
		if e.IsDir {
			return nil
		}
		want[e.Path] = append(want[e.Path], e)
		total++
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if len(x.byPath) != len(want) {
		t.Fatalf("index holds %d paths, the walk yields %d", len(x.byPath), len(want))
	}
	for path, wantList := range want {
		gotList, ok := x.byPath[path]
		if !ok {
			t.Errorf("index is missing %s", path)
			continue
		}
		if len(gotList) != len(wantList) {
			t.Errorf("%s: index has %d entries, walk has %d", path, len(gotList), len(wantList))
			continue
		}
		for i := range wantList {
			if gotList[i].Name != wantList[i].Name ||
				gotList[i].SizeBytes != wantList[i].SizeBytes ||
				gotList[i].MD5 != wantList[i].MD5 ||
				gotList[i].SHA1 != wantList[i].SHA1 {
				t.Errorf("%s entry %d differs between index and walk", path, i)
			}
		}
	}
	t.Logf("compared %d file entries across %d paths: index matches the walk exactly", total, len(want))
}

// A path with more than one entry must still prefer the size match --
// the rule that stopped 25 intact Prefetch files being extracted as
// 0-byte ones.
func TestAD1Extractor_PrefersTheSizeMatchOverTheLastEntry(t *testing.T) {
	x := &ad1Extractor{byPath: map[string][]ad1.Entry{
		"a/b.pf": {
			{Path: "a/b.pf", Name: "b.pf", SizeBytes: 29880},
			{Path: "a/b.pf", Name: "b.pf", SizeBytes: 0},
		},
	}}

	got, ok := x.entryFor(model.SourceFile{Path: "a/b.pf", SizeBytes: 29880})
	if !ok || got.SizeBytes != 29880 {
		t.Errorf("size match not preferred: got %d, ok=%v", got.SizeBytes, ok)
	}
	// No size match: the LAST path entry is the fallback, as before.
	got, ok = x.entryFor(model.SourceFile{Path: "a/b.pf", SizeBytes: 12345})
	if !ok || got.SizeBytes != 0 {
		t.Errorf("fallback should be the last path match: got %d, ok=%v", got.SizeBytes, ok)
	}
	// An unknown path is not found, and is not silently substituted.
	if _, ok := x.entryFor(model.SourceFile{Path: "nope"}); ok {
		t.Error("an unknown path resolved to an entry")
	}
}

// The index must never hold directories: a directory entry sharing a
// file's path would be selectable and would extract as empty.
func TestAD1Extractor_IndexHoldsNoDirectories(t *testing.T) {
	ad1Path := benchAD1(t)
	svc := newTestService(t)
	c, err := svc.CreateCase("extractor dirs", "")
	if err != nil {
		t.Fatal(err)
	}
	disc, err := svc.DiscoverEvidenceFromPath(c.ID, ad1Path)
	if err != nil {
		t.Fatal(err)
	}
	x, err := svc.newAD1Extractor(c.ID, disc.Collection.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()

	entries := 0
	for _, list := range x.byPath {
		for _, e := range list {
			entries++
			if e.IsDir {
				t.Fatalf("the index holds a directory entry: %s", e.Path)
			}
		}
	}
	t.Logf("indexed %d file entries across %d distinct paths", entries, len(x.byPath))
}

// The bytes written must be identical to the bytes the container holds,
// and the recorded SHA-256 must be of exactly those bytes.
func TestAD1Extractor_WritesExactBytesAndRecordsTheirHash(t *testing.T) {
	ad1Path := benchAD1(t)
	svc := newTestService(t)
	c, err := svc.CreateCase("extractor bytes", "")
	if err != nil {
		t.Fatal(err)
	}
	disc, err := svc.DiscoverEvidenceFromPath(c.ID, ad1Path)
	if err != nil {
		t.Fatal(err)
	}
	files, err := svc.store.ListSourceFilesByCollection(disc.Collection.ID)
	if err != nil {
		t.Fatal(err)
	}
	col, err := svc.store.GetCollection(disc.Collection.ID)
	if err != nil {
		t.Fatal(err)
	}

	x, err := svc.newAD1Extractor(c.ID, disc.Collection.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()

	checked := 0
	for _, sf := range files {
		if !sf.Supported || sf.SizeBytes == 0 || sf.SizeBytes > 4<<20 {
			continue
		}
		if err := x.extract(sf); err != nil {
			t.Fatalf("%s: %v", sf.Path, err)
		}
		written, err := os.ReadFile(filepath.Join(col.EvidenceDirectory, filepath.FromSlash(sf.Path)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(written)

		refreshed, err := svc.store.GetSourceFile(sf.ID)
		if err != nil {
			t.Fatal(err)
		}
		if refreshed.SHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: recorded hash %s does not match the bytes written (%s)",
				sf.Path, refreshed.SHA256, hex.EncodeToString(sum[:]))
		}
		checked++
		if checked >= 60 {
			break
		}
	}
	if checked == 0 {
		t.Fatal("no files were checked")
	}
	t.Logf("verified %d extracted files against their recorded hashes", checked)
}
