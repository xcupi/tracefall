package api

import (
	"crypto/sha512"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/ad1/ad1gen"
	"tracefall/internal/model"
)

// Phase 10A: forensic integrity hashing.
//
// The contract: SHA-512 covers the ORIGINAL evidence object, is computed
// before anything is extracted, is immutable afterwards, and does not
// weaken duplicate detection (which still uses archive_hash).

func sha512Hex(b []byte) string {
	sum := sha512.Sum512(b)
	return hex.EncodeToString(sum[:])
}

// A known fixture must produce the SHA-512 an independent calculation
// gives -- byte-identical, over the exact uploaded bytes.
func TestIntegrity_UploadHashMatchesIndependentCalculation(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Upload integrity")

	zip := buildZipBytes(t, map[string]string{
		"EvtxECmd/20260301_EvtxECmd_Output.csv": "TimeCreated,EventId\n2026-03-01T09:00:00.0000000Z,4624\n",
	})
	want := sha512Hex(zip)

	rec := uploadZip(t, mux, c.ID, zip)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)

	if disc.Collection.IntegritySHA512 != want {
		t.Errorf("integrity hash = %q\nwant                 %q", disc.Collection.IntegritySHA512, want)
	}
	if len(disc.Collection.IntegritySHA512) != 128 {
		t.Errorf("hash is %d hex chars, want 128 (SHA-512)", len(disc.Collection.IntegritySHA512))
	}
	// The dedup hash must remain a separate, unchanged SHA-256.
	if len(disc.Collection.ArchiveHash) != 64 {
		t.Errorf("archive_hash is %d hex chars, want 64 (SHA-256) -- duplicate detection must not have changed", len(disc.Collection.ArchiveHash))
	}
	if disc.Collection.ArchiveHash == disc.Collection.IntegritySHA512 {
		t.Error("archive_hash and integrity_sha512 are the same value; they must be independent")
	}
}

// The AD1 hash must cover the original AD1 bytes, not anything derived.
func TestIntegrity_AD1UploadHashesTheOriginalBytes(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "AD1 integrity")

	img := buildAD1(t, `E:\`, []ad1gen.File{
		{Path: "Windows/System32/winevt/Logs/Security.evtx", Data: attackEvtx()},
	})
	want := sha512Hex(img)

	rec := uploadAD1(t, mux, c.ID, img, "evidence.ad1")
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	if disc.Collection.IntegritySHA512 != want {
		t.Errorf("AD1 integrity hash does not match the uploaded bytes")
	}
}

// Same evidence -> same hash; one byte different -> different hash.
func TestIntegrity_HashIsContentAddressed(t *testing.T) {
	mux := newTestRouter(t)

	base := "TimeCreated,EventId\n2026-03-01T09:00:00.0000000Z,4624\n"
	files := map[string]string{"EvtxECmd/20260301_EvtxECmd_Output.csv": base}

	a := mustCreateCase(t, mux, "Integrity A")
	b := mustCreateCase(t, mux, "Integrity B")
	c := mustCreateCase(t, mux, "Integrity C")

	hashOf := func(caseID string, content map[string]string) string {
		rec := uploadZip(t, mux, caseID, buildZipBytes(t, content))
		if rec.Code != http.StatusOK {
			t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
		}
		var d DiscoverResult
		mustDecode(t, rec, &d)
		return d.Collection.IntegritySHA512
	}

	h1 := hashOf(a.ID, files)
	h2 := hashOf(b.ID, files)
	if h1 != h2 {
		t.Error("identical evidence produced different integrity hashes")
	}

	changed := map[string]string{"EvtxECmd/20260301_EvtxECmd_Output.csv": base + "x"}
	if h3 := hashOf(c.ID, changed); h3 == h1 {
		t.Error("a one-byte change produced the same integrity hash")
	}
}

// Directory hashing must be deterministic and content-derived.
func TestIntegrity_DirectoryHashIsDeterministicAndContentDerived(t *testing.T) {
	mux := newTestRouter(t)

	build := func(t *testing.T) string {
		dir := t.TempDir()
		for name, content := range map[string]string{
			"a/one.txt":   "first",
			"b/two.txt":   "second",
			"c/three.txt": "third",
		} {
			p := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}

	hashOf := func(name, dir string) string {
		c := mustCreateCase(t, mux, name)
		rec := discoverPath(t, mux, c.ID, dir)
		if rec.Code != http.StatusOK {
			t.Fatalf("discover: %d %s", rec.Code, rec.Body.String())
		}
		var d DiscoverResult
		mustDecode(t, rec, &d)
		return d.Collection.IntegritySHA512
	}

	// Two separately-created directories with identical CONTENT must
	// hash identically, even though their mtimes and inode order differ
	// -- the fingerprint is over relative paths plus file bytes, never
	// filesystem metadata.
	first := hashOf("dir A", build(t))
	second := hashOf("dir B", build(t))
	if first != second {
		t.Errorf("identical directory content produced different hashes:\n  %s\n  %s", first, second)
	}
	if len(first) != 128 {
		t.Errorf("directory hash is %d chars, want 128", len(first))
	}

	// Changing one file's content must change the hash.
	altered := build(t)
	if err := os.WriteFile(filepath.Join(altered, "b", "two.txt"), []byte("SECOND"), 0o644); err != nil {
		t.Fatal(err)
	}
	if h := hashOf("dir C", altered); h == first {
		t.Error("changing a file's content did not change the directory hash")
	}
}

// The hash must survive a reload and appear in the API and the export.
func TestIntegrity_SurvivesReloadAndAppearsInAPIAndExport(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Integrity persistence")
	zip := buildZipBytes(t, map[string]string{
		"EvtxECmd/20260301_EvtxECmd_Output.csv": "TimeCreated,EventId\n2026-03-01T09:00:00.0000000Z,4624\n",
	})
	rec := uploadZip(t, mux, c.ID, zip)
	var disc DiscoverResult
	mustDecode(t, rec, &disc)
	want := disc.Collection.IntegritySHA512
	if want == "" {
		t.Fatal("no integrity hash recorded at discovery")
	}

	// Re-read through the collection list.
	for _, col := range listCollections(t, mux, c.ID) {
		if col.ID == disc.Collection.ID && col.IntegritySHA512 != want {
			t.Errorf("collection list hash = %q, want %q", col.IntegritySHA512, want)
		}
	}
	// Re-read through collection detail.
	var detail CollectionDetail
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID, nil, &detail)
	if detail.IntegritySHA512 != want {
		t.Errorf("collection detail hash = %q, want %q", detail.IntegritySHA512, want)
	}
	// And in the case export.
	var export CaseExport
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/export", nil, &export)
	var found bool
	for _, col := range export.Collections {
		if col.ID == disc.Collection.ID {
			found = true
			if col.IntegritySHA512 != want {
				t.Errorf("exported hash = %q, want %q", col.IntegritySHA512, want)
			}
		}
	}
	if !found {
		t.Error("the collection is missing from the export entirely")
	}
}

// Importing, analyzing and deleting evidence must never change the hash:
// an integrity value that can drift is not integrity evidence.
func TestIntegrity_IsImmutableAcrossTheCaseLifecycle(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Integrity immutability")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Windows/System32/winevt/Logs/Security.evtx": attackEvtx(),
		"Users/jdoe/NTUSER.DAT":                      persistenceHive(),
	})
	original := disc.Collection.IntegritySHA512
	if original == "" {
		t.Fatal("no integrity hash at discovery")
	}

	hashNow := func(stage string) {
		for _, col := range listCollections(t, mux, c.ID) {
			if col.ID == disc.Collection.ID && col.IntegritySHA512 != original {
				t.Errorf("after %s the integrity hash changed to %q", stage, col.IntegritySHA512)
			}
		}
	}

	importAllFrom(t, mux, c.ID, disc)
	hashNow("import")
	analyze(t, mux, c.ID)
	hashNow("analysis")

	sources := listSourceFiles(t, mux, c.ID)
	for _, s := range sources {
		if s.ImportStatus == model.SourceFileImported {
			doJSON(t, mux, "DELETE", "/api/cases/"+c.ID+"/evidence/"+s.ID, nil, nil)
			break
		}
	}
	hashNow("evidence deletion")
}

// A discovery that FAILS must leave no collection at all, and therefore
// no integrity record -- a hash for evidence that was never ingested
// would be a misleading integrity claim.
func TestIntegrity_FailedDiscoveryLeavesNoIntegrityRecord(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Failed discovery integrity")

	rec := discoverPath(t, mux, c.ID, filepath.Join(t.TempDir(), "does-not-exist"))
	if rec.Code == http.StatusOK {
		t.Fatal("expected the discovery to fail")
	}
	if cols := listCollections(t, mux, c.ID); len(cols) != 0 {
		t.Errorf("collections = %d, want 0 -- a failed discovery must record nothing", len(cols))
	}
}
