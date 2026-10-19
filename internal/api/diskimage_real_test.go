package api

import (
	"os"
	"strings"
	"testing"

	"tracefall/internal/ingest"
	"tracefall/internal/ntfsvol"
)

// Real-image regression for the disk catalog's classifier. Gated because the
// image is not committed. Set
// TRACEFALL_REAL_DISK to its first segment (the .E01) to run it.
//
// What it pins, on the real image:
//   - Amcache.hve (ordinary name, REGF content) is supported, by content.
//   - A .lnk under a user's Recent folder is supported, by its header.
//   - SOFTWARE is supported by name, with no sniff needed.
//   - SRUDB.dat and WebCacheV01.dat have no parser, but they are still
//     cataloged, as unsupported. Before this, they were dropped silently.
//   - $MFTMirr is never cataloged, and nothing in a skipped folder is sniffed.
func TestReal_ContentOnlyArtifactsAreCandidates(t *testing.T) {
	seg := os.Getenv("TRACEFALL_REAL_DISK")
	if seg == "" {
		t.Skip("set TRACEFALL_REAL_DISK to a real Windows disk image (.E01)")
	}
	img, _, vols, _, err := openDiskImage([]string{seg})
	if err != nil {
		t.Fatalf("open image: %v", err)
	}
	defer img.Close()

	registry := ingest.Registry()
	type want struct {
		seen, supported, sniffed bool
	}
	expect := map[string]*want{
		"Windows/appcompat/Programs/Amcache.hve":                                {},
		"Users/<user>/AppData/Roaming/Microsoft/Windows/Recent/notes.txt.lnk": {},
		"Windows/System32/config/SOFTWARE":                                      {},
		"Windows/System32/sru/SRUDB.dat":                                        {},
		"Users/<user>/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat": {},
	}
	for _, ov := range vols {
		if _, err := ov.vol.Walk(func(f ntfsvol.File) error {
			e, ok := classifyDiskFile(ov.vol, f, registry)
			if !ok {
				return nil
			}
			if mirrorOfMFT(e.Rel) {
				t.Errorf("%s was cataloged; it mirrors $MFT and must not be", e.Rel)
			}
			if e.Sniff != nil && sniffSkipped(e.Rel) {
				t.Errorf("%s was sniffed by content inside a skipped folder", e.Rel)
			}
			if w, tracked := expect[canonicalUserPath(e.Rel)]; tracked {
				w.seen = true
				w.supported = e.Supported
				w.sniffed = e.Sniff != nil
			}
			return nil
		}); err != nil {
			t.Fatalf("walk: %v", err)
		}
	}
	for rel, w := range expect {
		if !w.seen {
			t.Errorf("%s is not cataloged at all", rel)
		}
	}
	if w := expect["Windows/appcompat/Programs/Amcache.hve"]; w.seen && (!w.supported || !w.sniffed) {
		t.Errorf("Amcache.hve: supported=%v sniffed=%v, want both true (identified by REGF content)", w.supported, w.sniffed)
	}
	if w := expect["Windows/System32/config/SOFTWARE"]; w.seen && (!w.supported || w.sniffed) {
		t.Errorf("SOFTWARE: supported=%v sniffed=%v, want supported and not sniffed (name decides)", w.supported, w.sniffed)
	}
	for _, rel := range []string{"Windows/System32/sru/SRUDB.dat", "Users/<user>/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat"} {
		if w := expect[rel]; w.seen && w.supported {
			t.Errorf("%s: supported=true, but no parser exists for it", rel)
		}
	}
}

// canonicalUserPath replaces the account name in Users/<name>/... with
// <user>, so the expectations hold for any Windows image, not one account.
func canonicalUserPath(rel string) string {
	parts := strings.SplitN(rel, "/", 3)
	if len(parts) == 3 && strings.EqualFold(parts[0], "Users") {
		return parts[0] + "/<user>/" + parts[2]
	}
	return rel
}
