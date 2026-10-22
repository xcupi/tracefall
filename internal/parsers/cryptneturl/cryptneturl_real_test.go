package cryptneturl

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"tracefall/internal/parsers"
)

// TRACEFALL_REAL_CRYPTNET_DIR is the root of a real Windows 10 collection. The
// expected figures were produced by a separate pass over the raw bytes (a
// Python script that reads urlSize, the FILETIME and the Content folder
// directly), not by this parser.
func TestRealCryptnetCache(t *testing.T) {
	root := os.Getenv("TRACEFALL_REAL_CRYPTNET_DIR")
	if root == "" {
		t.Skip("TRACEFALL_REAL_CRYPTNET_DIR not set")
	}
	var files []string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && New().Detect(filepath.ToSlash(p)) {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	man := sha256.New()
	for _, p := range files {
		b, _ := os.ReadFile(p)
		rel, _ := filepath.Rel(root, p)
		s := sha256.Sum256(b)
		fmt.Fprintf(man, "%s:%s\n", rel, hex.EncodeToString(s[:]))
	}
	if got := hex.EncodeToString(man.Sum(nil)); got != "c0a1f36d40012b7bc14eccf7d455cc6c01db245bd88c5b07414b2ef8a31ce549" {
		t.Fatalf("this is not the pinned collection (%d files, manifest %s)", len(files), got)
	}
	hosts, magics := map[string]int{}, map[string]int{}
	var first, last string
	for _, p := range files {
		rel, _ := filepath.Rel(root, p)
		res, err := New().ParseWithContext(p, parsers.ParseContext{EvidencePath: filepath.ToSlash(rel)})
		if err != nil || len(res.Events) != 1 {
			t.Fatalf("%s: %v", rel, err)
		}
		e := res.Events[0]
		if e.Extra["layout_verified"] != "true" || e.Extra["content_size_matches"] != "true" {
			t.Errorf("%s: %v", rel, e.Extra)
		}
		hosts[e.Extra["url_host"]]++
		magics[e.Extra["content_magic"]]++
		ts := e.Timestamp.Format("2006-01-02T15:04:05.0000000")
		if first == "" || ts < first {
			first = ts
		}
		if ts > last {
			last = ts
		}
	}
	if len(files) != 53 {
		t.Errorf("%d entries, want 53", len(files))
	}
	want := map[string]int{"cacerts.digicert.com": 1, "ctldl.windowsupdate.com": 21, "ocsp.digicert.com": 23, "ocsp.pki.goog": 3, "ocsp.sectigo.com": 1, "ocsp.usertrust.com": 1, "oneocsp.microsoft.com": 1, "s2.symcb.com": 1, "sv.symcd.com": 1}
	for h, n := range want {
		if hosts[h] != n {
			t.Errorf("host %s: %d, want %d", h, hosts[h], n)
		}
	}
	if len(hosts) != len(want) {
		t.Errorf("hosts %v", hosts)
	}
	for k, n := range map[string]int{"": 18, "cab": 3, "der": 32} {
		if magics[k] != n {
			t.Errorf("content kind %q: %d, want %d", k, magics[k], n)
		}
	}
	if first != "2023-07-12T06:13:25.4976677" || last != "2023-07-12T18:08:58.6070515" {
		t.Errorf("time range %s .. %s", first, last)
	}
	t.Logf("content kinds: %v; first %s last %s", magics, first, last)
	if strings.Contains(fmt.Sprint(magics), "pe") {
		t.Errorf("the pinned collection holds no executable retrieval, but one was reported: %v", magics)
	}
}
