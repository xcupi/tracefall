package cryptneturl

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"

	"tracefall/internal/model"
)

// metaFile builds a metadata entry from the layout published for the artifact
// (urlSize at 12, download FILETIME at 16, Last-Modified FILETIME at 88, hash
// size at 100, file size at 112, then the URL and the ETag in UTF-16LE), so a
// wrong reading in the parser cannot be hidden by the same mistake here.
func metaFile(url, etag string, size uint32, downloaded, lastMod time.Time) []byte {
	enc := func(s string) []byte {
		u := utf16.Encode([]rune(s + "\x00"))
		b := make([]byte, 2*len(u))
		for i, c := range u {
			binary.LittleEndian.PutUint16(b[2*i:], c)
		}
		return b
	}
	u, e := enc(url), []byte{}
	if etag != "" {
		e = enc(etag)
	}
	b := make([]byte, 116)
	binary.LittleEndian.PutUint32(b[0:], 0x70)
	binary.LittleEndian.PutUint32(b[4:], 0x20020101)
	binary.LittleEndian.PutUint32(b[12:], uint32(len(u)))
	ft := func(t time.Time) uint64 { return uint64(t.UnixNano()/100) + 116444736000000000 }
	binary.LittleEndian.PutUint64(b[16:], ft(downloaded))
	if !lastMod.IsZero() {
		binary.LittleEndian.PutUint64(b[88:], ft(lastMod))
	}
	binary.LittleEndian.PutUint32(b[100:], uint32(len(e)))
	binary.LittleEndian.PutUint32(b[112:], size)
	return append(append(b, u...), e...)
}

func tree(t *testing.T, name string, meta, content []byte) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "Users", "alice", "AppData", "LocalLow", "Microsoft", "CryptnetUrlCache")
	for _, d := range []string{"MetaData", "Content"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "MetaData", name), meta, 0o600); err != nil {
		t.Fatal(err)
	}
	if content != nil {
		if err := os.WriteFile(filepath.Join(root, "Content", name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(root, "MetaData", name)
}

const name32 = "BC456035A9E2885290EDC953764CC761"

var dl = time.Date(2026, 1, 5, 13, 4, 5, 123456700, time.UTC)

func TestDetect_ByPath(t *testing.T) {
	p := New()
	for _, ok := range []string{
		"Users/alice/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/" + name32,
		`C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\` + name32 + "_AA1E8580D4EBC816148CE81268683776",
		"x/cryptneturlcache/metadata/" + name32,
	} {
		if !p.Detect(ok) {
			t.Errorf("Detect(%q) = false", ok)
		}
	}
	for _, no := range []string{
		"Users/alice/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/" + name32, // the cached object, not its record
		"Users/alice/MetaData/" + name32,
		"Users/alice/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/notahash.txt",
	} {
		if p.Detect(no) {
			t.Errorf("Detect(%q) = true", no)
		}
	}
}

func TestConfirmContent_NeedsTheHeaderAndAUrl(t *testing.T) {
	p := New()
	good := metaFile("http://example.test/a.exe", "", 10, dl, time.Time{})
	if !p.ConfirmContent(good) {
		t.Error("a real-shaped entry should be confirmed")
	}
	bad := append([]byte(nil), good...)
	bad[0] = 0
	if p.ConfirmContent(bad) {
		t.Error("a wrong header length must not be confirmed")
	}
	if p.ConfirmContent([]byte("plain text file that happens to sit in the folder....")) {
		t.Error("text")
	}
}

func TestParse_ReadsTheFieldsAndChecksTheCachedObject(t *testing.T) {
	body := append([]byte("MZ"), make([]byte, 98)...)
	lm := time.Date(2025, 12, 1, 8, 0, 0, 0, time.UTC)
	path := tree(t, name32, metaFile("http://198.51.100.7/tools/x.exe", `"abc123"`, uint32(len(body)), dl, lm), body)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 || len(res.Raw) != 1 {
		t.Fatalf("events %d raw %d", len(res.Events), len(res.Raw))
	}
	e := res.Events[0]
	if e.EventType != model.EventCryptoURLRetrieval || e.ArtifactType != model.ArtifactCryptnetURLCache {
		t.Errorf("types %s %s", e.EventType, e.ArtifactType)
	}
	if !e.Timestamp.Equal(dl.Truncate(100 * time.Nanosecond)) {
		t.Errorf("timestamp %v, want %v", e.Timestamp, dl)
	}
	for k, want := range map[string]string{
		"url": "http://198.51.100.7/tools/x.exe", "url_host": "198.51.100.7", "file_size": "100",
		"etag": "abc123", "last_modified_header": "2025-12-01T08:00:00Z",
		"content_present": "true", "content_size_matches": "true", "content_magic": "pe",
		"entry_id": name32, "layout_verified": "true",
	} {
		if e.Extra[k] != want {
			t.Errorf("Extra[%s] = %q, want %q", k, e.Extra[k], want)
		}
	}
	if e.Extra["records_cause"] == "" {
		t.Error("the limit that the entry does not name the program must be on the record")
	}
}

func TestParse_ContentFacts(t *testing.T) {
	cases := map[string]struct {
		body  []byte
		magic string
	}{
		"pe":      {append([]byte("MZ"), make([]byte, 30)...), "pe"},
		"zip":     {append([]byte("PK\x03\x04"), make([]byte, 30)...), "zip"},
		"7z":      {append([]byte("7z\xbc\xaf\x27\x1c"), make([]byte, 30)...), "7z"},
		"cab":     {append([]byte("MSCF"), make([]byte, 30)...), "cab"},
		"der":     {append([]byte{0x30, 0x82, 0x01, 0x00}, make([]byte, 30)...), "der"},
		"text":    {[]byte("powershell -nop -c iex(...)    "), "text"},
		"unknown": {[]byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4}, "unknown"},
	}
	for n, c := range cases {
		path := tree(t, name32, metaFile("http://example.test/f", "", uint32(len(c.body)), dl, time.Time{}), c.body)
		res, err := New().Parse(path)
		if err != nil || len(res.Events) != 1 {
			t.Fatalf("%s: %v %d", n, err, len(res.Events))
		}
		if got := res.Events[0].Extra["content_magic"]; got != c.magic {
			t.Errorf("%s: content_magic = %q, want %q", n, got, c.magic)
		}
	}
}

func TestParse_MissingOrDifferentContentIsSaid(t *testing.T) {
	path := tree(t, name32, metaFile("http://example.test/f", "", 50, dl, time.Time{}), nil)
	res, _ := New().Parse(path)
	if res.Events[0].Extra["content_present"] != "false" || res.Events[0].Extra["content_magic"] != "" {
		t.Errorf("%v", res.Events[0].Extra)
	}
	path = tree(t, name32, metaFile("http://example.test/f", "", 50, dl, time.Time{}), make([]byte, 49))
	res, _ = New().Parse(path)
	if res.Events[0].Extra["content_size_matches"] != "false" {
		t.Errorf("a cached object of another size than recorded must be flagged: %v", res.Events[0].Extra)
	}
}

func TestParse_NoDownloadTimeIsUndated(t *testing.T) {
	path := tree(t, name32, metaFile("http://example.test/f", "", 0, time.Time{}, time.Time{}), []byte{})
	b, _ := os.ReadFile(path)
	binary.LittleEndian.PutUint64(b[16:], 0)
	os.WriteFile(path, b, 0o600)
	res, _ := New().Parse(path)
	if len(res.Events) != 1 || !res.Events[0].Timestamp.IsZero() {
		t.Fatalf("%+v", res.Events)
	}
}

func TestParse_HostileFilesNeverPanicAndNeverGuess(t *testing.T) {
	good := metaFile("http://example.test/f", `"x"`, 5, dl, time.Time{})
	corrupt := map[string]func([]byte) []byte{
		"truncated header": func(b []byte) []byte { return b[:60] },
		"url size huge":    func(b []byte) []byte { binary.LittleEndian.PutUint32(b[12:], 0xFFFFFFF0); return b },
		"url size odd":     func(b []byte) []byte { binary.LittleEndian.PutUint32(b[12:], 7); return b },
		"hash size huge":   func(b []byte) []byte { binary.LittleEndian.PutUint32(b[100:], 0x7FFFFFFF); return b },
		"cut in the url":   func(b []byte) []byte { return b[:130] },
		"no terminator":    func(b []byte) []byte { return append(b[:len(b)-2:len(b)-2], 'x', 0) },
	}
	for n, f := range corrupt {
		path := tree(t, name32, f(append([]byte(nil), good...)), nil)
		res, err := New().Parse(path)
		if err == nil && len(res.Events) != 0 && res.Events[0].Extra["layout_verified"] == "true" {
			t.Errorf("%s: a damaged entry was reported as verified: %v", n, res.Events[0].Extra)
		}
	}
}
