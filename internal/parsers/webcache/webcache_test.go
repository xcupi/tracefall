package webcache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/ese/esegen"
	"tracefall/internal/model"
)

func ft(t time.Time) []byte {
	return esegen.Le64(uint64(t.Unix()+11644473600)*10000000 + uint64(t.Nanosecond()/100))
}

func containersTable(rows ...esegen.Record) esegen.Table {
	return esegen.Table{Name: "Containers", Records: rows, Columns: []esegen.Column{
		{ID: 1, Name: "ContainerId", Type: esegen.Int64},
		{ID: 256, Name: "Name", Type: esegen.LongText, Codepage: 1200},
		{ID: 257, Name: "Directory", Type: esegen.LongText, Codepage: 1200},
	}}
}

func containerRow(id int64, name, dir string) esegen.Record {
	return esegen.Record{Fixed: map[uint32][]byte{1: esegen.Le64(uint64(id))}, Tagged: []esegen.Tagged{
		{ID: 256, Data: esegen.UTF16(name)}, {ID: 257, Data: esegen.UTF16(dir)}}}
}

func entryCols() []esegen.Column {
	return []esegen.Column{
		{ID: 1, Name: "EntryId", Type: esegen.Int64}, {ID: 2, Name: "ContainerId", Type: esegen.Int64},
		{ID: 3, Name: "CacheId", Type: esegen.Int64}, {ID: 4, Name: "UrlHash", Type: esegen.Int64},
		{ID: 5, Name: "SecureDirectory", Type: esegen.Uint32}, {ID: 6, Name: "FileSize", Type: esegen.Int64},
		{ID: 7, Name: "Type", Type: esegen.Uint32}, {ID: 8, Name: "Flags", Type: esegen.Uint32}, {ID: 9, Name: "AccessCount", Type: esegen.Uint32},
		{ID: 10, Name: "SyncTime", Type: esegen.Int64}, {ID: 11, Name: "CreationTime", Type: esegen.Int64}, {ID: 12, Name: "ExpiryTime", Type: esegen.Int64},
		{ID: 13, Name: "ModifiedTime", Type: esegen.Int64}, {ID: 14, Name: "AccessedTime", Type: esegen.Int64}, {ID: 15, Name: "PostCheckTime", Type: esegen.Int64},
		{ID: 256, Name: "Url", Type: esegen.LongText, Codepage: 1200}, {ID: 257, Name: "Filename", Type: esegen.LongText, Codepage: 1200},
		{ID: 258, Name: "FileExtension", Type: esegen.LongText, Codepage: 1200},
		{ID: 259, Name: "RequestHeaders", Type: esegen.LongBinary}, {ID: 260, Name: "ResponseHeaders", Type: esegen.LongBinary},
		{ID: 261, Name: "RedirectUrl", Type: esegen.LongText, Codepage: 1200},
	}
}

type entry struct {
	id         int64
	url, file  string
	size       int64
	count      uint32
	accessed   []byte
	created    []byte
	modified   []byte
	respHeader string
	reqHeader  string
	defunct    bool
}

func (e entry) record(container int64) esegen.Record {
	z := esegen.Le64(0)
	pick := func(b []byte) []byte {
		if b == nil {
			return z
		}
		return b
	}
	r := esegen.Record{Defunct: e.defunct, Fixed: map[uint32][]byte{
		1: esegen.Le64(uint64(e.id)), 2: esegen.Le64(uint64(container)), 3: z, 4: z, 5: esegen.Le32(0), 6: esegen.Le64(uint64(e.size)),
		7: esegen.Le32(1), 8: esegen.Le32(0), 9: esegen.Le32(e.count), 10: z, 11: pick(e.created), 12: z, 13: pick(e.modified), 14: pick(e.accessed), 15: z,
	}}
	r.Tagged = append(r.Tagged, esegen.Tagged{ID: 256, Data: esegen.UTF16(e.url)})
	if e.file != "" {
		r.Tagged = append(r.Tagged, esegen.Tagged{ID: 257, Data: esegen.UTF16(e.file)})
	}
	if e.reqHeader != "" {
		r.Tagged = append(r.Tagged, esegen.Tagged{ID: 259, Data: []byte(e.reqHeader)})
	}
	if e.respHeader != "" {
		r.Tagged = append(r.Tagged, esegen.Tagged{ID: 260, Data: []byte(e.respHeader)})
	}
	return r
}

func container(id int64, es ...entry) esegen.Table {
	var rs []esegen.Record
	for _, e := range es {
		rs = append(rs, e.record(id))
	}
	return esegen.Table{Name: "Container_" + itoa(id), Columns: entryCols(), Records: rs}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func write(t *testing.T, tables []esegen.Table, o esegen.Options) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "WebCacheV01.dat")
	if err := os.WriteFile(p, esegen.Build(tables, o), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func parse(t *testing.T, p string) ([]model.Event, []model.RawEvidence, *model.ParseCoverage) {
	t.Helper()
	res, err := Parser{}.Parse(p)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != len(res.Raw) {
		t.Fatalf("events %d and raw %d are not paired", len(res.Events), len(res.Raw))
	}
	return res.Events, res.Raw, res.Coverage
}

func noteMentions(c *model.ParseCoverage, s string) bool {
	for _, n := range c.Notes {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

var t0 = time.Date(2026, 3, 14, 9, 30, 15, 123456700, time.UTC)

const userDir = `C:\Users\alice\AppData\Local\Microsoft\Windows\`

func TestDetect(t *testing.T) {
	p := Parser{}
	for _, n := range []string{"WebCacheV01.dat", `Users\a\AppData\Local\Microsoft\Windows\WebCache\webcachev24.DAT`} {
		if !p.Detect(n) {
			t.Errorf("%q should be claimed", n)
		}
	}
	for _, n := range []string{"index.dat", "WebCacheV01.log", "WebCache.dat", "WebCacheV01.dat.bak"} {
		if p.Detect(n) {
			t.Errorf("%q must not be claimed", n)
		}
	}
	if !p.ConfirmContent([]byte{0, 0, 0, 0, 0xef, 0xcd, 0xab, 0x89}) || p.ConfirmContent([]byte("SQLite format 3\x00")) {
		t.Errorf("only an ESE header confirms")
	}
}

func TestParse_HistoryRecordsAreVisitsWithAnAccessCount(t *testing.T) {
	tb := []esegen.Table{
		containersTable(containerRow(2, "History", userDir+`History\History.IE5\`), containerRow(9, "MSHist012026031420260315", userDir+`History\History.IE5\MSHist\`)),
		container(2, entry{id: 1, url: "Visited: alice@https://example.com/a?x=1", count: 5, accessed: ft(t0), created: ft(t0.Add(-time.Hour)), modified: ft(t0.Add(3 * time.Hour))}),
		container(9,
			entry{id: 1, url: ":2026031420260315: alice@:Host: example.net", count: 2, accessed: ft(t0)},
			entry{id: 2, url: ":2026031420260315: alice@ms-settings:network", count: 1, accessed: ft(t0)},
		),
	}
	ev, raw, cov := parse(t, write(t, tb, esegen.Options{}))
	if len(ev) != 3 {
		t.Fatalf("events = %d", len(ev))
	}
	var visit, host, setting model.Event
	for _, e := range ev {
		switch {
		case strings.HasPrefix(e.Extra["url"], "https://example.com"):
			visit = e
		case e.Extra["url"] == "example.net":
			host = e
		default:
			setting = e
		}
	}
	if visit.EventType != model.EventBrowserVisit || visit.ArtifactType != model.ArtifactWebCache || visit.Parser != parserName {
		t.Errorf("visit: %+v", visit)
	}
	if !visit.Timestamp.Equal(t0.Truncate(100 * time.Nanosecond)) {
		t.Errorf("visit time = %v, want %v", visit.Timestamp, t0)
	}
	if visit.User != "alice" || visit.NetworkDest != "example.com" {
		t.Errorf("user=%q host=%q", visit.User, visit.NetworkDest)
	}
	for k, v := range map[string]string{"url": "https://example.com/a?x=1", "access_count": "5", "container_id": "2", "container_name": "History", "entry_id": "1", "record_kind": "url"} {
		if visit.Extra[k] != v {
			t.Errorf("Extra[%s] = %q, want %q", k, visit.Extra[k], v)
		}
	}
	if visit.Extra["creation_time"] != t0.Add(-time.Hour).Format(time.RFC3339Nano) {
		t.Errorf("creation_time = %q", visit.Extra["creation_time"])
	}
	if visit.Extra["modified_time_raw"] == "" || visit.Extra["modified_time"] != "" {
		t.Errorf("the history ModifiedTime is not an instant and must be kept as stored: %+v", visit.Extra)
	}
	if host.NetworkDest != "example.net" || host.Extra["record_kind"] != "daily_host" || host.Extra["history_period"] != "2026031420260315" {
		t.Errorf("daily host record: dest=%q %+v", host.NetworkDest, host.Extra)
	}
	if setting.NetworkDest != "" || setting.Extra["url"] != "ms-settings:network" {
		t.Errorf("a URL with no host: dest=%q %+v", setting.NetworkDest, setting.Extra)
	}
	if ev[0].SourceReference == ev[1].SourceReference || raw[0].SourceReference != ev[0].SourceReference {
		t.Errorf("source references: %q %q raw %q", ev[0].SourceReference, ev[1].SourceReference, raw[0].SourceReference)
	}
	if cov.Mapped != 3 || cov.RecordsRead != 3 || cov.Undated != 0 {
		t.Errorf("coverage %+v", cov)
	}
}

func TestParse_CacheEntryKeepsOnlySafeHeaders(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 34150\r\nSet-Cookie: session=SECRETVALUE; Path=/\r\nAuthorization: Bearer SECRETTOKEN\r\n\r\n"
	tb := []esegen.Table{
		containersTable(containerRow(3, "Content", userDir+`INetCache\IE\`)),
		container(3,
			entry{id: 7, url: "https://assets.example.org/feed?apikey=k", file: "feed[1].json", size: 34150, count: 1, accessed: ft(t0), created: ft(t0.Add(-time.Second)), respHeader: resp, reqHeader: "GET / HTTP/1.1\r\nCookie: SECRETCOOKIE\r\n"},
			entry{id: 8, url: "https://assets.example.org/binary", size: 5, count: 1, accessed: ft(t0), respHeader: "\x04\x00\x00\x00binary-not-http"},
		),
	}
	ev, _, _ := parse(t, write(t, tb, esegen.Options{}))
	if len(ev) != 2 {
		t.Fatalf("events = %d", len(ev))
	}
	e := ev[0]
	if e.EventType != model.EventBrowserCacheEntry || e.NetworkDest != "assets.example.org" || e.User != "alice" {
		t.Errorf("cache entry: type=%s dest=%q user=%q", e.EventType, e.NetworkDest, e.User)
	}
	for k, v := range map[string]string{"filename": "feed[1].json", "file_size": "34150", "response_status": "HTTP/1.1 200 OK", "content_type": "application/json; charset=utf-8", "container_name": "Content", "access_count": "1"} {
		if e.Extra[k] != v {
			t.Errorf("Extra[%s] = %q, want %q", k, e.Extra[k], v)
		}
	}
	for _, x := range ev {
		for k, v := range x.Extra {
			if strings.Contains(v, "SECRET") {
				t.Errorf("Extra[%s] carries a credential: %q", k, v)
			}
		}
	}
	if ev[1].Extra["response_status"] != "" {
		t.Errorf("a header blob that is not HTTP text must not be read as one: %+v", ev[1].Extra)
	}
}

func TestParse_CookiesAreNotReadAndOtherContainersAreCounted(t *testing.T) {
	tb := []esegen.Table{
		containersTable(containerRow(23, "Cookies", userDir), containerRow(4, "DOMStore", userDir), containerRow(10, "BackgroundTransferApi", userDir)),
		container(23, entry{id: 1, url: "Cookie:alice@example.com/", accessed: ft(t0)}, entry{id: 2, url: "Cookie:alice@example.org/", accessed: ft(t0)}),
		container(4, entry{id: 1, url: "DOMStore:https://www.example.com/", accessed: ft(t0)}),
		container(10, entry{id: 1, url: ":BackgroundTransferApi:GUID", accessed: ft(t0)}, entry{id: 2, url: ":BackgroundTransferApi:GUID2", accessed: ft(t0)}),
	}
	ev, _, cov := parse(t, write(t, tb, esegen.Options{}))
	if len(ev) != 0 {
		t.Errorf("events = %d: nothing here is history or cache", len(ev))
	}
	if !noteMentions(cov, "2 cookie records are not read") {
		t.Errorf("the cookie records are not accounted for: %v", cov.Notes)
	}
	if !noteMentions(cov, "container DOMStore (id 4): 1 records not interpreted") || !noteMentions(cov, "container BackgroundTransferApi (id 10): 2 records not interpreted") {
		t.Errorf("notes: %v", cov.Notes)
	}
	if cov.RecordsRead != 5 || cov.Unmapped != 5 || cov.Mapped != 0 {
		t.Errorf("coverage %+v", cov)
	}
}

func TestParse_UndatedDeletedAndOddTimes(t *testing.T) {
	gone := entry{id: 3, url: "Visited: alice@https://gone.example/", count: 1, accessed: ft(t0), defunct: true}
	tb := []esegen.Table{
		containersTable(containerRow(2, "History", userDir)),
		container(2,
			entry{id: 1, url: "Visited: alice@https://a.example/", count: 1, accessed: nil},                 // no access time
			entry{id: 2, url: "Visited: alice@https://b.example/", count: 1, accessed: ft(time.Unix(1, 0))}, // 1970
			gone,
		),
	}
	ev, _, cov := parse(t, write(t, tb, esegen.Options{}))
	if len(ev) != 2 {
		t.Fatalf("events = %d (a deleted record is not emitted)", len(ev))
	}
	for _, e := range ev {
		if !e.Timestamp.IsZero() {
			t.Errorf("%s was given the time %v", e.Extra["url"], e.Timestamp)
		}
	}
	if cov.Undated != 2 || !noteMentions(cov, "1 deleted") {
		t.Errorf("undated=%d notes=%v", cov.Undated, cov.Notes)
	}
}

func TestParse_ContainerListedButItsTableIsMissing(t *testing.T) {
	tb := []esegen.Table{containersTable(containerRow(2, "History", userDir), containerRow(5, "Content", userDir))}
	ev, _, cov := parse(t, write(t, tb, esegen.Options{}))
	if len(ev) != 0 || !noteMentions(cov, "container History (id 2): its table Container_2 is not in the database") {
		t.Errorf("events=%d notes=%v", len(ev), cov.Notes)
	}
}

func TestParse_WebCacheWithoutContainersAndNotESE(t *testing.T) {
	ev, _, cov := parse(t, write(t, []esegen.Table{{Name: "PartitionsEx", Columns: []esegen.Column{{ID: 1, Name: "PartitionId", Type: esegen.Int64}}}}, esegen.Options{}))
	if len(ev) != 0 || !noteMentions(cov, "no Containers table") {
		t.Errorf("events=%d notes=%v", len(ev), cov.Notes)
	}
	junk := filepath.Join(t.TempDir(), "WebCacheV01.dat")
	os.WriteFile(junk, []byte(strings.Repeat("not esedb ", 900)), 0o600)
	if _, err := (Parser{}).Parse(junk); err == nil {
		t.Errorf("a file that is not ESE was accepted")
	}
}

func TestParse_UserComesFromTheRecordOrTheContainerDirectory(t *testing.T) {
	tb := []esegen.Table{
		containersTable(containerRow(3, "Content", `C:\Users\bob\AppData\Local\Packages\x\AC\INetCache\`), containerRow(2, "History", `C:\Windows\system32\config\systemprofile\`)),
		container(3, entry{id: 1, url: "https://x.example/", accessed: ft(t0)}),
		container(2, entry{id: 1, url: "Visited: carol@https://y.example/", accessed: ft(t0)}),
	}
	ev, _, _ := parse(t, write(t, tb, esegen.Options{}))
	users := map[string]string{}
	for _, e := range ev {
		users[e.Extra["container_name"]] = e.User
	}
	if users["Content"] != "bob" || users["History"] != "carol" {
		t.Errorf("users = %v", users)
	}
}

func TestParse_DirtyDatabaseIsSaid(t *testing.T) {
	tb := []esegen.Table{containersTable(containerRow(2, "History", userDir)), container(2, entry{id: 1, url: "Visited: alice@https://a.example/", accessed: ft(t0)})}
	ev, _, cov := parse(t, write(t, tb, esegen.Options{State: 2}))
	if !noteMentions(cov, "not cleanly shut down") || ev[0].Extra["database_state"] != "dirty shutdown" {
		t.Errorf("notes=%v state=%q", cov.Notes, ev[0].Extra["database_state"])
	}
}

// Windows stores the container name and directory with a terminating NUL; a
// real file's "Content" is "Content\x00".
func TestParse_ContainerNamesWithTheirTerminatingNUL(t *testing.T) {
	nul := func(id int64, name, dir string) esegen.Record { return containerRow(id, name+"\x00", dir+"\x00") }
	tb := []esegen.Table{
		containersTable(nul(2, "History", userDir), nul(3, "Content", userDir), nul(23, "Cookies", userDir), nul(4, "DOMStore", userDir)),
		container(2, entry{id: 1, url: "Visited: alice@https://a.example/", count: 1, accessed: ft(t0)}),
		container(3, entry{id: 1, url: "https://b.example/", accessed: ft(t0)}),
		container(23, entry{id: 1, url: "Cookie:alice@c.example/", accessed: ft(t0)}),
		container(4, entry{id: 1, url: "DOMStore:https://d.example/", accessed: ft(t0)}),
	}
	ev, _, cov := parse(t, write(t, tb, esegen.Options{}))
	if len(ev) != 2 || ev[0].Extra["container_name"] != "History" && ev[1].Extra["container_name"] != "History" {
		t.Fatalf("events = %d %+v", len(ev), ev)
	}
	for _, e := range ev {
		if strings.Contains(e.Extra["container_name"], "\x00") || strings.Contains(e.Extra["container_directory"], "\x00") {
			t.Errorf("a NUL leaked into %+v", e.Extra)
		}
	}
	if !noteMentions(cov, "container Cookies (id 23): 1 cookie records are not read") || !noteMentions(cov, "container DOMStore (id 4): 1 records not interpreted") {
		t.Errorf("notes: %v", cov.Notes)
	}
}
