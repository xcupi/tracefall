package browserhistory_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/browserhistory"
)

// Reference instants, and their representation in each browser's epoch.
var (
	visitAt = time.Date(2026, 3, 1, 9, 15, 30, 0, time.UTC)
	// Chromium: microseconds since 1601-01-01 UTC.
	chromiumMicros = (visitAt.Unix() + 11644473600) * 1_000_000
	// Firefox: microseconds since 1970-01-01 UTC.
	firefoxMicros = visitAt.Unix() * 1_000_000
)

func chromiumDB(t *testing.T, dir string, walMode bool) string {
	t.Helper()
	path := filepath.Join(dir, "History")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if walMode {
		if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
			t.Fatal(err)
		}
	}
	stmts := []string{
		`CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)`,
		`CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO urls VALUES(1,'https://updates.example.test/payload','Download',3,?)`, chromiumMicros); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO urls VALUES(2,'https://intranet.example.test/wiki','Wiki',9,?)`, chromiumMicros); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO visits VALUES(1,1,?,805306368)`, chromiumMicros); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO visits VALUES(2,2,?,805306368)`, chromiumMicros+60_000_000); err != nil {
		t.Fatal(err)
	}
	return path
}

func firefoxDB(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "places.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range []string{
		`CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)`,
		`CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO moz_places VALUES(1,'https://updates.example.test/payload','Download',3)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO moz_historyvisits VALUES(1,1,?)`, firefoxMicros); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDetect(t *testing.T) {
	p := browserhistory.New()
	for _, name := range []string{
		"Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History",
		"Users/jdoe/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default-release/places.sqlite",
	} {
		if !p.Detect(name) {
			t.Errorf("Detect missed %q", name)
		}
	}
	if p.Detect("Security.evtx") {
		t.Error("Detect claimed an event log")
	}
	// Content detection is deliberately GONE. It used to accept any
	// SQLite database, which claimed every cookie store, favicon cache,
	// autofill database and saved-login store in a browser profile as
	// browser history and then failed each at import -- 25 files of
	// intact evidence reported as broken in one real image.
	if _, ok := any(p).(parsers.ContentDetector); ok {
		t.Error("browser history claims files by content again; any SQLite database would be claimed as history")
	}
	// The NAME match is confirmed against the bytes, so a file called
	// "History" that is not a database is not claimed.
	if !p.ConfirmContent([]byte("SQLite format 3\x00extra")) {
		t.Error("ConfirmContent rejected a SQLite database")
	}
	if p.ConfirmContent([]byte("regf....")) {
		t.Error("ConfirmContent accepted a registry hive as browser history")
	}
	// The databases that are NOT history must not be claimed at all.
	for _, name := range []string{
		"Cookies", "Login Data", "Favicons", "Web Data", "Media History",
		"Top Sites", "Shortcuts", "Network Action Predictor", "QuotaManager",
		"Reporting and NEL", "Safe Browsing Cookies", "cookies.sqlite",
		"formhistory.sqlite", "wpndatabase.db", "queue.sqlite3",
	} {
		full := "Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/" + name
		if p.Detect(full) {
			t.Errorf("Detect claimed %q as browser history", name)
		}
	}
}

// The epoch conversions differ by ~369 years; getting either wrong
// misplaces every visit, so each is asserted against a known instant.
func TestParse_ChromiumEpochAndFields(t *testing.T) {
	dir := t.TempDir()
	res, err := browserhistory.New().Parse(chromiumDB(t, dir, false))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 2 {
		t.Fatalf("events = %d, want 2", len(res.Events))
	}
	if len(res.Raw) != len(res.Events) {
		t.Fatal("raw records must pair 1:1 with events")
	}
	e := res.Events[0]
	if !e.Timestamp.Equal(visitAt) {
		t.Errorf("visit time = %v, want %v (WebKit epoch conversion is wrong)", e.Timestamp, visitAt)
	}
	if e.EventType != model.EventBrowserVisit || e.ArtifactType != model.ArtifactBrowserHistory {
		t.Errorf("type/artifact = %q/%q", e.EventType, e.ArtifactType)
	}
	if e.Extra["url"] != "https://updates.example.test/payload" {
		t.Errorf("url = %q", e.Extra["url"])
	}
	if e.Extra["page_title"] != "Download" {
		t.Errorf("title = %q", e.Extra["page_title"])
	}
	if e.Extra["visit_count"] != "3" {
		t.Errorf("visit_count = %q", e.Extra["visit_count"])
	}
	if e.NetworkDest != "updates.example.test" {
		t.Errorf("NetworkDest = %q, want the visited host", e.NetworkDest)
	}
	if e.Extra["browser"] != "chromium" {
		t.Errorf("browser = %q", e.Extra["browser"])
	}
	if e.Extra["timestamp_epoch"] == "" {
		t.Error("the epoch conversion used is not documented on the event")
	}
}

func TestParse_FirefoxEpochAndFields(t *testing.T) {
	dir := t.TempDir()
	res, err := browserhistory.New().Parse(firefoxDB(t, dir))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(res.Events))
	}
	if !res.Events[0].Timestamp.Equal(visitAt) {
		t.Errorf("visit time = %v, want %v (Unix epoch conversion is wrong)", res.Events[0].Timestamp, visitAt)
	}
	if res.Events[0].Extra["browser"] != "firefox" {
		t.Errorf("browser = %q", res.Events[0].Extra["browser"])
	}
}

// THE critical forensic property: parsing must not alter the evidence.
//
// A plain SQLite open on a database with an uncheckpointed WAL
// checkpoints it into the main file and deletes the sidecars -- silently
// modifying evidence. This proves Tracefall does not do that, and that
// it still reads the data held in the WAL.
func TestParse_DoesNotModifyEvidence(t *testing.T) {
	src := t.TempDir()
	dbPath := chromiumDB(t, src, true)

	// Add a row and leave it in an un-checkpointed WAL, then snapshot the
	// whole directory as "the evidence".
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`PRAGMA wal_autocheckpoint=0`)
	if _, err := db.Exec(`INSERT INTO urls VALUES(3,'https://inwal.example.test/late','In WAL',1,?)`, chromiumMicros+120_000_000); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO visits VALUES(3,3,?,805306368)`, chromiumMicros+120_000_000); err != nil {
		t.Fatal(err)
	}

	evidence := t.TempDir()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if b, err := os.ReadFile(dbPath + suffix); err == nil {
			if err := os.WriteFile(filepath.Join(evidence, "History"+suffix), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	db.Close()

	before := snapshot(t, evidence)
	res, err := browserhistory.New().Parse(filepath.Join(evidence, "History"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	after := snapshot(t, evidence)

	if before != after {
		t.Errorf("PARSING MODIFIED THE EVIDENCE:\n  before: %s\n  after:  %s", before, after)
	}
	// And the WAL content must actually have been read -- a "safe"
	// implementation that silently loses the most recent browsing would
	// be its own kind of failure.
	var sawWALRow bool
	for _, e := range res.Events {
		if e.NetworkDest == "inwal.example.test" {
			sawWALRow = true
		}
	}
	if !sawWALRow {
		t.Error("the visit held in the write-ahead log was not recovered")
	}
}

func snapshot(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var parts []string
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		parts = append(parts, e.Name()+"="+hex.EncodeToString(sum[:])[:16])
	}
	sort.Strings(parts)
	return joinAll(parts)
}

func joinAll(p []string) string {
	out := ""
	for _, s := range p {
		out += s + " "
	}
	return out
}

// A SQLite database that is not browser history must be reported
// honestly, not guessed at.
func TestParse_UnknownSchemaIsAStructuredFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "History")
	db, _ := sql.Open("sqlite", path)
	db.Exec(`CREATE TABLE something_else(id INTEGER PRIMARY KEY, value TEXT)`)
	db.Close()

	_, err := browserhistory.New().Parse(path)
	if !errors.Is(err, browserhistory.ErrUnknownSchema) {
		t.Errorf("error = %v, want ErrUnknownSchema", err)
	}
}

func TestParse_NonSQLiteIsRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "History")
	if err := os.WriteFile(path, []byte("this is not a database at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := browserhistory.New().Parse(path); !errors.Is(err, browserhistory.ErrNotSQLite) {
		t.Errorf("error = %v, want ErrNotSQLite", err)
	}
}

// A truncated/corrupt database must fail safely rather than panic.
func TestParse_CorruptDatabaseFailsSafely(t *testing.T) {
	dir := t.TempDir()
	good := chromiumDB(t, dir, false)
	raw, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(t.TempDir(), "History")
	if err := os.WriteFile(broken, raw[:len(raw)/3], 0o644); err != nil {
		t.Fatal(err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic on a truncated database: %v", r)
		}
	}()
	if _, err := browserhistory.New().Parse(broken); err == nil {
		t.Log("truncated database parsed without error (SQLite tolerated it); no panic, which is the requirement")
	}
}

func TestParse_IsDeterministic(t *testing.T) {
	dir := t.TempDir()
	path := chromiumDB(t, dir, false)
	first, err := browserhistory.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		again, err := browserhistory.New().Parse(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(again.Events) != len(first.Events) {
			t.Fatalf("run %d produced %d events, first run %d", i, len(again.Events), len(first.Events))
		}
		for j := range first.Events {
			if first.Events[j].ComputeDedupHash() != again.Events[j].ComputeDedupHash() {
				t.Fatalf("run %d event %d changed identity", i, j)
			}
		}
	}
}
