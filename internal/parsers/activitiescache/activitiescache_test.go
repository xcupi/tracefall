package activitiescache_test

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/activitiescache"
)

var activityAt = time.Date(2021, 4, 29, 18, 30, 0, 0, time.UTC)

// buildDB writes a database from the given statements and returns its
// path inside a user-shaped directory, so user context is derivable.
func buildDB(t *testing.T, name string, stmts []string, rows func(*sql.DB)) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "Users", "jdoe", "AppData")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if rows != nil {
		rows(db)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

const activitySchema = `CREATE TABLE Activity(
	Id TEXT, AppId TEXT, ActivityType INTEGER, Payload TEXT,
	StartTime INTEGER, EndTime INTEGER, LastModifiedTime INTEGER,
	LastModifiedOnClient INTEGER, PlatformDeviceId TEXT)`

func appIDJSON(path string) string {
	b, _ := json.Marshal([]map[string]string{{"application": path, "platform": "windows_win32"}})
	return string(b)
}

func payloadJSON(display, uri string) string {
	b, _ := json.Marshal(map[string]string{"displayText": display, "contentUri": uri})
	return string(b)
}

func TestParse_ValidDatabaseDecodesWithHonestSemantics(t *testing.T) {
	path := buildDB(t, "ActivitiesCache.db", []string{activitySchema}, func(db *sql.DB) {
		db.Exec(`INSERT INTO Activity VALUES(?,?,?,?,?,?,?,?,?)`,
			"id-1", appIDJSON(`C:\Tools\editor.exe`), 5,
			payloadJSON("report.docx", "file:///C:/Docs/report.docx"),
			activityAt.Unix(), activityAt.Add(time.Hour).Unix(),
			activityAt.Unix(), activityAt.Unix(), "device-1")
	})

	res, err := activitiescache.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	e := res.Events[0]
	if e.EventType != model.EventActivityRecorded {
		t.Errorf("event type = %q", e.EventType)
	}
	if !e.Timestamp.Equal(activityAt) {
		t.Errorf("timestamp = %s, want %s", e.Timestamp, activityAt)
	}
	if e.User != "jdoe" {
		t.Errorf("user = %q, want jdoe from the evidence path", e.User)
	}
	if got := e.Extra["application"]; got != `C:\Tools\editor.exe` {
		t.Errorf("application = %q", got)
	}
	if got := e.Extra["activity_type"]; got != "application or file opened" {
		t.Errorf("activity type = %q", got)
	}
	if !strings.Contains(e.Extra["evidence_meaning"], "NOT a process-creation record") {
		t.Errorf("evidence_meaning does not disclaim process creation: %q", e.Extra["evidence_meaning"])
	}
	if len(res.Raw) != len(res.Events) {
		t.Error("every event must carry a raw record")
	}
}

// An undocumented ActivityType must be reported as its raw number, never
// given an invented label.
func TestParse_UnknownActivityTypeIsNotNamed(t *testing.T) {
	path := buildDB(t, "ActivitiesCache.db", []string{activitySchema}, func(db *sql.DB) {
		db.Exec(`INSERT INTO Activity VALUES(?,?,?,?,?,?,?,?,?)`,
			"id-1", appIDJSON(`C:\a.exe`), 9999, payloadJSON("x", ""),
			activityAt.Unix(), 0, 0, 0, "")
	})
	res, err := activitiescache.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	e := res.Events[0]
	if got := e.Extra["activity_type_raw"]; got != "9999" {
		t.Errorf("raw type = %q, want 9999", got)
	}
	if !strings.Contains(e.Extra["activity_type"], "not a value Tracefall recognizes") {
		t.Errorf("an unknown type was labelled %q", e.Extra["activity_type"])
	}
}

// A row with no usable timestamp keeps its identity and says so.
func TestParse_RowWithoutTimestampIsKeptAndFlagged(t *testing.T) {
	path := buildDB(t, "ActivitiesCache.db", []string{activitySchema}, func(db *sql.DB) {
		db.Exec(`INSERT INTO Activity VALUES(?,?,?,?,?,?,?,?,?)`,
			"id-1", appIDJSON(`C:\a.exe`), 5, payloadJSON("doc", ""), 0, 0, 0, 0, "")
	})
	res, err := activitiescache.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("a row with no timestamp was dropped; got %d events", len(res.Events))
	}
	e := res.Events[0]
	if !e.Timestamp.IsZero() {
		t.Errorf("a timestamp was invented: %s", e.Timestamp)
	}
	if e.Extra["timestamp_basis"] == "" {
		t.Error("no timestamp_basis explains the missing time")
	}
}

// A valid database with no activities is not a failure.
func TestParse_EmptyDatabaseIsNotAFailure(t *testing.T) {
	path := buildDB(t, "ActivitiesCache.db", []string{activitySchema}, nil)
	res, err := activitiescache.New().Parse(path)
	if err != nil {
		t.Fatalf("an empty but valid database was reported as an error: %v", err)
	}
	if len(res.Events) != 0 {
		t.Errorf("got %d events from an empty database", len(res.Events))
	}
}

// A SQLite database with another schema is NOT this artifact -- a
// distinct answer from "this artifact is broken".
func TestParse_ForeignSchemaIsReportedAsNotThisArtifact(t *testing.T) {
	path := buildDB(t, "ActivitiesCache.db",
		[]string{`CREATE TABLE unrelated(id INTEGER PRIMARY KEY, note TEXT)`}, nil)
	_, err := activitiescache.New().Parse(path)
	if !errors.Is(err, activitiescache.ErrNotActivitiesCache) {
		t.Errorf("err = %v, want ErrNotActivitiesCache", err)
	}
}

// Truncation and corruption must not panic.
func TestParse_CorruptDatabaseIsHandledWithoutPanicking(t *testing.T) {
	good := buildDB(t, "ActivitiesCache.db", []string{activitySchema}, func(db *sql.DB) {
		db.Exec(`INSERT INTO Activity VALUES('a','[]',5,'{}',?,0,0,0,'')`, activityAt.Unix())
	})
	data, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"empty":          {},
		"tiny":           []byte("SQLite"),
		"truncated":      data[:len(data)/2],
		"header only":    data[:100],
		"not a database": []byte(strings.Repeat("not a database at all ", 100)),
	}
	for name, bytes := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: panic: %v", name, r)
				}
			}()
			p := filepath.Join(t.TempDir(), "ActivitiesCache.db")
			if err := os.WriteFile(p, bytes, 0o644); err != nil {
				t.Fatal(err)
			}
			// Either an error or zero events is acceptable; a panic is not.
			_, _ = activitiescache.New().Parse(p)
		}()
	}
}

// The evidence file must never be modified, and no journal or WAL may be
// written beside it -- the reason the parser stages a copy.
func TestParse_EvidenceIsNeverModified(t *testing.T) {
	path := buildDB(t, "ActivitiesCache.db", []string{activitySchema}, func(db *sql.DB) {
		db.Exec(`INSERT INTO Activity VALUES('a','[]',5,'{}',?,0,0,0,'')`, activityAt.Unix())
	})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	entriesBefore, _ := os.ReadDir(dir)

	if _, err := activitiescache.New().Parse(path); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("the database was modified by parsing it")
	}
	entriesAfter, _ := os.ReadDir(dir)
	if len(entriesAfter) != len(entriesBefore) {
		var names []string
		for _, e := range entriesAfter {
			names = append(names, e.Name())
		}
		t.Errorf("parsing wrote files beside the evidence: %v", names)
	}
}

// Detection must not depend on the filename alone.
func TestDetect_ContentAndNameAreBothHandled(t *testing.T) {
	p := activitiescache.New()
	if !p.Detect("Users/j/AppData/Local/ConnectedDevicesPlatform/L.j/ActivitiesCache.db") {
		t.Error("the canonical filename was not matched")
	}
	if p.Detect("Users/j/Documents/notes.txt") {
		t.Error("an unrelated filename was matched")
	}
	// The name match is CONFIRMED by the bytes; there is deliberately no
	// content detection any more. Accepting any SQLite database made
	// this parser claim cookie stores, favicon caches and Windows
	// notification databases as Windows Timeline the moment the browser
	// history parser stopped claiming them first.
	if !p.ConfirmContent([]byte("SQLite format 3\x00rest of header")) {
		t.Error("the SQLite signature was not confirmed")
	}
	if p.ConfirmContent([]byte("not a database")) {
		t.Error("a non-SQLite header was confirmed")
	}
	if _, ok := any(p).(parsers.ContentDetector); ok {
		t.Error("this parser claims files by content again; any SQLite database would become Windows Timeline")
	}
}

func TestParse_IsDeterministic(t *testing.T) {
	path := buildDB(t, "ActivitiesCache.db", []string{activitySchema}, func(db *sql.DB) {
		for i := 0; i < 20; i++ {
			db.Exec(`INSERT INTO Activity VALUES(?,?,?,?,?,?,?,?,?)`,
				fmt.Sprintf("id-%02d", i), appIDJSON(fmt.Sprintf(`C:\a%d.exe`, i)), 5,
				payloadJSON(fmt.Sprintf("doc%d", i), ""),
				activityAt.Add(time.Duration(i)*time.Minute).Unix(), 0, 0, 0, "")
		}
	})
	first, err := activitiescache.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := activitiescache.New().Parse(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(again.Events) != len(first.Events) {
			t.Fatalf("run %d produced %d events, first %d", i, len(again.Events), len(first.Events))
		}
		for j := range first.Events {
			if again.Events[j].SourceReference != first.Events[j].SourceReference ||
				!again.Events[j].Timestamp.Equal(first.Events[j].Timestamp) {
				t.Fatalf("run %d differs at event %d", i, j)
			}
		}
	}
}

// Unicode and very long values must survive bounded.
func TestParse_UnicodeAndLongValuesAreBoundedNotCorrupted(t *testing.T) {
	long := strings.Repeat("x", 50000)
	path := buildDB(t, "ActivitiesCache.db", []string{activitySchema}, func(db *sql.DB) {
		db.Exec(`INSERT INTO Activity VALUES(?,?,?,?,?,?,?,?,?)`,
			"id-1", appIDJSON(`C:\Tools\日本語.exe`), 5,
			payloadJSON("報告書-日本語.docx", "file:///C:/"+long),
			activityAt.Unix(), 0, 0, 0, "")
	})
	res, err := activitiescache.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	e := res.Events[0]
	if !strings.Contains(e.Extra["application"], "日本語") {
		t.Errorf("the Unicode application path did not survive: %q", e.Extra["application"])
	}
	if got := e.Extra["display_text"]; got != "報告書-日本語.docx" {
		t.Errorf("the Unicode display text = %q", got)
	}
	if len(e.Extra["content_uri"]) > 9000 {
		t.Errorf("a 50KB URI was not bounded: %d bytes", len(e.Extra["content_uri"]))
	}
}

// A large database must parse in bounded time and memory.
func TestScale_ManyActivities(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in short mode")
	}
	const n = 20000
	path := buildDB(t, "ActivitiesCache.db", []string{activitySchema}, func(db *sql.DB) {
		tx, _ := db.Begin()
		st, err := tx.Prepare(`INSERT INTO Activity VALUES(?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			st.Exec(fmt.Sprintf("id-%06d", i), appIDJSON(fmt.Sprintf(`C:\apps\a%d.exe`, i%500)), 5,
				payloadJSON(fmt.Sprintf("document-%d.docx", i), fmt.Sprintf("file:///C:/docs/%d", i)),
				activityAt.Add(time.Duration(i)*time.Second).Unix(), 0, 0, 0, "device-1")
		}
		st.Close()
		tx.Commit()
	})

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	res, err := activitiescache.New().Parse(path)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)

	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != n {
		t.Errorf("got %d events, want %d", len(res.Events), n)
	}
	t.Logf("%d activities parsed in %v (%.1f MiB allocated)",
		len(res.Events), elapsed.Round(time.Millisecond),
		float64(after.TotalAlloc-before.TotalAlloc)/(1<<20))
	if elapsed > 60*time.Second {
		t.Errorf("parsing %d activities took %v", n, elapsed)
	}
}
