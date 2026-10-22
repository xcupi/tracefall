package grafanadb

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

// Canary values planted in the secret columns. None may reach any output.
var canaries = []string{"PWHASH-canary-1", "SALT-canary-2", "RANDS-canary-3", "APIKEY-canary-4", "AUTHTOK-canary-5", "PREVTOK-canary-6",
	"DSPASS-canary-7", "BASICPASS-canary-8", "SECUREJSON-canary-9", "JSONOPT-canary-10"}

const schemaFull = `
CREATE TABLE user (id INTEGER PRIMARY KEY, version INTEGER, login TEXT, email TEXT, name TEXT, password TEXT, salt TEXT, rands TEXT, company TEXT, org_id INTEGER, is_admin INTEGER, email_verified INTEGER, theme TEXT, created DATETIME, updated DATETIME, help_flags1 INTEGER, last_seen_at DATETIME, is_disabled INTEGER, is_service_account BOOLEAN, uid TEXT);
CREATE TABLE org_user (id INTEGER PRIMARY KEY, org_id INTEGER, user_id INTEGER, role TEXT, created DATETIME, updated DATETIME);
CREATE TABLE login_attempt (id INTEGER PRIMARY KEY, username TEXT, ip_address TEXT, created INTEGER);
CREATE TABLE api_key (id INTEGER PRIMARY KEY, org_id INTEGER, name TEXT, key TEXT, role TEXT, created DATETIME, updated DATETIME, expires INTEGER, service_account_id INTEGER, last_used_at DATETIME, is_revoked INTEGER);
CREATE TABLE data_source (id INTEGER PRIMARY KEY, org_id INTEGER, version INTEGER, type TEXT, name TEXT, access TEXT, url TEXT, password TEXT, user TEXT, database TEXT, basic_auth INTEGER, basic_auth_user TEXT, basic_auth_password TEXT, is_default INTEGER, json_data TEXT, created DATETIME, updated DATETIME, with_credentials INTEGER, secure_json_data TEXT, read_only INTEGER, uid TEXT);
CREATE TABLE user_auth_token (id INTEGER PRIMARY KEY, user_id INTEGER, auth_token TEXT, prev_auth_token TEXT, user_agent TEXT, client_ip TEXT, auth_token_seen INTEGER, seen_at INTEGER, rotated_at INTEGER, created_at INTEGER, updated_at INTEGER, revoked_at INTEGER, external_session_id INTEGER);
`

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}

func newDB(t *testing.T, schema string) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "grafana.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, schema)
	return db, path
}

func closeDB(t *testing.T, db *sql.DB) {
	t.Helper()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

// fullFixture: users alice01 (admin, seen), backdoor01 (server admin,
// never-seen sentinel), sa-1-svc (service account).
func fullFixture(t *testing.T) string {
	db, path := newDB(t, schemaFull)
	mustExec(t, db, `INSERT INTO user (id,login,email,name,password,salt,rands,is_admin,created,updated,last_seen_at,is_disabled,is_service_account) VALUES
	 (1,'alice01','alice01@example.invalid','Alice One','PWHASH-canary-1','SALT-canary-2','RANDS-canary-3',1,'2026-10-22 08:21:07','2026-10-22 08:21:07','2026-10-22 08:21:08',0,0),
	 (2,'backdoor01','b@example.invalid','Back Door','PWHASH-canary-1','SALT-canary-2','RANDS-canary-3',1,'2026-10-22 08:21:08','2026-10-22 08:21:08','2016-10-22 08:21:08',0,0),
	 (3,'sa-1-svc','sa-1-svc@example.invalid','svc','PWHASH-canary-1','SALT-canary-2','RANDS-canary-3',0,'2026-10-22 08:21:08','2026-10-22 08:21:09','2016-10-22 08:21:08',1,1)`)
	mustExec(t, db, `INSERT INTO org_user (id,org_id,user_id,role) VALUES (1,1,1,'Admin'),(2,1,2,'Viewer'),(3,2,2,'Admin'),(4,1,3,'Editor')`)
	mustExec(t, db, `INSERT INTO login_attempt (id,username,ip_address,created) VALUES (1,'alice01','203.0.113.9',1792657267),(2,'alice01','203.0.113.9',1792657268)`)
	mustExec(t, db, `INSERT INTO api_key (id,org_id,name,key,role,created,expires,service_account_id,last_used_at,is_revoked) VALUES
	 (1,1,'ci-token','APIKEY-canary-4','Viewer','2026-10-22 08:21:08',NULL,3,NULL,0),
	 (2,1,'old-token','APIKEY-canary-4','Admin','2026-10-22 08:21:09',1792700000,NULL,'2026-10-22 09:00:00',1)`)
	mustExec(t, db, `INSERT INTO data_source (id,org_id,type,name,access,url,password,user,database,basic_auth,basic_auth_password,is_default,json_data,created,updated,secure_json_data) VALUES
	 (1,1,'mssql','sql01','proxy','sql01.example.invalid:1433','','svc_ro','metrics',0,'',1,'{"opt":"JSONOPT-canary-10"}','2026-10-22 08:21:08','2026-10-22 08:21:09','SECUREJSON-canary-9'),
	 (2,1,'prometheus','prom','proxy','http://u:DSPASS-canary-7@203.0.113.20:9090/x?password=BASICPASS-canary-8','','','',1,'BASICPASS-canary-8',0,'{}','2026-10-22 08:21:10','2026-10-22 08:21:10','')`)
	mustExec(t, db, `INSERT INTO user_auth_token (id,user_id,auth_token,prev_auth_token,user_agent,client_ip,seen_at,rotated_at,created_at,revoked_at) VALUES
	 (1,1,'AUTHTOK-canary-5','PREVTOK-canary-6','Mozilla/5.0 test','203.0.113.9',0,1792657268,1792657268,0)`)
	closeDB(t, db)
	return path
}

func byType(evs []model.Event) map[string][]model.Event {
	m := map[string][]model.Event{}
	for _, e := range evs {
		m[e.EventType] = append(m[e.EventType], e)
	}
	return m
}

func TestDetect_And_Confirm(t *testing.T) {
	p := New()
	for _, n := range []string{"grafana.db", "var/lib/grafana/grafana.db", `x\Grafana.DB`} {
		if !p.Detect(n) {
			t.Errorf("%q not detected", n)
		}
	}
	for _, n := range []string{"grafana.db-wal", "grafana.sqlite", "mygrafana.db", "grafana.log"} {
		if p.Detect(n) {
			t.Errorf("%q detected", n)
		}
	}
	if !p.ConfirmContent([]byte("SQLite format 3\x00rest")) {
		t.Error("magic not confirmed")
	}
	if p.ConfirmContent([]byte("SQLite format 3 ")) || p.ConfirmContent([]byte("hello")) || p.ConfirmContent(nil) {
		t.Error("non-SQLite confirmed")
	}
	var _ parsers.ContentConfirmer = p
	var _ parsers.ArtifactParser = p
}

func TestParse_EmitsEachRecordKind(t *testing.T) {
	path := fullFixture(t)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	m := byType(res.Events)
	want := map[string]int{model.EventGrafanaUser: 3, model.EventGrafanaToken: 2, model.EventGrafanaDataSource: 2, model.EventGrafanaLoginAttempt: 2, model.EventGrafanaSession: 1}
	for k, n := range want {
		if len(m[k]) != n {
			t.Errorf("%s = %d, want %d", k, len(m[k]), n)
		}
	}
	if len(res.Raw) != len(res.Events) {
		t.Errorf("raw %d events %d", len(res.Raw), len(res.Events))
	}
	for _, e := range res.Events {
		if e.ArtifactType != model.ArtifactGrafanaDB || e.Parser != "grafanadb@1" || e.FilePath != "grafana.db" || e.SourceReference == "" || e.Confidence == 0 ||
			e.Extra["records_outcome"] != "stored by Grafana; shows state, not who caused it" {
			t.Errorf("provenance %+v", e)
		}
	}
	refs := map[string]bool{}
	for _, e := range res.Events {
		if refs[e.SourceReference] {
			t.Errorf("duplicate reference %s", e.SourceReference)
		}
		refs[e.SourceReference] = true
	}

	u := m[model.EventGrafanaUser][0]
	for k, v := range map[string]string{"grafana_user_id": "1", "login": "alice01", "email": "alice01@example.invalid", "name": "Alice One", "server_admin": "true",
		"service_account": "false", "disabled": "false", "org_role": "Admin", "created": "2026-10-22 08:21:07", "updated": "2026-10-22 08:21:07", "last_seen_at": "2026-10-22 08:21:08",
		"timestamp_basis": timestampBasisUTCText} {
		if u.Extra[k] != v {
			t.Errorf("user Extra[%s] = %q, want %q", k, u.Extra[k], v)
		}
	}
	if !u.Timestamp.Equal(time.Date(2026, 10, 22, 8, 21, 7, 0, time.UTC)) {
		t.Errorf("user ts %v", u.Timestamp)
	}
	if got := m[model.EventGrafanaUser][1].Extra["org_role"]; got != "Admin" {
		t.Errorf("highest role = %q (Viewer and Admin rows)", got)
	}
	if sa := m[model.EventGrafanaUser][2]; sa.Extra["service_account"] != "true" || sa.Extra["disabled"] != "true" || sa.Extra["org_role"] != "Editor" {
		t.Errorf("service account %+v", sa.Extra)
	}

	tk := m[model.EventGrafanaToken]
	if tk[0].Extra["name"] != "ci-token" || tk[0].Extra["role"] != "Viewer" || tk[0].Extra["service_account_id"] != "3" || tk[0].Extra["revoked"] != "false" {
		t.Errorf("token %+v", tk[0].Extra)
	}
	for _, k := range []string{"expires", "last_used_at"} {
		if _, has := tk[0].Extra[k]; has {
			t.Errorf("NULL %s was emitted", k)
		}
	}
	if tk[1].Extra["expires"] != "1792700000" || tk[1].Extra["last_used_at"] != "2026-10-22 09:00:00" || tk[1].Extra["revoked"] != "true" {
		t.Errorf("token 2 %+v", tk[1].Extra)
	}

	ds := m[model.EventGrafanaDataSource]
	for k, v := range map[string]string{"name": "sql01", "type": "mssql", "url": "sql01.example.invalid:1433", "user": "svc_ro", "database": "metrics", "access": "proxy",
		"basic_auth": "false", "is_default": "true", "secrets_stored": "true"} {
		if ds[0].Extra[k] != v {
			t.Errorf("datasource Extra[%s] = %q, want %q", k, ds[0].Extra[k], v)
		}
	}
	if ds[1].Extra["secrets_stored"] != "true" { // basic_auth_password only
		t.Errorf("ds2 %+v", ds[1].Extra)
	}
	if _, has := ds[0].Extra["json_data"]; has {
		t.Error("json_data emitted")
	}

	la := m[model.EventGrafanaLoginAttempt]
	if la[0].Extra["login"] != "alice01" || la[0].Extra["source_address"] != "203.0.113.9" || la[0].NetworkSource != "203.0.113.9" ||
		!la[0].Timestamp.Equal(time.Unix(1792657267, 0).UTC()) || !strings.Contains(la[0].Extra["note"], "not a complete record of failed logins") {
		t.Errorf("attempt %+v ts=%v", la[0].Extra, la[0].Timestamp)
	}
	if la[0].Extra["note"] != attemptNote {
		t.Errorf("note = %q", la[0].Extra["note"])
	}

	s := m[model.EventGrafanaSession][0]
	if s.Extra["user_id"] != "1" || s.Extra["client_ip"] != "203.0.113.9" || s.Extra["user_agent"] != "Mozilla/5.0 test" || !s.Timestamp.Equal(time.Unix(1792657268, 0).UTC()) {
		t.Errorf("session %+v", s.Extra)
	}
	if s.Extra["rotated_at"] != "1792657268" {
		t.Errorf("rotated_at %q", s.Extra["rotated_at"])
	}
	for _, k := range []string{"revoked_at", "seen_at"} {
		if _, has := s.Extra[k]; has {
			t.Errorf("zero %s emitted", k)
		}
	}
}

func TestParse_NeverSeenSentinelIsNotALoginTime(t *testing.T) {
	res, err := New().Parse(fullFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	us := byType(res.Events)[model.EventGrafanaUser]
	for _, i := range []int{1, 2} {
		x := us[i].Extra
		if x["last_seen"] != "never" {
			t.Errorf("user %d last_seen = %q", i+1, x["last_seen"])
		}
		if _, has := x["last_seen_at"]; has {
			t.Errorf("user %d prints the sentinel: %q", i+1, x["last_seen_at"])
		}
	}
	if us[0].Extra["last_seen"] != "" {
		t.Errorf("a real last_seen_at was marked %q", us[0].Extra["last_seen"])
	}
	for _, r := range res.Raw {
		if strings.Contains(r.Raw, "2016-10-22") {
			t.Errorf("raw record prints the sentinel: %s", r.Raw)
		}
	}
}

func TestParse_NoSecretReachesAnyOutput(t *testing.T) {
	res, err := New().Parse(fullFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	for _, c := range canaries {
		if strings.Contains(string(b), c) {
			t.Errorf("secret %q reached the output", c)
		}
	}
	ds := byType(res.Events)[model.EventGrafanaDataSource][1]
	if strings.Contains(ds.Extra["url"], "u:") || strings.Contains(strings.ToLower(ds.Extra["url"]), "password=BASICPASS") {
		t.Errorf("url userinfo/query secret kept: %q", ds.Extra["url"])
	}
	for _, f := range forbiddenColumns {
		for tbl, cols := range wantedColumns {
			for _, c := range cols {
				if c == f {
					t.Errorf("%s selects forbidden column %s", tbl, f)
				}
			}
		}
	}
}

func TestParse_MissingOptionalTablesAndColumns(t *testing.T) {
	db, path := newDB(t, `
CREATE TABLE user (id INTEGER PRIMARY KEY, login TEXT, email TEXT, is_admin INTEGER, created DATETIME);
CREATE TABLE org_user (id INTEGER PRIMARY KEY, user_id INTEGER, role TEXT);
CREATE TABLE login_attempt (id INTEGER PRIMARY KEY, username TEXT, ip_address TEXT, created INTEGER);`)
	mustExec(t, db, `INSERT INTO user (id,login,email,is_admin,created) VALUES (1,'alice01','a@example.invalid',0,'2026-10-22 08:21:07')`)
	mustExec(t, db, `INSERT INTO login_attempt VALUES (1,'alice01','203.0.113.9',1792657267)`)
	closeDB(t, db)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	m := byType(res.Events)
	if len(m[model.EventGrafanaUser]) != 1 || len(m[model.EventGrafanaLoginAttempt]) != 1 || len(res.Events) != 2 {
		t.Fatalf("%v", m)
	}
	u := m[model.EventGrafanaUser][0].Extra
	if u["login"] != "alice01" || u["server_admin"] != "false" {
		t.Errorf("%v", u)
	}
	for _, k := range []string{"service_account", "disabled", "last_seen", "last_seen_at", "name", "updated", "org_role"} {
		if _, has := u[k]; has {
			t.Errorf("absent column surfaced as %s=%q", k, u[k])
		}
	}
	notes := strings.Join(res.Coverage.Notes, "|")
	for _, tbl := range []string{"api_key", "data_source", "user_auth_token"} {
		if !strings.Contains(notes, "table "+tbl+" is not present") {
			t.Errorf("no note for missing %s: %s", tbl, notes)
		}
	}
}

func TestParse_RefusesOtherSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grafana.db")
	db, _ := sql.Open("sqlite", path)
	mustExec(t, db, `CREATE TABLE urls (id INTEGER); CREATE TABLE visits (id INTEGER)`)
	closeDB(t, db)
	if _, err := New().Parse(path); !errors.Is(err, ErrNotGrafana) {
		t.Fatalf("err = %v", err)
	}
	// user + org_user alone, without login_attempt or api_key, is not enough
	db, path = newDB(t, `CREATE TABLE user (id INTEGER, login TEXT); CREATE TABLE org_user (id INTEGER, user_id INTEGER)`)
	closeDB(t, db)
	if _, err := New().Parse(path); !errors.Is(err, ErrNotGrafana) {
		t.Fatalf("err = %v", err)
	}
	// user + org_user + api_key is enough
	db, path = newDB(t, `CREATE TABLE user (id INTEGER, login TEXT); CREATE TABLE org_user (id INTEGER, user_id INTEGER); CREATE TABLE api_key (id INTEGER, name TEXT)`)
	mustExec(t, db, `INSERT INTO api_key VALUES (1,'t')`)
	closeDB(t, db)
	if res, err := New().Parse(path); err != nil || len(res.Events) != 1 {
		t.Fatalf("err = %v", err)
	}
}

func TestParse_CorruptAndNonSQLiteFilesError(t *testing.T) {
	dir := t.TempDir()
	text := filepath.Join(dir, "a", "grafana.db")
	os.MkdirAll(filepath.Dir(text), 0o755)
	os.WriteFile(text, []byte("not a database at all"), 0o600)
	if _, err := New().Parse(text); !errors.Is(err, ErrNotSQLite) {
		t.Errorf("text err = %v", err)
	}
	// good magic, destroyed body
	good := fullFixture(t)
	b, _ := os.ReadFile(good)
	corrupt := filepath.Join(dir, "b", "grafana.db")
	os.MkdirAll(filepath.Dir(corrupt), 0o755)
	junk := append([]byte{}, b[:100]...)
	for i := 0; i < 8192; i++ {
		junk = append(junk, byte(i*7+3))
	}
	os.WriteFile(corrupt, junk, 0o600)
	res, err := New().Parse(corrupt)
	if err == nil {
		t.Fatalf("corrupt file parsed: %d events", len(res.Events))
	}
	if _, err := New().Parse(filepath.Join(dir, "missing.db")); err == nil {
		t.Error("missing file did not error")
	}
	// SQLite magic only
	m := filepath.Join(dir, "c", "grafana.db")
	os.MkdirAll(filepath.Dir(m), 0o755)
	os.WriteFile(m, []byte("SQLite format 3\x00"), 0o600)
	if _, err := New().Parse(m); err == nil {
		t.Error("magic-only file parsed")
	}
}

func TestParse_RowCapIsExplicit(t *testing.T) {
	old := maxRows
	maxRows = 5
	defer func() { maxRows = old }()
	db, path := newDB(t, schemaFull)
	mustExec(t, db, `INSERT INTO user (id,login,created) VALUES (1,'alice01','2026-10-22 08:21:07')`)
	for i := 1; i <= 8; i++ {
		mustExec(t, db, `INSERT INTO login_attempt VALUES (?,?,?,?)`, i, "alice01", "203.0.113.9", 1792657267+i)
	}
	closeDB(t, db)
	res, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	la := byType(res.Events)[model.EventGrafanaLoginAttempt]
	if len(la) != 5 || la[4].SourceReference != "login_attempt:id=5" {
		t.Fatalf("attempts = %d", len(la))
	}
	if !res.Coverage.LimitReached || !strings.Contains(strings.Join(res.Coverage.Notes, "|"), "table login_attempt: only the first 5 rows (by id) were read") {
		t.Errorf("coverage %+v", res.Coverage)
	}
}

func TestParse_OrderedByIDAndDeterministic(t *testing.T) {
	db, path := newDB(t, schemaFull)
	mustExec(t, db, `INSERT INTO login_attempt VALUES (30,'c','203.0.113.3',1792657269),(10,'a','203.0.113.1',1792657267),(20,'b','203.0.113.2',1792657268)`)
	mustExec(t, db, `INSERT INTO user (id,login,created) VALUES (1,'alice01','2026-10-22 08:21:07')`)
	closeDB(t, db)
	a, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	var refs []string
	for _, e := range byType(a.Events)[model.EventGrafanaLoginAttempt] {
		refs = append(refs, e.SourceReference)
	}
	if strings.Join(refs, ",") != "login_attempt:id=10,login_attempt:id=20,login_attempt:id=30" {
		t.Errorf("order %v", refs)
	}
	b, _ := New().Parse(path)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Error("not deterministic")
	}
}

func fileSum(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func listDir(t *testing.T, d string) string {
	es, _ := os.ReadDir(d)
	var n []string
	for _, e := range es {
		n = append(n, e.Name())
	}
	sort.Strings(n)
	return strings.Join(n, ",")
}

func TestParse_DoesNotModifyEvidence(t *testing.T) {
	path := fullFixture(t)
	before, dirBefore := fileSum(t, path), listDir(t, filepath.Dir(path))
	if _, err := New().Parse(path); err != nil {
		t.Fatal(err)
	}
	if fileSum(t, path) != before {
		t.Error("evidence bytes changed")
	}
	if listDir(t, filepath.Dir(path)) != dirBefore {
		t.Errorf("directory changed: %s -> %s", dirBefore, listDir(t, filepath.Dir(path)))
	}
}

func TestParse_UncheckpointedWALIsReadWithoutTouchingEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grafana.db")
	db, _ := sql.Open("sqlite", path)
	db.SetMaxOpenConns(1)
	mustExec(t, db, `PRAGMA journal_mode=WAL`)
	mustExec(t, db, `PRAGMA wal_autocheckpoint=0`)
	mustExec(t, db, schemaFull)
	mustExec(t, db, `INSERT INTO user (id,login,created) VALUES (1,'alice01','2026-10-22 08:21:07')`)
	mustExec(t, db, `INSERT INTO login_attempt VALUES (1,'alice01','203.0.113.9',1792657267)`)
	// freeze a copy while the WAL still holds the rows
	dir := t.TempDir()
	for _, s := range []string{"", "-wal"} {
		b, err := os.ReadFile(path + s)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, "grafana.db"+s), b, 0o600)
	}
	closeDB(t, db)
	frozen := filepath.Join(dir, "grafana.db")
	hDB, hWAL, names := fileSum(t, frozen), fileSum(t, frozen+"-wal"), listDir(t, dir)
	res, err := New().Parse(frozen)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 2 {
		t.Errorf("events from WAL = %d, want 2", len(res.Events))
	}
	if fileSum(t, frozen) != hDB || fileSum(t, frozen+"-wal") != hWAL || listDir(t, dir) != names {
		t.Error("evidence or its sidecars changed")
	}
}

const realDBSHA = "02a41b138666be05bc3392bff44fd3ffe1f6db0de97895ac111c39213d21afa3"

func TestReal_GrafanaDB(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_GRAFANA_DB")
	if path == "" {
		t.Skip("TRACEFALL_REAL_GRAFANA_DB not set")
	}
	if got := fileSum(t, path); got != realDBSHA {
		t.Skipf("sample hash %s is not the pinned one", got)
	}
	res, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if fileSum(t, path) != realDBSHA {
		t.Fatal("evidence changed")
	}
	// independent counts and secret values, read through a copy
	dir := t.TempDir()
	b, _ := os.ReadFile(path)
	cp := filepath.Join(dir, "x.db")
	os.WriteFile(cp, b, 0o600)
	db, err := sql.Open("sqlite", "file:"+cp+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	count := func(tbl string) int {
		var n int
		if err := db.QueryRow("SELECT count(*) FROM " + tbl).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	m := byType(res.Events)
	for ev, tbl := range map[string]string{model.EventGrafanaUser: "user", model.EventGrafanaToken: "api_key", model.EventGrafanaDataSource: "data_source",
		model.EventGrafanaLoginAttempt: "login_attempt", model.EventGrafanaSession: "user_auth_token"} {
		t.Logf("%s events=%d independent %s count=%d", ev, len(m[ev]), tbl, count(tbl))
		if len(m[ev]) != count(tbl) {
			t.Errorf("%s: %d events, %d rows", ev, len(m[ev]), count(tbl))
		}
	}
	out, _ := json.Marshal(res)
	var secrets []string
	for _, q := range []string{`SELECT password FROM user`, `SELECT salt FROM user`, `SELECT rands FROM user`, `SELECT key FROM api_key`,
		`SELECT secure_json_data FROM data_source`, `SELECT auth_token FROM user_auth_token`, `SELECT prev_auth_token FROM user_auth_token`} {
		rows, err := db.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var s sql.NullString
			rows.Scan(&s)
			if len(s.String) >= 8 {
				secrets = append(secrets, s.String)
			}
		}
		rows.Close()
	}
	if len(secrets) == 0 {
		t.Fatal("no secret values found to test against")
	}
	for _, s := range secrets {
		if strings.Contains(string(out), s) {
			t.Error("a secret value from the database reached the output")
		}
	}
	t.Logf("checked %d secret values for absence", len(secrets))
	never := 0
	for _, u := range m[model.EventGrafanaUser] {
		if u.Extra["last_seen"] == "never" {
			never++
		}
		if strings.HasPrefix(u.Extra["last_seen_at"], "2016") {
			t.Errorf("sentinel printed for %s", u.Extra["login"])
		}
	}
	var wantNever int
	db.QueryRow(`SELECT count(*) FROM user WHERE abs(strftime('%s',last_seen_at) - strftime('%s',datetime(created,'-10 years'))) <= 86400`).Scan(&wantNever)
	t.Logf("never-seen users=%d independent=%d", never, wantNever)
	if never != wantNever || never == 0 {
		t.Errorf("never-seen %d, independent %d", never, wantNever)
	}
	_ = fmt.Sprint
}
