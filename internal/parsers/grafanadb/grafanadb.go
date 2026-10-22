// Package grafanadb parses a Grafana database (grafana.db, SQLite).
//
// # What it reads, and what it never reads
//
// Only these tables, each ordered by id and capped: user, org_user (for the
// organisation role), login_attempt, api_key, data_source, user_auth_token.
// Columns are chosen from a fixed allow-list. The password, salt, rands, api
// key, session token, data-source password and secure_json_data columns are
// never selected as values (a data source's secrets are reduced to a
// secrets_stored flag by length() inside SQL), and json_data is not read.
//
// # What a row proves
//
// A row is what Grafana stored. It shows state, not who caused it. The
// login_attempt table holds only attempts against existing accounts and is
// pruned, so it is not a complete record of failed logins.
//
// # Time
//
// Grafana documents that it stores datetimes in UTC; user, api_key and
// data_source times are read as UTC on that basis (Extra["timestamp_basis"]).
// login_attempt and user_auth_token use Unix seconds. A last_seen_at within a
// day of "created minus ten years" is Grafana's never-seen sentinel and is
// reported as last_seen=never, never as a login time.
//
// # Evidence is never modified
//
// The database and its -wal/-shm/-journal sidecars are copied into a private
// scratch directory and the copy is opened read-only, so recovery of a hot WAL
// happens on the copy. The evidence file is only read as bytes.
package grafanadb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite" // the pure-Go driver Tracefall already depends on

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "grafanadb@1"

var (
	// ErrNotSQLite means the file does not start with the SQLite signature.
	ErrNotSQLite = errors.New("grafanadb: not a SQLite database")
	// ErrNotGrafana means it is SQLite but lacks the Grafana tables.
	ErrNotGrafana = errors.New("grafanadb: SQLite database is not a Grafana database")
	// ErrTooLarge means the database exceeds the size ceiling.
	ErrTooLarge = errors.New("grafanadb: database exceeds the maximum size")
)

const (
	sqliteMagic = "SQLite format 3\x00"
	maxDBBytes  = 2 << 30

	timestampBasisUTCText = "UTC: Grafana documents that it stores datetimes in UTC"
	timestampBasisUnix    = "Unix seconds (UTC)"
	attemptNote           = "Grafana records only attempts for existing accounts and prunes old rows, so this table is not a complete record of failed logins"
	recordsOutcome        = "stored by Grafana; shows state, not who caused it"
)

// maxRows is a variable only so a test can lower it.
var maxRows = 50000

// wantedColumns is the allow-list of columns read as values, per table.
var wantedColumns = map[string][]string{
	"user":            {"id", "login", "email", "name", "is_admin", "is_service_account", "is_disabled", "created", "updated", "last_seen_at"},
	"org_user":        {"id", "user_id", "role"},
	"login_attempt":   {"id", "username", "ip_address", "created"},
	"api_key":         {"id", "name", "role", "service_account_id", "created", "expires", "last_used_at", "is_revoked"},
	"data_source":     {"id", "name", "type", "url", "user", "database", "access", "basic_auth", "is_default", "created", "updated"},
	"user_auth_token": {"id", "user_id", "client_ip", "user_agent", "seen_at", "rotated_at", "created_at", "revoked_at"},
}

// secretColumns of data_source are only ever tested with length(); their
// values are not selected.
var secretColumns = []string{"secure_json_data", "password", "basic_auth_password"}

// forbiddenColumns must never appear in wantedColumns (a test checks).
var forbiddenColumns = []string{"password", "salt", "rands", "key", "auth_token", "prev_auth_token", "basic_auth_password", "secure_json_data", "json_data"}

// Parser implements parsers.ArtifactParser and parsers.ContentConfirmer.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactGrafanaDB }

// Detect matches the file name grafana.db only.
func (Parser) Detect(relPath string) bool {
	return strings.EqualFold(filepath.Base(strings.ReplaceAll(relPath, `\`, "/")), "grafana.db")
}

// ConfirmContent requires the SQLite signature followed by its NUL byte. The
// tables are checked when the file is parsed.
func (Parser) ConfirmContent(header []byte) bool {
	return len(header) >= len(sqliteMagic) && string(header[:len(sqliteMagic)]) == sqliteMagic
}

func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if info.Size() > maxDBBytes {
		return parsers.ParseResult{}, fmt.Errorf("%w: %d bytes", ErrTooLarge, info.Size())
	}
	f, err := os.Open(absPath) // read-only
	if err != nil {
		return parsers.ParseResult{}, err
	}
	hdr := make([]byte, len(sqliteMagic))
	n, _ := io.ReadFull(f, hdr)
	f.Close()
	if !(Parser{}).ConfirmContent(hdr[:n]) {
		return parsers.ParseResult{}, ErrNotSQLite
	}

	work, cleanup, err := copyForReading(absPath)
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("grafanadb: preparing a working copy: %w", err)
	}
	defer cleanup()
	db, err := openReadOnly(work)
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("grafanadb: opening the working copy: %w", err)
	}
	defer db.Close()

	tables, err := listTables(db)
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("grafanadb: reading the schema: %w", err)
	}
	if !(tables["user"] && tables["org_user"] && (tables["login_attempt"] || tables["api_key"])) {
		return parsers.ParseResult{}, fmt.Errorf("%w (tables found: %s)", ErrNotGrafana, sortedKeys(tables))
	}

	r := &reader{db: db, base: filepath.Base(absPath), tables: tables, cov: &model.ParseCoverage{}}
	roles, err := r.orgRoles()
	if err != nil {
		return parsers.ParseResult{}, err
	}
	steps := []func(map[string]string) error{r.users, r.tokens, r.dataSources, r.loginAttempts, r.sessions}
	for _, s := range steps {
		if err := s(roles); err != nil {
			return parsers.ParseResult{}, err
		}
	}
	r.cov.Mapped = len(r.res.Events)
	for _, e := range r.res.Events {
		if e.Timestamp.IsZero() {
			r.cov.Undated++
		}
	}
	r.res.Coverage = r.cov
	return r.res, nil
}

func openReadOnly(path string) (*sql.DB, error) {
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

func copyForReading(dbPath string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "tracefall-grafanadb-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		src := dbPath + suffix
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := copyFile(src, filepath.Join(dir, "grafana.db"+suffix)); err != nil {
			cleanup()
			return "", func() {}, err
		}
	}
	return filepath.Join(dir, "grafana.db"), cleanup, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func listTables(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		m[strings.ToLower(n)] = true
	}
	return m, rows.Err()
}

func sortedKeys(m map[string]bool) string {
	var k []string
	for n := range m {
		k = append(k, n)
	}
	sort.Strings(k)
	if len(k) > 20 {
		k = append(k[:20], "...")
	}
	return strings.Join(k, ", ")
}

type reader struct {
	db     *sql.DB
	base   string
	tables map[string]bool
	res    parsers.ParseResult
	cov    *model.ParseCoverage
}

type row map[string]string // a column is absent when it is missing or NULL

func (r *reader) note(s string) { r.cov.Notes = append(r.cov.Notes, s) }

func (r *reader) columns(table string) (map[string]bool, error) {
	rows, err := r.db.Query(`PRAGMA table_info("` + table + `")`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		m[strings.ToLower(name)] = true
	}
	return m, rows.Err()
}

// fetch reads one table in id order with only the allow-listed columns that
// exist. countRows adds the rows to the coverage record count.
func (r *reader) fetch(table string, countRows bool) ([]row, error) {
	if !r.tables[table] {
		r.note("table " + table + " is not present")
		return nil, nil
	}
	have, err := r.columns(table)
	if err != nil {
		return nil, fmt.Errorf("grafanadb: probing %s: %w", table, err)
	}
	if !have["id"] {
		r.note("table " + table + " has no id column and was not read")
		return nil, nil
	}
	var names, exprs []string
	for _, c := range wantedColumns[table] {
		if have[c] {
			names = append(names, c)
			exprs = append(exprs, `CAST("`+c+`" AS TEXT)`)
		}
	}
	if table == "data_source" {
		any := []string{}
		for _, c := range secretColumns {
			if have[c] {
				any = append(any, `length(COALESCE("`+c+`",''))>0`)
			}
		}
		if len(any) > 0 {
			names = append(names, "secrets_stored")
			exprs = append(exprs, `CASE WHEN `+strings.Join(any, " OR ")+` THEN 'true' ELSE 'false' END`)
		}
	}
	q := `SELECT ` + strings.Join(exprs, ", ") + ` FROM "` + table + `" ORDER BY "id" LIMIT ` + strconv.Itoa(maxRows+1)
	rows, err := r.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("grafanadb: reading %s: %w", table, err)
	}
	defer rows.Close()
	var out []row
	for rows.Next() {
		vals := make([]sql.NullString, len(names))
		ptrs := make([]any, len(names))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			r.cov.RecordsFailed++
			continue
		}
		if len(out) >= maxRows {
			r.cov.LimitReached = true
			r.note(fmt.Sprintf("table %s: only the first %d rows (by id) were read; more rows exist", table, maxRows))
			break
		}
		rw := row{}
		for i, n := range names {
			if vals[i].Valid {
				rw[n] = vals[i].String
			}
		}
		out = append(out, rw)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("grafanadb: reading %s: %w", table, err)
	}
	if countRows {
		r.cov.RecordsRead += len(out)
	}
	return out, nil
}

var roleRank = map[string]int{"admin": 3, "editor": 2, "viewer": 1, "none": 0}

func rank(role string) int {
	if v, ok := roleRank[strings.ToLower(role)]; ok {
		return v
	}
	return -1
}

func (r *reader) orgRoles() (map[string]string, error) {
	rows, err := r.fetch("org_user", false)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, rw := range rows {
		uid, role := rw["user_id"], rw["role"]
		if uid == "" || role == "" {
			continue
		}
		if cur, ok := m[uid]; !ok || rank(role) > rank(cur) {
			m[uid] = role
		}
	}
	return m, nil
}

var dtLayouts = []string{"2006-01-02 15:04:05.999999999", "2006-01-02T15:04:05.999999999Z07:00", "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999 -0700 MST"}

// parseDT reads a Grafana datetime as UTC. ok is false when it cannot.
func parseDT(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, l := range dtLayouts {
		if t, err := time.ParseInLocation(l, s, time.UTC); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// parseUnix reads Unix seconds. Zero and out-of-range values are not times.
func parseUnix(s string) (time.Time, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n <= 0 || n > 253402300799 {
		return time.Time{}, false
	}
	return time.Unix(n, 0).UTC(), true
}

func boolText(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "t", "yes":
		return "true"
	}
	return "false"
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "\u2026"
}

var (
	urlUserinfoRE = regexp.MustCompile(`(//)[^/@\s]*@`)
	urlSecretRE   = regexp.MustCompile(`(?i)((?:pass(?:word)?|pwd|secret|token|key)=)[^&;\s]+`)
)

// cleanURL removes credentials a data-source URL may carry.
func cleanURL(s string) (string, bool) {
	c := urlUserinfoRE.ReplaceAllString(s, "$1")
	removed := c != s
	c2 := urlSecretRE.ReplaceAllString(c, "${1}REDACTED")
	return c2, removed || c2 != c
}

func (r *reader) add(table string, rw row, typ string, ts time.Time, x map[string]string) {
	ref := table + ":id=" + rw["id"]
	x["records_outcome"] = recordsOutcome
	raw := map[string]string{"table": table}
	for k, v := range x {
		raw[k] = v
	}
	b, _ := json.Marshal(raw) // map keys are sorted
	r.res.Events = append(r.res.Events, model.Event{
		Timestamp: ts, EventType: typ, ArtifactType: model.ArtifactGrafanaDB, Parser: parserName,
		FilePath: r.base, SourceReference: ref, Confidence: 0.95, Extra: x,
	})
	r.res.Raw = append(r.res.Raw, model.RawEvidence{SourceReference: ref, Raw: string(b)})
}

func copyIf(x map[string]string, rw row, pairs ...string) {
	for i := 0; i+1 < len(pairs); i += 2 {
		if v, ok := rw[pairs[i]]; ok {
			x[pairs[i+1]] = v
		}
	}
}

func (r *reader) users(roles map[string]string) error {
	rows, err := r.fetch("user", true)
	if err != nil {
		return err
	}
	for _, rw := range rows {
		x := map[string]string{"grafana_user_id": rw["id"]}
		copyIf(x, rw, "login", "login", "email", "email", "name", "name", "created", "created", "updated", "updated")
		if v, ok := rw["is_admin"]; ok {
			x["server_admin"] = boolText(v)
		}
		if v, ok := rw["is_service_account"]; ok {
			x["service_account"] = boolText(v)
		}
		if v, ok := rw["is_disabled"]; ok {
			x["disabled"] = boolText(v)
		}
		if role, ok := roles[rw["id"]]; ok {
			x["org_role"] = role
		}
		created, createdOK := parseDT(rw["created"])
		var ts time.Time
		if createdOK {
			ts = created
			x["timestamp_basis"] = timestampBasisUTCText
		}
		if ls, ok := rw["last_seen_at"]; ok {
			seen, seenOK := parseDT(ls)
			if createdOK && seenOK && absDur(seen.Sub(created.AddDate(-10, 0, 0))) <= 24*time.Hour {
				x["last_seen"] = "never"
			} else {
				x["last_seen_at"] = ls
			}
		}
		r.add("user", rw, model.EventGrafanaUser, ts, x)
	}
	return nil
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func (r *reader) tokens(map[string]string) error {
	rows, err := r.fetch("api_key", true)
	if err != nil {
		return err
	}
	for _, rw := range rows {
		x := map[string]string{}
		copyIf(x, rw, "name", "name", "role", "role", "service_account_id", "service_account_id", "created", "created", "expires", "expires", "last_used_at", "last_used_at")
		if v, ok := rw["is_revoked"]; ok {
			x["revoked"] = boolText(v)
		}
		if t, ok := parseUnix(rw["expires"]); ok {
			x["expires_utc"] = t.Format(time.RFC3339)
		}
		var ts time.Time
		if t, ok := parseDT(rw["created"]); ok {
			ts = t
			x["timestamp_basis"] = timestampBasisUTCText
		}
		r.add("api_key", rw, model.EventGrafanaToken, ts, x)
	}
	return nil
}

func (r *reader) dataSources(map[string]string) error {
	rows, err := r.fetch("data_source", true)
	if err != nil {
		return err
	}
	for _, rw := range rows {
		x := map[string]string{}
		copyIf(x, rw, "name", "name", "type", "type", "user", "user", "database", "database", "access", "access", "created", "created", "updated", "updated", "secrets_stored", "secrets_stored")
		if v, ok := rw["url"]; ok {
			c, changed := cleanURL(v)
			x["url"] = c
			if changed {
				x["url_credentials"] = "removed"
			}
		}
		if v, ok := rw["basic_auth"]; ok {
			x["basic_auth"] = boolText(v)
		}
		if v, ok := rw["is_default"]; ok {
			x["is_default"] = boolText(v)
		}
		var ts time.Time
		if t, ok := parseDT(rw["created"]); ok {
			ts = t
			x["timestamp_basis"] = timestampBasisUTCText
		}
		r.add("data_source", rw, model.EventGrafanaDataSource, ts, x)
	}
	return nil
}

func (r *reader) loginAttempts(map[string]string) error {
	rows, err := r.fetch("login_attempt", true)
	if err != nil {
		return err
	}
	for _, rw := range rows {
		x := map[string]string{"note": attemptNote}
		copyIf(x, rw, "username", "login", "ip_address", "source_address")
		var ts time.Time
		if t, ok := parseUnix(rw["created"]); ok {
			ts = t
			x["timestamp_basis"] = timestampBasisUnix
		}
		r.add("login_attempt", rw, model.EventGrafanaLoginAttempt, ts, x)
		r.res.Events[len(r.res.Events)-1].NetworkSource = rw["ip_address"]
	}
	return nil
}

func (r *reader) sessions(map[string]string) error {
	rows, err := r.fetch("user_auth_token", true)
	if err != nil {
		return err
	}
	for _, rw := range rows {
		x := map[string]string{}
		copyIf(x, rw, "user_id", "user_id", "client_ip", "client_ip")
		if v, ok := rw["user_agent"]; ok {
			x["user_agent"] = clip(v, 256)
		}
		for _, k := range []string{"seen_at", "rotated_at", "revoked_at"} {
			if v, ok := rw[k]; ok {
				if t, ok := parseUnix(v); ok {
					x[k] = v
					x[k+"_utc"] = t.Format(time.RFC3339)
				}
			}
		}
		var ts time.Time
		if t, ok := parseUnix(rw["created_at"]); ok {
			ts = t
			x["timestamp_basis"] = timestampBasisUnix
		}
		r.add("user_auth_token", rw, model.EventGrafanaSession, ts, x)
	}
	return nil
}
