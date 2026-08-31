// Package browserhistory parses browser history databases.
//
// # Exactly which formats, and no more
//
// Two SQLite schemas are supported, and the artifact catalog says so
// rather than claiming "browser history" generically:
//
//	Chromium  Chrome, Edge, Brave, Opera and other Chromium forks --
//	          the "History" database, tables urls + visits
//	Firefox   places.sqlite, tables moz_places + moz_historyvisits
//
// Safari, Internet Explorer/WebCacheV01.dat (ESE), and any other format
// are NOT parsed. A database matching neither schema is reported as a
// structured parse failure naming what was found.
//
// # Evidence is never modified
//
// This is the part that matters most. Opening a SQLite database normally
// can WRITE to it: if a hot write-ahead log or rollback journal is
// present -- which is exactly what copying a profile from a running
// machine produces -- SQLite recovers it, checkpointing the WAL into the
// main database and deleting the sidecar files. That silently alters
// evidence and destroys the -wal that a competent examiner would want.
//
// Two approaches were measured against a database with an uncheckpointed
// WAL:
//
//	plain open       evidence file's hash CHANGED, -wal and -shm deleted
//	immutable=1      evidence unchanged, but the database was unreadable
//	                 (its schema lived in the WAL)
//
// So neither is acceptable alone. This package instead copies the
// database AND its sidecars into a scratch directory and opens the COPY,
// where SQLite may recover freely. The evidence is opened read-only, for
// reading bytes, and is never handed to SQLite at all. Verified by
// TestParse_DoesNotModifyEvidence.
package browserhistory

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // the pure-Go driver Tracefall already depends on

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "browserhistory@1"

var (
	// ErrNotSQLite means the file is not a SQLite database.
	ErrNotSQLite = errors.New("browserhistory: not a SQLite database")
	// ErrUnknownSchema means it IS SQLite, but matches no history schema
	// this package knows.
	ErrUnknownSchema = errors.New("browserhistory: SQLite database does not match a supported browser history schema")
	// ErrTooLarge means the database exceeds the size ceiling.
	ErrTooLarge = errors.New("browserhistory: database exceeds the maximum size")
)

const (
	sqliteMagic  = "SQLite format 3\x00"
	maxDBBytes   = 2 << 30 // 2 GiB
	maxVisitRows = 500_000
)

// Flavor identifies which supported schema a database matched.
type Flavor string

const (
	FlavorChromium Flavor = "chromium"
	FlavorFirefox  Flavor = "firefox"
)

// Parser implements parsers.ArtifactParser and parsers.ContentDetector.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactBrowserHistory }

// Detect matches the filenames the supported browsers use.
func (Parser) Detect(relPath string) bool {
	switch strings.ToLower(filepath.Base(relPath)) {
	case "history", "places.sqlite":
		return true
	}
	return false
}

// DetectContent matches the SQLite signature.
//
// This is intentionally broad: it says "this is a SQLite database", not
// "this is browser history", because the schema cannot be determined
// without opening it and discovery must not open files. A SQLite
// database that turns out to be something else is reported as an
// unsupported-schema parse failure at import, which is the honest place
// for that determination.
func (Parser) DetectContent(header []byte) bool {
	return len(header) >= len(sqliteMagic) && string(header[:len(sqliteMagic)]) == sqliteMagic
}

// Visit is one recorded page visit.
type Visit struct {
	URL        string
	Title      string
	VisitTime  time.Time
	VisitCount int
}

// Parse reads a browser history database and emits one event per visit.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if info.Size() > maxDBBytes {
		return parsers.ParseResult{}, fmt.Errorf("%w: %d bytes", ErrTooLarge, info.Size())
	}
	header := make([]byte, len(sqliteMagic))
	f, err := os.Open(absPath) // read-only; the evidence is never opened for writing
	if err != nil {
		return parsers.ParseResult{}, err
	}
	n, _ := io.ReadFull(f, header)
	f.Close()
	if n < len(sqliteMagic) || string(header[:n]) != sqliteMagic {
		return parsers.ParseResult{}, ErrNotSQLite
	}

	work, cleanup, err := copyForReading(absPath)
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("browserhistory: preparing a working copy: %w", err)
	}
	defer cleanup()

	db, err := sql.Open("sqlite", work)
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("browserhistory: opening the working copy: %w", err)
	}
	defer db.Close()

	flavor, err := detectFlavor(db)
	if err != nil {
		return parsers.ParseResult{}, err
	}

	visits, err := readVisits(db, flavor)
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("browserhistory: reading visits: %w", err)
	}

	sourceName := filepath.Base(absPath)
	profile := profileFromPath(absPath)
	user := userFromPath(absPath)

	var out parsers.ParseResult
	for i, v := range visits {
		if v.VisitTime.IsZero() {
			// A visit row with no usable timestamp cannot be placed on a
			// timeline, and the database file's mtime is not a visit
			// time. Dropped rather than invented -- the same rule the
			// other parsers follow.
			continue
		}
		extra := map[string]string{
			"browser":         string(flavor),
			"browser_source":  sourceName,
			"url":             truncate(v.URL, 2048),
			"visit_count":     strconv.Itoa(v.VisitCount),
			"timestamp_epoch": epochNote(flavor),
		}
		if v.Title != "" {
			extra["page_title"] = truncate(v.Title, 512)
		}
		if profile != "" {
			extra["browser_profile"] = profile
		}

		ev := model.Event{
			Timestamp:   v.VisitTime.UTC(),
			User:        user,
			EventType:   model.EventBrowserVisit,
			ProcessName: browserProcess(flavor),
			FilePath:    sourceName,
			// NetworkDest carries the visited host, so browser activity
			// groups under the network category and participates in
			// entity/temporal correlation the same way any other
			// network-adjacent event does -- matching how the Sysmon DNS
			// event type is already handled.
			NetworkDest:     hostFromURL(v.URL),
			ArtifactType:    model.ArtifactBrowserHistory,
			Parser:          parserName,
			Confidence:      1.0,
			SourceReference: "visit:" + strconv.Itoa(i),
			Extra:           extra,
		}

		rawJSON, _ := json.Marshal(map[string]any{
			"browser":     string(flavor),
			"source_file": sourceName,
			"url":         v.URL,
			"title":       v.Title,
			"visit_time":  v.VisitTime.UTC(),
			"visit_count": v.VisitCount,
		})
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, model.RawEvidence{SourceReference: ev.SourceReference, Raw: string(rawJSON)})
	}
	return out, nil
}

// copyForReading copies the database and any sidecar files into a
// scratch directory, returning the path of the copy.
//
// The sidecars matter: a -wal holds committed transactions that are not
// yet in the main database, so omitting it would silently lose the most
// recent browsing -- exactly the part an investigation usually cares
// about most.
func copyForReading(dbPath string) (workPath string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "tracefall-browserdb-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup = func() { os.RemoveAll(dir) }

	base := filepath.Base(dbPath)
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		src := dbPath + suffix
		if _, statErr := os.Stat(src); statErr != nil {
			continue // absent sidecars are normal
		}
		if copyErr := copyFile(src, filepath.Join(dir, base+suffix)); copyErr != nil {
			cleanup()
			return "", func() {}, copyErr
		}
	}
	return filepath.Join(dir, base), cleanup, nil
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

// detectFlavor identifies the schema by the tables actually present,
// never by filename.
func detectFlavor(db *sql.DB) (Flavor, error) {
	names := map[string]bool{}
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		// Unreadable master table means this is not a usable database.
		return "", fmt.Errorf("%w: %v", ErrUnknownSchema, err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err == nil {
			names[strings.ToLower(n)] = true
		}
	}
	rows.Close()

	switch {
	case names["urls"] && names["visits"]:
		return FlavorChromium, nil
	case names["moz_places"] && names["moz_historyvisits"]:
		return FlavorFirefox, nil
	default:
		return "", fmt.Errorf("%w (tables found: %s)", ErrUnknownSchema, sortedNames(names))
	}
}

// readVisits pulls the visit rows for the detected schema.
//
// Timestamp conversion, documented in docs/evidence-triage.md:
//
//	Chromium  microseconds since 1601-01-01 UTC (the WebKit/Windows epoch)
//	Firefox   microseconds since 1970-01-01 UTC (the Unix epoch)
//
// Getting these the wrong way round misplaces every visit by roughly
// 369 years, so each is converted by its own explicit function rather
// than a shared "microseconds" helper.
func readVisits(db *sql.DB, flavor Flavor) ([]Visit, error) {
	var query string
	switch flavor {
	case FlavorChromium:
		query = `SELECT u.url, u.title, v.visit_time, u.visit_count
		         FROM visits v JOIN urls u ON u.id = v.url
		         ORDER BY v.visit_time ASC, v.id ASC`
	case FlavorFirefox:
		query = `SELECT p.url, IFNULL(p.title,''), v.visit_date, IFNULL(p.visit_count,0)
		         FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id
		         ORDER BY v.visit_date ASC, v.id ASC`
	default:
		return nil, ErrUnknownSchema
	}

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Visit
	for rows.Next() {
		if len(out) >= maxVisitRows {
			break
		}
		var url, title string
		var raw sql.NullInt64
		var count sql.NullInt64
		if err := rows.Scan(&url, &title, &raw, &count); err != nil {
			continue // one unreadable row must not discard the rest
		}
		v := Visit{URL: url, Title: title, VisitCount: int(count.Int64)}
		if raw.Valid {
			switch flavor {
			case FlavorChromium:
				v.VisitTime = fromWebKitMicroseconds(raw.Int64)
			case FlavorFirefox:
				v.VisitTime = fromUnixMicroseconds(raw.Int64)
			}
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// fromWebKitMicroseconds converts microseconds since 1601-01-01 UTC.
func fromWebKitMicroseconds(us int64) time.Time {
	if us <= 0 {
		return time.Time{}
	}
	const epochDeltaSeconds = 11644473600
	sec := us/1_000_000 - epochDeltaSeconds
	return plausible(time.Unix(sec, (us%1_000_000)*1000).UTC())
}

// fromUnixMicroseconds converts microseconds since 1970-01-01 UTC.
func fromUnixMicroseconds(us int64) time.Time {
	if us <= 0 {
		return time.Time{}
	}
	return plausible(time.Unix(us/1_000_000, (us%1_000_000)*1000).UTC())
}

// plausible rejects timestamps outside a believable range rather than
// placing a visit in the year 1601 or 30000 -- a wrong epoch shows up as
// an absurd date, and an absurd date is dropped, not displayed.
func plausible(t time.Time) time.Time {
	if t.Year() < 1995 || t.Year() > 2200 {
		return time.Time{}
	}
	return t
}

func epochNote(f Flavor) string {
	if f == FlavorChromium {
		return "microseconds since 1601-01-01 UTC (WebKit epoch)"
	}
	return "microseconds since 1970-01-01 UTC (Unix epoch)"
}

func browserProcess(f Flavor) string {
	if f == FlavorChromium {
		return "chrome.exe"
	}
	return "firefox.exe"
}

// hostFromURL extracts the host without parsing the whole URL, so a
// malformed URL cannot produce an error -- it simply yields "".
func hostFromURL(u string) string {
	rest := u
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.Index(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	if i := strings.Index(rest, ":"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// profileFromPath recovers the browser profile directory name from the
// evidence path when it contains one, e.g. ".../User Data/Default/History".
func profileFromPath(path string) string {
	parts := strings.Split(strings.ReplaceAll(path, `\`, "/"), "/")
	for i := len(parts) - 2; i >= 0; i-- {
		p := parts[i]
		if strings.EqualFold(p, "Default") || strings.HasPrefix(strings.ToLower(p), "profile ") ||
			strings.HasSuffix(strings.ToLower(p), ".default-release") || strings.HasSuffix(strings.ToLower(p), ".default") {
			return p
		}
	}
	return ""
}

func userFromPath(path string) string {
	parts := strings.Split(strings.ReplaceAll(path, `\`, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "Users") || strings.EqualFold(parts[i], "Documents and Settings") {
			name := parts[i+1]
			if name != "" && !strings.EqualFold(name, "Public") && !strings.EqualFold(name, "Default") {
				return name
			}
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func sortedNames(set map[string]bool) string {
	var out []string
	for n := range set {
		out = append(out, n)
	}
	if len(out) > 8 {
		out = out[:8]
	}
	return strings.Join(out, ", ")
}
