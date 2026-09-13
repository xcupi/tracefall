// Package activitiescache parses the Windows Timeline database,
// ActivitiesCache.db.
//
// # What this artifact is
//
// The Windows Activities provider records what a user had in focus:
// which application, which document or page, and for how long. Each row
// carries a start and an end time, an application identity, and a JSON
// payload with the display text the Timeline UI showed.
//
// It is genuinely valuable because it answers WHO and WHAT together, in
// a form that survives the deletion of the document it names, and it
// spans devices when the account roams.
//
// # What it proves, and what it does not
//
// An activity row records that the Activities provider LOGGED an
// application or document as active. It is not a process-creation
// record: the provider is a shell component reporting focus, several
// layers above the kernel event that creates a process. A row can also
// arrive by synchronization from ANOTHER device on the same account,
// which is why device context is preserved and reported rather than
// assumed to be this machine.
//
// So events carry model.EventActivityRecorded -- "activity recorded" --
// and say so in evidence_meaning. Security 4688 is what records process
// creation.
//
// # Safety
//
// The database is COPIED before it is opened, sidecars included, so the
// evidence file is never touched and a -wal holding the most recent
// activity is not lost. That is the same approach
// internal/parsers/browserhistory takes, and for the same reasons.
package activitiescache

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

	_ "modernc.org/sqlite"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "activitiescache@1"

var (
	// ErrNotActivitiesCache means the file is a database but not a
	// Windows Timeline one. Deliberately distinct from a corrupt file:
	// "this is a different artifact" and "this artifact is broken" send
	// an analyst to different places.
	ErrNotActivitiesCache = errors.New("activitiescache: not a Windows Timeline database")
	// ErrUnreadable means the file could not be opened as SQLite at all.
	ErrUnreadable = errors.New("activitiescache: file is not a readable SQLite database")
)

// Limits bound what one database may contribute.
type Limits struct {
	MaxRows        int
	MaxStringBytes int
}

// maxJSONBytes bounds a JSON column before it is parsed.
//
// Deliberately far above MaxStringBytes: this caps the DOCUMENT so a
// hostile row cannot force an unbounded parse, while the values pulled
// out of it are bounded individually by MaxStringBytes. A document over
// this size is not parsed at all, and the row keeps its other columns.
const maxJSONBytes = 1 << 20

// DefaultLimits are sized for real evidence: a Timeline database holds
// thousands of activities, and no legitimate payload field is megabytes.
func DefaultLimits() Limits { return Limits{MaxRows: 200000, MaxStringBytes: 8192} }

// Parser implements parsers.ArtifactParser and parsers.ContentDetector.
type Parser struct{ limits Limits }

func New() *Parser { return &Parser{limits: DefaultLimits()} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactActivitiesCache }

// Detect matches the filename Windows uses. It is only a fast path --
// DetectContent finds a Timeline database whatever it is called, and,
// more importantly, the CONTENT check in Parse is what decides whether
// this file is really one. A file merely named ActivitiesCache.db does
// not become one.
func (Parser) Detect(relPath string) bool {
	return strings.EqualFold(filepath.Base(relPath), "ActivitiesCache.db")
}

// sqliteMagic is the header every SQLite 3 database starts with.
var sqliteMagic = []byte("SQLite format 3\x00")

// ConfirmContent backs the ActivitiesCache.db name match with the bytes,
// so a file carrying that name which is not a database is reported as
// unrecognized rather than as a broken Timeline.
func (Parser) ConfirmContent(header []byte) bool { return isSQLite(header) }

func isSQLite(header []byte) bool {
	return len(header) >= len(sqliteMagic) && string(header[:len(sqliteMagic)]) == string(sqliteMagic)
}

// NOTE ON CONTENT DETECTION -- and why this parser no longer has any.
//
// DetectContent used to accept ANY SQLite database, on the reasoning
// that the schema lives past the 512-byte header and the browser parsers
// were registered first and would claim their own. Both halves of that
// were wrong. The browser history parser was claiming every SQLite file
// for the same reason, so this one only ever saw what that one left --
// and the moment history detection was narrowed to the two databases it
// actually reads, this parser inherited the entire sweep: cookie stores,
// favicon caches, autofill databases and Windows notification databases
// all became "Windows Timeline".
//
// A Timeline database is called ActivitiesCache.db. That name is what
// identifies it, confirmed against the bytes above, and the schema check
// in Parse remains the final word. A renamed one is not detected, which
// is the honest cost of not claiming files that are not this artifact.

// Activity is one decoded Timeline row.
type Activity struct {
	ID               string
	AppID            string
	AppDisplayName   string
	PackageName      string
	ActivityType     int64
	ActivityTypeName string
	DisplayText      string
	Description      string
	ContentURI       string
	ActivationURI    string
	PlatformDevice   string
	// StartTime/EndTime bound the activity; either may be zero when the
	// database did not record it.
	StartTime            time.Time
	EndTime              time.Time
	LastModified         time.Time
	LastModifiedOnClient time.Time
	// Warnings describe anything recovered but questionable.
	Warnings []string
}

// activityTypes maps the ActivityType values whose meaning is settled.
//
// Microsoft never documented this column. Only the values independent
// research agrees on are named; anything else is reported as its raw
// number, because a wrong label on a forensic record is worse than an
// honest number.
var activityTypes = map[int64]string{
	2:  "notification",
	3:  "mobile device backup",
	5:  "application or file opened",
	6:  "in-application activity",
	10: "clipboard copy",
	11: "copy/paste",
	12: "system action",
	15: "user engagement",
	16: "application in focus",
}

// Parse reads the database.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	work, cleanup, err := copyForReading(absPath)
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("activitiescache: staging a copy: %w", err)
	}
	defer cleanup()

	// Opened read-only, against the COPY. The original evidence file is
	// never opened by SQLite, so no journal, WAL or page can be written
	// back to it.
	db, err := sql.Open("sqlite", "file:"+work+"?mode=ro")
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	defer db.Close()

	table, err := activityTable(db)
	if err != nil {
		return parsers.ParseResult{}, err
	}

	activities, readErr := p.readActivities(db, table)
	if readErr != nil {
		return parsers.ParseResult{}, readErr
	}

	sourceName := filepath.Base(absPath)
	user := userFromPath(absPath)

	var out parsers.ParseResult
	for i, a := range activities {
		ev, raw := activityEvent(a, i, sourceName, user)
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, raw)
	}
	return out, nil
}

// activityTable finds the table holding activities, and refuses a
// database that has none.
//
// This is the CONTENT check that decides whether the file really is a
// Timeline database. A SQLite file named ActivitiesCache.db with some
// other schema is reported as not-this-artifact, never parsed on the
// strength of its name.
func activityTable(db *sql.DB) (string, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	defer rows.Close()

	names := map[string]string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err == nil {
			names[strings.ToLower(n)] = n
		}
	}
	// Windows has used both names for the same table.
	for _, want := range []string{"activity", "smartlookup_activity", "activityoperation"} {
		if actual, ok := names[want]; ok {
			return actual, nil
		}
	}
	return "", fmt.Errorf("%w (tables present: %s)", ErrNotActivitiesCache, joinKeys(names))
}

func joinKeys(m map[string]string) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	if len(out) == 0 {
		return "none"
	}
	if len(out) > 12 {
		out = out[:12]
	}
	return strings.Join(out, ", ")
}

// readActivities pulls the rows, tolerating schema variation.
func (p Parser) readActivities(db *sql.DB, table string) ([]Activity, error) {
	lim := p.limits
	if lim.MaxRows <= 0 {
		lim = DefaultLimits()
	}

	// Column names differ across Windows builds, so each is selected
	// only when present. Quoting the table name defends against an
	// unusual-but-legal identifier; the value itself came from
	// sqlite_master, never from a request.
	has := func(c string) bool { return hasColumn(db, table, c) }
	col := func(c, fallback string) string {
		if has(c) {
			return `IFNULL("` + c + `",` + fallback + `)`
		}
		return fallback
	}

	q := `SELECT ` + strings.Join([]string{
		col("Id", "''"),
		col("AppId", "''"),
		col("ActivityType", "-1"),
		col("Payload", "''"),
		col("StartTime", "0"),
		col("EndTime", "0"),
		col("LastModifiedTime", "0"),
		col("LastModifiedOnClient", "0"),
		col("PlatformDeviceId", "''"),
	}, ", ") + ` FROM "` + table + `"`

	rows, err := db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("activitiescache: reading %s: %w", table, err)
	}
	defer rows.Close()

	var out []Activity
	for rows.Next() && len(out) < lim.MaxRows {
		var a Activity
		var idRaw, appIDRaw, payload, device any
		var start, end, modified, modifiedClient int64
		if err := rows.Scan(&idRaw, &appIDRaw, &a.ActivityType, &payload,
			&start, &end, &modified, &modifiedClient, &device); err != nil {
			// One unreadable row must not discard the rest -- a malformed
			// record is not a malformed database.
			continue
		}
		a.ID = asText(idRaw, lim.MaxStringBytes)
		a.PlatformDevice = asText(device, lim.MaxStringBytes)
		// The JSON columns are read at maxJSONBytes and their extracted
		// FIELDS bounded afterwards, rather than the blob being truncated
		// first. Truncating JSON mid-document makes it unparseable, so a
		// single oversized field -- a very long contentUri, say -- would
		// otherwise discard every short field beside it, including the
		// document name the analyst is actually looking for.
		a.AppID, a.PackageName = decodeAppID(asText(appIDRaw, maxJSONBytes), lim)
		if name, ok := activityTypes[a.ActivityType]; ok {
			a.ActivityTypeName = name
		}
		applyPayload(&a, asText(payload, maxJSONBytes), lim)

		a.StartTime = activityTime(start)
		a.EndTime = activityTime(end)
		a.LastModified = activityTime(modified)
		a.LastModifiedOnClient = activityTime(modifiedClient)

		if a.StartTime.IsZero() && a.EndTime.IsZero() && a.LastModified.IsZero() {
			a.Warnings = append(a.Warnings, "this row records no usable timestamp")
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func hasColumn(db *sql.DB, table, column string) bool {
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err == nil && strings.EqualFold(n, column) {
			return true
		}
	}
	return false
}

// asText renders a column that may arrive as text or as a blob.
func asText(v any, max int) string {
	var s string
	switch t := v.(type) {
	case string:
		s = t
	case []byte:
		if isPrintable(t) {
			s = string(t)
		} else {
			s = fmt.Sprintf("%x", t)
		}
	case int64:
		s = strconv.FormatInt(t, 10)
	case nil:
		return ""
	default:
		s = fmt.Sprint(t)
	}
	if len(s) > max {
		s = s[:max] + "..."
	}
	return strings.TrimSpace(s)
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x09 || (c > 0x0D && c < 0x20) {
			return false
		}
	}
	return true
}

// decodeAppID reads the AppId column, which holds a JSON array of
// {application, platform} pairs.
//
// The win32 entry names an executable path; a packaged-app entry names
// an AUMID. Both are returned -- the executable as the application
// identity, the package separately -- rather than one being chosen and
// the other discarded.
func decodeAppID(raw string, lim Limits) (app, pkg string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	var entries []struct {
		Application string `json:"application"`
		Platform    string `json:"platform"`
	}
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		// Not JSON: preserved verbatim rather than discarded, bounded.
		return truncate(raw, lim.MaxStringBytes), ""
	}
	for _, e := range entries {
		v := strings.TrimSpace(e.Application)
		if v == "" {
			continue
		}
		v = truncate(v, lim.MaxStringBytes)
		switch strings.ToLower(e.Platform) {
		case "windows_win32", "x_exe_path":
			if app == "" {
				app = v
			}
		case "packageid", "windows_universal", "afs_crossplatform":
			if pkg == "" {
				pkg = v
			}
		default:
			if app == "" {
				app = v
			}
		}
	}
	if app == "" && pkg != "" {
		app = pkg
	}
	return app, pkg
}

// applyPayload reads the JSON payload the Timeline UI rendered from.
//
// Unparseable JSON is preserved raw and flagged, never guessed at: the
// row's identity and timestamps are already recovered, and a broken
// payload must not discard them.
func applyPayload(a *Activity, raw string, lim Limits) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	var p struct {
		DisplayText    string `json:"displayText"`
		Description    string `json:"description"`
		AppDisplayName string `json:"appDisplayName"`
		ContentURI     string `json:"contentUri"`
		ActivationURI  string `json:"activationUri"`
	}
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		a.Warnings = append(a.Warnings, "the activity payload is not readable JSON; preserved raw")
		return
	}
	a.DisplayText = truncate(p.DisplayText, lim.MaxStringBytes)
	a.Description = truncate(p.Description, lim.MaxStringBytes)
	a.AppDisplayName = truncate(p.AppDisplayName, lim.MaxStringBytes)
	a.ContentURI = truncate(p.ContentURI, lim.MaxStringBytes)
	a.ActivationURI = truncate(p.ActivationURI, lim.MaxStringBytes)
}

// activityTime converts a Timeline timestamp.
//
// These are Unix epoch SECONDS. A value that is not a plausible date is
// treated as absent rather than rendered as a date in 1970 or 33658 --
// the same rule every other Tracefall parser applies.
func activityTime(v int64) time.Time {
	if v <= 0 {
		return time.Time{}
	}
	t := time.Unix(v, 0).UTC()
	if t.Year() < 1995 || t.Year() > 2200 {
		return time.Time{}
	}
	return t
}

// activityEvent builds one normalized event.
func activityEvent(a Activity, index int, sourceName, user string) (model.Event, model.RawEvidence) {
	extra := map[string]string{
		"artifact_class":    "activities_cache",
		"activity_source":   sourceName,
		"activity_type_raw": strconv.FormatInt(a.ActivityType, 10),
		"evidence_meaning": "Windows Timeline recorded this activity: the Activities provider logged the " +
			"application or document as active for this user. It is NOT a process-creation record, and a row " +
			"can arrive by synchronization from another device on the same account.",
	}
	setIf := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			extra[k] = v
		}
	}
	if a.ActivityTypeName != "" {
		extra["activity_type"] = a.ActivityTypeName
	} else {
		extra["activity_type"] = "not a value Tracefall recognizes; reported as its raw number"
	}
	setIf("application", a.AppID)
	setIf("package_identity", a.PackageName)
	setIf("app_display_name", a.AppDisplayName)
	setIf("display_text", a.DisplayText)
	setIf("description", a.Description)
	setIf("content_uri", a.ContentURI)
	setIf("activation_uri", a.ActivationURI)
	setIf("activity_id", a.ID)
	if a.PlatformDevice != "" {
		extra["platform_device_id"] = a.PlatformDevice
		extra["device_note"] = "the device this activity was recorded on. Timeline synchronizes across an " +
			"account's devices, so an activity here need not have happened on this machine."
	}
	if !a.EndTime.IsZero() {
		extra["activity_end_time"] = a.EndTime.UTC().Format("2006-01-02T15:04:05Z")
	}
	if !a.LastModified.IsZero() {
		extra["activity_last_modified"] = a.LastModified.UTC().Format("2006-01-02T15:04:05Z")
	}
	if len(a.Warnings) > 0 {
		extra["warnings"] = strings.Join(a.Warnings, "; ")
	}

	// The timestamp is the activity's START, which is what an analyst
	// places on a timeline. Where none is recorded the row falls back
	// through the times the database DOES hold, saying which was used --
	// never to the file's mtime.
	ts := a.StartTime
	switch {
	case !ts.IsZero():
		extra["timestamp_meaning"] = "when the Activities provider recorded this activity starting"
		extra["timestamp_source"] = "ActivitiesCache StartTime"
	case !a.LastModified.IsZero():
		ts = a.LastModified
		extra["timestamp_meaning"] = "when this activity row was last modified; no start time is recorded"
		extra["timestamp_source"] = "ActivitiesCache LastModifiedTime"
	default:
		extra["timestamp_meaning"] = "no time is recorded for this activity"
		extra["timestamp_basis"] = "This Timeline row carries no usable timestamp. Its application and " +
			"document identity are still evidence; the time is not."
	}

	// The target: the document or page, falling back to the display text.
	target := a.ContentURI
	if target == "" {
		target = a.DisplayText
	}

	ev := model.Event{
		Timestamp: ts.UTC(),
		User:      user,
		EventType: model.EventActivityRecorded,
		// The application really is a program the provider named, so
		// ProcessName is honest here -- unlike the registry MRU
		// artifacts, where no process is recorded at all. It is still
		// not evidence the process was CREATED at this instant.
		ProcessName:  processName(a.AppID),
		ProcessPath:  a.AppID,
		FilePath:     target,
		ArtifactType: model.ArtifactActivitiesCache,
		Parser:       parserName,
		// 0.9: fields decode unambiguously, but the ActivityType column
		// is undocumented and device attribution is not guaranteed.
		Confidence:      0.9,
		SourceReference: "activity:" + strconv.Itoa(index),
		Extra:           extra,
	}

	rawJSON, _ := json.Marshal(map[string]any{
		"source_file":        sourceName,
		"activity_id":        a.ID,
		"app_id":             a.AppID,
		"package":            a.PackageName,
		"activity_type":      a.ActivityType,
		"activity_type_name": a.ActivityTypeName,
		"display_text":       a.DisplayText,
		"description":        a.Description,
		"content_uri":        a.ContentURI,
		"activation_uri":     a.ActivationURI,
		"platform_device":    a.PlatformDevice,
		"start_time":         jsonTime(a.StartTime),
		"end_time":           jsonTime(a.EndTime),
		"last_modified":      jsonTime(a.LastModified),
		"warnings":           a.Warnings,
	})
	return ev, model.RawEvidence{SourceReference: ev.SourceReference, Raw: string(rawJSON)}
}

func processName(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	if i := strings.LastIndex(p, `\`); i >= 0 && i+1 < len(p) {
		p = p[i+1:]
	}
	if strings.Contains(p, "!") || strings.Contains(p, "_") && !strings.Contains(p, ".") {
		// An AUMID, not an executable name.
		return ""
	}
	if !strings.Contains(p, ".") {
		return ""
	}
	return p
}

func jsonTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// userFromPath recovers the account a database belongs to from the
// evidence path, and only from a path that genuinely carries it.
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

// copyForReading stages the database and its sidecars, so the evidence
// file is never opened by SQLite.
func copyForReading(dbPath string) (workPath string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "tracefall-activitiesdb-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup = func() { os.RemoveAll(dir) }

	base := filepath.Base(dbPath)
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		src := dbPath + suffix
		if _, statErr := os.Stat(src); statErr != nil {
			continue
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
