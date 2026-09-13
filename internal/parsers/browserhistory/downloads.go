package browserhistory

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/model"
)

// Browser downloads (Phase 16).
//
// # Why this lives in the history parser
//
// Chromium keeps downloads in the SAME database as visits, so a separate
// parser could not reach them -- discovery assigns one parser per file,
// and this one already claims History. Firefox keeps them in
// places.sqlite too, as annotations on a place row.
//
// The EVENTS are kept distinct: model.ArtifactBrowserDownload, not
// ArtifactBrowserHistory. A download and a page visit are different
// claims about different actions, and merging them would let "this file
// arrived on the machine" read as "this page was viewed".
//
// # What a download record proves
//
// That the browser retrieved a resource to a local path, and what the
// browser recorded about how that went. It is NOT evidence the file was
// opened, and NOT evidence it was executed. Those need Prefetch, Amcache
// or a process-creation record -- and the event says so.

// maxDownloadRecords bounds how many download rows one database
// contributes. A real browser profile holds hundreds; the cap exists so
// a crafted database cannot turn one file into unbounded work.
const maxDownloadRecords = 100000

// Download is one recovered download record.
//
// Every time field may be zero, and a zero time means the database did
// not record it. Nothing here substitutes a surrogate.
type Download struct {
	URL        string
	TargetPath string
	Referrer   string
	MIMEType   string
	// StartTime is when the download began; EndTime when it finished.
	StartTime time.Time
	EndTime   time.Time
	// TotalBytes is the expected size and ReceivedBytes what arrived;
	// -1 for either means the database did not record it.
	TotalBytes    int64
	ReceivedBytes int64
	// State is the browser's own state value, rendered to a name where
	// the mapping is documented and left as the raw number otherwise.
	State     string
	StateRaw  string
	DangerRaw string
	// Opened reports whether the browser recorded the user opening the
	// file FROM THE BROWSER. It is a browser flag, not filesystem
	// evidence, and false does not mean the file was never opened.
	Opened    bool
	HasOpened bool
}

// chromiumDownloadStates maps Chromium's downloads.state column.
//
// Only the values with a settled meaning are named; anything else is
// reported as the raw number rather than guessed at.
var chromiumDownloadStates = map[int64]string{
	0: "in progress",
	1: "complete",
	2: "cancelled",
	3: "interrupted (pre-Chrome 26)",
	4: "interrupted",
}

// hasTable reports whether a table exists, so a missing one is "this
// database does not carry downloads" rather than a query error.
func hasTable(db *sql.DB, name string) bool {
	var found string
	err := db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND lower(name)=lower(?)`, name).Scan(&found)
	return err == nil && found != ""
}

// hasColumn reports whether a table has a column. Chromium's downloads
// schema has grown over many versions, and querying a column that does
// not exist fails the whole statement -- so the query is built from what
// the database actually has.
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

// readDownloads pulls download records for the detected schema.
//
// A database with no downloads table returns no rows and no error: a
// history database that records no downloads is a valid artifact with
// zero records of that kind.
func readDownloads(db *sql.DB, flavor Flavor) ([]Download, error) {
	switch flavor {
	case FlavorChromium:
		return readChromiumDownloads(db)
	case FlavorFirefox:
		return readFirefoxDownloads(db)
	default:
		return nil, nil
	}
}

func readChromiumDownloads(db *sql.DB) ([]Download, error) {
	if !hasTable(db, "downloads") {
		return nil, nil
	}
	// Columns are selected conditionally because the schema differs
	// across Chromium versions; an absent column yields an absent field
	// rather than a failed parse.
	cols := []string{
		"IFNULL(target_path,'')",
		"IFNULL(start_time,0)",
		"IFNULL(end_time,0)",
		"IFNULL(total_bytes,-1)",
		"IFNULL(received_bytes,-1)",
		"IFNULL(state,-1)",
	}
	// An ORDERED list, not a map. The columns are appended to the SELECT
	// in this order and scanned in the same order below; ranging over a
	// map here would emit them in Go's randomized iteration order while
	// the scan stayed fixed, so every row would fail to scan and the
	// whole table would silently yield nothing.
	optional := []struct{ name, expr string }{
		{"referrer", "IFNULL(referrer,'')"},
		{"mime_type", "IFNULL(mime_type,'')"},
		{"danger_type", "IFNULL(danger_type,-1)"},
		{"opened", "IFNULL(opened,-1)"},
	}
	present := map[string]bool{}
	for _, o := range optional {
		if hasColumn(db, "downloads", o.name) {
			present[o.name] = true
			cols = append(cols, o.expr)
		}
	}
	// The URL lives in a separate chain table on modern Chromium and in
	// a column on older ones.
	urlExpr := "''"
	switch {
	case hasTable(db, "downloads_url_chains"):
		// The LAST chain entry is the URL the bytes actually came from,
		// after any redirects; the first is what the user clicked. Both
		// matter, and the final one is the download's own URL.
		urlExpr = `IFNULL((SELECT c.url FROM downloads_url_chains c
		                   WHERE c.id = d.id ORDER BY c.chain_index DESC LIMIT 1), '')`
	case hasColumn(db, "downloads", "url"):
		urlExpr = "IFNULL(d.url,'')"
	}
	cols = append(cols, urlExpr)

	q := `SELECT ` + strings.Join(cols, ", ") + ` FROM downloads d ORDER BY d.start_time ASC, d.id ASC`
	rows, err := db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("reading Chromium downloads: %w", err)
	}
	defer rows.Close()

	var out []Download
	for rows.Next() && len(out) < maxDownloadRecords {
		var d Download
		var start, end, state int64
		var referrer, mime string
		var danger, opened int64 = -1, -1

		targets := []any{&d.TargetPath, &start, &end, &d.TotalBytes, &d.ReceivedBytes, &state}
		if present["referrer"] {
			targets = append(targets, &referrer)
		}
		if present["mime_type"] {
			targets = append(targets, &mime)
		}
		if present["danger_type"] {
			targets = append(targets, &danger)
		}
		if present["opened"] {
			targets = append(targets, &opened)
		}
		var url string
		targets = append(targets, &url)

		if err := rows.Scan(targets...); err != nil {
			// One unreadable row must not discard the rest.
			continue
		}
		d.URL = url
		d.Referrer = referrer
		d.MIMEType = mime
		d.StartTime = fromWebKitMicroseconds(start)
		d.EndTime = fromWebKitMicroseconds(end)
		if name, ok := chromiumDownloadStates[state]; ok {
			d.State = name
		}
		if state >= 0 {
			d.StateRaw = strconv.FormatInt(state, 10)
		}
		if danger >= 0 {
			d.DangerRaw = strconv.FormatInt(danger, 10)
		}
		if opened >= 0 {
			d.Opened = opened != 0
			d.HasOpened = true
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// readFirefoxDownloads reads downloads from places.sqlite.
//
// Modern Firefox records them as ANNOTATIONS on a place row rather than
// in a table of their own: moz_annos rows whose attribute is
// "downloads/destinationFileURI" carry the local path, and
// "downloads/metaData" carries a JSON blob with the end time and state.
// Older Firefox used a moz_downloads table, which is read when present.
func readFirefoxDownloads(db *sql.DB) ([]Download, error) {
	if hasTable(db, "moz_downloads") {
		return readLegacyFirefoxDownloads(db)
	}
	if !hasTable(db, "moz_annos") || !hasTable(db, "moz_anno_attributes") {
		return nil, nil
	}

	q := `SELECT IFNULL(p.url,''), IFNULL(a.content,''), IFNULL(a.dateAdded,0),
	             IFNULL(attr.name,'')
	      FROM moz_annos a
	      JOIN moz_anno_attributes attr ON attr.id = a.anno_attribute_id
	      JOIN moz_places p ON p.id = a.place_id
	      WHERE attr.name IN ('downloads/destinationFileURI','downloads/metaData')
	      ORDER BY a.place_id ASC, attr.name ASC`
	rows, err := db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("reading Firefox download annotations: %w", err)
	}
	defer rows.Close()

	// Annotations arrive one row per attribute, so they are folded back
	// into one download per URL.
	byURL := map[string]*Download{}
	var order []string
	for rows.Next() && len(order) < maxDownloadRecords {
		var url, content, attr string
		var added int64
		if err := rows.Scan(&url, &content, &added, &attr); err != nil {
			continue
		}
		d, ok := byURL[url]
		if !ok {
			d = &Download{URL: url, TotalBytes: -1, ReceivedBytes: -1}
			byURL[url] = d
			order = append(order, url)
		}
		switch attr {
		case "downloads/destinationFileURI":
			d.TargetPath = fileURIToPath(content)
			d.StartTime = fromUnixMicroseconds(added)
		case "downloads/metaData":
			applyFirefoxMetadata(d, content)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Download, 0, len(order))
	for _, u := range order {
		out = append(out, *byURL[u])
	}
	return out, nil
}

// applyFirefoxMetadata reads the JSON blob Firefox stores.
//
// Unknown or unparseable JSON is ignored rather than guessed at: the
// download's URL and destination are already recovered from the other
// annotation, and a malformed metadata blob must not discard them.
func applyFirefoxMetadata(d *Download, content string) {
	var meta struct {
		State      *int64 `json:"state"`
		EndTime    *int64 `json:"endTime"`
		FileSize   *int64 `json:"fileSize"`
		Referrer   string `json:"referrer"`
		Deleted    *bool  `json:"deleted"`
		TotalBytes *int64 `json:"totalBytes"`
	}
	if err := json.Unmarshal([]byte(content), &meta); err != nil {
		return
	}
	if meta.EndTime != nil && *meta.EndTime > 0 {
		// Firefox writes this one in MILLISECONDS since the Unix epoch,
		// unlike the microsecond columns elsewhere in places.sqlite.
		d.EndTime = time.UnixMilli(*meta.EndTime).UTC()
		if d.EndTime.Year() < 1995 || d.EndTime.Year() > 2200 {
			d.EndTime = time.Time{}
		}
	}
	if meta.State != nil {
		d.StateRaw = strconv.FormatInt(*meta.State, 10)
	}
	if meta.FileSize != nil && *meta.FileSize >= 0 {
		d.ReceivedBytes = *meta.FileSize
	}
	if meta.TotalBytes != nil && *meta.TotalBytes >= 0 {
		d.TotalBytes = *meta.TotalBytes
	}
	if meta.Referrer != "" {
		d.Referrer = meta.Referrer
	}
}

func readLegacyFirefoxDownloads(db *sql.DB) ([]Download, error) {
	rows, err := db.Query(`SELECT IFNULL(source,''), IFNULL(target,''), IFNULL(startTime,0),
	                              IFNULL(endTime,0), IFNULL(state,-1), IFNULL(maxBytes,-1),
	                              IFNULL(currBytes,-1), IFNULL(referrer,''), IFNULL(mimeType,'')
	                       FROM moz_downloads ORDER BY startTime ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("reading legacy Firefox downloads: %w", err)
	}
	defer rows.Close()

	var out []Download
	for rows.Next() && len(out) < maxDownloadRecords {
		var d Download
		var start, end, state int64
		if err := rows.Scan(&d.URL, &d.TargetPath, &start, &end, &state,
			&d.TotalBytes, &d.ReceivedBytes, &d.Referrer, &d.MIMEType); err != nil {
			continue
		}
		d.TargetPath = fileURIToPath(d.TargetPath)
		d.StartTime = fromUnixMicroseconds(start)
		d.EndTime = fromUnixMicroseconds(end)
		if state >= 0 {
			d.StateRaw = strconv.FormatInt(state, 10)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// fileURIToPath turns "file:///C:/Users/..." into a Windows path.
// A value that is not a file URI is returned unchanged.
func fileURIToPath(s string) string {
	if !strings.HasPrefix(strings.ToLower(s), "file:///") {
		return s
	}
	p := s[len("file:///"):]
	p = strings.ReplaceAll(p, "/", `\`)
	return decodePercent(p)
}

// decodePercent expands %XX escapes, leaving anything malformed alone.
func decodePercent(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := hexVal(s[i+1])
			lo, ok2 := hexVal(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// downloadEvents turns recovered downloads into normalized events.
func downloadEvents(downloads []Download, flavor Flavor, sourceName, profile, user string) ([]model.Event, []model.RawEvidence) {
	var events []model.Event
	var raws []model.RawEvidence

	for i, d := range downloads {
		if d.URL == "" && d.TargetPath == "" {
			// A row naming neither a source nor a destination carries no
			// recoverable evidence.
			continue
		}
		extra := map[string]string{
			"browser":        string(flavor),
			"browser_source": sourceName,
			"url":            truncate(d.URL, 2048),
			"evidence_meaning": "Browser download record: the browser retrieved this resource to the local path " +
				"shown. It is NOT evidence that the file was opened, and NOT evidence that it was executed -- " +
				"those require corroboration from an execution artifact such as Prefetch, Amcache or a " +
				"process-creation record.",
		}
		setIf := func(k, v string) {
			if strings.TrimSpace(v) != "" {
				extra[k] = v
			}
		}
		setIf("download_target_path", d.TargetPath)
		setIf("download_referrer", d.Referrer)
		setIf("content_type", d.MIMEType)
		setIf("download_state", d.State)
		setIf("download_state_raw", d.StateRaw)
		setIf("download_danger_type_raw", d.DangerRaw)
		setIf("browser_profile", profile)
		if name := baseName(d.TargetPath); name != "" {
			extra["file_name"] = name
		}
		if d.TotalBytes >= 0 {
			extra["download_total_bytes"] = strconv.FormatInt(d.TotalBytes, 10)
		}
		if d.ReceivedBytes >= 0 {
			extra["download_received_bytes"] = strconv.FormatInt(d.ReceivedBytes, 10)
		}
		if !d.EndTime.IsZero() {
			extra["download_end_time"] = d.EndTime.UTC().Format("2006-01-02T15:04:05Z")
		}
		if d.HasOpened {
			extra["download_opened_in_browser"] = strconv.FormatBool(d.Opened)
			extra["download_opened_note"] = "a flag the BROWSER sets when the file is opened from its own " +
				"downloads UI. False does not mean the file was never opened, and true is not evidence of " +
				"execution."
		}

		// The timestamp is the download's START time where recorded.
		ts := d.StartTime
		switch {
		case !ts.IsZero():
			extra["timestamp_meaning"] = "when the browser began retrieving this resource"
			extra["timestamp_source"] = "download start time recorded by the browser"
		case !d.EndTime.IsZero():
			ts = d.EndTime
			extra["timestamp_meaning"] = "when the browser finished retrieving this resource; no start time is recorded"
			extra["timestamp_source"] = "download end time recorded by the browser"
		default:
			extra["timestamp_meaning"] = "no time is recorded for this download"
			extra["timestamp_basis"] = "This download record carries neither a start nor an end time. The URL " +
				"and destination are still evidence; the time is not."
		}

		ev := model.Event{
			Timestamp: ts.UTC(),
			User:      user,
			EventType: model.EventBrowserDownload,
			// The browser is the process that did the retrieving, which
			// is a true statement about this record.
			ProcessName: browserProcess(flavor),
			// FilePath is where the file LANDED -- the fact an analyst
			// pivots on, and what ties a download to a later execution
			// artifact naming the same path.
			FilePath:        d.TargetPath,
			NetworkDest:     hostFromURL(d.URL),
			ArtifactType:    model.ArtifactBrowserDownload,
			Parser:          parserName,
			Confidence:      1.0,
			SourceReference: "download:" + strconv.Itoa(i),
			Extra:           extra,
		}

		rawJSON, _ := json.Marshal(map[string]any{
			"browser":        string(flavor),
			"source_file":    sourceName,
			"url":            d.URL,
			"target_path":    d.TargetPath,
			"referrer":       d.Referrer,
			"mime_type":      d.MIMEType,
			"start_time":     jsonTime(d.StartTime),
			"end_time":       jsonTime(d.EndTime),
			"total_bytes":    d.TotalBytes,
			"received_bytes": d.ReceivedBytes,
			"state":          d.State,
			"state_raw":      d.StateRaw,
		})
		events = append(events, ev)
		raws = append(raws, model.RawEvidence{SourceReference: ev.SourceReference, Raw: string(rawJSON)})
	}
	return events, raws
}

func jsonTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func baseName(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	if i := strings.LastIndex(p, `\`); i >= 0 && i+1 < len(p) {
		return p[i+1:]
	}
	return p
}
