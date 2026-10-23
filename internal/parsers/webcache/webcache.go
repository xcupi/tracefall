// Package webcache reads the Internet Explorer / Edge Legacy WebCache database
// (WebCacheV01.dat, an ESE database).
//
// Containers lists the database's containers (History, daily MSHist history,
// Content, Cookies, DOMStore, BackgroundTransferApi, ...). Each has a table
// Container_<id> of records.
//
// What is read:
//
//   - History and MSHist* containers: one record per URL, with the last access
//     time and an access count. That is not one record per visit: a URL visited
//     five times is one record with a count of five. The events are
//     browser_visit with that reading stated in their fields.
//   - Content containers: cache entries (URL, file name, size, times, and the
//     HTTP status line and content type of the cached response). A cache entry
//     shows that a copy was held, not that the user chose to load it.
//
// What is not read: cookie containers (by design, as for every browser in
// Tracefall: the records name sites and sessions and the project has no place
// to keep what must not be displayed), and every other container, which is
// counted and named in the parse notes. Request and response headers are not
// copied beyond the status line and content type, because they can carry
// cookies and tokens.
//
// The history ModifiedTime is not an instant: in the sample it differs from the
// access time by whole hours, which is a local-time reading. It is kept as
// stored and never used as a time.
package webcache

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/ese"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "webcache@1"

const (
	maxFileBytes = 8 << 30
	maxEvents    = 5_000_000
	maxRawBytes  = 8 << 10
	maxNotes     = 24
	maxHeader    = 200
)

var (
	nameRe   = regexp.MustCompile(`(?i)^webcachev\d+\.dat$`)
	mshistRe = regexp.MustCompile(`^:(\d{16}): ([^@]*)@(.*)$`)
	userRe   = regexp.MustCompile(`(?i)[\\/]Users[\\/]([^\\/]+)[\\/]`)
)

type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactWebCache }

func (Parser) Detect(relPath string) bool {
	return nameRe.MatchString(filepath.Base(strings.ReplaceAll(relPath, `\`, "/")))
}

// ConfirmContent accepts an ESE header: a file with this name that is not an
// ESE database is not this artifact.
func (Parser) ConfirmContent(header []byte) bool {
	return len(header) >= 8 && bytes.Equal(header[4:8], []byte{0xef, 0xcd, 0xab, 0x89})
}

type containerKind int

const (
	kindOther containerKind = iota
	kindHistory
	kindMSHist
	kindContent
	kindCookies
)

func classify(name string) containerKind {
	switch {
	case strings.EqualFold(name, "History"):
		return kindHistory
	case strings.HasPrefix(strings.ToLower(name), "mshist"):
		return kindMSHist
	case strings.EqualFold(name, "Content"):
		return kindContent
	case strings.EqualFold(name, "Cookies"):
		return kindCookies
	}
	return kindOther
}

type cont struct {
	id   int64
	name string
	dir  string
	kind containerKind
}

func (Parser) Parse(absPath string) (parsers.ParseResult, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if st.Size() > maxFileBytes {
		return parsers.ParseResult{}, fmt.Errorf("webcache: %d bytes is larger than the %d byte limit", st.Size(), int64(maxFileBytes))
	}
	db, err := ese.Open(f, st.Size())
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("webcache: %w", err)
	}
	var (
		res   parsers.ParseResult
		cov   = &model.ParseCoverage{}
		notes []string
	)
	note := func(s string) {
		if len(notes) < maxNotes {
			notes = append(notes, s)
		}
	}
	state := db.State.String()
	if db.State != ese.StateCleanShutdown {
		note(fmt.Sprintf("the database was not cleanly shut down (%s); changes still in the transaction log are not in it", state))
	}
	finish := func() (parsers.ParseResult, error) {
		cov.Mapped = len(res.Events)
		cov.Notes = notes
		res.Coverage = cov
		return res, nil
	}

	ct := db.Table("Containers")
	if ct == nil {
		note("no Containers table: this WebCache holds no history or cache containers")
		return finish()
	}
	var cs []cont
	if _, err := ct.Scan(func(r ese.Row) error {
		if r.Defunct {
			return nil
		}
		id, _ := r.Get("ContainerId")
		nm, _ := r.Get("Name")
		dr, _ := r.Get("Directory")
		if id.Null || id.Err != nil {
			return nil
		}
		c := cont{id: id.Int()}
		if !nm.Null && nm.Err == nil {
			c.name = strings.TrimRight(nm.Text(), "\x00")
		}
		if !dr.Null && dr.Err == nil {
			c.dir = strings.TrimRight(dr.Text(), "\x00")
		}
		c.kind = classify(c.name)
		cs = append(cs, c)
		return nil
	}); err != nil {
		return parsers.ParseResult{}, fmt.Errorf("webcache: reading Containers: %w", err)
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].id < cs[j].id })

	var deleted, unreadable int
	for _, c := range cs {
		t := db.Table("Container_" + strconv.FormatInt(c.id, 10))
		if t == nil {
			note(fmt.Sprintf("container %s (id %d): its table Container_%d is not in the database", c.name, c.id, c.id))
			continue
		}
		stats, err := t.Scan(func(r ese.Row) error {
			if r.Defunct {
				return nil
			}
			cov.RecordsRead++
			if c.kind == kindOther || c.kind == kindCookies {
				cov.Unmapped++
				return nil
			}
			if len(res.Events) >= maxEvents {
				cov.LimitReached = true
				return nil
			}
			ev, raw, ok := build(r, c, state)
			if !ok {
				cov.RecordsFailed++
				return nil
			}
			if ev.Timestamp.IsZero() {
				cov.Undated++
			}
			res.Events = append(res.Events, ev)
			res.Raw = append(res.Raw, raw)
			return nil
		})
		if err != nil {
			return parsers.ParseResult{}, fmt.Errorf("webcache: reading %s: %w", t.Name, err)
		}
		deleted += stats.Defunct
		unreadable += stats.Unreadable
		switch {
		case c.kind == kindCookies && stats.Live > 0:
			note(fmt.Sprintf("container %s (id %d): %d cookie records are not read", c.name, c.id, stats.Live))
		case c.kind == kindOther && stats.Live > 0:
			note(fmt.Sprintf("container %s (id %d): %d records not interpreted", c.name, c.id, stats.Live))
		}
	}
	if deleted > 0 {
		note(fmt.Sprintf("%d deleted records are still in the file and were not emitted", deleted))
	}
	if unreadable > 0 {
		cov.RecordsFailed += unreadable
		note(fmt.Sprintf("%d entries could not be decoded as records", unreadable))
	}
	return finish()
}

// instant converts a stored FILETIME; ok is false for zero or an implausible year.
func instant(v ese.Value) (time.Time, bool) {
	if v.Null || v.Err != nil {
		return time.Time{}, false
	}
	t, ok := ese.FileTime(v.Int())
	if !ok || t.Year() < 1995 || t.Year() > 2100 {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func build(r ese.Row, c cont, state string) (model.Event, model.RawEvidence, bool) {
	get := func(n string) ese.Value { v, _ := r.Get(n); return v }
	entry := get("EntryId")
	if entry.Null || entry.Err != nil {
		return model.Event{}, model.RawEvidence{}, false
	}
	ref := fmt.Sprintf("container:%d#entry:%d", c.id, entry.Int())
	extra := map[string]string{
		"container_id": strconv.FormatInt(c.id, 10), "container_name": c.name, "entry_id": strconv.FormatInt(entry.Int(), 10),
		"database_state": state, "browser": "ie_edge_legacy",
	}
	if c.dir != "" {
		extra["container_directory"] = c.dir
	}
	var raw []string
	text := func(name string) string {
		v := get(name)
		if v.Null || v.Err != nil {
			return ""
		}
		raw = append(raw, name+"="+hex.EncodeToString(v.Raw))
		return strings.TrimRight(v.Text(), "\x00")
	}
	num := func(col, key string) {
		v := get(col)
		if v.Null || v.Err != nil {
			return
		}
		raw = append(raw, col+"="+hex.EncodeToString(v.Raw))
		extra[key] = strconv.FormatInt(v.Int(), 10)
	}
	when := func(col, key string) time.Time {
		v := get(col)
		if v.Null || v.Err != nil {
			return time.Time{}
		}
		raw = append(raw, col+"="+hex.EncodeToString(v.Raw))
		if v.Int() == 0 {
			return time.Time{}
		}
		if t, ok := instant(v); ok {
			extra[key] = t.Format(time.RFC3339Nano)
			return t
		}
		extra[key+"_raw"] = strconv.FormatInt(v.Int(), 10)
		return time.Time{}
	}

	raw = append(raw, "EntryId="+hex.EncodeToString(entry.Raw))
	rawURL := text("Url")
	num("AccessCount", "access_count")
	num("Flags", "flags")
	num("Type", "type")
	num("FileSize", "file_size")
	when("SyncTime", "sync_time")
	when("CreationTime", "creation_time")
	when("ExpiryTime", "expiry_time")
	when("PostCheckTime", "post_check_time")
	accessed := when("AccessedTime", "accessed_time")

	ev := model.Event{ArtifactType: model.ArtifactWebCache, Parser: parserName, SourceReference: ref, Confidence: 0.9, Timestamp: accessed}
	if accessed.IsZero() {
		if v := get("AccessedTime"); !v.Null && v.Err == nil {
			extra["timestamp_raw"] = strconv.FormatInt(v.Int(), 10)
		}
	}

	var host string
	switch c.kind {
	case kindHistory, kindMSHist:
		ev.EventType = model.EventBrowserVisit
		extra["record_kind"] = "url"
		u := rawURL
		switch {
		case c.kind == kindMSHist && mshistRe.MatchString(u):
			m := mshistRe.FindStringSubmatch(u)
			extra["history_period"] = m[1]
			ev.User = strings.TrimSpace(m[2])
			rest := m[3]
			if strings.HasPrefix(rest, ":Host: ") {
				extra["record_kind"] = "daily_host"
				u = strings.TrimPrefix(rest, ":Host: ")
				host = u
			} else {
				u = rest
			}
		case strings.HasPrefix(u, "Visited: "):
			rest := strings.TrimPrefix(u, "Visited: ")
			if i := strings.IndexByte(rest, '@'); i >= 0 {
				ev.User = rest[:i]
				u = rest[i+1:]
			} else {
				u = rest
			}
		}
		extra["url"] = u
		if host == "" {
			host = hostOf(u)
		}
		// The history ModifiedTime is not an instant (see the package comment).
		if v := get("ModifiedTime"); !v.Null && v.Err == nil && v.Int() != 0 {
			raw = append(raw, "ModifiedTime="+hex.EncodeToString(v.Raw))
			extra["modified_time_raw"] = strconv.FormatInt(v.Int(), 10)
		}
	case kindContent:
		ev.EventType = model.EventBrowserCacheEntry
		extra["url"] = rawURL
		extra["record_kind"] = "cache_entry"
		host = hostOf(rawURL)
		if fn := text("Filename"); fn != "" {
			extra["filename"] = fn
		}
		if ext := text("FileExtension"); ext != "" {
			extra["file_extension"] = ext
		}
		if ru := text("RedirectUrl"); ru != "" {
			extra["redirect_url"] = ru
		}
		when("ModifiedTime", "modified_time")
		if v := get("ResponseHeaders"); !v.Null && v.Err == nil {
			status, ctype := httpSummary(v.Raw)
			if status != "" {
				extra["response_status"] = status
			}
			if ctype != "" {
				extra["content_type"] = ctype
			}
		}
	}
	ev.NetworkDest = host
	if ev.User == "" {
		if m := userRe.FindStringSubmatch(c.dir); m != nil {
			ev.User = m[1]
		}
	}
	ev.Extra = extra
	rt := strings.Join(raw, ";")
	if len(rt) > maxRawBytes {
		rt = rt[:maxRawBytes]
	}
	return ev, model.RawEvidence{SourceReference: ref, Raw: rt}, true
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

// httpSummary returns the status line and content type of a stored response if
// the blob is HTTP text. Nothing else in the headers is read: they can carry
// cookies and tokens.
func httpSummary(b []byte) (status, ctype string) {
	if !bytes.HasPrefix(b, []byte("HTTP/")) {
		return "", ""
	}
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) > maxHeader {
			line = line[:maxHeader]
		}
		if i == 0 {
			status = line
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "content-type") {
			ctype = strings.TrimSpace(v)
			break
		}
		if line == "" {
			break
		}
	}
	return status, ctype
}
