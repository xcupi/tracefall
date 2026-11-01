// Package srum reads the System Resource Usage Monitor database (SRUDB.dat).
//
// SRUM is an ESE database. About once an hour Windows writes, for each
// application and service, what it used since the last write: CPU cycles,
// foreground time, disk I/O and bytes sent and received per network interface.
// A row shows that an application was running and doing that much work in the
// interval ending at the row's timestamp. It does not show what the application
// did, and the interval is not the moment of any single action.
//
// Rows name applications and users by number. SruDbIdMapTable maps the number to
// a path, service name, package name or SID; a number the map does not hold is
// reported as a number and never given a name.
//
// Only the tables with a documented layout are interpreted (application
// resource usage, network data usage, network connectivity, push notifications,
// and the SDP network provider, whose columns are also checked against the
// database before a row is read). Every other table is counted, listed in the
// coverage census and named in the parse notes, not guessed at. docs/srum-coverage.md
// lists each table seen and why it is or is not interpreted.
//
// Network columns are interval totals by application, interface or object. They
// are not flows: nothing in this package states or implies a destination, a
// transfer or an outcome, and the events say so (evidence_meaning, limitations).
// Records the engine has marked deleted are not emitted; their number is noted.
//
// The timestamps are the database's own: a JET date-time (OLE Automation date)
// with no zone, read as UTC, which the SRUM service writes at the end of an
// aggregation interval. They have not been calibrated against the host's real
// clock or any other artifact. A database
// copied while Windows was running can lack its newest records, which are still
// in the SRU log files; the database header says when that is possible.
package srum

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"tracefall/internal/ese"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "srum@1"

// ErrLimitExceeded is a reader/index resource ceiling, not source corruption.
var ErrLimitExceeded = errors.New("srum: reader or id index safety limit exceeded")

const (
	maxFileBytes = 8 << 30
	maxEvents    = 5_000_000
	maxRawBytes  = 8 << 10
	maxNotes     = 24
	// maxCensusTables bounds the table census kept with the parse.
	maxCensusTables = 64
)

type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactSRUM }

// Detect claims the database by its name. The header alone cannot tell SRUM
// from any other ESE database, so the file's tables are checked when it is read.
func (Parser) Detect(relPath string) bool {
	return strings.EqualFold(filepath.Base(strings.ReplaceAll(relPath, `\`, "/")), "srudb.dat")
}

// ConfirmContent accepts an ESE header: a file called SRUDB.dat that is not an
// ESE database is not this artifact.
func (Parser) ConfirmContent(header []byte) bool {
	return len(header) >= 8 && bytes.Equal(header[4:8], []byte{0xef, 0xcd, 0xab, 0x89})
}

type kind int

const (
	kindApp kind = iota + 1
	kindNetUse
	kindNetConn
	kindPush
	kindSDPNet
)

// The table names are the GUIDs of the SRUM providers, which do not change
// between Windows versions.
var tableKinds = map[string]kind{
	"{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": kindApp,
	"{973F5D5C-1D90-4944-BE8E-24B94231A174}": kindNetUse,
	"{DD6636C4-8929-4683-974E-22C046A43763}": kindNetConn,
	"{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}": kindPush,
	"{EEE2F477-0659-5C47-EF03-6D6BEFD441B3}": kindSDPNet,
}

// eventTypes names what each interpreted table becomes, for the census.
var eventTypes = map[kind]string{
	kindApp: model.EventSRUMAppUsage, kindNetUse: model.EventSRUMNetworkUsage, kindNetConn: model.EventSRUMNetworkConnection,
	kindPush: model.EventSRUMPushNotification, kindSDPNet: model.EventSRUMSDPNetwork,
}

// requiredColumns is the layout a table must have before it is read, for the
// tables whose layout is checked against the database rather than assumed.
// The first four columns are the SRUM common ones.
var requiredColumns = map[kind][]struct {
	name string
	typ  ese.ColType
}{
	kindSDPNet: {
		{"AutoIncId", ese.TypeInt32}, {"TimeStamp", ese.TypeDateTime}, {"AppId", ese.TypeInt32}, {"UserId", ese.TypeInt32},
		{"BytesInBound", ese.TypeInt64}, {"BytesOutBound", ese.TypeInt64}, {"BytesTotal", ese.TypeInt64},
	},
}

// layoutMatches reports whether the table has every column the interpretation
// reads, with the documented type. A table that does not is counted, not read.
func layoutMatches(t *ese.Table, k kind) bool {
	for _, c := range requiredColumns[k] {
		col := t.Column(c.name)
		if col == nil || col.Type != c.typ {
			return false
		}
	}
	return true
}

// Texts every network event carries so that a counter is never read as more
// than it is. Destination and outcome come from network evidence, never from
// SRUM.
const (
	meaningNetUse  = "Bytes the SRUM service recorded for one application on one network interface during an interval ending at the row time. An interval total by application and interface, not a flow."
	meaningNetConn = "SRUM recorded that a network interface profile was connected, for the stated seconds, in an interval ending at the row time. An interval record of connectivity, not a flow."
	meaningSDPNet  = "Inbound, outbound and total byte counters the SRUM SDP network provider wrote for one object (public tools describe it as, for example, a network adapter) during an interval ending at the row time. An interval total by object, not a flow."
	limitsNet      = "Not a flow: carries no destination, remote address, protocol, port or content, and no direction beyond sent/received (in/out). It does not show that data left the host, that any remote party received it, or what happened to it. A destination or an outcome must come from network evidence, never from SRUM."
	timeBasis      = "End of the aggregation interval, written by the SRUM service as a JET date-time (OLE Automation date: an 8-byte float of days since 1899-12-30; no zone is stored and the value is read as UTC). Not the moment of any action. The time has not been calibrated against the host's real clock or any other artifact."
)

type idEntry struct {
	typ  int64
	blob []byte
}

var ifTypes = map[uint64]string{6: "ethernet", 71: "wifi", 24: "loopback", 131: "tunnel", 243: "wwan", 244: "wwan"}

func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	return p.parse(context.Background(), absPath, nil)
}

func (p Parser) ParseStream(ctx context.Context, path string, _ parsers.ParseContext, sink parsers.RecordSink) (*model.ParseCoverage, error) {
	res, err := p.parse(ctx, path, sink)
	err = idIndexError(err)
	if res.Coverage == nil {
		res.Coverage = &model.ParseCoverage{}
	}
	if errors.Is(err, ErrLimitExceeded) {
		res.Coverage.LimitReached = true
	}
	return res.Coverage, err
}

func (Parser) parse(ctx context.Context, absPath string, sink parsers.RecordSink) (parsers.ParseResult, error) {
	if err := ctx.Err(); err != nil {
		return parsers.ParseResult{}, err
	}
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
		if sink != nil {
			return parsers.ParseResult{Coverage: &model.ParseCoverage{LimitReached: true}}, fmt.Errorf("%w: input exceeds %d bytes", ErrLimitExceeded, int64(maxFileBytes))
		}
		return parsers.ParseResult{}, fmt.Errorf("srum: %d bytes is larger than the %d byte limit", st.Size(), int64(maxFileBytes))
	}
	db, err := ese.Open(f, st.Size())
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("srum: %w", err)
	}
	idTable := db.Table("SruDbIdMapTable")
	if idTable == nil {
		return parsers.ParseResult{}, fmt.Errorf("srum: no SruDbIdMapTable: this is an ESE database but not a SRUM database")
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
		note(fmt.Sprintf("the database was not cleanly shut down (%s); records that were still in the SRU log files are not in it", state))
	}

	ids := map[int64]idEntry{}
	var disk *idStore
	if sink != nil {
		disk, err = openIDStore(ctx)
		if err != nil {
			return parsers.ParseResult{Coverage: cov}, err
		}
		defer disk.close()
	}
	flush := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if sink == nil || len(res.Events) == 0 {
			return nil
		}
		err := sink(res)
		res = parsers.ParseResult{}
		return err
	}
	idStats, err := idTable.Scan(func(r ese.Row) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if r.Defunct {
			return nil
		}
		ix, _ := r.Get("IdIndex")
		ty, _ := r.Get("IdType")
		bl, _ := r.Get("IdBlob")
		if ix.Null || ix.Err != nil {
			if disk != nil {
				cov.RecordsFailed++
				return fmt.Errorf("%w: missing or unreadable id index", ese.ErrCorrupt)
			}
			return nil
		}
		if disk != nil && (ty.Err != nil || bl.Err != nil) {
			cov.RecordsFailed++
			return fmt.Errorf("%w: unreadable id value", ese.ErrCorrupt)
		}
		e := idEntry{typ: -1}
		if !ty.Null && ty.Err == nil {
			e.typ = ty.Int()
		}
		if !bl.Null && bl.Err == nil {
			e.blob = bl.Raw
		}
		if disk != nil {
			if len(e.blob) > 64<<10 {
				return fmt.Errorf("%w: id blob exceeds 64 KiB", ErrLimitExceeded)
			}
			_, err := disk.put.ExecContext(ctx, ix.Int(), e.typ, e.blob)
			return err
		}
		ids[ix.Int()] = e
		return nil
	})
	if err != nil {
		return parsers.ParseResult{Coverage: cov}, fmt.Errorf("srum: reading the id map: %w", err)
	}
	if disk != nil {
		note(fmt.Sprintf("id map: %d live records, %d deleted records; excluded from provider record counts", idStats.Live, idStats.Defunct))
		if idStats.Unreadable > 0 {
			cov.RecordsFailed = idStats.Unreadable
			return parsers.ParseResult{Coverage: cov}, fmt.Errorf("%w: unreadable SRUM id map records", ese.ErrCorrupt)
		}
		if err = disk.finish(ctx); err != nil {
			return parsers.ParseResult{Coverage: cov}, err
		}
	}
	if idStats.Unreadable > 0 {
		note(fmt.Sprintf("%d entries of the id map could not be read; the applications and users they name are shown as numbers", idStats.Unreadable))
	}

	names := make([]string, 0, len(db.Tables()))
	for _, t := range db.Tables() {
		names = append(names, t.Name)
	}
	sort.Strings(names)
	var deleted, unreadable int
	moreTables := 0
	var census []model.CoverageTable
	addCensus := func(row model.CoverageTable) {
		if len(census) < maxCensusTables {
			census = append(census, row)
		} else {
			cov.TablesUnlisted++
		}
	}
	for _, name := range names {
		t := db.Table(name)
		k, known := tableKinds[strings.ToUpper(name)]
		if !known && !strings.HasPrefix(name, "{") {
			continue // the engine's own tables, the id map, the checkpoint table
		}
		if known && !layoutMatches(t, k) {
			note(fmt.Sprintf("table %s: its columns are not the documented layout, so it was counted and not interpreted", name))
			known = false
		}
		if !known {
			stats, err := t.Scan(func(ese.Row) error { return ctx.Err() })
			if err != nil {
				return parsers.ParseResult{Coverage: cov}, fmt.Errorf("srum: reading table %s: %w", name, err)
			}
			cov.RecordsRead += stats.Live
			cov.Unmapped += stats.Live
			deleted += stats.Defunct
			unreadable += stats.Unreadable
			addCensus(model.CoverageTable{Table: name, Rows: stats.Live, Deleted: stats.Defunct})
			if stats.Live > 0 {
				if len(notes) < maxNotes {
					note(fmt.Sprintf("table %s: %d records not interpreted (no known layout)", name, stats.Live))
				} else {
					moreTables++
				}
			}
			continue
		}
		stats, err := t.Scan(func(r ese.Row) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if r.Defunct {
				return nil
			}
			cov.RecordsRead++
			if sink == nil && len(res.Events) >= maxEvents {
				cov.LimitReached = true
				return nil
			}
			if disk != nil {
				clear(ids)
				for _, col := range []string{"AppId", "UserId"} {
					v, _ := r.Get(col)
					if v.Null || v.Err != nil {
						continue
					}
					e, ok, err := disk.lookup(ctx, v.Int())
					if err != nil {
						return err
					}
					if ok {
						ids[v.Int()] = e
					}
				}
			}
			ev, raw, ok := build(r, k, name, ids, state)
			if !ok {
				cov.RecordsFailed++
				return nil
			}
			if ev.Timestamp.IsZero() {
				cov.Undated++
			}
			cov.Mapped++
			res.Events = append(res.Events, ev)
			res.Raw = append(res.Raw, raw)
			if sink != nil && len(res.Events) >= 128 {
				return flush()
			}
			return nil
		})
		if err != nil {
			return parsers.ParseResult{Coverage: cov}, fmt.Errorf("srum: reading table %s: %w", name, err)
		}
		deleted += stats.Defunct
		unreadable += stats.Unreadable
		addCensus(model.CoverageTable{Table: name, Rows: stats.Live, Interpreted: true, Event: eventTypes[k], Deleted: stats.Defunct})
	}
	cov.Tables = census
	clean := db.State == ese.StateCleanShutdown
	cov.CleanShutdown = &clean
	cov.DatabaseState = state
	if moreTables > 0 {
		note(fmt.Sprintf("%d more tables with records were not interpreted", moreTables))
	}
	if deleted > 0 {
		note(fmt.Sprintf("%d deleted records are still in the file and were not emitted", deleted))
	}
	if unreadable > 0 {
		cov.RecordsFailed += unreadable
		note(fmt.Sprintf("%d entries could not be decoded as records", unreadable))
	}
	cov.Notes = notes
	if sink != nil {
		if cov.RecordsFailed > 0 {
			return parsers.ParseResult{Coverage: cov}, fmt.Errorf("%w: %d unreadable SRUM provider records", ese.ErrCorrupt, cov.RecordsFailed)
		}
		if err := flush(); err != nil {
			return parsers.ParseResult{Coverage: cov}, err
		}
	}
	res.Coverage = cov
	return res, nil
}

func snake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				p := s[i-1]
				if (p >= 'a' && p <= 'z') || (p >= '0' && p <= '9') {
					b.WriteByte('_')
				}
			}
			b.WriteRune(r + 32)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// build turns one record into an event. ok is false when the record's key
// columns cannot be read.
func build(r ese.Row, k kind, table string, ids map[int64]idEntry, state string) (model.Event, model.RawEvidence, bool) {
	get := func(n string) ese.Value { v, _ := r.Get(n); return v }
	auto := get("AutoIncId")
	if auto.Null || auto.Err != nil {
		return model.Event{}, model.RawEvidence{}, false
	}
	ref := fmt.Sprintf("table:%s#id:%d", table, auto.Int())
	extra := map[string]string{"srum_table": table, "srum_auto_inc_id": strconv.FormatInt(auto.Int(), 10), "database_state": state}
	var raw []string
	put := func(name string) {
		v := get(name)
		switch {
		case v.Err != nil:
			raw = append(raw, name+"=ERR")
		case v.Null:
			raw = append(raw, name+"=NULL")
		default:
			raw = append(raw, name+"="+hex.EncodeToString(v.Raw))
		}
	}
	num := func(col, key string) {
		put(col)
		if v := get(col); !v.Null && v.Err == nil {
			extra[key] = strconv.FormatInt(v.Int(), 10)
		}
	}

	ev := model.Event{ArtifactType: model.ArtifactSRUM, Parser: parserName, SourceReference: ref, Confidence: 0.9}
	extra["time_basis"] = timeBasis

	put("TimeStamp")
	ts := get("TimeStamp")
	if t, ok := ts.Time(); ok && t.Year() >= 1995 && t.Year() <= 2100 {
		ev.Timestamp = t.UTC()
	} else if !ts.Null && ts.Err == nil {
		extra["timestamp_raw"] = hex.EncodeToString(ts.Raw)
	} else {
		extra["timestamp_raw"] = ""
	}

	put("AppId")
	put("UserId")
	if v := get("AppId"); !v.Null && v.Err == nil {
		extra["app_id"] = strconv.FormatInt(v.Int(), 10)
		if k == kindSDPNet {
			resolveSDPObject(extra, ids, v.Int())
		} else {
			resolveApp(&ev, extra, ids, v.Int())
		}
	} else if k == kindSDPNet {
		extra["sdp_object_resolved"] = "false"
	} else {
		extra["app_resolved"] = "false"
	}
	if v := get("UserId"); !v.Null && v.Err == nil {
		extra["user_id"] = strconv.FormatInt(v.Int(), 10)
		resolveUser(&ev, extra, ids, v.Int())
	} else {
		extra["user_resolved"] = "false"
	}

	switch k {
	case kindApp:
		ev.EventType = model.EventSRUMAppUsage
		for _, c := range []string{"ForegroundCycleTime", "BackgroundCycleTime", "FaceTime", "ForegroundContextSwitches", "BackgroundContextSwitches",
			"ForegroundBytesRead", "ForegroundBytesWritten", "ForegroundNumReadOperations", "ForegroundNumWriteOperations", "ForegroundNumberOfFlushes",
			"BackgroundBytesRead", "BackgroundBytesWritten", "BackgroundNumReadOperations", "BackgroundNumWriteOperations", "BackgroundNumberOfFlushes"} {
			num(c, snake(c))
		}
	case kindNetUse:
		ev.EventType = model.EventSRUMNetworkUsage
		num("BytesSent", "bytes_sent")
		num("BytesRecvd", "bytes_received")
		iface(r, extra, &raw)
		num("L2ProfileId", "l2_profile_id")
		num("L2ProfileFlags", "l2_profile_flags")
		extra["evidence_meaning"], extra["limitations"] = meaningNetUse, limitsNet
	case kindNetConn:
		ev.EventType = model.EventSRUMNetworkConnection
		num("ConnectedTime", "connected_seconds")
		put("ConnectStartTime")
		if v := get("ConnectStartTime"); !v.Null && v.Err == nil {
			if t, ok := ese.FileTime(v.Int()); ok && t.Year() >= 1995 && t.Year() <= 2100 {
				extra["connect_start"] = t.Format(time.RFC3339Nano)
			} else {
				extra["connect_start_raw"] = strconv.FormatInt(v.Int(), 10)
			}
		}
		iface(r, extra, &raw)
		num("L2ProfileId", "l2_profile_id")
		num("L2ProfileFlags", "l2_profile_flags")
		extra["evidence_meaning"], extra["limitations"] = meaningNetConn, limitsNet
	case kindSDPNet:
		ev.EventType = model.EventSRUMSDPNetwork
		num("BytesInBound", "bytes_in_bound")
		num("BytesOutBound", "bytes_out_bound")
		num("BytesTotal", "bytes_total")
		extra["evidence_meaning"], extra["limitations"] = meaningSDPNet, limitsNet
	case kindPush:
		ev.EventType = model.EventSRUMPushNotification
		num("NotificationType", "notification_type")
		num("PayloadSize", "payload_size")
		num("NetworkType", "network_type")
	}
	ev.Extra = extra
	text := strings.Join(raw, ";")
	if len(text) > maxRawBytes {
		text = text[:maxRawBytes]
	}
	return ev, model.RawEvidence{SourceReference: ref, Raw: text}, true
}

func iface(r ese.Row, extra map[string]string, raw *[]string) {
	v, _ := r.Get("InterfaceLuid")
	if v.Null || v.Err != nil {
		return
	}
	*raw = append(*raw, "InterfaceLuid="+hex.EncodeToString(v.Raw))
	luid := uint64(v.Int())
	extra["interface_luid"] = strconv.FormatUint(luid, 10)
	it := luid >> 48
	extra["interface_type"] = strconv.FormatUint(it, 10)
	extra["interface_type_name"] = ifTypes[it]
}

// resolveSDPObject names the object an SDP row is about. The provider's ids are
// of a type no cited source documents, and the object is not necessarily a
// program, so it is never given a process name or path: the stored text is
// shown as written, and an id the map does not hold stays a number.
func resolveSDPObject(extra map[string]string, ids map[int64]idEntry, id int64) {
	extra["sdp_object_resolved"] = "false"
	e, ok := ids[id]
	if !ok {
		return
	}
	extra["sdp_object_id_type"] = idTypeName(e.typ)
	if len(e.blob) == 0 {
		return
	}
	text, ok := utf16Text(e.blob)
	if !ok || e.typ == 3 {
		extra["sdp_object_raw"] = hex.EncodeToString(e.blob)
		return
	}
	extra["sdp_object"] = text
	extra["sdp_object_resolved"] = "true"
}

func resolveApp(ev *model.Event, extra map[string]string, ids map[int64]idEntry, id int64) {
	extra["app_resolved"] = "false"
	e, ok := ids[id]
	if !ok {
		return
	}
	extra["app_id_type"] = idTypeName(e.typ)
	if len(e.blob) == 0 {
		return
	}
	text, ok := utf16Text(e.blob)
	if !ok {
		extra["app_id_raw"] = hex.EncodeToString(e.blob)
		return
	}
	switch e.typ {
	case 0, 1, 2:
		extra["app_id_raw"] = text
		extra["app"] = text
		extra["app_resolved"] = "true"
		if e.typ == 0 {
			if strings.HasPrefix(text, "!!") {
				// "!!name!time!n": a program SRUM could not tie to a file
				rest := strings.TrimPrefix(text, "!!")
				if i := strings.IndexByte(rest, '!'); i >= 0 {
					rest = rest[:i]
				}
				ev.ProcessName = rest
			} else {
				ev.ProcessPath = text
				ev.ProcessName = text[strings.LastIndexAny(text, `\/`)+1:]
			}
		}
	}
}

func resolveUser(ev *model.Event, extra map[string]string, ids map[int64]idEntry, id int64) {
	extra["user_resolved"] = "false"
	e, ok := ids[id]
	if !ok || len(e.blob) == 0 {
		return
	}
	if e.typ != 3 {
		extra["user_raw"] = hex.EncodeToString(e.blob)
		return
	}
	s, ok := parseSID(e.blob)
	if !ok {
		extra["user_raw"] = "invalid-sid:" + hex.EncodeToString(e.blob)
		return
	}
	ev.User = s
	extra["user_sid"] = s
	extra["user_resolved"] = "true"
}

func idTypeName(t int64) string {
	switch t {
	case 0:
		return "path"
	case 1:
		return "service"
	case 2:
		return "package"
	case 3:
		return "sid"
	}
	return fmt.Sprintf("unknown(%d)", t)
}

// parseSID reads a binary SID and refuses anything whose length does not match
// its own sub-authority count.
func parseSID(b []byte) (string, bool) {
	if len(b) < 8 || b[0] != 1 {
		return "", false
	}
	n := int(b[1])
	if n > 15 || len(b) != 8+4*n {
		return "", false
	}
	var auth uint64
	for _, c := range b[2:8] {
		auth = auth<<8 | uint64(c)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-1-%d", auth)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return sb.String(), true
}

// utf16Text decodes UTF-16LE text and drops the terminating NULs. ok is false
// for an odd number of bytes, which is not text.
func utf16Text(b []byte) (string, bool) {
	if len(b)%2 != 0 {
		return "", false
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:]))
	}
	for len(u) > 0 && u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	return string(utf16.Decode(u)), true
}
