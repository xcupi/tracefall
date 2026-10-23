package srum

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"tracefall/internal/ese/esegen"
	"tracefall/internal/model"
)

const (
	guidApp     = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
	guidNetUse  = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
	guidNetConn = "{DD6636C4-8929-4683-974E-22C046A43763}"
	guidPush    = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}"
	guidTimeln  = "{5C8CF1C7-7257-4F13-B223-970EF5939312}"
)

func col(id uint32, name string, typ int) esegen.Column {
	return esegen.Column{ID: id, Name: name, Type: typ}
}

func common() []esegen.Column {
	return []esegen.Column{col(1, "AutoIncId", esegen.Int32), col(2, "TimeStamp", esegen.DateTime), col(3, "AppId", esegen.Int32), col(4, "UserId", esegen.Int32)}
}

func idMapTable(rows ...esegen.Record) esegen.Table {
	return esegen.Table{Name: "SruDbIdMapTable", HasLVTree: false, Records: rows, Columns: []esegen.Column{
		col(1, "IdType", esegen.Uint8), col(2, "IdIndex", esegen.Int32), {ID: 256, Name: "IdBlob", Type: esegen.LongBinary},
	}}
}

func idRow(typ byte, idx int32, blob []byte) esegen.Record {
	r := esegen.Record{Fixed: map[uint32][]byte{1: {typ}, 2: esegen.Le32(uint32(idx))}}
	if blob != nil {
		r.Tagged = []esegen.Tagged{{ID: 256, Data: blob}}
	}
	return r
}

func sid(sub ...uint32) []byte {
	b := []byte{1, byte(len(sub)), 0, 0, 0, 0, 0, 5}
	for _, s := range sub {
		b = append(b, esegen.Le32(s)...)
	}
	return b
}

// ole encodes t as a JET date-time (days since 1899-12-30, as a float64).
func ole(t time.Time) []byte {
	days := float64(t.Sub(time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC))) / float64(24*time.Hour)
	return esegen.Le64(math.Float64bits(days))
}

func filetime(t time.Time) []byte {
	return esegen.Le64(uint64(t.Unix()+11644473600) * 10000000)
}

func i32(v int) []byte   { return esegen.Le32(uint32(int32(v))) }
func i64(v int64) []byte { return esegen.Le64(uint64(v)) }

func appTable(rows ...esegen.Record) esegen.Table {
	c := append(common(),
		col(5, "ForegroundCycleTime", esegen.Int64), col(6, "BackgroundCycleTime", esegen.Int64), col(7, "FaceTime", esegen.Int64),
		col(8, "ForegroundContextSwitches", esegen.Int32), col(9, "BackgroundContextSwitches", esegen.Int32),
		col(10, "ForegroundBytesRead", esegen.Int64), col(11, "ForegroundBytesWritten", esegen.Int64),
		col(12, "ForegroundNumReadOperations", esegen.Int32), col(13, "ForegroundNumWriteOperations", esegen.Int32), col(14, "ForegroundNumberOfFlushes", esegen.Int32),
		col(15, "BackgroundBytesRead", esegen.Int64), col(16, "BackgroundBytesWritten", esegen.Int64),
		col(17, "BackgroundNumReadOperations", esegen.Int32), col(18, "BackgroundNumWriteOperations", esegen.Int32), col(19, "BackgroundNumberOfFlushes", esegen.Int32))
	return esegen.Table{Name: guidApp, Columns: c, Records: rows}
}

func appRow(id int, ts []byte, app, user int, fgCycles, face, fgRead, fgWrite, bgRead int64) esegen.Record {
	return esegen.Record{Fixed: map[uint32][]byte{
		1: i32(id), 2: ts, 3: i32(app), 4: i32(user), 5: i64(fgCycles), 6: i64(7), 7: i64(face), 8: i32(11), 9: i32(12),
		10: i64(fgRead), 11: i64(fgWrite), 12: i32(1), 13: i32(2), 14: i32(3), 15: i64(bgRead), 16: i64(0), 17: i32(0), 18: i32(0), 19: i32(0),
	}}
}

func netUseTable(rows ...esegen.Record) esegen.Table {
	c := append(common(), col(5, "InterfaceLuid", esegen.Int64), col(6, "L2ProfileId", esegen.Int32), col(7, "L2ProfileFlags", esegen.Int32),
		col(8, "BytesSent", esegen.Int64), col(9, "BytesRecvd", esegen.Int64))
	return esegen.Table{Name: guidNetUse, Columns: c, Records: rows}
}

func netUseRow(id int, ts []byte, app, user int, luid, sent, recv int64) esegen.Record {
	return esegen.Record{Fixed: map[uint32][]byte{1: i32(id), 2: ts, 3: i32(app), 4: i32(user), 5: i64(luid), 6: i32(0), 7: i32(0), 8: i64(sent), 9: i64(recv)}}
}

func write(t *testing.T, tables []esegen.Table, o esegen.Options) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "SRUDB.dat")
	if err := os.WriteFile(p, esegen.Build(tables, o), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func utf16z(s string) []byte { return append(esegen.UTF16(s), 0, 0) }

var t0 = time.Date(2026, 3, 14, 9, 30, 0, 0, time.UTC)

func standardIDs() esegen.Table {
	return idMapTable(
		idRow(0, 1, utf16z(`\device\harddiskvolume3\windows\system32\svchost.exe`)),
		idRow(0, 2, utf16z(`!!powershell.exe!2026/03/14:09:00:00!0`)),
		idRow(1, 3, utf16z("DnsCache")),
		idRow(2, 4, utf16z("Microsoft.Windows.Search_1.14.9.190")),
		idRow(3, 5, sid(21, 111, 222, 333, 1001)),
		idRow(3, 6, sid(18)),
	)
}

func parse(t *testing.T, path string) ([]model.Event, []model.RawEvidence, *model.ParseCoverage) {
	t.Helper()
	res, err := Parser{}.Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Events) != len(res.Raw) {
		t.Fatalf("events %d and raw records %d are not paired", len(res.Events), len(res.Raw))
	}
	return res.Events, res.Raw, res.Coverage
}

func TestDetect(t *testing.T) {
	p := Parser{}
	for _, n := range []string{`Windows/System32/sru/SRUDB.dat`, `C:\Windows\System32\sru\srudb.DAT`, "SRUDB.dat"} {
		if !p.Detect(n) {
			t.Errorf("%q should be claimed", n)
		}
	}
	for _, n := range []string{"SRUDB.dat.bak", "SRU.log", "WebCacheV01.dat", "srudb.txt"} {
		if p.Detect(n) {
			t.Errorf("%q must not be claimed", n)
		}
	}
	if !p.ConfirmContent([]byte{0, 0, 0, 0, 0xef, 0xcd, 0xab, 0x89, 0x20, 0x06}) {
		t.Errorf("an ESE header must confirm")
	}
	if p.ConfirmContent([]byte("MZ\x90\x00 not an esedb at all")) || p.ConfirmContent(nil) {
		t.Errorf("a file that is not an ESE database must not confirm")
	}
}

func TestParse_ApplicationResourceUsage(t *testing.T) {
	p := write(t, []esegen.Table{standardIDs(), appTable(
		appRow(1, ole(t0), 1, 5, 123456789, 5000, 4096, 2048, 77),
		appRow(2, ole(t0.Add(time.Hour)), 2, 6, 5, 0, 0, 0, 0),
	)}, esegen.Options{})
	ev, raw, cov := parse(t, p)
	if len(ev) != 2 {
		t.Fatalf("events = %d", len(ev))
	}
	e := ev[0]
	if e.EventType != model.EventSRUMAppUsage || e.ArtifactType != model.ArtifactSRUM || e.Parser != parserName {
		t.Errorf("type=%s artifact=%s parser=%s", e.EventType, e.ArtifactType, e.Parser)
	}
	if !e.Timestamp.Equal(t0) {
		t.Errorf("timestamp = %v, want %v", e.Timestamp, t0)
	}
	if e.ProcessPath != `\device\harddiskvolume3\windows\system32\svchost.exe` || e.ProcessName != "svchost.exe" {
		t.Errorf("process = %q / %q", e.ProcessPath, e.ProcessName)
	}
	if e.User != "S-1-5-21-111-222-333-1001" {
		t.Errorf("user = %q", e.User)
	}
	want := map[string]string{
		"srum_table": guidApp, "app_id": "1", "user_id": "5", "app_resolved": "true",
		"foreground_cycle_time": "123456789", "background_cycle_time": "7", "face_time": "5000",
		"foreground_bytes_read": "4096", "foreground_bytes_written": "2048", "background_bytes_read": "77",
		"foreground_context_switches": "11", "background_context_switches": "12",
	}
	for k, v := range want {
		if e.Extra[k] != v {
			t.Errorf("Extra[%s] = %q, want %q", k, e.Extra[k], v)
		}
	}
	if ev[0].SourceReference == ev[1].SourceReference || ev[0].SourceReference == "" {
		t.Errorf("source references %q and %q must be set and different", ev[0].SourceReference, ev[1].SourceReference)
	}
	if raw[0].SourceReference != ev[0].SourceReference || raw[0].Raw == "" {
		t.Errorf("raw record is not tied to its event: %+v", raw[0])
	}
	if cov == nil || cov.RecordsRead != 2 || cov.Mapped != 2 || cov.Undated != 0 {
		t.Errorf("coverage = %+v", cov)
	}
}

func TestParse_TheIdMapNamesAppsInEveryForm(t *testing.T) {
	p := write(t, []esegen.Table{standardIDs(), appTable(
		appRow(1, ole(t0), 2, 5, 1, 1, 1, 1, 1),   // !!name!time!n
		appRow(2, ole(t0), 3, 5, 1, 1, 1, 1, 1),   // service
		appRow(3, ole(t0), 4, 6, 1, 1, 1, 1, 1),   // package
		appRow(4, ole(t0), 99, 98, 1, 1, 1, 1, 1), // ids the map does not hold
	)}, esegen.Options{})
	ev, _, _ := parse(t, p)
	e := ev[0]
	if e.Extra["app_id_type"] != "path" || e.ProcessName != "powershell.exe" || e.ProcessPath != "" {
		t.Errorf("!!form: type=%q name=%q path=%q (a name without a directory is not a path)", e.Extra["app_id_type"], e.ProcessName, e.ProcessPath)
	}
	if e.Extra["app_id_raw"] != `!!powershell.exe!2026/03/14:09:00:00!0` {
		t.Errorf("the stored text must be kept as written: %q", e.Extra["app_id_raw"])
	}
	if s := ev[1]; s.Extra["app_id_type"] != "service" || s.Extra["app"] != "DnsCache" || s.ProcessPath != "" {
		t.Errorf("service: %+v / %+v", s.Extra, s.ProcessPath)
	}
	if s := ev[2]; s.Extra["app_id_type"] != "package" || s.Extra["app"] != "Microsoft.Windows.Search_1.14.9.190" || s.User != "S-1-5-18" {
		t.Errorf("package: %+v user=%q", s.Extra, s.User)
	}
	u := ev[3]
	if u.Extra["app_resolved"] != "false" || u.Extra["app"] != "" || u.ProcessName != "" || u.ProcessPath != "" || u.User != "" {
		t.Errorf("an id with no map entry must stay an id: %+v name=%q user=%q", u.Extra, u.ProcessName, u.User)
	}
	if u.Extra["app_id"] != "99" || u.Extra["user_id"] != "98" || u.Extra["user_resolved"] != "false" {
		t.Errorf("ids must still be shown: %+v", u.Extra)
	}
}

func TestParse_NetworkUsageAndInterface(t *testing.T) {
	wifi := int64(71) << 48
	eth := int64(6)<<48 | 0x1234<<24
	p := write(t, []esegen.Table{standardIDs(), netUseTable(
		netUseRow(1, ole(t0), 1, 5, wifi, 1000, 2000),
		netUseRow(2, ole(t0), 1, 5, eth, 3, 4),
		netUseRow(3, ole(t0), 1, 5, int64(250)<<48, 3, 4),
	)}, esegen.Options{})
	ev, _, _ := parse(t, p)
	if len(ev) != 3 || ev[0].EventType != model.EventSRUMNetworkUsage {
		t.Fatalf("events = %d", len(ev))
	}
	if ev[0].Extra["bytes_sent"] != "1000" || ev[0].Extra["bytes_received"] != "2000" || ev[0].Extra["interface_type"] != "71" || ev[0].Extra["interface_type_name"] != "wifi" {
		t.Errorf("wifi row: %+v", ev[0].Extra)
	}
	if ev[1].Extra["interface_type_name"] != "ethernet" || ev[1].Extra["interface_luid"] != strconv.FormatInt(eth, 10) {
		t.Errorf("ethernet row: %+v", ev[1].Extra)
	}
	if ev[2].Extra["interface_type_name"] != "" || ev[2].Extra["interface_type"] != "250" {
		t.Errorf("an interface type that is not known must be a number only: %+v", ev[2].Extra)
	}
}

func TestParse_NetworkConnectivityAndPush(t *testing.T) {
	start := t0.Add(-90 * time.Minute)
	conn := esegen.Table{Name: guidNetConn, Columns: append(common(), col(5, "InterfaceLuid", esegen.Int64), col(6, "L2ProfileId", esegen.Int32),
		col(7, "ConnectedTime", esegen.Int32), col(8, "ConnectStartTime", esegen.Int64), col(9, "L2ProfileFlags", esegen.Int32)),
		Records: []esegen.Record{{Fixed: map[uint32][]byte{1: i32(1), 2: ole(t0), 3: i32(1), 4: i32(5), 5: i64(int64(71) << 48), 6: i32(7), 7: i32(5400), 8: filetime(start), 9: i32(0)}}}}
	push := esegen.Table{Name: guidPush, Columns: append(common(), col(5, "NotificationType", esegen.Int32), col(6, "PayloadSize", esegen.Int32), col(7, "NetworkType", esegen.Int32)),
		Records: []esegen.Record{{Fixed: map[uint32][]byte{1: i32(1), 2: ole(t0), 3: i32(4), 4: i32(5), 5: i32(1), 6: i32(8383), 7: i32(0)}}}}
	ev, _, _ := parse(t, write(t, []esegen.Table{standardIDs(), conn, push}, esegen.Options{}))
	if len(ev) != 2 {
		t.Fatalf("events = %d", len(ev))
	}
	var c, p model.Event
	for _, e := range ev {
		switch e.EventType {
		case model.EventSRUMNetworkConnection:
			c = e
		case model.EventSRUMPushNotification:
			p = e
		}
	}
	if c.Extra["connected_seconds"] != "5400" || c.Extra["connect_start"] != start.Format(time.RFC3339Nano) || c.Extra["l2_profile_id"] != "7" {
		t.Errorf("connectivity: %+v", c.Extra)
	}
	if p.Extra["notification_type"] != "1" || p.Extra["payload_size"] != "8383" || p.Extra["app"] != "Microsoft.Windows.Search_1.14.9.190" {
		t.Errorf("push: %+v", p.Extra)
	}
}

func TestParse_UndatedStaysUndatedAndIsCounted(t *testing.T) {
	zero := esegen.Le64(0)
	nan := esegen.Le64(math.Float64bits(math.NaN()))
	ancient := ole(time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC))
	p := write(t, []esegen.Table{standardIDs(), appTable(
		appRow(1, ole(t0), 1, 5, 1, 1, 1, 1, 1), appRow(2, zero, 1, 5, 1, 1, 1, 1, 1), appRow(3, nan, 1, 5, 1, 1, 1, 1, 1), appRow(4, ancient, 1, 5, 1, 1, 1, 1, 1),
	)}, esegen.Options{})
	ev, _, cov := parse(t, p)
	if len(ev) != 4 {
		t.Fatalf("an undated record is still evidence: events = %d", len(ev))
	}
	for _, i := range []int{1, 2, 3} {
		if !ev[i].Timestamp.IsZero() {
			t.Errorf("event %d was given the time %v", i, ev[i].Timestamp)
		}
		if ev[i].Extra["timestamp_raw"] == "" {
			t.Errorf("event %d keeps no trace of the stored value", i)
		}
	}
	if cov.Undated != 3 {
		t.Errorf("Undated = %d, want 3", cov.Undated)
	}
}

func TestParse_DeletedRecordsAreNotEmittedAndAreCounted(t *testing.T) {
	gone := appRow(2, ole(t0), 1, 5, 1, 1, 1, 1, 1)
	gone.Defunct = true
	ev, _, cov := parse(t, write(t, []esegen.Table{standardIDs(), appTable(appRow(1, ole(t0), 1, 5, 1, 1, 1, 1, 1), gone)}, esegen.Options{}))
	if len(ev) != 1 {
		t.Fatalf("events = %d, a deleted record is not a live one", len(ev))
	}
	if !noteMentions(cov, "1 deleted") {
		t.Errorf("the deleted record is not accounted for: %v", cov.Notes)
	}
}

func noteMentions(c *model.ParseCoverage, s string) bool {
	for _, n := range c.Notes {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

func TestParse_DirtyDatabaseIsSaid(t *testing.T) {
	tb := []esegen.Table{standardIDs(), appTable(appRow(1, ole(t0), 1, 5, 1, 1, 1, 1, 1))}
	ev, _, cov := parse(t, write(t, tb, esegen.Options{State: 2}))
	if !noteMentions(cov, "not cleanly shut down") || ev[0].Extra["database_state"] != "dirty shutdown" {
		t.Errorf("dirty: notes=%v state=%q", cov.Notes, ev[0].Extra["database_state"])
	}
	_, _, cov = parse(t, write(t, tb, esegen.Options{}))
	if noteMentions(cov, "not cleanly shut down") {
		t.Errorf("a clean database must not claim otherwise: %v", cov.Notes)
	}
}

func TestParse_TablesItDoesNotInterpretAreNamedAndCounted(t *testing.T) {
	other := esegen.Table{Name: guidTimeln, Columns: common(), Records: []esegen.Record{
		{Fixed: map[uint32][]byte{1: i32(1), 2: ole(t0), 3: i32(1), 4: i32(5)}}, {Fixed: map[uint32][]byte{1: i32(2), 2: ole(t0), 3: i32(1), 4: i32(5)}}}}
	ev, _, cov := parse(t, write(t, []esegen.Table{standardIDs(), other}, esegen.Options{}))
	if len(ev) != 0 {
		t.Errorf("events = %d, a table with no known layout must not be guessed at", len(ev))
	}
	if !noteMentions(cov, guidTimeln) || !noteMentions(cov, "2 records") || cov.Unmapped != 2 {
		t.Errorf("notes=%v unmapped=%d", cov.Notes, cov.Unmapped)
	}
}

func TestParse_RefusesWhatIsNotSRUM(t *testing.T) {
	cases := map[string][]esegen.Table{
		"an ESE database with no id map": {appTable(appRow(1, ole(t0), 1, 5, 1, 1, 1, 1, 1))},
	}
	for name, tb := range cases {
		if _, err := (Parser{}).Parse(write(t, tb, esegen.Options{})); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	junk := filepath.Join(t.TempDir(), "SRUDB.dat")
	os.WriteFile(junk, []byte(strings.Repeat("not a database ", 1000)), 0o600)
	if _, err := (Parser{}).Parse(junk); err == nil {
		t.Errorf("a file that is not ESE was accepted")
	}
}

func TestParse_HostileIdBlobsAreShownAsStoredNotInvented(t *testing.T) {
	ids := idMapTable(
		idRow(3, 1, []byte{1, 9, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0}), // says 9 sub-authorities, holds 1
		idRow(3, 2, []byte{2}),           // wrong revision and far too short
		idRow(0, 3, []byte{'a', 0, 'b'}), // odd length
		idRow(0, 4, nil),                 // no blob at all
		idRow(9, 5, []byte{1, 2, 3}),     // a type nobody documents
	)
	ev, _, _ := parse(t, write(t, []esegen.Table{ids, appTable(
		appRow(1, ole(t0), 3, 1, 1, 1, 1, 1, 1), appRow(2, ole(t0), 4, 2, 1, 1, 1, 1, 1), appRow(3, ole(t0), 5, 1, 1, 1, 1, 1, 1),
	)}, esegen.Options{}))
	if len(ev) != 3 {
		t.Fatalf("events = %d", len(ev))
	}
	if ev[0].User != "" || !strings.HasPrefix(ev[0].Extra["user_raw"], "invalid-sid:") {
		t.Errorf("a malformed SID must not become a user: user=%q raw=%q", ev[0].User, ev[0].Extra["user_raw"])
	}
	if ev[0].Extra["app_id_raw"] != "610062" {
		t.Errorf("odd-length text should be kept as hex, got %q", ev[0].Extra["app_id_raw"])
	}
	if ev[1].Extra["app_resolved"] != "false" {
		t.Errorf("an empty blob names nothing: %+v", ev[1].Extra)
	}
	if ev[2].Extra["app_id_type"] != "unknown(9)" || ev[2].Extra["app"] != "" {
		t.Errorf("an undocumented id type must not be read as text: %+v", ev[2].Extra)
	}
}

func TestParse_OnlyATypeThreeEntryWithAWellFormedSIDIsAUser(t *testing.T) {
	wrongRev := sid(21, 1, 2, 3, 4)
	wrongRev[0] = 2
	ids := idMapTable(
		idRow(0, 1, sid(21, 1, 2, 3, 4)), // a path-type entry whose bytes happen to be a SID
		idRow(3, 2, wrongRev),            // right type and length, wrong revision
		idRow(3, 3, sid(21, 1, 2, 3, 4)),
		idRow(0, 4, utf16z(`\device\harddiskvolume3\x.exe`)),
	)
	ev, _, _ := parse(t, write(t, []esegen.Table{ids, appTable(
		appRow(1, ole(t0), 4, 1, 1, 1, 1, 1, 1), appRow(2, ole(t0), 4, 2, 1, 1, 1, 1, 1), appRow(3, ole(t0), 4, 3, 1, 1, 1, 1, 1),
	)}, esegen.Options{}))
	if ev[0].User != "" || ev[0].Extra["user_resolved"] != "false" || ev[0].Extra["user_raw"] == "" {
		t.Errorf("a path-type entry is not a user: user=%q %+v", ev[0].User, ev[0].Extra)
	}
	if ev[1].User != "" || !strings.HasPrefix(ev[1].Extra["user_raw"], "invalid-sid:") {
		t.Errorf("a SID with revision 2 is not read: user=%q %+v", ev[1].User, ev[1].Extra)
	}
	if ev[2].User != "S-1-5-21-1-2-3-4" {
		t.Errorf("the good SID: %q", ev[2].User)
	}
}
