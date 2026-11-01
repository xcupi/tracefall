package srum

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"tracefall/internal/ese/esegen"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const guidSDPNet = "{EEE2F477-0659-5C47-EF03-6D6BEFD441B3}"

func sdpNetCols() []esegen.Column {
	return append(common(), col(5, "BytesInBound", esegen.Int64), col(6, "BytesOutBound", esegen.Int64), col(7, "BytesTotal", esegen.Int64))
}

func sdpNetRow(id int, ts []byte, app, user int, in, out, total int64) esegen.Record {
	return esegen.Record{Fixed: map[uint32][]byte{1: i32(id), 2: ts, 3: i32(app), 4: i32(user), 5: i64(in), 6: i64(out), 7: i64(total)}}
}

func sdpNetTable(rows ...esegen.Record) esegen.Table {
	return esegen.Table{Name: guidSDPNet, Columns: sdpNetCols(), Records: rows}
}

// sdpIDs holds ids of the type the SDP tables use for their object (type 4,
// which no cited source documents), a path-type id and a SID.
func sdpIDs() esegen.Table {
	return idMapTable(
		idRow(4, 1, utf16z("nic-a")),
		idRow(0, 2, utf16z(`\device\harddiskvolume3\windows\system32\svchost.exe`)),
		idRow(3, 5, sid(21, 111, 222, 333, 1001)),
	)
}

func TestParse_SDPNetworkTableIsInterpretedAsIntervalCounters(t *testing.T) {
	p := write(t, []esegen.Table{sdpIDs(), sdpNetTable(
		sdpNetRow(1, ole(t0), 1, 5, 1000, 250, 1250),
		sdpNetRow(2, ole(t0.Add(time.Hour)), 99, 98, 7, 8, 15),
	)}, esegen.Options{})
	ev, raw, cov := parse(t, p)
	if len(ev) != 2 {
		t.Fatalf("events = %d, want 2", len(ev))
	}
	e := ev[0]
	if e.EventType != model.EventSRUMSDPNetwork || e.ArtifactType != model.ArtifactSRUM || e.Parser != parserName {
		t.Errorf("type=%s artifact=%s parser=%s", e.EventType, e.ArtifactType, e.Parser)
	}
	if !e.Timestamp.Equal(t0) {
		t.Errorf("timestamp = %v, want %v", e.Timestamp, t0)
	}
	for k, v := range map[string]string{"bytes_in_bound": "1000", "bytes_out_bound": "250", "bytes_total": "1250", "srum_table": guidSDPNet, "sdp_object": "nic-a", "sdp_object_resolved": "true", "app_id": "1"} {
		if e.Extra[k] != v {
			t.Errorf("Extra[%s] = %q, want %q", k, e.Extra[k], v)
		}
	}
	// The object is not a process: it must never become one.
	if e.ProcessName != "" || e.ProcessPath != "" {
		t.Errorf("an SDP object became a process: %q %q", e.ProcessName, e.ProcessPath)
	}
	if e.User != "S-1-5-21-111-222-333-1001" {
		t.Errorf("user = %q", e.User)
	}
	u := ev[1]
	if u.Extra["sdp_object_resolved"] != "false" || u.Extra["sdp_object"] != "" || u.Extra["app_id"] != "99" || u.User != "" {
		t.Errorf("an id the map does not hold must stay a number: %+v", u.Extra)
	}
	if raw[0].SourceReference != e.SourceReference || !strings.Contains(raw[0].Raw, "BytesInBound=") || !strings.Contains(raw[0].Raw, "BytesOutBound=") || !strings.Contains(raw[0].Raw, "BytesTotal=") {
		t.Errorf("raw cells are not kept: %q", raw[0].Raw)
	}
	if cov.Mapped != 2 || cov.RecordsRead != 2 || cov.Unmapped != 0 {
		t.Errorf("coverage = %+v", cov)
	}
}

func TestParse_SDPNetworkPathTypeIdIsNeverAProcess(t *testing.T) {
	p := write(t, []esegen.Table{sdpIDs(), sdpNetTable(sdpNetRow(1, ole(t0), 2, 5, 1, 2, 3))}, esegen.Options{})
	ev, _, _ := parse(t, p)
	if len(ev) != 1 {
		t.Fatalf("events = %d, want 1", len(ev))
	}
	if ev[0].ProcessName != "" || ev[0].ProcessPath != "" {
		t.Errorf("an SDP row must not name a process: %q %q", ev[0].ProcessName, ev[0].ProcessPath)
	}
	if ev[0].Extra["sdp_object"] == "" {
		t.Errorf("the stored text must still be shown as written: %+v", ev[0].Extra)
	}
}

func TestParse_SDPNetworkOutOfRangeTimeStaysUndatedWithRawBytes(t *testing.T) {
	zero := esegen.Le64(0)
	nan := esegen.Le64(math.Float64bits(math.NaN()))
	ancient := ole(time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC))
	future := ole(time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC))
	p := write(t, []esegen.Table{sdpIDs(), sdpNetTable(
		sdpNetRow(1, ole(t0), 1, 5, 1, 1, 2), sdpNetRow(2, zero, 1, 5, 1, 1, 2), sdpNetRow(3, nan, 1, 5, 1, 1, 2),
		sdpNetRow(4, ancient, 1, 5, 1, 1, 2), sdpNetRow(5, future, 1, 5, 1, 1, 2),
	)}, esegen.Options{})
	ev, raw, cov := parse(t, p)
	if len(ev) != 5 {
		t.Fatalf("an undated row is still evidence: events = %d", len(ev))
	}
	want := map[int][]byte{1: zero, 2: nan, 3: ancient, 4: future}
	for i, b := range want {
		if !ev[i].Timestamp.IsZero() {
			t.Errorf("event %d was given the time %v", i, ev[i].Timestamp)
		}
		if ev[i].Extra["timestamp_raw"] != hexOf(b) {
			t.Errorf("event %d raw time = %q, want %q", i, ev[i].Extra["timestamp_raw"], hexOf(b))
		}
		if !strings.Contains(raw[i].Raw, "TimeStamp="+hexOf(b)) {
			t.Errorf("event %d raw evidence lost the stored bytes: %q", i, raw[i].Raw)
		}
	}
	if cov.Undated != 4 {
		t.Errorf("Undated = %d, want 4", cov.Undated)
	}
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}

func TestParse_SDPNetworkDeletedRecordsAreNotEmittedAndAreCensused(t *testing.T) {
	gone := sdpNetRow(2, ole(t0), 1, 5, 9, 9, 18)
	gone.Defunct = true
	p := write(t, []esegen.Table{sdpIDs(), sdpNetTable(sdpNetRow(1, ole(t0), 1, 5, 1, 1, 2), gone)}, esegen.Options{})
	ev, _, cov := parse(t, p)
	if len(ev) != 1 {
		t.Fatalf("events = %d, a deleted record is not a live one", len(ev))
	}
	row := tableRow(t, cov, guidSDPNet)
	if row.Rows != 1 || row.Deleted != 1 || !row.Interpreted || row.Event != model.EventSRUMSDPNetwork {
		t.Errorf("census row = %+v", row)
	}
}

func tableRow(t *testing.T, c *model.ParseCoverage, name string) model.CoverageTable {
	t.Helper()
	for _, r := range c.Tables {
		if r.Table == name {
			return r
		}
	}
	t.Fatalf("table %s is not in the census %+v", name, c.Tables)
	return model.CoverageTable{}
}

func TestParse_SDPNetworkWithAnotherSchemaStaysCountedNotInterpreted(t *testing.T) {
	// BytesTotal declared as 32-bit: not the documented layout, so no row of the
	// table may be read as if it were.
	cols := append(common(), col(5, "BytesInBound", esegen.Int64), col(6, "BytesOutBound", esegen.Int64), col(7, "BytesTotal", esegen.Int32))
	tb := esegen.Table{Name: guidSDPNet, Columns: cols, Records: []esegen.Record{
		{Fixed: map[uint32][]byte{1: i32(1), 2: ole(t0), 3: i32(1), 4: i32(5), 5: i64(1), 6: i64(2), 7: i32(3)}}}}
	ev, _, cov := parse(t, write(t, []esegen.Table{sdpIDs(), tb}, esegen.Options{}))
	if len(ev) != 0 {
		t.Fatalf("a table with another layout was interpreted: %d events", len(ev))
	}
	row := tableRow(t, cov, guidSDPNet)
	if row.Interpreted || row.Rows != 1 || cov.Unmapped != 1 {
		t.Errorf("census row = %+v unmapped=%d", row, cov.Unmapped)
	}
	if !noteMentions(cov, guidSDPNet) || !noteMentions(cov, "layout") {
		t.Errorf("the mismatch is not said: %v", cov.Notes)
	}
	// A missing column is the same.
	tb = esegen.Table{Name: guidSDPNet, Columns: append(common(), col(5, "BytesInBound", esegen.Int64), col(6, "BytesOutBound", esegen.Int64)),
		Records: []esegen.Record{{Fixed: map[uint32][]byte{1: i32(1), 2: ole(t0), 3: i32(1), 4: i32(5), 5: i64(1), 6: i64(2)}}}}
	ev, _, cov = parse(t, write(t, []esegen.Table{sdpIDs(), tb}, esegen.Options{}))
	if len(ev) != 0 || tableRow(t, cov, guidSDPNet).Interpreted {
		t.Errorf("a table missing a documented column was interpreted: %d events", len(ev))
	}
}

func TestParse_CoverageCensusListsEveryProviderTable(t *testing.T) {
	timeline := esegen.Table{Name: guidTimeln, Columns: common(), Records: []esegen.Record{
		{Fixed: map[uint32][]byte{1: i32(1), 2: ole(t0), 3: i32(1), 4: i32(5)}}, {Fixed: map[uint32][]byte{1: i32(2), 2: ole(t0), 3: i32(1), 4: i32(5)}}}}
	empty := esegen.Table{Name: "{17F4D97B-F26A-5E79-3A82-90040A47D13D}", Columns: common()}
	p := write(t, []esegen.Table{sdpIDs(), appTable(appRow(1, ole(t0), 2, 5, 1, 1, 1, 1, 1)), sdpNetTable(sdpNetRow(1, ole(t0), 1, 5, 1, 1, 2)), timeline, empty}, esegen.Options{State: 2})
	_, _, cov := parse(t, p)
	if len(cov.Tables) != 4 {
		t.Fatalf("census = %+v, want 4 provider tables", cov.Tables)
	}
	if r := tableRow(t, cov, guidApp); !r.Interpreted || r.Rows != 1 || r.Event != model.EventSRUMAppUsage {
		t.Errorf("app row %+v", r)
	}
	if r := tableRow(t, cov, guidTimeln); r.Interpreted || r.Rows != 2 || r.Event != "" {
		t.Errorf("timeline row %+v", r)
	}
	if r := tableRow(t, cov, "{17F4D97B-F26A-5E79-3A82-90040A47D13D}"); r.Interpreted || r.Rows != 0 {
		t.Errorf("empty table row %+v: an empty table is listed, not hidden", r)
	}
	if cov.CleanShutdown == nil || *cov.CleanShutdown || cov.DatabaseState != "dirty shutdown" {
		t.Errorf("state: %q %v", cov.DatabaseState, cov.CleanShutdown)
	}
	_, _, cov = parse(t, write(t, []esegen.Table{sdpIDs(), appTable()}, esegen.Options{}))
	if cov.CleanShutdown == nil || !*cov.CleanShutdown || cov.DatabaseState != "clean shutdown" {
		t.Errorf("clean state: %q %v", cov.DatabaseState, cov.CleanShutdown)
	}
	// 4 tables, 2 interpreted, 2 rows not interpreted.
	_, _, cov = parse(t, p)
	if got, want := cov.TableSummary(), "4 tables, 2 interpreted, 2 rows not interpreted"; got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
}

func TestParse_CoverageCensusIsBoundedAndSaysSo(t *testing.T) {
	tbs := []esegen.Table{sdpIDs()}
	for i := 0; i < maxCensusTables+3; i++ {
		tbs = append(tbs, esegen.Table{Name: "{00000000-0000-0000-0000-" + pad12(i) + "}", Columns: common(), Records: []esegen.Record{{Fixed: map[uint32][]byte{1: i32(1), 2: ole(t0), 3: i32(1), 4: i32(5)}}}})
	}
	_, _, cov := parse(t, write(t, tbs, esegen.Options{}))
	if len(cov.Tables) != maxCensusTables || cov.TablesUnlisted != 3 {
		t.Fatalf("listed %d unlisted %d", len(cov.Tables), cov.TablesUnlisted)
	}
	if !strings.Contains(cov.TableSummary(), "3 more tables not listed") || !strings.HasPrefix(cov.TableSummary(), "67 tables") {
		t.Errorf("summary = %q", cov.TableSummary())
	}
}

func pad12(i int) string { return fmt.Sprintf("%012d", i) }

func TestParse_CoverageSummaryIsEmptyWithoutACensus(t *testing.T) {
	if s := (&model.ParseCoverage{RecordsRead: 3, Mapped: 3}).TableSummary(); s != "" {
		t.Errorf("a source with no census must not claim one: %q", s)
	}
}

func TestStreamAndBatchAgreeOnSDPAndCensus(t *testing.T) {
	rows := make([]esegen.Record, 300)
	for i := range rows {
		rows[i] = sdpNetRow(i+1, ole(t0.Add(time.Duration(i)*time.Minute)), 1, 5, int64(i), int64(2*i), int64(3*i))
	}
	gone := sdpNetRow(1000, ole(t0), 1, 5, 1, 1, 2)
	gone.Defunct = true
	rows = append(rows, gone)
	tb := sdpNetTable(rows...)
	tb.LeafCapacity = 16
	path := write(t, []esegen.Table{sdpIDs(), appTable(appRow(1, ole(t0), 2, 5, 1, 1, 1, 1, 1)), tb}, esegen.Options{})
	legacy, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	var got parsers.ParseResult
	cov, err := New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(b parsers.ParseResult) error {
		got.Events = append(got.Events, b.Events...)
		got.Raw = append(got.Raw, b.Raw...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Events, legacy.Events) || !reflect.DeepEqual(got.Raw, legacy.Raw) {
		t.Fatal("stream and batch events differ")
	}
	if !reflect.DeepEqual(cov.Tables, legacy.Coverage.Tables) || cov.DatabaseState != legacy.Coverage.DatabaseState || len(cov.Tables) != 2 {
		t.Errorf("census differs: stream %+v batch %+v", cov.Tables, legacy.Coverage.Tables)
	}
	if r := tableRow(t, cov, guidSDPNet); r.Rows != 300 || r.Deleted != 1 {
		t.Errorf("stream census row = %+v", r)
	}
}

// bannedClaims are words that would turn an interval counter into a conclusion
// about a transfer: where it went, who received it, what it contained.
var bannedClaims = []string{"exfil", "upload", "uploaded", "transferred to", "sent to", "destination", "remote host", "remote party", "stolen", "leak"}

func TestParse_NetworkEventsStateWhatTheCountersAreAndAreNot(t *testing.T) {
	conn := esegen.Table{Name: guidNetConn, Columns: append(common(), col(5, "InterfaceLuid", esegen.Int64), col(6, "L2ProfileId", esegen.Int32),
		col(7, "ConnectedTime", esegen.Int32), col(8, "ConnectStartTime", esegen.Int64), col(9, "L2ProfileFlags", esegen.Int32)),
		Records: []esegen.Record{{Fixed: map[uint32][]byte{1: i32(1), 2: ole(t0), 3: i32(1), 4: i32(5), 5: i64(int64(71) << 48), 6: i32(7), 7: i32(5400), 8: filetime(t0), 9: i32(0)}}}}
	ev, _, _ := parse(t, write(t, []esegen.Table{sdpIDs(), netUseTable(netUseRow(1, ole(t0), 1, 5, int64(6)<<48, 10, 20)), conn,
		sdpNetTable(sdpNetRow(1, ole(t0), 1, 5, 1, 2, 3))}, esegen.Options{}))
	if len(ev) != 3 {
		t.Fatalf("events = %d, want 3", len(ev))
	}
	for _, e := range ev {
		m, l := e.Extra["evidence_meaning"], e.Extra["limitations"]
		if m == "" || l == "" {
			t.Errorf("%s: evidence_meaning=%q limitations=%q", e.EventType, m, l)
			continue
		}
		for _, w := range []string{"interval", "not a flow"} {
			if !strings.Contains(strings.ToLower(m+" "+l), w) {
				t.Errorf("%s: wording lacks %q: %q / %q", e.EventType, w, m, l)
			}
		}
		for _, w := range []string{"destination", "protocol", "content"} {
			if !strings.Contains(strings.ToLower(l), w) {
				t.Errorf("%s: limitations do not rule out %q: %q", e.EventType, w, l)
			}
		}
		// The words may only appear to deny the claim; never as a bare statement.
		for _, w := range []string{"exfil", "upload", "stolen", "leak"} {
			if strings.Contains(strings.ToLower(m), w) {
				t.Errorf("%s: meaning uses %q: %q", e.EventType, w, m)
			}
		}
	}
}

func TestParse_EveryEventStatesItsTimeBasisAndThatItIsNotCalibrated(t *testing.T) {
	ev, _, _ := parse(t, write(t, []esegen.Table{sdpIDs(), appTable(appRow(1, ole(t0), 2, 5, 1, 1, 1, 1, 1)),
		sdpNetTable(sdpNetRow(1, ole(t0), 1, 5, 1, 2, 3))}, esegen.Options{}))
	if len(ev) != 2 {
		t.Fatalf("events = %d", len(ev))
	}
	for _, e := range ev {
		b := strings.ToLower(e.Extra["time_basis"])
		for _, w := range []string{"end of", "interval", "ole automation", "not been calibrated"} {
			if !strings.Contains(b, w) {
				t.Errorf("%s: time_basis lacks %q: %q", e.EventType, w, e.Extra["time_basis"])
			}
		}
	}
}

func TestParse_SDPNetworkSaysBytesTotalIsNotTheSumOfTheOtherTwo(t *testing.T) {
	// 1000 in + 250 out stored with a total of 900: the three counters are shown
	// as stored and the event never adds them or claims the total is their sum.
	ev, _, _ := parse(t, write(t, []esegen.Table{sdpIDs(), sdpNetTable(sdpNetRow(1, ole(t0), 1, 5, 1000, 250, 900))}, esegen.Options{}))
	if len(ev) != 1 || ev[0].Extra["bytes_total"] != "900" {
		t.Fatalf("events=%d extra=%+v", len(ev), ev)
	}
	l := ev[0].Extra["limitations"]
	if !strings.Contains(l, "BytesTotal") || !strings.Contains(l, "not the sum") {
		t.Errorf("the total's status is not said: %q", l)
	}
	for k := range ev[0].Extra {
		if k == "bytes_sum" || k == "bytes_combined" {
			t.Errorf("a derived total %q was invented", k)
		}
	}
}
