package srum

import (
	"encoding/json"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// TestParse_RealSRUDBAgainstSecondDecoder compares this parser's decode of any
// SRUDB.dat with a dump made by an independent decoder (dissect.esedb, via
// tools/oracle.py kept with the verification notes). Set TRACEFALL_SRUM_DB to the
// database and TRACEFALL_SRUM_ORACLE to the dump. Nothing about the database is
// pinned: the rule is general. Only counts of matches and mismatches are
// logged, never values.
func TestParse_RealSRUDBAgainstSecondDecoder(t *testing.T) {
	dbPath, oraclePath := os.Getenv("TRACEFALL_SRUM_DB"), os.Getenv("TRACEFALL_SRUM_ORACLE")
	if dbPath == "" || oraclePath == "" {
		t.Skip("TRACEFALL_SRUM_DB and TRACEFALL_SRUM_ORACLE not set")
	}
	raw, err := os.ReadFile(oraclePath)
	if err != nil {
		t.Skipf("oracle not present: %v", err)
	}
	type orow struct {
		ID      int64             `json:"id"`
		App     *int64            `json:"app"`
		User    *int64            `json:"user"`
		TsMs    *int64            `json:"ts_ms"`
		Cols    map[string]*int64 `json:"cols"`
		AppType *int64            `json:"app_type"`
		AppText *string           `json:"app_text"`
		UserSID *string           `json:"user_sid"`
	}
	var oracle struct {
		Tables map[string]struct {
			Kind    string            `json:"kind"`
			Rows    int               `json:"rows"`
			Sums    map[string]string `json:"sums"`
			MinMs   *int64            `json:"min_ms"`
			MaxMs   *int64            `json:"max_ms"`
			Undated int               `json:"undated"`
		} `json:"tables"`
		AllTables map[string]int    `json:"all_tables"`
		Sample    map[string][]orow `json:"sample"`
	}
	if err := json.Unmarshal(raw, &oracle); err != nil {
		t.Fatal(err)
	}
	res, err := Parser{}.Parse(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	// Which event column holds which database column.
	extraKey := map[string]map[string]string{
		"app": {}, "netuse": {"BytesSent": "bytes_sent", "BytesRecvd": "bytes_received", "L2ProfileId": "l2_profile_id", "L2ProfileFlags": "l2_profile_flags"},
		"netconn": {"ConnectedTime": "connected_seconds", "L2ProfileId": "l2_profile_id", "L2ProfileFlags": "l2_profile_flags"},
		"push":    {"NotificationType": "notification_type", "PayloadSize": "payload_size", "NetworkType": "network_type"},
		"sdpnet":  {"BytesInBound": "bytes_in_bound", "BytesOutBound": "bytes_out_bound", "BytesTotal": "bytes_total"},
	}
	for _, c := range []string{"ForegroundCycleTime", "BackgroundCycleTime", "FaceTime", "ForegroundContextSwitches", "BackgroundContextSwitches",
		"ForegroundBytesRead", "ForegroundBytesWritten", "ForegroundNumReadOperations", "ForegroundNumWriteOperations", "ForegroundNumberOfFlushes",
		"BackgroundBytesRead", "BackgroundBytesWritten", "BackgroundNumReadOperations", "BackgroundNumWriteOperations", "BackgroundNumberOfFlushes"} {
		extraKey["app"][c] = snake(c)
	}

	byTable := map[string][]model.Event{}
	for _, e := range res.Events {
		byTable[e.Extra["srum_table"]] = append(byTable[e.Extra["srum_table"]], e)
	}

	// Table census: every table the other decoder lists, with its row count.
	listed := map[string]model.CoverageTable{}
	for _, r := range res.Coverage.Tables {
		listed[r.Table] = r
	}
	provider := 0
	censusMismatch := 0
	for name, n := range oracle.AllTables {
		if !strings.HasPrefix(name, "{") {
			continue
		}
		provider++
		if r, ok := listed[name]; !ok || r.Rows != n {
			censusMismatch++
		}
	}
	if len(listed) != provider || censusMismatch != 0 {
		t.Errorf("census: %d tables here, %d in the other decoder, %d differences", len(listed), provider, censusMismatch)
	}
	t.Logf("census: %d provider tables, %d differences in table list or row count", provider, censusMismatch)
	t.Logf("database state %q; summary %q; unmapped %d of %d records read", res.Coverage.DatabaseState, res.Coverage.TableSummary(), res.Coverage.Unmapped, res.Coverage.RecordsRead)
	for _, r := range res.Coverage.Tables {
		t.Logf("census table %s rows=%d deleted=%d interpreted=%t event=%q", r.Table, r.Rows, r.Deleted, r.Interpreted, r.Event)
	}

	for name, ot := range oracle.Tables {
		evs := byTable[name]
		keys := extraKey[ot.Kind]
		bad := 0
		if len(evs) != ot.Rows {
			t.Errorf("%s: %d events, %d rows in the other decoder", ot.Kind, len(evs), ot.Rows)
			bad++
		}
		sums := map[string]*big.Int{}
		undated := 0
		var minT, maxT time.Time
		for _, e := range evs {
			for col, k := range keys {
				if v, ok := e.Extra[k]; ok {
					n, _ := new(big.Int).SetString(v, 10)
					if sums[col] == nil {
						sums[col] = new(big.Int)
					}
					sums[col].Add(sums[col], n)
				}
			}
			if e.Timestamp.IsZero() {
				undated++
				continue
			}
			if minT.IsZero() || e.Timestamp.Before(minT) {
				minT = e.Timestamp
			}
			if e.Timestamp.After(maxT) {
				maxT = e.Timestamp
			}
		}
		for col, k := range keys {
			_ = k
			want, _ := new(big.Int).SetString(ot.Sums[col], 10)
			got := sums[col]
			if got == nil {
				got = new(big.Int)
			}
			if got.Cmp(want) != 0 {
				t.Errorf("%s: sum of %s differs", ot.Kind, col)
				bad++
			}
		}
		if undated != ot.Undated {
			t.Errorf("%s: %d undated here, %d there", ot.Kind, undated, ot.Undated)
			bad++
		}
		if ot.MinMs != nil && (minT.UnixMilli() != *ot.MinMs || maxT.UnixMilli() != *ot.MaxMs) {
			t.Errorf("%s: min/max time differ", ot.Kind)
			bad++
		}

		byID := map[int64]model.Event{}
		for _, e := range evs {
			n, _ := strconv.ParseInt(e.Extra["srum_auto_inc_id"], 10, 64)
			byID[n] = e
		}
		match, mismatch := 0, 0
		for _, o := range oracle.Sample[name] {
			e, ok := byID[o.ID]
			good := ok
			if ok {
				if o.TsMs == nil {
					good = good && e.Timestamp.IsZero()
				} else {
					good = good && e.Timestamp.UnixMilli() == *o.TsMs
				}
				for col, k := range keys {
					if o.Cols[col] == nil {
						good = good && e.Extra[k] == ""
					} else {
						good = good && e.Extra[k] == strconv.FormatInt(*o.Cols[col], 10)
					}
				}
				if o.Cols["InterfaceLuid"] != nil {
					good = good && e.Extra["interface_luid"] == strconv.FormatUint(uint64(*o.Cols["InterfaceLuid"]), 10)
				}
				if o.Cols["ConnectStartTime"] != nil {
					v := *o.Cols["ConnectStartTime"]
					if s := e.Extra["connect_start"]; s != "" {
						pt, err := time.Parse(time.RFC3339Nano, s)
						good = good && err == nil && pt.UnixMilli() == (v-116444736000000000)/10000
					} else {
						good = good && e.Extra["connect_start_raw"] == strconv.FormatInt(v, 10)
					}
				}
				if o.App != nil {
					good = good && e.Extra["app_id"] == strconv.FormatInt(*o.App, 10)
				}
				if o.UserSID != nil {
					good = good && e.User == *o.UserSID
				} else {
					good = good && e.User == ""
				}
				if ot.Kind == "sdpnet" {
					if o.AppText != nil {
						good = good && e.Extra["sdp_object"] == *o.AppText
					} else {
						good = good && e.Extra["sdp_object"] == ""
					}
					good = good && e.ProcessName == "" && e.ProcessPath == ""
				}
			}
			if good {
				match++
			} else {
				mismatch++
			}
		}
		t.Logf("%s: rows %d/%d, sampled rows matching %d mismatching %d, aggregate differences %d", ot.Kind, len(evs), ot.Rows, match, mismatch, bad)
		if mismatch != 0 {
			t.Errorf("%s: %d sampled rows differ from the other decoder", ot.Kind, mismatch)
		}
		if len(oracle.Sample[name]) < 200 && len(oracle.Sample[name]) < ot.Rows {
			t.Errorf("%s: fewer than 200 sampled rows", ot.Kind)
		}
	}
}
