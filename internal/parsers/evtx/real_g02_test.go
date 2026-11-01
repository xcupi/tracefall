package evtx_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	nativeevtx "tracefall/internal/evtx"
	"tracefall/internal/parsers"
	parser "tracefall/internal/parsers/evtx"
)

// TestRealG02Coverage runs a directory of real native logs through the real
// reader and Normalize and compares the result with an independent decoder's
// census (python-evtx). It prints COUNTS and FIELD NAMES only, never values.
//
//	TRACEFALL_REAL_EVTX_DIR   directory holding the .evtx files (read-only)
//	TRACEFALL_REAL_PY_CENSUS  JSON {"census": {"file|provider|channel|id": n}}
//	TRACEFALL_REAL_PY_SAMPLES JSON {"file|provider|channel|id": [{"system":{"record_id":n},"data":[[name,value]...]}]}
//	TRACEFALL_REAL_IDS        comma list of event IDs to report per-ID (optional)
func TestRealG02Coverage(t *testing.T) {
	dir := os.Getenv("TRACEFALL_REAL_EVTX_DIR")
	if dir == "" {
		t.Skip("TRACEFALL_REAL_EVTX_DIR not set")
	}
	type kind struct {
		provider, channel string
		id                int
	}
	type tally struct{ records, mapped int }
	goTally := map[kind]*tally{}
	// Presence of each normalized field on the events actually produced.
	presence := map[string]map[string]int{}
	produced := map[string]int{}
	var read, mapped, unmapped, failed int
	files, _ := filepath.Glob(filepath.Join(dir, "*.evtx"))
	sort.Strings(files)
	for _, f := range files {
		cov, err := parser.New().ParseStream(context.Background(), f, parsers.ParseContext{}, func(r parsers.ParseResult) error {
			for _, e := range r.Events {
				label := fmt.Sprintf("%s/%d", e.EventType, e.EventID)
				produced[label]++
				if presence[label] == nil {
					presence[label] = map[string]int{}
				}
				for name, v := range map[string]string{"@user": e.User, "@network_source": e.NetworkSource, "@process_name": e.ProcessName, "@process_path": e.ProcessPath, "@command_line": e.CommandLine} {
					if v != "" {
						presence[label][name]++
					}
				}
				if e.PID != 0 {
					presence[label]["@pid"]++
				}
				if e.Timestamp.IsZero() {
					presence[label]["@undated"]++
				}
				for k := range e.Extra {
					if !strings.HasPrefix(k, "evtx_") {
						presence[label][k]++
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(f), err)
		}
		read += cov.RecordsRead
		mapped += cov.Mapped
		unmapped += cov.Unmapped
		failed += cov.RecordsFailed
		if cov.UnlistedRecords != 0 {
			t.Errorf("%s: %d records fell outside the per-kind census", filepath.Base(f), cov.UnlistedRecords)
		}
		for _, row := range cov.ByEvent {
			k := kind{row.Provider, row.Channel, row.EventID}
			if goTally[k] == nil {
				goTally[k] = &tally{}
			}
			goTally[k].records += row.Records
			goTally[k].mapped += row.Mapped
		}
	}
	fmt.Printf("TOTALS records_read=%d mapped=%d unmapped=%d records_failed=%d files=%d\n", read, mapped, unmapped, failed, len(files))

	pl := make([]string, 0, len(produced))
	for l := range produced {
		pl = append(pl, l)
	}
	sort.Strings(pl)
	if os.Getenv("TRACEFALL_REAL_PRESENCE") != "" {
		for _, l := range pl {
			if !strings.Contains(os.Getenv("TRACEFALL_REAL_PRESENCE"), strings.SplitN(l, "/", 2)[0]) {
				continue
			}
			ks := make([]string, 0, len(presence[l]))
			for k := range presence[l] {
				ks = append(ks, k)
			}
			sort.Strings(ks)
			var sb strings.Builder
			for _, k := range ks {
				fmt.Fprintf(&sb, " %s=%d", k, presence[l][k])
			}
			fmt.Printf("PRESENCE %s events=%d:%s\n", l, produced[l], sb.String())
		}
	}

	// Independent census, aggregated to (provider, channel, id).
	pyTally := map[kind]int{}
	if p := os.Getenv("TRACEFALL_REAL_PY_CENSUS"); p != "" {
		var doc struct {
			Census map[string]int `json:"census"`
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		pyTotal := 0
		for key, n := range doc.Census {
			parts := strings.Split(key, "|")
			var id int
			fmt.Sscan(parts[3], &id)
			pyTally[kind{parts[1], parts[2], id}] += n
			pyTotal += n
		}
		diff := 0
		for k, g := range goTally {
			if pyTally[k] != g.records {
				diff++
				fmt.Printf("CENSUS-MISMATCH %q %q %d go=%d py=%d\n", k.provider, k.channel, k.id, g.records, pyTally[k])
			}
		}
		for k, n := range pyTally {
			if goTally[k] == nil {
				diff++
				fmt.Printf("CENSUS-MISSING-IN-GO %q %q %d py=%d\n", k.provider, k.channel, k.id, n)
			}
		}
		fmt.Printf("CENSUS-COMPARE go_total=%d py_total=%d kinds=%d kind_mismatches=%d\n", read, pyTotal, len(goTally), diff)
	}

	// Per-ID report for the requested IDs.
	want := map[int]bool{}
	for _, s := range strings.Split(os.Getenv("TRACEFALL_REAL_IDS"), ",") {
		var id int
		if _, err := fmt.Sscan(s, &id); err == nil {
			want[id] = true
		}
	}
	keys := make([]kind, 0, len(goTally))
	for k := range goTally {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].channel != keys[j].channel {
			return keys[i].channel < keys[j].channel
		}
		return keys[i].id < keys[j].id
	})
	for _, k := range keys {
		if want[k.id] {
			g := goTally[k]
			fmt.Printf("ID %q %q %d records=%d mapped=%d unmapped=%d py_records=%d\n", k.provider, k.channel, k.id, g.records, g.mapped, g.records-g.mapped, pyTally[k])
		}
	}
	// Top still-unmapped kinds.
	sort.Slice(keys, func(i, j int) bool {
		a, b := goTally[keys[i]], goTally[keys[j]]
		if a.records-a.mapped != b.records-b.mapped {
			return a.records-a.mapped > b.records-b.mapped
		}
		return keys[i].id < keys[j].id
	})
	for i, k := range keys {
		g := goTally[k]
		if i >= 15 || g.records-g.mapped == 0 {
			break
		}
		fmt.Printf("TOP-UNMAPPED %2d %q %q %d unmapped=%d of %d\n", i+1, k.provider, k.channel, k.id, g.records-g.mapped, g.records)
	}

	// Field-by-field comparison with the independent decoder's sampled records.
	sp := os.Getenv("TRACEFALL_REAL_PY_SAMPLES")
	if sp == "" {
		return
	}
	var samples map[string][]struct {
		System struct {
			RecordID uint64 `json:"record_id"`
		} `json:"system"`
		Data [][2]string `json:"data"`
	}
	b, err := os.ReadFile(sp)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &samples); err != nil {
		t.Fatal(err)
	}
	type cmp struct {
		records, match, mismatch, goOnly, unnamed int
		cats                                      map[string]int
	}
	res := map[string]*cmp{}
	mismatchNames := map[string]map[string]int{}
	for _, f := range files {
		base := filepath.Base(f)
		wantRec := map[uint64]string{}
		for key, recs := range samples {
			if strings.HasPrefix(key, base+"|") {
				for _, r := range recs {
					wantRec[r.System.RecordID] = key
				}
			}
		}
		if len(wantRec) == 0 {
			continue
		}
		fh, err := nativeevtx.Open(f, nativeevtx.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		_, err = fh.Walk(func(rec nativeevtx.Record) error {
			key, ok := wantRec[rec.System.EventRecordID]
			if !ok {
				return nil
			}
			var py [][2]string
			for _, r := range samples[key] {
				if r.System.RecordID == rec.System.EventRecordID {
					py = r.Data
				}
			}
			c := res[key]
			if c == nil {
				c = &cmp{cats: map[string]int{}}
				res[key] = c
				mismatchNames[key] = map[string]int{}
			}
			c.records++
			seen := map[string]bool{}
			for _, kv := range py {
				name, pv := kv[0], strings.TrimSpace(kv[1])
				if name == "" {
					c.unnamed++
					continue
				}
				seen[name] = true
				gv, present := rec.Data[name]
				cat, ok := "", false
				if present {
					cat, ok = sameValue(gv, pv)
				}
				if ok {
					c.match++
					c.cats[cat]++
				} else {
					c.mismatch++
					if cat == "" {
						cat = "other"
					}
					c.cats["MISMATCH:"+cat]++
					mismatchNames[key][name]++
				}
			}
			for name := range rec.Data {
				if !seen[name] && !strings.HasPrefix(name, "Data") {
					c.goOnly++
				}
			}
			return nil
		})
		fh.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	names := make([]string, 0, len(res))
	for k := range res {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, key := range names {
		c := res[key]
		parts := strings.Split(key, "|")
		fmt.Printf("FIELDS %q id=%s sampled_records=%d fields_match=%d fields_mismatch=%d go_only_names=%d unnamed_skipped=%d match_kinds=%v mismatch_field_names=%v\n",
			parts[1], parts[3], c.records, c.match, c.mismatch, c.goOnly, c.unnamed, c.cats, mismatchNames[key])
	}
}

// sameValue decides whether the reader's rendering of a Data value and the
// independent decoder's rendering are the same recorded value, and says how:
// byte-identical, a number rendered with different hex padding, binary rendered
// in base64 vs hex, a GUID differing only in letter case, or text that differs
// only in whitespace layout. Anything else is a mismatch.
func sameValue(gv, pv string) (string, bool) {
	if gv == pv {
		return "exact", true
	}
	if strings.HasPrefix(strings.ToLower(gv), "0x") && strings.HasPrefix(strings.ToLower(pv), "0x") {
		a, e1 := strconv.ParseUint(gv[2:], 16, 64)
		b, e2 := strconv.ParseUint(pv[2:], 16, 64)
		if e1 == nil && e2 == nil && a == b {
			return "hex_padding", true
		}
	}
	if raw, err := base64.StdEncoding.DecodeString(pv); err == nil && len(raw) > 0 && strings.EqualFold(hex.EncodeToString(raw), gv) {
		return "binary_b64_vs_hex", true
	}
	if strings.EqualFold(gv, pv) {
		return "case_only", true
	}
	if strings.Join(strings.Fields(gv), " ") == strings.Join(strings.Fields(pv), " ") {
		return "whitespace_layout", true
	}
	if sg, sp := guidBytes(gv), guidBytes(pv); sg != nil && sp != nil {
		swapped := append([]byte{}, sp...)
		for _, r := range [][2]int{{0, 4}, {4, 6}, {6, 8}} {
			for i, j := r[0], r[1]-1; i < j; i, j = i+1, j-1 {
				swapped[i], swapped[j] = swapped[j], swapped[i]
			}
		}
		if string(swapped) == string(sg) {
			return "guid_byte_order_differs", false
		}
	}
	return "", false
}

func guidBytes(s string) []byte {
	s = strings.Trim(strings.TrimSpace(s), "{}")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}
