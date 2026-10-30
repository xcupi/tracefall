package defenderhistory

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"tracefall/internal/parsers"
)

func parseSyntheticHistory(t *testing.T, b []byte) parsers.ParseResult {
	t.Helper()
	p := filepath.Join(t.TempDir(), "neutral-history")
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := New().Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestHistoryParsedIdentity(t *testing.T) {
	for _, ticks := range []uint64{0, 133029417789094421} {
		a := fixture()
		r, err := Decode(a)
		if err != nil {
			t.Fatal(err)
		}
		binary.LittleEndian.PutUint64(a[r.Times[1].Offset+8:], ticks)
		original := parseSyntheticHistory(t, a).Events[0]
		distinct := append([]byte(nil), a...)
		distinct[r.Entries[1].Offset+8] ^= 0xff
		if original.ComputeDedupHash() == parseSyntheticHistory(t, distinct).Events[0].ComputeDedupHash() {
			t.Errorf("ticks=%d: distinct GUID collapsed", ticks)
		}
		changed := append([]byte(nil), a...)
		changed[r.Entries[0].Offset+8] ^= 1
		if original.ComputeDedupHash() == parseSyntheticHistory(t, changed).Events[0].ComputeDedupHash() {
			t.Errorf("ticks=%d: changed content of same detection collapsed", ticks)
		}
		again := parseSyntheticHistory(t, a).Events[0]
		again.CollectionID = "collection-b"
		again.SourceFileID = "source-b"
		if original.ComputeDedupHash() != again.ComputeDedupHash() {
			t.Errorf("ticks=%d: identical recollection split", ticks)
		}
	}
}

func TestHistoryTimestampSerializationBoundary(t *testing.T) {
	// Integer FILETIME boundary derived from the independently specified UTC calendar end.
	last := time.Date(9999, 12, 31, 23, 59, 59, 999999900, time.UTC)
	maxTicks := uint64(last.Unix()+11644473600)*10000000 + uint64(last.Nanosecond()/100)
	for _, ticks := range []uint64{0, 1, 133029417789094421, maxTicks, maxTicks + 1, ^uint64(0)} {
		t.Run(strconv.FormatUint(ticks, 10), func(t *testing.T) {
			b := fixture()
			r, err := Decode(b)
			if err != nil {
				t.Fatal(err)
			}
			offset := r.Times[1].Offset
			binary.LittleEndian.PutUint64(b[offset+8:], ticks)
			out := parseSyntheticHistory(t, b)
			e := out.Events[0]
			invalid := ticks > maxTicks
			undated := ticks == 0 || invalid
			if e.Timestamp.IsZero() != undated {
				t.Errorf("undated=%v, got %v", undated, e.Timestamp)
			}
			wantUndated := int64(0)
			if undated {
				wantUndated = 1
			}
			if int64(out.Coverage.Undated) != wantUndated {
				t.Errorf("undated count=%d want=%d", out.Coverage.Undated, wantUndated)
			}
			reason := "initial_detection_time outside supported FILETIME calendar 1601..9999; timestamp left undated; raw ticks retained"
			if invalid {
				if e.Extra["timestamp_normalization_note"] != reason {
					t.Errorf("missing exact reason: %v", e.Extra)
				}
				if len(out.Coverage.Notes) != 2 || out.Coverage.Notes[1] != reason {
					t.Errorf("coverage reason: %v", out.Coverage.Notes)
				}
			} else if e.Extra["timestamp_normalization_note"] != "" || len(out.Coverage.Notes) != 1 {
				t.Errorf("unexpected normalization note")
			}
			if !undated {
				want := time.Unix(int64(ticks/10000000)-11644473600, int64(ticks%10000000)*100).UTC()
				if !e.Timestamp.Equal(want) {
					t.Errorf("100ns precision lost: got=%v want=%v", e.Timestamp, want)
				}
			}
			if e.Extra["initial_detection_time_filetime"] != strconv.FormatUint(ticks, 10) {
				t.Error("original ticks lost")
			}
			if _, err := json.Marshal(e); err != nil {
				t.Errorf("event JSON: %v", err)
			}
			var raw struct {
				SourceBytes []byte
				Record      *Record
			}
			if err := json.Unmarshal([]byte(out.Raw[0].Raw), &raw); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw.SourceBytes, b) || raw.Record.Times[1].Ticks != ticks || raw.Record.Entries[rawTimeEntryIndex(raw.Record, offset)].Bits != ticks {
				t.Error("raw bytes or typed ticks changed")
			}
			if _, err := json.Marshal(raw); err != nil {
				t.Errorf("raw JSON: %v", err)
			}
		})
	}
}

func rawTimeEntryIndex(r *Record, offset int) int {
	for i, e := range r.Entries {
		if e.Offset == offset {
			return i
		}
	}
	return -1
}
