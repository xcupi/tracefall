package winevent_test

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"tracefall/internal/evtx/evtxgen"
	"tracefall/internal/model"
	native "tracefall/internal/parsers/evtx"
	"tracefall/internal/parsers/evtxcsv"
	"tracefall/internal/parsers/winevent"
)

// G02 coverage tests. Every fixture uses neutral values (host01, alice,
// 203.0.113.0/24, C:\Users\alice); the field NAMES and value SHAPES follow
// what real native records carry, the values are invented.

var g02Time = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

// g02Both pushes ONE record through the raw-EVTX parser (built bytes) and the
// EvtxECmd CSV parser (a row carrying the same name/value pairs and the same
// record number) and returns the single event each produced.
func g02Both(t *testing.T, in winevent.Input, recordID uint64) (nat, csvEv model.Event) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "log.evtx")
	if err := os.WriteFile(bin, evtxgen.Build([]evtxgen.Event{{RecordID: recordID, Timestamp: g02Time, Computer: "HOST01", Channel: in.Channel, Provider: in.Provider, EventID: in.EventID, Data: in.Data}}), 0o600); err != nil {
		t.Fatal(err)
	}
	cp := filepath.Join(dir, "EvtxECmd.csv")
	f, err := os.Create(cp)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(in.Data))
	for k := range in.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+": "+in.Data[k])
	}
	w := csv.NewWriter(f)
	_ = w.Write([]string{"TimeCreated", "EventId", "Provider", "Channel", "ComputerName", "PayloadData1", "RecordNumber"})
	_ = w.Write([]string{g02Time.Format(time.RFC3339), fmt.Sprint(in.EventID), in.Provider, in.Channel, "HOST01", strings.Join(parts, "; "), fmt.Sprint(recordID)})
	w.Flush()
	if err := w.Error(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	a, err := native.New().Parse(bin)
	if err != nil {
		t.Fatal(err)
	}
	b, err := evtxcsv.New().Parse(cp)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Events) != 1 || len(b.Events) != 1 {
		t.Fatalf("native mapped %d, csv mapped %d records, want 1 each", len(a.Events), len(b.Events))
	}
	return a.Events[0], b.Events[0]
}

// g02Parity requires the two paths to agree on every normalized field and on
// the dedup identity (only the evtx_* System provenance extras are native-only).
func g02Parity(t *testing.T, in winevent.Input) model.Event {
	t.Helper()
	a, b := g02Both(t, in, 77)
	ae, be := a, b
	ae.Extra, be.Extra = map[string]string{}, map[string]string{}
	for k, v := range a.Extra {
		if !strings.HasPrefix(k, "evtx_") || k == "evtx_record_id" {
			ae.Extra[k] = v
		}
	}
	for k, v := range b.Extra {
		if !strings.HasPrefix(k, "evtx_") || k == "evtx_record_id" {
			be.Extra[k] = v
		}
	}
	ae.Parser, be.Parser, ae.SourceReference, be.SourceReference = "", "", "", ""
	if fmt.Sprintf("%#v", ae) != fmt.Sprintf("%#v", be) {
		t.Errorf("native and CSV normalized events differ:\nnative %+v\ncsv    %+v", ae, be)
	}
	if a.ComputeDedupHash() != b.ComputeDedupHash() {
		t.Error("native and CSV paths produce different dedup identities for the same record")
	}
	return a
}

// g02Direct normalizes one Input against a fresh event.
func g02Direct(in winevent.Input) (model.Event, bool) {
	e := model.Event{Extra: map[string]string{}}
	ok := winevent.Normalize(&e, in)
	return e, ok
}

// g02Expect checks type, user, source, process fields and exact Extra values
// and asserts that every key in absent is NOT recorded at all.
func g02Expect(t *testing.T, e model.Event, typ, user, src string, want map[string]string, absent ...string) {
	t.Helper()
	if e.EventType != typ || e.User != user || e.NetworkSource != src {
		t.Errorf("type/user/source = %q/%q/%q, want %q/%q/%q", e.EventType, e.User, e.NetworkSource, typ, user, src)
	}
	for k, v := range want {
		got, ok := e.Extra[k]
		if !ok || got != v {
			t.Errorf("extra[%s] = %q (recorded=%v), want %q", k, got, ok, v)
		}
	}
	for _, k := range absent {
		if v, ok := e.Extra[k]; ok {
			t.Errorf("extra[%s] must be absent, recorded as %q", k, v)
		}
	}
	if e.Extra["evidence_meaning"] == "" || e.Extra["limitations"] == "" {
		t.Error("event lacks evidence_meaning/limitations")
	}
}

// g02Gate asserts the ID is claimed ONLY for the exact provider and channel:
// every other combination is not mapped and leaves the event untouched apart
// from the provider/channel annotations.
func g02Gate(t *testing.T, in winevent.Input) {
	t.Helper()
	for name, bad := range map[string]winevent.Input{
		"wrong provider": {Channel: in.Channel, Provider: "Unrelated-Provider", EventID: in.EventID, Data: in.Data},
		"wrong channel":  {Channel: "Application", Provider: in.Provider, EventID: in.EventID, Data: in.Data},
		"no provider":    {Channel: in.Channel, EventID: in.EventID, Data: in.Data},
		"no channel":     {Provider: in.Provider, EventID: in.EventID, Data: in.Data},
	} {
		e, ok := g02Direct(bad)
		if ok {
			t.Errorf("%s: mapped as %q", name, e.EventType)
		}
		if e.EventType != "" || e.User != "" || len(e.Extra) > 2 {
			t.Errorf("%s: event was modified: %+v", name, e)
		}
	}
}

// g02Distinct fails when two events that differ only in the named field share
// a dedup identity, or when an identical re-collection stops collapsing.
func g02Distinct(t *testing.T, a, b winevent.Input) {
	t.Helper()
	ea, oka := g02Direct(a)
	eb, okb := g02Direct(b)
	if !oka || !okb {
		t.Fatalf("both inputs must map (a=%v b=%v)", oka, okb)
	}
	for _, e := range []*model.Event{&ea, &eb} {
		e.Timestamp, e.Host, e.EventID, e.ArtifactType, e.Provider = g02Time, "HOST01", a.EventID, model.ArtifactWindowsEventLog, a.Channel
	}
	if ea.ComputeDedupHash() == eb.ComputeDedupHash() {
		t.Errorf("two different records collapse to one identity: %+v vs %+v", a.Data, b.Data)
	}
	ec, _ := g02Direct(a)
	ec.Timestamp, ec.Host, ec.EventID, ec.ArtifactType, ec.Provider = g02Time, "HOST01", a.EventID, model.ArtifactWindowsEventLog, a.Channel
	if ea.ComputeDedupHash() != ec.ComputeDedupHash() {
		t.Error("an identical recollection no longer collapses")
	}
}
