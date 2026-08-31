package api

import (
	"net/http"
	"testing"

	"tracefall/internal/model"
)

// A PowerShell console history records no timestamps, so its events
// carry a zero Timestamp by design. A collection holding one must NOT
// report an event range starting in year 1 -- that would describe the
// evidence as spanning two millennia and put a date on screen that was
// never in the artifact. The undated events are counted instead, so
// they are excluded from the range without being silently dropped.
func TestCollectionDetail_UndatedEventsAreCountedNotRanged(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Undated events")

	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		// Has real timestamps.
		"Windows/System32/winevt/Logs/Security.evtx": attackEvtx(),
		// Has none, by design.
		"Users/jdoe/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt": []byte(
			"whoami /priv\nnet user\n"),
	})
	jobID, code := startImport(t, mux, c.ID, disc.Collection.ID, selectableIDs(disc))
	if code != http.StatusAccepted {
		t.Fatalf("start import: status %d, want 202", code)
	}
	if _, final := pollJob(t, mux, c.ID, jobID); final.ParseErrors != 0 {
		t.Fatalf("unexpected parse errors: %d", final.ParseErrors)
	}

	var detail CollectionDetail
	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID, nil, &detail)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}

	if detail.UndatedEvents != 2 {
		t.Errorf("undated_events = %d, want 2 (the two console-history commands)", detail.UndatedEvents)
	}
	if detail.EarliestEvent == nil {
		t.Fatal("earliest_event is nil despite the event log having real timestamps")
	}
	// The actual regression: a zero timestamp must never become the
	// start of the reported range.
	if detail.EarliestEvent.IsZero() {
		t.Error("earliest_event is the zero time -- a timestamp-less event was treated as the earliest event")
	}
	if y := detail.EarliestEvent.UTC().Year(); y < 1970 {
		t.Errorf("earliest_event year = %d; a timestamp-less event leaked into the range", y)
	}
	if detail.LatestEvent == nil || detail.LatestEvent.Before(*detail.EarliestEvent) {
		t.Errorf("latest_event (%v) is not at or after earliest_event (%v)", detail.LatestEvent, detail.EarliestEvent)
	}
}

// The events themselves must still be stored with a zero timestamp --
// excluding them from the RANGE must not tempt anyone into stamping
// them with a substitute time.
func TestCollectionDetail_UndatedEventsKeepTheirZeroTimestamp(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Undated preserved")

	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Users/jdoe/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt": []byte(
			"whoami /priv\n"),
	})
	jobID, _ := startImport(t, mux, c.ID, disc.Collection.ID, selectableIDs(disc))
	pollJob(t, mux, c.ID, jobID)

	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &events)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if !events[0].Timestamp.IsZero() {
		t.Errorf("timestamp = %v, want the zero time -- the artifact records none and none may be invented",
			events[0].Timestamp)
	}
	if events[0].Extra["timestamp_known"] != "false" {
		t.Errorf("timestamp_known = %q, want %q", events[0].Extra["timestamp_known"], "false")
	}
}
