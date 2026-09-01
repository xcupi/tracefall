package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// Display timezone (issues 6 and 7).
//
// The whole feature is only acceptable if it is PRESENTATION-ONLY. Most
// of these tests exist to prove the negative: that changing the display
// timezone changes nothing about the evidence, the ordering, or the
// analysis.

func getDisplay(t *testing.T, mux http.Handler) DisplaySettings {
	t.Helper()
	var out struct {
		Display DisplaySettings `json:"display"`
	}
	doJSON(t, mux, "GET", "/api/settings", nil, &out)
	return out.Display
}

func setTZ(t *testing.T, mux http.Handler, tz string) *httpStatus {
	t.Helper()
	rec := doJSON(t, mux, "PUT", "/api/settings", map[string]string{"timezone": tz}, nil)
	return &httpStatus{Code: rec.Code, Body: rec.Body.String()}
}

type httpStatus struct {
	Code int
	Body string
}

// The default must be UTC, and must stay UTC without an explicit choice.
func TestSettings_DefaultsToUTC(t *testing.T) {
	mux := newTestRouter(t)
	d := getDisplay(t, mux)
	if d.Timezone != "UTC" {
		t.Errorf("default timezone = %q, want UTC", d.Timezone)
	}
	if d.OffsetLabel != "UTC+00:00" {
		t.Errorf("default offset = %q, want UTC+00:00", d.OffsetLabel)
	}
}

// A valid IANA zone is accepted, persisted, and described correctly.
func TestSettings_AcceptsIANAZones(t *testing.T) {
	cases := []struct {
		tz          string
		wantAbbr    string
		wantOffsetP string // offset prefix, so DST does not make this brittle
	}{
		{"UTC", "UTC", "UTC+00:00"},
		{"Asia/Jakarta", "WIB", "UTC+07:00"},
		{"Asia/Tokyo", "JST", "UTC+09:00"},
		{"Asia/Singapore", "+08", "UTC+08:00"},
	}
	for _, tc := range cases {
		t.Run(tc.tz, func(t *testing.T) {
			mux := newTestRouter(t)
			if s := setTZ(t, mux, tc.tz); s.Code != http.StatusOK {
				t.Fatalf("PUT /api/settings %s: status %d (%s)", tc.tz, s.Code, s.Body)
			}
			d := getDisplay(t, mux)
			if d.Timezone != tc.tz {
				t.Errorf("timezone = %q, want %q", d.Timezone, tc.tz)
			}
			if d.OffsetLabel != tc.wantOffsetP {
				t.Errorf("offset = %q, want %q", d.OffsetLabel, tc.wantOffsetP)
			}
			if tc.wantAbbr != "" && d.Abbreviation != tc.wantAbbr {
				t.Errorf("abbreviation = %q, want %q", d.Abbreviation, tc.wantAbbr)
			}
		})
	}
}

// A negative-offset zone must work exactly as a positive one does.
func TestSettings_NegativeOffsetZone(t *testing.T) {
	mux := newTestRouter(t)
	if s := setTZ(t, mux, "America/New_York"); s.Code != http.StatusOK {
		t.Fatalf("status %d: %s", s.Code, s.Body)
	}
	d := getDisplay(t, mux)
	if !strings.HasPrefix(d.OffsetLabel, "UTC-") {
		t.Errorf("America/New_York offset = %q, want a negative UTC offset", d.OffsetLabel)
	}
	if d.Abbreviation != "EST" && d.Abbreviation != "EDT" {
		t.Errorf("abbreviation = %q, want EST or EDT", d.Abbreviation)
	}
}

// DST must be handled by the timezone database, not by a fixed offset.
// The same zone must produce different offsets in January and July.
func TestSettings_DSTIsHandledByTheDatabase(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("tzdb unavailable: %v", err)
	}
	winter := time.Date(2021, 1, 15, 12, 0, 0, 0, time.UTC).In(loc)
	summer := time.Date(2021, 7, 15, 12, 0, 0, 0, time.UTC).In(loc)
	_, wOff := winter.Zone()
	_, sOff := summer.Zone()
	if wOff == sOff {
		t.Fatalf("no DST difference for America/New_York: winter=%d summer=%d", wOff, sOff)
	}
	if wOff != -5*3600 || sOff != -4*3600 {
		t.Errorf("offsets = winter %d, summer %d; want -18000 and -14400", wOff, sOff)
	}
	// Europe/London: +00:00 in winter, +01:00 (BST) in summer.
	lon, err := time.LoadLocation("Europe/London")
	if err != nil {
		t.Fatal(err)
	}
	_, lw := time.Date(2021, 1, 15, 12, 0, 0, 0, time.UTC).In(lon).Zone()
	_, ls := time.Date(2021, 7, 15, 12, 0, 0, 0, time.UTC).In(lon).Zone()
	if lw != 0 || ls != 3600 {
		t.Errorf("Europe/London offsets = %d, %d; want 0 and 3600", lw, ls)
	}
}

// The exact conversion the requirement names must hold.
func TestSettings_SameInstantInDifferentZones(t *testing.T) {
	const stored = "2021-04-25T18:31:49Z"
	instant, err := time.Parse(time.RFC3339, stored)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		tz   string
		want string
	}{
		{"UTC", "2021-04-25 18:31:49"},
		{"Asia/Jakarta", "2021-04-26 01:31:49"},
		{"Asia/Tokyo", "2021-04-26 03:31:49"},
		{"America/New_York", "2021-04-25 14:31:49"}, // EDT, UTC-4
	}
	for _, tc := range cases {
		loc, err := time.LoadLocation(tc.tz)
		if err != nil {
			t.Fatalf("%s: %v", tc.tz, err)
		}
		got := instant.In(loc).Format("2006-01-02 15:04:05")
		if got != tc.want {
			t.Errorf("%s: %s -> %q, want %q", tc.tz, stored, got, tc.want)
		}
		// The instant itself is untouched by conversion.
		if !instant.In(loc).Equal(instant) {
			t.Errorf("%s: conversion changed the instant", tc.tz)
		}
	}
}

// An invalid identifier must be rejected, not silently ignored.
func TestSettings_RejectsInvalidTimezones(t *testing.T) {
	bad := []string{
		"Asia/Jakata",      // typo
		"Mars/Olympus",     // not a place
		"+07:00",           // fixed offset: cannot express DST
		"-05:00",           //
		"UTC+7",            // not an IANA identifier
		"Local",            // depends on the server's own zone
		"",                 // empty
		"../../etc/passwd", // path traversal shaped input
	}
	for _, tz := range bad {
		t.Run(tz, func(t *testing.T) {
			mux := newTestRouter(t)
			s := setTZ(t, mux, tz)
			if s.Code != http.StatusBadRequest {
				t.Errorf("PUT timezone=%q: status %d, want 400", tz, s.Code)
			}
			// And the setting must be unchanged.
			if d := getDisplay(t, mux); d.Timezone != "UTC" {
				t.Errorf("a rejected timezone still changed the setting to %q", d.Timezone)
			}
		})
	}
}

// THE critical guarantee: changing the display timezone must not touch
// stored timestamps, ordering, or any analysis result.
func TestSettings_TimezoneIsPresentationOnly(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Timezone is presentation only")

	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Windows/Prefetch/A.pf":               samplePrefetch(),
		"Windows/System32/winevt/Logs/S.evtx": attackEvtx(),
	})
	ids := selectableIDs(disc)
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID+"/import",
		map[string][]string{"source_file_ids": ids}, nil)
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil)

	type snapshot struct {
		timeline    []model.Event
		findings    []model.Finding
		correlation []model.Correlation
	}
	take := func() snapshot {
		var s snapshot
		doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &s.timeline)
		doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings", nil, &s.findings)
		doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/correlations", nil, &s.correlation)
		return s
	}

	before := take()
	if len(before.timeline) == 0 {
		t.Fatal("no events to compare")
	}

	for _, tz := range []string{"Asia/Jakarta", "America/New_York", "Australia/Sydney", "UTC"} {
		if s := setTZ(t, mux, tz); s.Code != http.StatusOK {
			t.Fatalf("set %s: %d %s", tz, s.Code, s.Body)
		}
		after := take()

		// 1. Stored timestamps are byte-identical, still UTC.
		if len(after.timeline) != len(before.timeline) {
			t.Fatalf("%s: timeline length changed from %d to %d", tz, len(before.timeline), len(after.timeline))
		}
		for i := range before.timeline {
			if !after.timeline[i].Timestamp.Equal(before.timeline[i].Timestamp) {
				t.Errorf("%s: event %d timestamp changed from %s to %s",
					tz, i, before.timeline[i].Timestamp, after.timeline[i].Timestamp)
			}
			if _, off := after.timeline[i].Timestamp.Zone(); off != 0 {
				t.Errorf("%s: stored timestamp is no longer UTC (offset %d)", tz, off)
			}
			// 2. Ordering is unchanged -- it follows the instant, never
			// the display zone.
			if after.timeline[i].ID != before.timeline[i].ID {
				t.Errorf("%s: event order changed at index %d", tz, i)
			}
		}
		// 3. Analysis results are unchanged.
		if len(after.findings) != len(before.findings) {
			t.Errorf("%s: finding count changed from %d to %d", tz, len(before.findings), len(after.findings))
		}
		for i := range before.findings {
			if after.findings[i].ID != before.findings[i].ID {
				t.Errorf("%s: finding %d id changed", tz, i)
			}
			if after.findings[i].Severity != before.findings[i].Severity {
				t.Errorf("%s: finding %d severity changed", tz, i)
			}
		}
		if len(after.correlation) != len(before.correlation) {
			t.Errorf("%s: correlation count changed", tz)
		}
	}
}

// Changing the timezone must not make the case's analysis stale.
func TestSettings_TimezoneDoesNotRequireReanalysis(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Timezone does not invalidate")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Windows/Prefetch/A.pf": samplePrefetch(),
	})
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/evidence/"+disc.Collection.ID+"/import",
		map[string][]string{"source_file_ids": selectableIDs(disc)}, nil)
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil)

	var before struct {
		Case model.Case `json:"case"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &before)

	setTZ(t, mux, "Asia/Jakarta")

	var after struct {
		Case model.Case `json:"case"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, &after)

	if after.Case.Status != before.Case.Status {
		t.Errorf("case status changed from %q to %q after a timezone change", before.Case.Status, after.Case.Status)
	}
	if after.Case.Status != model.CaseStatusAnalyzed {
		t.Errorf("case is no longer analyzed after a display-only change: %q", after.Case.Status)
	}
	if before.Case.AnalyzedAt == nil || after.Case.AnalyzedAt == nil {
		t.Fatal("analyzed_at missing")
	}
	if !after.Case.AnalyzedAt.Equal(*before.Case.AnalyzedAt) {
		t.Error("analyzed_at changed after a timezone change")
	}
}

// The setting must not be stored on a case or an evidence record.
func TestSettings_NotStoredInCaseOrEvidence(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "Timezone isolation")
	setTZ(t, mux, "Asia/Jakarta")

	rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID, nil, nil)
	if strings.Contains(rec.Body.String(), "Asia/Jakarta") {
		t.Error("the display timezone leaked into the case payload")
	}
	rec = doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/export", nil, nil)
	if strings.Contains(rec.Body.String(), "Asia/Jakarta") {
		t.Error("the display timezone leaked into the case export")
	}
}

// The shortlist offered by the UI must contain only valid identifiers.
func TestSettings_CommonTimezonesAreAllValid(t *testing.T) {
	for _, tz := range CommonTimezones {
		if _, err := time.LoadLocation(tz); err != nil {
			t.Errorf("shortlisted timezone %q is not loadable: %v", tz, err)
		}
	}
	if CommonTimezones[0] != "UTC" {
		t.Errorf("UTC must be offered first, got %q", CommonTimezones[0])
	}
}
