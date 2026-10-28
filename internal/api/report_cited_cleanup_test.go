package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/report"
)

func TestReport_CitedSpoolFailureCleanup(t *testing.T) {
	for _, mode := range []string{"source-error", "marshal-error", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			each := func(fn func(model.Event) error) error {
				if err := fn(model.Event{ID: "one"}); err != nil {
					return err
				}
				switch mode {
				case "source-error":
					return errors.New("source failure")
				case "marshal-error":
					return fn(model.Event{Timestamp: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)})
				default:
					cancel()
					return nil
				}
			}
			file, _, err := spoolCitedFile(ctx, dir, each)
			if err == nil || file.Path != "" {
				t.Fatal("partial spool returned as success")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("partial spool leak: entries=%d err=%v", len(entries), err)
			}
		})
	}
}

func TestReport_MultipleSpoolOwnershipAndLateError(t *testing.T) {
	s, id, now := citedFixture(t)
	// Force the old timeline opener to fail after the cited spool has succeeded.
	dir := s.reportsDir(id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	obstacle := filepath.Join(dir, fmt.Sprintf("timeline-%d-%d.spool", spoolSeq.Load()+1, os.Getpid()))
	if err := os.Mkdir(obstacle, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.buildReport(id, now); err == nil {
		t.Fatal("late build unexpectedly succeeded")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(obstacle) {
		t.Fatal("cited spool retained after later timeline error")
	}
	if err := os.Remove(obstacle); err != nil {
		t.Fatal(err)
	}
	b, err := s.buildReport(id, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.spools) != 2 {
		t.Fatalf("expected two owned spools, got %d", len(b.spools))
	}
	files := append([]report.File{{Name: "report.html", Data: b.HTML}}, b.Files...)
	mismatches, err := report.Verify(b.ManifestJSON, files)
	if err != nil || len(mismatches) > 0 {
		t.Fatalf("manifest verification: %v %v", mismatches, err)
	}
	// Writing more than one consumer must not consume or prematurely release it.
	for i := 0; i < 2; i++ {
		if _, _, err := writeBundleFile(filepath.Join(t.TempDir(), "report.zip"), now, b); err != nil {
			t.Fatal(err)
		}
	}
	b.release()
	b.release()
	for _, p := range b.spools {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("success spool not released")
		}
	}
	entries, err = os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("leftover report spool or partial file")
	}
}

func TestReport_CitedDisplayRetentionAndFullFacts(t *testing.T) {
	s, id, _ := citedFixture(t)
	fs, _ := s.store.ListFindings(id)
	cs, _ := s.store.ListCorrelations(id)
	ids := findingEventIDs(fs)
	for _, c := range cs {
		ids = append(ids, c.EventIDs...)
	}
	file, c, err := s.spoolReportCited(context.Background(), id, ids, fs, cs)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Path)
	bound := maxKeyEvents + maxFindingEvents*(len(fs)+len(cs))
	if len(c.display) > bound || len(c.display) >= len(c.meta) {
		t.Fatalf("full-row cache not display bounded: %d bound=%d meta=%d", len(c.display), bound, len(c.meta))
	}
	if len(c.meta) != 520 || c.rows != 523 || len(c.key) != 300 || c.keyOmitted != 220 {
		t.Fatalf("counts changed: meta=%d rows=%d key=%d omitted=%d", len(c.meta), c.rows, len(c.key), c.keyOmitted)
	}
	for _, e := range c.key {
		if e.SourceReference == "" || e.Extra == nil {
			t.Fatal("metadata substituted for full displayed evidence")
		}
	}
}

func TestReport_CitedCompactFindingAndTimelineParity(t *testing.T) {
	s, id, _ := citedFixture(t)
	cs, err := s.store.ListCorrelations(id)
	if err != nil {
		t.Fatal(err)
	}
	refs := append([]string{}, cs[0].EventIDs...)
	// Reverse reference order: finding display follows event time/ID, not ID-list
	// position. Include repeated, missing, foreign and padded tokens unchanged.
	for i, j := 0, len(refs)-1; i < j; i, j = i+1, j-1 {
		refs[i], refs[j] = refs[j], refs[i]
	}
	fs := []model.Finding{{ID: "all-evidence", CaseID: id, RuleID: "retired-fixture", SupportingEvents: refs}}
	ids := findingEventIDs(fs)
	for _, c := range cs {
		ids = append(ids, c.EventIDs...)
	}
	file, c, err := s.spoolReportCited(context.Background(), id, ids, fs, cs)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Path)
	old, err := s.store.EventsByIDs(ids)
	if err != nil {
		t.Fatal(err)
	}
	full := map[string]model.Event{}
	for _, e := range old {
		if e.CaseID == id {
			full[e.ID] = e
		}
	}
	lookup := func(id string) (model.Event, bool) { e, ok := full[id]; return e, ok }
	src := map[string]model.SourceFile{}
	want := reportFinding(1, fs[0], lookup, src, nil, nil)
	got := reportFinding(1, fs[0], c.lookup, src, nil, nil)
	if !reflect.DeepEqual(got, want) {
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(want)
		t.Fatalf("complete explanation/display parity: got=%s want=%s", a, b)
	}
	events := []model.Event{}
	cited := map[string]bool{}
	for id, e := range full {
		events = append(events, e)
		cited[id] = true
	}
	sortEvents(events)
	// Unknown-time ties must use Go ID ordering too.
	if events[0].ID != "event-000" || got.Events[0].ID != "event-000" {
		t.Fatal("fixture does not exercise sorted selection")
	}
	agg := newTimelineAgg()
	for _, e := range events {
		agg.add(e)
	}
	oldTimeline := reportTimeline(agg, events, cited, src)
	newTimeline := timelineFromAgg(agg, c.key, src)
	newTimeline.KeyOmitted = c.keyOmitted
	if !reflect.DeepEqual(oldTimeline, newTimeline) {
		t.Fatal("compact key timeline changed counts, order, unknown times or fields")
	}
	// Deterministic regardless of SQL return order; the indexed keys themselves
	// are sorted by parsed instants, not their serialized timestamp strings.
	sort.Slice(events, func(i, j int) bool { return events[i].ID > events[j].ID })
	if !reflect.DeepEqual(oldTimeline, reportTimeline(agg, events, cited, src)) {
		t.Fatal("timeline depends on source order")
	}
}
