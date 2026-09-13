package prefetchraw_test

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/parsers/prefetchraw"
	"tracefall/internal/prefetch"
)

// End-to-end over real Windows 10 evidence: every MAM-compressed .pf in
// a case directory must parse into normalized Prefetch events.
//
// Skips when no such corpus is present, so a clean checkout still
// passes -- and says why, rather than reporting a success it did not
// earn.
func realPrefetchDir() string {
	var found string
	_ = filepath.WalkDir("../../../data/cases", func(path string, d os.DirEntry, err error) error {
		if err != nil || found != "" {
			return nil //nolint:nilerr // absence is a skip, not a failure
		}
		if d != nil && d.IsDir() && strings.EqualFold(d.Name(), "Prefetch") {
			found = path
		}
		return nil
	})
	return found
}

func TestParser_RealWindowsCorpusEndToEnd(t *testing.T) {
	dir := realPrefetchDir()
	if dir == "" {
		t.Skip("no real Prefetch corpus in this working tree")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("corpus unreadable: %v", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	p := prefetchraw.New()
	var parsed, failed, empty, totalEvents int
	var compressedEvents, rejectedNonPrefetch int
	for _, name := range names {
		full := filepath.Join(dir, name)
		info, err := os.Stat(full)
		if err != nil || info.Size() == 0 {
			continue
		}
		head, err := os.ReadFile(full)
		if err != nil || len(head) < 8 || string(head[:3]) != "MAM" {
			continue
		}

		// MAM is a general Windows compression container, not a Prefetch
		// format, and this directory also holds the application
		// compatibility databases wrapped the same way. Those must be
		// REJECTED, and the rejection is asserted here rather than
		// skipped -- the parser used to accept them on the container tag
		// alone and report an unsupported compression method for files
		// that were never Prefetch.
		if !p.Detect(name) {
			if _, err := p.Parse(full); err == nil {
				t.Errorf("%s: a non-Prefetch MAM container parsed as Prefetch", name)
			} else if !errors.Is(err, prefetch.ErrNotPrefetch) {
				t.Errorf("%s: rejected as %v, want ErrNotPrefetch", name, err)
			}
			rejectedNonPrefetch++
			continue
		}

		res, err := p.Parse(full)
		if err != nil {
			failed++
			t.Errorf("%s: %v", name, err)
			continue
		}
		parsed++
		if len(res.Events) == 0 {
			// Legitimate: a Prefetch file with no usable execution time
			// produces no events rather than an invented one.
			empty++
			continue
		}
		totalEvents += len(res.Events)

		for _, e := range res.Events {
			if e.ArtifactType != model.ArtifactPrefetch {
				t.Errorf("%s: artifact type = %q", name, e.ArtifactType)
			}
			if e.EventType != model.EventPrefetchExecution {
				t.Errorf("%s: event type = %q", name, e.EventType)
			}
			if e.Timestamp.IsZero() || e.Timestamp.Year() <= 1601 {
				t.Errorf("%s: implausible timestamp %s", name, e.Timestamp)
			}
			if e.ProcessName == "" {
				t.Errorf("%s: event has no process name", name)
			}
			if e.Extra["prefetch_container"] != "" {
				compressedEvents++
			}
		}
		if len(res.Raw) != len(res.Events) {
			t.Errorf("%s: %d raw records for %d events", name, len(res.Raw), len(res.Events))
		}
	}
	if parsed == 0 {
		t.Skip("no MAM Prefetch files in the corpus")
	}
	if failed != 0 {
		t.Errorf("%d of %d real MAM Prefetch files failed to parse", failed, parsed+failed)
	}
	if totalEvents == 0 {
		t.Error("no execution events from the whole corpus")
	}
	if compressedEvents != totalEvents {
		t.Errorf("%d of %d events recorded their MAM container", compressedEvents, totalEvents)
	}
	t.Logf("parsed %d real MAM Prefetch files -> %d execution events (%d files had no usable run time); "+
		"%d non-Prefetch MAM containers correctly rejected",
		parsed, totalEvents, empty, rejectedNonPrefetch)
}

// The same evidence must produce byte-identical events on every run.
func TestParser_RealCorpusIsDeterministic(t *testing.T) {
	dir := realPrefetchDir()
	if dir == "" {
		t.Skip("no real Prefetch corpus in this working tree")
	}
	entries, _ := os.ReadDir(dir)
	p := prefetchraw.New()
	var checked int
	for _, e := range entries {
		if e.IsDir() || checked >= 10 {
			continue
		}
		full := filepath.Join(dir, e.Name())
		head, err := os.ReadFile(full)
		if err != nil || len(head) < 8 || string(head[:3]) != "MAM" {
			continue
		}
		first, err := p.Parse(full)
		if err != nil {
			continue
		}
		for i := 0; i < 3; i++ {
			again, err := p.Parse(full)
			if err != nil {
				t.Fatalf("%s run %d: %v", e.Name(), i, err)
			}
			if len(again.Events) != len(first.Events) {
				t.Fatalf("%s run %d: %d events, want %d", e.Name(), i, len(again.Events), len(first.Events))
			}
			for j := range first.Events {
				if !again.Events[j].Timestamp.Equal(first.Events[j].Timestamp) ||
					again.Events[j].ProcessName != first.Events[j].ProcessName ||
					again.Events[j].SourceReference != first.Events[j].SourceReference {
					t.Fatalf("%s run %d event %d differed", e.Name(), i, j)
				}
			}
		}
		checked++
	}
	if checked == 0 {
		t.Skip("no MAM files to check")
	}
	t.Logf("verified deterministic events for %d real files", checked)
}
