package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"tracefall/internal/model"
)

// Phase 15: the same evidence imported repeatedly must produce identical
// forensic content. This is the test the extraction change has to pass:
// an optimization that altered which bytes were extracted, or in what
// order events were produced, would show up here.

// forensicFingerprint reduces a case to a stable digest of everything
// that must not change between identical imports.
func forensicFingerprint(t *testing.T, svc *Service, caseID string) (string, map[string]any) {
	t.Helper()

	events, err := svc.store.ListEvents(caseID)
	if err != nil {
		t.Fatal(err)
	}
	// Sorted by a content key, not by ID: IDs are freshly generated per
	// import and are SUPPOSED to differ. What must not differ is the
	// forensic content.
	type key struct {
		dedup, path, ref, typ string
		ts                    time.Time
	}
	keys := make([]key, 0, len(events))
	for _, e := range events {
		keys = append(keys, key{e.DedupHash, e.FilePath, e.SourceReference, e.EventType, e.Timestamp})
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.dedup != b.dedup {
			return a.dedup < b.dedup
		}
		if a.ref != b.ref {
			return a.ref < b.ref
		}
		return a.path < b.path
	})

	h := sha256.New()
	enc := json.NewEncoder(h)
	for _, k := range keys {
		_ = enc.Encode(k)
	}

	files, err := svc.store.ListSourceFiles(caseID)
	if err != nil {
		t.Fatal(err)
	}
	hashes := make([]string, 0, len(files))
	for _, f := range files {
		if f.SHA256 != "" {
			hashes = append(hashes, f.Path+":"+f.SHA256)
		}
	}
	sort.Strings(hashes)
	for _, s := range hashes {
		_, _ = h.Write([]byte(s))
	}

	findings, _ := svc.store.ListFindings(caseID)
	correlations, _ := svc.store.ListCorrelations(caseID)

	return hex.EncodeToString(h.Sum(nil)), map[string]any{
		"events":       len(events),
		"source_files": len(hashes),
		"findings":     len(findings),
		"correlations": len(correlations),
	}
}

func TestIngestDeterminism_ThreeImportsProduceIdenticalEvidence(t *testing.T) {
	ad1 := benchAD1(t)

	var firstPrint string
	var firstCounts map[string]any
	for run := 1; run <= 3; run++ {
		svc := newTestService(t)
		c, err := svc.CreateCase("determinism run", "")
		if err != nil {
			t.Fatal(err)
		}
		disc, err := svc.DiscoverEvidenceFromPath(c.ID, ad1)
		if err != nil {
			t.Fatal(err)
		}
		files, err := svc.store.ListSourceFilesByCollection(disc.Collection.ID)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(files))
		for _, f := range files {
			if f.Supported {
				ids = append(ids, f.ID)
			}
		}
		if _, err := svc.ImportEvidence(c.ID, disc.Collection.ID, ids); err != nil {
			t.Fatalf("run %d import: %v", run, err)
		}
		if _, err := svc.AnalyzeCase(c.ID); err != nil {
			t.Fatalf("run %d analyze: %v", run, err)
		}

		print, counts := forensicFingerprint(t, svc, c.ID)
		t.Logf("run %d: fingerprint=%s %v", run, print[:16], counts)

		if run == 1 {
			firstPrint, firstCounts = print, counts
			continue
		}
		if print != firstPrint {
			t.Errorf("run %d produced different forensic content:\n  run 1: %s %v\n  run %d: %s %v",
				run, firstPrint, firstCounts, run, print, counts)
		}
		for k, v := range firstCounts {
			if counts[k] != v {
				t.Errorf("run %d: %s = %v, run 1 had %v", run, k, counts[k], v)
			}
		}
	}
}

// Phase 16: cancelling mid-import must leave no half-imported file, no
// leaked handle, and an honest report of what was not reached.
func TestIngestCancellation_StopsCleanlyMidImport(t *testing.T) {
	ad1 := benchAD1(t)
	svc := newTestService(t)
	c, err := svc.CreateCase("cancel mid import", "")
	if err != nil {
		t.Fatal(err)
	}
	disc, err := svc.DiscoverEvidenceFromPath(c.ID, ad1)
	if err != nil {
		t.Fatal(err)
	}
	files, err := svc.store.ListSourceFilesByCollection(disc.Collection.ID)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(files))
	for _, f := range files {
		if f.Supported {
			ids = append(ids, f.ID)
		}
	}

	jobID, err := svc.StartImport(c.ID, disc.Collection.ID, ids)
	if err != nil {
		t.Fatal(err)
	}
	// Let it get properly into PARSING before stopping it. The AD1 index
	// is built first (one walk, ~1.5 s on the test image), so cancelling
	// too early only ever exercises shutdown during setup -- which is
	// worth working, but is not the case that matters.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if p, err := svc.ImportJob(c.ID, jobID); err == nil && p.FilesParsed > 20 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if _, err := svc.CancelImport(c.ID, jobID); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	waitUntil := time.Now().Add(2 * time.Minute)
	var final ImportProgress
	for time.Now().Before(waitUntil) {
		p, err := svc.ImportJob(c.ID, jobID)
		if err != nil {
			t.Fatalf("the job record disappeared: %v", err)
		}
		final = p
		if p.Done {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !final.Done {
		t.Fatal("the cancelled import never finished")
	}
	t.Logf("cancelled: phase=%s cancelled=%v files parsed=%d persisted=%d",
		final.Phase, final.Cancelled, final.FilesParsed, final.FilesPersisted)

	if final.Phase != PhaseCancelled {
		t.Errorf("phase = %q, want %q", final.Phase, PhaseCancelled)
	}

	// Every file is either fully imported or untouched -- never partial.
	after, err := svc.store.ListSourceFilesByCollection(disc.Collection.ID)
	if err != nil {
		t.Fatal(err)
	}
	imported, discovered, other := 0, 0, 0
	for _, f := range after {
		switch f.ImportStatus {
		case model.SourceFileImported:
			imported++
			if f.EventCount < 0 {
				t.Errorf("%s: imported with a negative event count", f.Path)
			}
		case model.SourceFileDiscovered:
			discovered++
		default:
			other++
		}
	}
	t.Logf("after cancellation: imported=%d still-discovered=%d other=%d", imported, discovered, other)
	if imported+discovered+other != len(after) {
		t.Error("source file states do not account for every file")
	}
	// Cancelling during PARSING must leave nothing imported: phase 1
	// produces only in-memory results, and nothing is durable until the
	// persist phase. Cancelling during PERSISTENCE may leave files
	// imported -- every one of them complete, which the event check
	// below verifies. Both are safe; which one happened depends on
	// timing, so the assertion is on the invariant rather than on a
	// count that is not deterministic.
	if final.FilesPersisted == 0 && imported != 0 {
		t.Errorf("nothing was persisted, yet %d files are marked imported", imported)
	}
	if final.FilesParsed == 0 {
		t.Error("cancellation happened before any file was parsed; this run exercised only setup shutdown")
	}

	// Every event must belong to a file that really was imported.
	events, err := svc.store.ListEvents(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	importedIDs := map[string]bool{}
	for _, f := range after {
		if f.ImportStatus == model.SourceFileImported {
			importedIDs[f.ID] = true
		}
	}
	for _, e := range events {
		if !importedIDs[e.SourceFileID] {
			t.Fatalf("event %s belongs to source file %s, which is not marked imported", e.ID, e.SourceFileID)
		}
	}
	t.Logf("%d events, all belonging to imported files", len(events))
}
