package api

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"tracefall/internal/ingest"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/store"
)

// errSegmentedPending wraps ErrImportInProgress (so the existing HTTP mapping
// applies): a segmented import is pending in the case, so evidence deletion and
// other imports must wait -- they could not see its pending rows.
var errSegmentedPending = fmt.Errorf("%w: a segmented import is pending in this case; wait for it to finish or restart the server to recover it", ErrImportInProgress)

const (
	// DefaultSegmentedMinBytes is the source size from which a streaming source
	// is admitted in bounded segments instead of one transaction.
	DefaultSegmentedMinBytes int64 = 512 << 20
	// DefaultSegmentEvents bounds the events of one committed segment.
	DefaultSegmentEvents = 5000
	// segmentRawBytes bounds the raw text of one committed segment.
	segmentRawBytes = 16 << 20
)

// segmentedImport is the policy and live state shared by Service copies.
type segmentedImport struct {
	minBytes int64
	events   int
	live     sync.Map // source id -> struct{}: imports running in this process
	// test seams
	hook    func(segIndex int) error // called after a segment commits
	noAbort bool                     // simulate a process that died: no abort
}

func newSegmentedImport() *segmentedImport {
	return &segmentedImport{minBytes: DefaultSegmentedMinBytes, events: DefaultSegmentEvents}
}

// SetSegmentedImport configures when a source is admitted in segments
// (minBytes <= 0 disables it) and how many events one segment holds.
func (s *Service) SetSegmentedImport(minBytes int64, segmentEvents int) {
	s.seg.minBytes = minBytes
	if segmentEvents > 0 {
		s.seg.events = segmentEvents
	}
}

// wantsSegmented: only a streaming parser can be admitted in segments, and only
// when the source is large enough that one transaction is the wrong shape.
func (s *Service) wantsSegmented(size int64, p parsers.ArtifactParser) bool {
	if s.seg.minBytes <= 0 || size < s.seg.minBytes {
		return false
	}
	_, ok := p.(parsers.StreamingParser)
	return ok
}

// refuseIfSegmentedPending fails when a segmented import is pending in the case.
func (s *Service) refuseIfSegmentedPending(caseID string) error {
	has, err := s.store.CaseHasImportingSource(caseID)
	if err != nil {
		return err
	}
	if has {
		return errSegmentedPending
	}
	return nil
}

// RecoverSegmentedImports aborts segmented imports left importing by a stopped
// process: their pending rows are removed and the source becomes failed with a
// disclosed reason, so it can be imported again. Call once at startup, before
// serving requests.
func (s *Service) RecoverSegmentedImports(ctx context.Context) ([]store.RecoveredImport, error) {
	return s.store.RecoverOrphanedImports(ctx, func(id string) bool {
		_, running := s.seg.live.Load(id)
		return running
	})
}

// segmentedJob is one source selected for segmented admission.
type segmentedJob struct {
	sf model.SourceFile
	p  parsers.ArtifactParser
	pc parsers.ParseContext
}

// importSegmented streams one source through its parser and commits it in
// bounded segments. Nothing it writes is visible until Finalize flips the
// source to imported; any failure removes every segment. It returns the number
// of NEW events (the rest were already known) and the records parsed.
func (s *Service) importSegmented(job segmentedJob, caseID, collectionID, root string, prog *progressSink) (newCount, records int, err error) {
	sf := job.sf
	if err = s.store.BeginSegmentedImport(sf.ID); err != nil {
		return 0, 0, err
	}
	s.seg.live.Store(sf.ID, struct{}{})
	defer s.seg.live.Delete(sf.ID)

	parent := prog.context()
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(ingest.WithSegmentedStream(parent))
	defer cancel()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if prog.cancelled() {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-stopped }()

	// Blank hosts inherit the collection's single persisted host, as the
	// ordinary path does. Only the persisted collection scope is available
	// here: a source cannot name its own host before it has been read.
	collectionHost := ""
	if hosts, herr := s.store.CollectionHosts(caseID, collectionID); herr == nil {
		persisted := make([]model.Event, 0, len(hosts))
		for _, h := range hosts {
			persisted = append(persisted, model.Event{Host: h})
		}
		collectionHost = unambiguousHost(persisted)
	}

	var (
		events   []model.Event
		raw      []model.RawEvidence
		rawBytes int
		index    int
		totals   store.SegmentTotals
	)
	flush := func() error {
		if len(events) == 0 && len(raw) == 0 {
			return nil
		}
		newEvents, observations, derr := deduplicateForImport(s.store, caseID, collectionID, sf.ID, events, raw)
		if derr != nil {
			return derr
		}
		cp := store.SegmentCheckpoint{Index: index, Records: len(events), Position: fmt.Sprintf("records=%d", records)}
		t, cerr := s.store.CommitSegment(ctx, sf.ID, cp, store.SegmentPayload{Raw: raw, Events: newEvents, Observations: observations})
		if cerr != nil {
			return fmt.Errorf("committing segment %d: %w", index, cerr)
		}
		totals = t
		newCount += len(newEvents)
		if s.seg.hook != nil {
			if herr := s.seg.hook(index); herr != nil {
				return herr
			}
		}
		index++
		events, raw, rawBytes = nil, nil, 0
		return nil
	}

	cov, perr := ingest.ParseFileStream(ctx, caseID, collectionID, sf.ID, root, sf.Path, job.p, job.pc, func(b ingest.ParsedFile) error {
		for i := range b.Events {
			if collectionHost != "" && normalizeHost(b.Events[i].Host) == "" {
				markInheritedHost(&b.Events[i], collectionHost, "collection")
			}
		}
		events = append(events, b.Events...)
		raw = append(raw, b.Raw...)
		records += len(b.Events)
		for _, r := range b.Raw {
			rawBytes += len(r.Raw)
		}
		if len(events) >= s.seg.events || rawBytes >= segmentRawBytes {
			return flush()
		}
		return nil
	})
	if perr == nil {
		perr = flush()
	}
	if perr == nil {
		perr = s.store.FinalizeSegmentedImport(context.Background(), sf.ID, store.FinalizeExpectation{
			SegmentTotals: store.SegmentTotals{Segments: totals.Segments, Records: records, Raw: totals.Raw, Events: totals.Events, Observations: totals.Observations},
			Coverage:      cov,
			ImportedAt:    time.Now().UTC(),
		})
	}
	if perr == nil {
		return newCount, records, nil
	}
	if cancelledByAnalyst := prog.cancelled(); cancelledByAnalyst && !errors.Is(perr, context.Canceled) {
		perr = fmt.Errorf("%w: %v", context.Canceled, perr)
	}
	if !s.seg.noAbort {
		// A fresh context: ctx is usually already cancelled here.
		if aerr := s.store.AbortSegmentedImport(context.Background(), sf.ID, "import stopped before finalization: "+perr.Error()); aerr != nil {
			return 0, 0, fmt.Errorf("%w (and removing its pending segments failed: %v; startup recovery will remove them)", perr, aerr)
		}
	}
	return 0, 0, perr
}

// deduplicateForImport is deduplicateIn for one segment of an importing
// source: a hash is "known" when a visible event or an earlier segment of this
// same source already holds it.
func deduplicateForImport(st *store.Store, caseID, collectionID, sourceFileID string, events []model.Event, raw []model.RawEvidence) ([]model.Event, []model.EventObservation, error) {
	newEvents := make([]model.Event, 0, len(events))
	observations := make([]model.EventObservation, 0, len(events))
	canonicalID := make(map[string]string, len(events))
	for i, ev := range events {
		hash := ev.ComputeDedupHash()
		ev.DedupHash = hash
		eventID, ok := canonicalID[hash]
		if !ok {
			existing, found, err := st.FindEventByDedupHashForImport(caseID, hash, sourceFileID)
			if err != nil {
				return nil, nil, err
			}
			if found {
				eventID = existing.ID
			} else {
				eventID = ev.ID
				newEvents = append(newEvents, ev)
			}
			canonicalID[hash] = eventID
		}
		var rawEvidenceID string
		if i < len(raw) {
			rawEvidenceID = raw[i].ID
		}
		observations = append(observations, model.EventObservation{
			ID: uuid.NewString(), EventID: eventID, CaseID: caseID, CollectionID: collectionID,
			SourceFileID: ev.SourceFileID, RawEvidenceID: rawEvidenceID, SourceReference: ev.SourceReference,
		})
	}
	return newEvents, observations, nil
}
