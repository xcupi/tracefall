package api

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"tracefall/internal/ingest"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/store"
)

// Segmented import admits one very large streaming source in bounded segments
// that stay hidden from every reader until the source is verified and published
// with one status flip. Known, deliberate limits of this implementation:
//
//   - Only artifact types listed in segmentedArtifacts take this path (host
//     resolution must equal the single-transaction path); others keep it.
//   - Checkpoints are written but NOT used to resume: after a failure, cancel or
//     process death the pending segments are removed and the source is imported
//     again from the beginning.
//   - There is no lock between two server processes on one database: starting a
//     second process runs startup recovery and aborts the first one's live import.
//   - Progress is reported per file, not per segment, while a segmented import
//     runs.
//   - It reduces neither the database size nor the total parse time.
//
// errSegmentedPending wraps ErrImportInProgress (so the existing HTTP mapping
// applies): a segmented import is pending in the case, so evidence deletion and
// other imports must wait -- they could not see its pending rows.
var errSegmentedPending = fmt.Errorf("%w: a segmented import is pending in this case; wait for it to finish or restart the server to recover it", ErrImportInProgress)

// errSegmentedRecovering: the pending import was interrupted and is being cleaned up.
var errSegmentedRecovering = fmt.Errorf("%w: an interrupted segmented import in this case is being cleaned up after a restart; try again when the cleanup has finished", ErrImportInProgress)

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
	hook     func(segIndex int) error // called after a segment commits
	noAbort  bool                     // simulate a process that died: no abort
	abortErr error                    // simulate a failing abort
	mutate   func(*model.Event)       // test seam: alter a parsed event
	hostsErr error                    // simulate a failing host lookup
	// recovering is how many interrupted imports a background recovery has yet
	// to clean up; while it is above zero the case guards say so.
	recovering atomic.Int64
	// recoverHook is a test seam, called before each orphan is cleaned up.
	recoverHook func(sourceFileID string)
}

func newSegmentedImport() *segmentedImport {
	return &segmentedImport{minBytes: DefaultSegmentedMinBytes, events: DefaultSegmentEvents}
}

// SetSegmentedImport configures when a source is admitted in segments
// (minBytes <= 0 disables it) and how many events one segment holds. The fields
// are not synchronized: call it before the Service serves requests.
func (s *Service) SetSegmentedImport(minBytes int64, segmentEvents int) {
	s.seg.minBytes = minBytes
	if segmentEvents > 0 {
		s.seg.events = segmentEvents
	}
}

// segmentedArtifacts are the artifact types verified to be admitted in segments
// with exactly the single-transaction result. Host resolution is the reason for
// the allowlist: the ordinary path resolves a blank host from the source's OWN
// named host first and only then from the collection, which needs the whole
// source read beforehand. These parsers never name a host, so only the
// collection scope applies and it is known before the first segment.
// A source of another type keeps the single-transaction path.
var segmentedArtifacts = map[string]bool{model.ArtifactMSSQLLog: true}

// wantsSegmented: only a streaming parser of a verified artifact type can be
// admitted in segments, and only when the source is large enough that one
// transaction is the wrong shape.
func (s *Service) wantsSegmented(size int64, p parsers.ArtifactParser) bool {
	if s.seg.minBytes <= 0 || size < s.seg.minBytes || !segmentedArtifacts[p.ArtifactType()] {
		return false
	}
	_, ok := p.(parsers.StreamingParser)
	return ok
}

// refuseIfSegmentedPending fails when a segmented import is pending in the case.
func (s *Service) refuseIfSegmentedPending(caseID string) error {
	ids, err := s.store.CaseImportingSourceIDs(caseID)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	// A source this process is importing right now is "pending"; otherwise it is
	// an orphan, being cleaned up while a recovery runs, stuck after that.
	for _, id := range ids {
		if _, running := s.seg.live.Load(id); running {
			return errSegmentedPending
		}
	}
	if s.seg.recovering.Load() > 0 {
		return errSegmentedRecovering
	}
	return errSegmentedPending
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

// segmentedAbortError: the import failed AND its pending segments could not be
// removed. The source stays importing (hidden) until startup recovery.
type segmentedAbortError struct{ cause, abort error }

func (e *segmentedAbortError) Error() string {
	return fmt.Sprintf("%v (and removing its pending segments failed: %v; the case stays blocked and the rows stay hidden until the server restarts and recovers them)", e.cause, e.abort)
}
func (e *segmentedAbortError) Unwrap() error { return e.cause }

// errSegmentedHostNamed: a source of a verified-hostless type named a host. The
// segmented path cannot reproduce the ordinary source-then-collection host
// resolution without reading the source twice, so it stops rather than guess.
var errSegmentedHostNamed = errors.New("segmented import stopped: the source names its own host, which the segmented path cannot resolve identically to a normal import")

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
	hosts, herr := s.store.CollectionHosts(caseID, collectionID)
	if s.seg.hostsErr != nil {
		herr = s.seg.hostsErr
	}
	if herr != nil {
		return 0, 0, s.abortSegmented(sf.ID, fmt.Errorf("reading the collection's hosts: %w", herr), prog)
	}
	{
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
			if s.seg.mutate != nil {
				s.seg.mutate(&b.Events[i])
			}
			if normalizeHost(b.Events[i].Host) != "" {
				return errSegmentedHostNamed
			}
			if collectionHost != "" {
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
	return 0, 0, s.abortSegmented(sf.ID, perr, prog)
}

// abortSegmented removes every pending segment of the source. A cancelled
// import or a duplicate-content source goes back to discovered, exactly as the
// single-transaction path leaves it (nothing was imported, nothing failed);
// any other failure leaves it failed with the disclosed outcome.
func (s *Service) abortSegmented(id string, cause error, prog *progressSink) error {
	if s.seg.noAbort {
		return cause
	}
	var aerr error
	if s.seg.abortErr != nil {
		aerr = s.seg.abortErr
	} else {
		aerr = s.store.AbortSegmentedImport(context.Background(), id, "import stopped before finalization: "+cause.Error())
	}
	if aerr != nil {
		return &segmentedAbortError{cause: cause, abort: aerr}
	}
	if errors.Is(cause, context.Canceled) || errors.Is(cause, store.ErrDuplicateSourceFile) {
		applied, rerr := s.store.RetryFailedSource(id)
		if rerr != nil || !applied {
			return fmt.Errorf("%w (and returning the source to discovered did not succeed: applied=%v err=%v)", cause, applied, rerr)
		}
	}
	return cause
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

// StartSegmentedRecovery cleans up, in the background, the segmented imports a
// stopped process left importing, so the server can listen at once instead of
// waiting minutes (about 44 for 4.6 million pending rows). The orphans are the
// sources importing at this moment -- nothing in a new process can be importing
// yet -- so an import started later is never touched. Until an orphan is
// cleaned its rows stay hidden and its case refuses imports and deletions with
// a message that says why; other cases are unaffected. It returns the number of
// orphans and a channel closed when the cleanup is over (nil when there is
// nothing to do). report, when given, receives what was removed and any error.
// Cancelling ctx stops between segments: the cleanup is idempotent and resumes
// at the next start.
func (s *Service) StartSegmentedRecovery(ctx context.Context, report func([]store.RecoveredImport, error)) (int, <-chan struct{}, error) {
	ids, err := s.store.ImportingSourceIDs()
	if err != nil {
		return 0, nil, err
	}
	if len(ids) == 0 {
		return 0, nil, nil
	}
	s.seg.recovering.Add(int64(len(ids)))
	done := make(chan struct{})
	go func() {
		defer close(done)
		var all []store.RecoveredImport
		var errs []error
		for _, id := range ids {
			rec, rerr := s.store.RecoverImportingSources(ctx, []string{id}, nil, s.seg.recoverHook)
			all = append(all, rec...)
			if rerr != nil {
				errs = append(errs, rerr)
			}
			s.seg.recovering.Add(-1)
		}
		if report != nil {
			report(all, errors.Join(errs...))
		}
	}()
	return len(ids), done, nil
}
