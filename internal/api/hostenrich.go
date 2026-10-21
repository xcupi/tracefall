// Host enrichment (Phase 7.1). Some artifact formats never record a
// hostname at all -- Prefetch and registry hives have no field for one --
// so their normalized events arrive from the parsers with Host blank,
// while a sibling Windows Event Log file in the same acquisition names
// the host on every record. Resolving that blank is this file's only job.
//
// It matters more than it looks: Host is one of the fields
// model.Event.ComputeDedupHash mixes in, so an event whose host is filled
// in gets a *different* dedup hash than the same event left blank. Host
// resolution therefore has to happen before anything is persisted, and
// has to produce the same answer no matter what order the files were
// processed in -- otherwise the same real-world event, re-observed in a
// second collection whose files happened to be ordered differently, would
// fail to deduplicate against its first observation.
package api

import (
	"strings"

	"tracefall/internal/model"
)

// normalizeHost matches how model.Event.ComputeDedupHash normalizes Host
// (upper-cased, trimmed), so "WKSTN-042", "wkstn-042", and " WKSTN-042 "
// are recognized here as the one host they actually are, exactly as
// deduplication already treats them.
func normalizeHost(h string) string {
	return strings.ToUpper(strings.TrimSpace(h))
}

// unambiguousHost returns the one host that every host-bearing event
// across scopes agrees on, or "" if those events name no host at all or
// name more than one.
//
// "More than one" deliberately yields "" rather than a majority vote: a
// scope containing two genuine hosts gives Tracefall no evidence at all
// about which of them a host-less Prefetch record belongs to, and
// guessing the more frequent one would fabricate provenance that the
// evidence doesn't support. Blank is the honest answer, and it's what
// internal/correlate then correctly declines to match on.
//
// When one host is named with inconsistent spelling/casing across events
// (all normalizing equal), the lexicographically smallest spelling
// actually observed is returned -- a real observed value, never a
// synthesized one, chosen by a rule that can't depend on event order.
func unambiguousHost(scopes ...[]model.Event) string {
	var norm, spelling string
	for _, events := range scopes {
		for _, e := range events {
			n := normalizeHost(e.Host)
			if n == "" {
				continue
			}
			switch {
			case norm == "":
				norm, spelling = n, e.Host
			case n != norm:
				return "" // two distinct hosts in scope -- ambiguous
			case e.Host < spelling:
				spelling = e.Host
			}
		}
	}
	return spelling
}

// pendingImport is one source file parsed but not yet persisted -- see
// Service.ImportEvidence, which parses every selected file up front
// precisely so enrichBatchHosts below can see the whole batch at once.
type pendingImport struct {
	sourceFile model.SourceFile
	events     []model.Event
	raw        []model.RawEvidence
}

// enrichBatchHosts fills in a host, in place, for every event in the
// batch that doesn't carry one, using the narrowest scope that names
// exactly one host:
//
//  1. the event's own source file -- strongest signal available. A single
//     artifact file that names one host and leaves some records blank is
//     describing one machine; those blanks are that machine's.
//  2. this collection -- one acquisition, from one host in the ordinary
//     case. This is the scope that resolves the common real shape: an
//     EvtxECmd CSV naming the host, alongside Prefetch/registry files
//     that structurally cannot.
//
// A case is an investigation boundary, not a machine identity. An anonymous
// new collection must not inherit a host from earlier acquisitions. Repeated
// acquisitions still resolve identically when their own files name the host.
//
// If no scope names exactly one host, the events stay blank: Tracefall
// does not invent a hostname (see unambiguousHost on why a majority vote
// would be inventing one).
//
// Every scope is computed from the complete batch plus observations already
// persisted for this collection, before any of the batch is written -- which is
// what makes the outcome independent of the order files are processed in.
// The previous implementation resolved each file against only what was
// already in the database at that moment, so a Prefetch file processed
// before its collection's Event Log file saw no host yet and stayed blank
// forever, while the same two files in the opposite order resolved
// correctly. This also collapses what used to be one ListEvents query per
// imported file into a single query per import.
func (s *Service) enrichBatchHosts(caseID, collectionID string, batch []pendingImport) error {
	needsHost := false
	for _, p := range batch {
		for _, e := range p.events {
			if normalizeHost(e.Host) == "" {
				needsHost = true
				break
			}
		}
		if needsHost {
			break
		}
	}
	if !needsHost {
		return nil
	}

	persisted, err := s.store.ListEvents(caseID)
	if err != nil {
		return err
	}
	var persistedThisCollection []model.Event
	byID := make(map[string]model.Event, len(persisted))
	for _, e := range persisted {
		byID[e.ID] = e
		if e.CollectionID == collectionID {
			persistedThisCollection = append(persistedThisCollection, e)
		}
	}
	// A recollected event is deduplicated against its first sighting, so it
	// is not persisted under this collection. Its host is part of its
	// identity hash, so an observation in THIS collection pointing at it is
	// a strong, explicit statement of this collection's host.
	sfs, err := s.store.ListSourceFilesByCollection(collectionID)
	if err != nil {
		return err
	}
	for _, sf := range sfs {
		obs, err := s.store.ListEventObservationsBySourceFile(sf.ID)
		if err != nil {
			return err
		}
		for _, o := range obs {
			if o.CollectionID != collectionID {
				continue
			}
			if e, ok := byID[o.EventID]; ok && e.CollectionID != collectionID {
				persistedThisCollection = append(persistedThisCollection, e)
			}
		}
	}
	batchEvents := make([]model.Event, 0, len(batch))
	for _, p := range batch {
		batchEvents = append(batchEvents, p.events...)
	}

	collectionHost := unambiguousHost(batchEvents, persistedThisCollection)

	for i := range batch {
		events := batch[i].events
		host := unambiguousHost(events)
		if host == "" {
			host = collectionHost
		}
		if host == "" {
			continue // genuinely unknown -- never fabricated
		}
		for j := range events {
			if normalizeHost(events[j].Host) == "" {
				events[j].Host = host
			}
		}
	}
	return nil
}
