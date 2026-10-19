package model

import "time"

// EventRef is the part of an event that the correlators which must look at
// every event need: where it happened, what produced it, and when. It is
// deliberately small. A full Event carries its parsed Extra map, which is
// most of an event's memory; a case's worth of EventRefs fits where a
// case's worth of full events does not.
type EventRef struct {
	ID           string
	Host         string
	ProcessName  string
	ArtifactType string
	Timestamp    time.Time
}

// RefOf projects an event to its EventRef.
func RefOf(e Event) EventRef {
	return EventRef{
		ID:           e.ID,
		Host:         e.Host,
		ProcessName:  e.ProcessName,
		ArtifactType: e.ArtifactType,
		Timestamp:    e.Timestamp,
	}
}

// EventFilter selects events by event type OR artifact type. A consumer
// names every type it reads, so a filtered load returns the same events, in
// the same order, as a full load would give it for those types. A filter
// that names a type the consumer reads and misses one it needs silently
// drops results, so the superset is always the safe choice.
//
// All selects every event; it is what a consumer without a declared filter
// gets.
type EventFilter struct {
	All       bool
	Types     []string
	Artifacts []string
}

// EventSource is where analysis reads a case's events from. A case's events
// are kept in the database, not in memory: the analysis asks for the slice
// it needs, when it needs it, and drops it afterwards.
type EventSource interface {
	// Load returns the events the filter selects, ordered by timestamp, then
	// ID.
	Load(f EventFilter) ([]Event, error)
	// Refs returns a reference to every event, ordered by timestamp, then ID.
	Refs() ([]EventRef, error)
}

// SliceSource serves an in-memory event slice through the EventSource
// interface. Tests and the single-slice entry points use it; the production
// path reads from the store.
type SliceSource []Event

func (s SliceSource) Load(f EventFilter) ([]Event, error) {
	if f.All {
		return []Event(s), nil
	}
	types := setOf(f.Types)
	artifacts := setOf(f.Artifacts)
	var out []Event
	for _, e := range s {
		if types[e.EventType] || artifacts[e.ArtifactType] {
			out = append(out, e)
		}
	}
	return out, nil
}

func (s SliceSource) Refs() ([]EventRef, error) {
	out := make([]EventRef, len(s))
	for i, e := range s {
		out[i] = RefOf(e)
	}
	return out, nil
}

func setOf(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
