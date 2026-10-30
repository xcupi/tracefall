package detect

import (
	"fmt"
	"testing"
	"tracefall/internal/model"
)

type identityInputSource struct {
	model.SliceSource
	eachCalls int
}

func (s *identityInputSource) Load(f model.EventFilter) ([]model.Event, error) {
	if f.All {
		return nil, fmt.Errorf("full-case load forbidden")
	}
	return s.SliceSource.Load(f)
}
func (s *identityInputSource) Each(need func(string) bool, fn func(model.Event) error) error {
	s.eachCalls++
	return s.SliceSource.Each(need, fn)
}
func TestTemporalMalformedObservationIDsAbstain(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		es := temporalPair()
		es[1].ProcessPath = es[0].ProcessPath
		es[1].Host = "host02"
		es[0].ID, es[1].ID = "", ""
		if duplicate {
			es[0].ID, es[1].ID = "duplicate", "duplicate"
		}
		if got := (executionThenPersistence{}).Evaluate(es); len(got) != 0 {
			t.Errorf("duplicate=%v: malformed observation IDs joined hosts: %+v", duplicate, got)
		}
	}
}

func TestTemporalMetadataIDsCannotReplaceObservationIdentity(t *testing.T) {
	es := temporalPair()
	es[1].ProcessPath = es[0].ProcessPath
	es[1].Host = "host02"
	es = append(es, model.Event{ID: "exec", CaseID: "case", CollectionID: "other", Host: "host02", EventType: "identity"})
	if got := (executionThenPersistence{}).Evaluate(es); len(got) != 0 {
		t.Fatal("metadata ID replaced real execution identity", got)
	}
}

func TestTemporalInputsNeverLoadAll(t *testing.T) {
	es := temporalPair()
	es[1].ProcessPath = es[0].ProcessPath
	src := &identityInputSource{SliceSource: model.SliceSource(es)}
	fs, err := RunFrom("case", src)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range fs {
		if f.RuleID == (executionThenPersistence{}).ID() {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("temporal findings=%d want=1", n)
	}
	if src.eachCalls != 1 {
		t.Fatalf("inventory passes=%d want=1", src.eachCalls)
	}
}
