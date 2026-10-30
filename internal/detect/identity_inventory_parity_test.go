package detect

import (
	"context"
	"errors"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"tracefall/internal/model"
	"tracefall/internal/store"
)

func temporalFindings(fs []model.Finding) []model.Finding {
	out := []model.Finding{}
	for _, f := range fs {
		if f.RuleID == (executionThenPersistence{}).ID() {
			f.CreatedAt = time.Time{}
			out = append(out, f)
		}
	}
	return out
}

func TestTemporalInventoryStreamingParity(t *testing.T) {
	for _, field := range []string{"domain", "host_role", "os_product_name", "os_current_build"} {
		for _, conflict := range []bool{false, true} {
			t.Run(field+map[bool]string{true: "-conflict", false: "-compatible"}[conflict], func(t *testing.T) {
				es := temporalPair()
				es[1].ProcessPath = es[0].ProcessPath
				es[1].Host, es[1].CollectionID = "host01.example.test", "acq2"
				es = append(es, model.Event{ID: "alias", CaseID: "case", CollectionID: "acq", Host: "host01.example.test", EventType: "unrelated"})
				a, b := "one", "one"
				if field == "domain" {
					a, b = "example.test", "example.test"
				}
				if conflict {
					b = "two"
					// Keep both observations on an already-known identical name:
					// missing alias proof must not mask a lost contradiction.
					es[1].Host = es[0].Host
				}
				es = append(es, model.Event{ID: "meta-a", CaseID: "case", CollectionID: "acq", Host: "host01", EventType: "unrelated", Extra: map[string]string{field: a}}, model.Event{ID: "meta-b", CaseID: "case", CollectionID: "acq3", Host: "host01", EventType: "unrelated", Extra: map[string]string{field: b}})
				before := mustJSON(t, es)
				direct := temporalFindings((executionThenPersistence{}).Evaluate(es))
				want := 1
				if conflict {
					want = 0
				}
				if len(direct) != want {
					t.Fatalf("direct findings=%d want=%d", len(direct), want)
				}
				full := temporalFindings(Run("case", es))
				if len(full) != want {
					t.Fatalf("Run findings=%d want=%d", len(full), want)
				}
				for seed := int64(0); seed < 4; seed++ {
					shuffled := append([]model.Event(nil), es...)
					rand.New(rand.NewSource(seed)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
					src := &identityInputSource{SliceSource: model.SliceSource(shuffled)}
					got, err := RunFrom("case", src)
					if err != nil {
						t.Fatal(err)
					}
					if mustJSON(t, temporalFindings(got)) != mustJSON(t, full) {
						t.Fatal("stream/shuffle parity lost", got, full)
					}
				}
				s, err := store.Open(filepath.Join(t.TempDir(), "events.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				if err = s.CreateCase(model.Case{ID: "case", Name: "neutral"}); err != nil {
					t.Fatal(err)
				}
				for _, id := range []string{"acq", "acq2", "acq3"} {
					if err = s.SaveCollection(model.Collection{ID: id, CaseID: "case"}); err != nil {
						t.Fatal(err)
					}
				}
				persisted := append([]model.Event(nil), es...)
				for _, id := range []string{"acq", "acq2", "acq3"} {
					if err = s.SaveSourceFiles([]model.SourceFile{{ID: id, CaseID: "case", CollectionID: id}}); err != nil {
						t.Fatal(err)
					}
				}
				for i := range persisted {
					persisted[i].DedupHash = persisted[i].ID
					persisted[i].SourceFileID = persisted[i].CollectionID
				}
				if err = s.SaveEvents(persisted); err != nil {
					t.Fatal(err)
				}
				got, err := RunFrom("case", s.EventSourceFor("case"))
				if err != nil {
					t.Fatal(err)
				}
				if mustJSON(t, temporalFindings(got)) != mustJSON(t, full) {
					t.Fatal("store parity lost", got, full)
				}
				if mustJSON(t, es) != before {
					t.Fatal("source evidence mutated")
				}
			})
		}
	}
}

type failingIdentitySource struct{ model.SliceSource }

func (s failingIdentitySource) Each(func(string) bool, func(model.Event) error) error {
	return context.Canceled
}
func TestTemporalInventoryFailureReturnsNoPartialFindings(t *testing.T) {
	es := temporalPair()
	es[1].ProcessPath = es[0].ProcessPath
	got, err := RunFrom("case", failingIdentitySource{model.SliceSource(es)})
	if got != nil || !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "identity inventory") {
		t.Fatalf("findings=%+v error=%v", got, err)
	}
}

func TestTemporalInventoryIsOptIn(t *testing.T) {
	n := 0
	for _, r := range All() {
		in, ok := r.(interface{ Inputs() model.EventFilter })
		if !ok {
			t.Fatalf("missing inputs: %s", r.ID())
		}
		if in.Inputs().All {
			t.Fatalf("full-case filter: %s", r.ID())
		}
		if c, ok := r.(interface{ NeedsIdentityInventory() bool }); ok && c.NeedsIdentityInventory() {
			n++
			if r.ID() != (executionThenPersistence{}).ID() {
				t.Fatal("unexpected inventory consumer", r.ID())
			}
		}
	}
	if n != 1 {
		t.Fatalf("inventory consumers=%d want=1", n)
	}
}

func TestTemporalMetadataEmptyIDsRemainIdentityContext(t *testing.T) {
	es := temporalPair()
	es[1].ProcessPath = es[0].ProcessPath
	es = append(es, model.Event{CaseID: "case", CollectionID: "acq", Host: "host01", Extra: map[string]string{"host_role": "server"}}, model.Event{CaseID: "case", CollectionID: "acq2", Host: "host01", Extra: map[string]string{"host_role": "server"}})
	if got := (executionThenPersistence{}).Evaluate(es); len(got) != 1 {
		t.Fatal("metadata invalidated valid citations", got)
	}
	es[len(es)-1].Extra["host_role"] = "workstation"
	if got := (executionThenPersistence{}).Evaluate(es); len(got) != 0 {
		t.Fatal("empty-ID identity contradiction discarded", got)
	}
}
