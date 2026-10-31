package api

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/store"
)

func TestInvestigationCacheReuseAndCopy(t *testing.T) {
	var c investigationModelCache
	var calls int
	revision := func(context.Context) (store.ChangeToken, error) { return store.ChangeToken{}, nil }
	original := []model.Investigation{{ID: "i", CaseID: "c", Hosts: []string{"host01"}, Users: []string{}, EventIDs: []string{"e"}, FindingIDs: []string{"f"}, CorrelationIDs: []string{"r"}, Techniques: []string{"T1059"}, Tactics: []string{"execution"}, CollectionIDs: []string{"col"}, SourceFileIDs: []string{"src"}, ScoreRationale: []string{"reason"}}}
	build := func() ([]model.Investigation, error) {
		calls++
		b, _ := json.Marshal(original)
		var out []model.Investigation
		_ = json.Unmarshal(b, &out)
		return out, nil
	}
	get := func() []model.Investigation {
		t.Helper()
		out, e := c.get(context.Background(), "c", revision, build)
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	first := get()
	first[0].ID = "changed"
	v := reflect.ValueOf(&first[0]).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() == reflect.Slice && f.Len() > 0 {
			f.Index(0).SetString("changed")
		}
	}
	second := get()
	if !reflect.DeepEqual(second, original) {
		t.Fatal("cached mutable state leaked or nil/empty shape changed")
	}
	if calls != 1 {
		t.Fatalf("unchanged case recomputed %d times, want 1", calls)
	}
	v = reflect.ValueOf(&second[0]).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() == reflect.Slice && f.Len() > 0 {
			f.Index(0).SetString("warm mutation")
		}
	}
	if !reflect.DeepEqual(get(), original) || calls != 1 {
		t.Fatal("warm returned arrays alias cache")
	}
}

func TestInvestigationCacheNilAndEmptyShape(t *testing.T) {
	for _, input := range [][]model.Investigation{nil, {}, {{ID: "nil-slices"}}} {
		var c investigationModelCache
		for i := 0; i < 2; i++ {
			out, e := c.get(context.Background(), "c", func(context.Context) (store.ChangeToken, error) { return store.ChangeToken{}, nil }, func() ([]model.Investigation, error) { return input, nil })
			if e != nil || !reflect.DeepEqual(out, input) {
				t.Fatalf("nil/empty shape changed: err=%v", e)
			}
		}
	}
}

func TestInvestigationCacheConcurrentCold(t *testing.T) {
	var c investigationModelCache
	var calls atomic.Int32
	revision := func(context.Context) (store.ChangeToken, error) { return store.ChangeToken{}, nil }
	start := make(chan struct{})
	entered := make(chan struct{})
	build := func() ([]model.Investigation, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-start
		return []model.Investigation{{ID: "i"}}, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := c.get(context.Background(), "c", revision, build)
			if e != nil {
				t.Error(e)
			}
		}()
	}
	<-entered
	close(start)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("concurrent cold builds=%d, want 1", calls.Load())
	}
}

func TestInvestigationCacheCancellationAtPublication(t *testing.T) {
	var c investigationModelCache
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reads := 0
	_, e := c.get(ctx, "c", func(context.Context) (store.ChangeToken, error) {
		reads++
		if reads == 2 {
			cancel()
		}
		return store.ChangeToken{}, nil
	}, func() ([]model.Investigation, error) { return []model.Investigation{{ID: "not-published"}}, nil })
	if e != context.Canceled || len(c.models) != 0 {
		t.Fatalf("cancelled publication err=%v retained=%d", e, len(c.models))
	}
}

func TestInvestigationCacheCancelledRequest(t *testing.T) {
	var c investigationModelCache
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	_, err := c.get(ctx, "c", func(context.Context) (store.ChangeToken, error) { return store.ChangeToken{}, nil }, func() ([]model.Investigation, error) { calls++; return nil, nil })
	if err != context.Canceled || calls != 0 {
		t.Fatalf("cancelled request err=%v builds=%d", err, calls)
	}
}

func TestInvestigationCacheCancelledLeaderDoesNotPoisonWaiter(t *testing.T) {
	var c investigationModelCache
	revision := func(context.Context) (store.ChangeToken, error) { return store.ChangeToken{}, nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		_, e := c.get(ctx, "c", revision, func() ([]model.Investigation, error) { close(entered); <-ctx.Done(); return nil, ctx.Err() })
		if e != context.Canceled {
			t.Errorf("leader: %v", e)
		}
	}()
	awaitInvestigationTest(t, entered)
	// An unrelated case must complete while c's leader is blocked.
	otherDone := make(chan struct{})
	go func() {
		defer close(otherDone)
		_, e := c.get(context.Background(), "other", revision, func() ([]model.Investigation, error) { return []model.Investigation{{ID: "other"}}, nil })
		if e != nil {
			t.Error(e)
		}
	}()
	awaitInvestigationTest(t, otherDone)
	waiterRevision := make(chan struct{})
	waiterDone := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(waiterDone)
		out, e := c.get(context.Background(), "c", func(ctx context.Context) (store.ChangeToken, error) {
			once.Do(func() { close(waiterRevision) })
			return revision(ctx)
		}, func() ([]model.Investigation, error) { return []model.Investigation{{ID: "good"}}, nil })
		if e != nil || len(out) != 1 || out[0].ID != "good" {
			t.Errorf("waiter poisoned: %v", e)
		}
	}()
	awaitInvestigationTest(t, waiterRevision)
	cancel()
	awaitInvestigationTest(t, leaderDone)
	awaitInvestigationTest(t, waiterDone)
	if len(c.flights) != 0 {
		t.Fatal("retained completed flight")
	}
}

func TestInvestigationCacheCancelledWaiter(t *testing.T) {
	var c investigationModelCache
	revision := func(context.Context) (store.ChangeToken, error) { return store.ChangeToken{}, nil }
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, e := c.get(context.Background(), "c", revision, func() ([]model.Investigation, error) {
			close(entered)
			<-release
			return []model.Investigation{{ID: "good"}}, nil
		})
		if e != nil {
			t.Error(e)
		}
	}()
	awaitInvestigationTest(t, entered)
	ctx, cancel := context.WithCancel(context.Background())
	waiterDone := make(chan struct{})
	checked := make(chan struct{})
	go func() {
		defer close(waiterDone)
		_, e := c.get(ctx, "c", func(ctx context.Context) (store.ChangeToken, error) { close(checked); return revision(ctx) }, func() ([]model.Investigation, error) { t.Error("waiter became leader"); return nil, nil })
		if e != context.Canceled {
			t.Errorf("waiter cancellation: %v", e)
		}
	}()
	awaitInvestigationTest(t, checked)
	cancel()
	awaitInvestigationTest(t, waiterDone)
	close(release)
	awaitInvestigationTest(t, done)
}

func TestInvestigationCacheBoundedRetentionAndCaseIsolation(t *testing.T) {
	var c investigationModelCache
	revision := func(context.Context) (store.ChangeToken, error) { return store.ChangeToken{}, nil }
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("case-%d", i)
		out, e := c.get(context.Background(), id, revision, func() ([]model.Investigation, error) { return []model.Investigation{{ID: id, CaseID: id}}, nil })
		if e != nil || len(out) != 1 || out[0].CaseID != id {
			t.Fatalf("case isolation %s: %v", id, e)
		}
		if c.caseID != id || len(c.flights) != 0 || len(c.models) > investigationCacheBytes {
			t.Fatal("retention bound exceeded")
		}
	}
	before := string(c.models)
	_, e := c.get(context.Background(), "large", revision, func() ([]model.Investigation, error) {
		return []model.Investigation{{Summary: strings.Repeat("x", investigationCacheBytes+1)}}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if string(c.models) != before {
		t.Fatal("oversized models retained")
	}
}

func TestInvestigationCacheOversizedColdCoalesces(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var c investigationModelCache
		entered := make(chan struct{})
		release := make(chan struct{})
		leaderDone := make(chan struct{})
		var calls atomic.Int32
		build := func() ([]model.Investigation, error) {
			if calls.Add(1) == 1 {
				close(entered)
			}
			<-release
			return []model.Investigation{{Summary: strings.Repeat("x", investigationCacheBytes+1)}}, nil
		}
		revision := func(context.Context) (store.ChangeToken, error) { return store.ChangeToken{}, nil }
		go func() {
			defer close(leaderDone)
			_, e := c.get(context.Background(), "large", revision, build)
			if e != nil {
				t.Error(e)
			}
		}()
		awaitInvestigationTest(t, entered)
		// Join a waiter before releasing the cold leader.
		waiterDone := make(chan struct{})
		checked := make(chan struct{})
		var once sync.Once
		go func() {
			defer close(waiterDone)
			_, e := c.get(context.Background(), "large", func(ctx context.Context) (store.ChangeToken, error) {
				once.Do(func() { close(checked) })
				return revision(ctx)
			}, build)
			if e != nil {
				t.Error(e)
			}
		}()
		awaitInvestigationTest(t, checked)
		// synctest ensures the waiter has joined the blocked flight.
		synctest.Wait()
		close(release)
		awaitInvestigationTest(t, leaderDone)
		awaitInvestigationTest(t, waiterDone)
		if calls.Load() != 1 {
			t.Fatalf("oversized cold builds=%d, want 1", calls.Load())
		}
		if len(c.models) != 0 || len(c.flights) != 0 {
			t.Fatal("oversized completed result retained")
		}
	})
}

func TestInvestigationCacheBoundsActiveKeys(t *testing.T) {
	var c investigationModelCache
	revision := func(context.Context) (store.ChangeToken, error) { return store.ChangeToken{}, nil }
	release := make(chan struct{})
	entered := make(chan struct{}, investigationCacheFlights)
	var wg sync.WaitGroup
	for i := 0; i < investigationCacheFlights; i++ {
		wg.Add(1)
		id := fmt.Sprintf("case-%d", i)
		go func() {
			defer wg.Done()
			_, e := c.get(context.Background(), id, revision, func() ([]model.Investigation, error) { entered <- struct{}{}; <-release; return nil, nil })
			if e != nil {
				t.Error(e)
			}
		}()
	}
	for i := 0; i < investigationCacheFlights; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("cold keys blocked")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	checked := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, e := c.get(ctx, "overflow", func(ctx context.Context) (store.ChangeToken, error) { close(checked); return revision(ctx) }, func() ([]model.Investigation, error) { t.Error("active keys exceeded limit"); return nil, nil })
		if e != context.Canceled {
			t.Errorf("overflow: %v", e)
		}
	}()
	awaitInvestigationTest(t, checked)
	cancel()
	awaitInvestigationTest(t, done)
	c.mu.Lock()
	n := len(c.flights)
	c.mu.Unlock()
	if n != investigationCacheFlights {
		t.Fatalf("active keys=%d", n)
	}
	close(release)
	wg.Wait()
	if len(c.flights) != 0 {
		t.Fatal("flight keys leaked")
	}
}

// Deadlines bound concurrency tests without timing-based assertions.
func awaitInvestigationTest(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("operation blocked")
	}
}
