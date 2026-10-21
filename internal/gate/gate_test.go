package gate

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// No more than Size holders are ever inside at once, however many ask.
func TestGate_NeverAdmitsMoreThanItsSize(t *testing.T) {
	g := New(3)
	var inside, over atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := g.Acquire(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			if inside.Add(1) > 3 {
				over.Add(1)
			}
			time.Sleep(2 * time.Millisecond)
			inside.Add(-1)
			release()
		}()
	}
	wg.Wait()
	if over.Load() != 0 {
		t.Fatalf("%d holders were admitted beyond the size", over.Load())
	}
	st := g.Stats()
	if st.PeakRunning > 3 || st.Admitted != 60 || st.Running != 0 || st.Waiting != 0 {
		t.Fatalf("stats after the run: %+v", st)
	}
}

// A waiter whose client goes away leaves the queue, takes no slot, and the
// slot count is not disturbed.
func TestGate_AWaiterThatGivesUpTakesNothing(t *testing.T) {
	g := New(1)
	hold, _ := g.Acquire(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := g.Acquire(ctx); err == nil {
		t.Fatal("a full gate admitted a waiter")
	}
	if g.Stats().Waiting != 0 {
		t.Fatalf("the abandoned waiter is still counted: %+v", g.Stats())
	}
	hold()
	hold() // releasing twice must not free a slot that is not held
	r1, _ := g.Acquire(context.Background())
	got := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if release, err := g.Acquire(ctx); err == nil {
			release()
			close(got)
		}
	}()
	select {
	case <-got:
		t.Fatal("a double release let a second holder in")
	case <-time.After(150 * time.Millisecond):
	}
	r1()
}

func TestGate_SizeIsAtLeastOne(t *testing.T) {
	if New(0).Size() != 1 || New(-4).Size() != 1 {
		t.Fatal("a gate of size 0 would block forever")
	}
}
