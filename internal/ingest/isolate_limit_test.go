package ingest

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"tracefall/internal/gate"
	"tracefall/internal/parsers"
)

// worker writes a shell script that stands in for `tracefall parse-worker`: it
// ignores its arguments, takes a while, and answers with an empty result.
func slowWorker(t *testing.T, seconds string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "worker.sh")
	body := "#!/bin/sh\ncat >/dev/null\nsleep " + seconds + "\necho '{\"result\":{\"Events\":null,\"Raw\":null}}'\n"
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// However many parses are asked for at once, no more than the limit run: each
// may use its whole memory limit, so the burst's cost is fixed by the server.
func TestSubprocess_NeverRunsMoreWorkersThanItsLimit(t *testing.T) {
	g := gate.New(2)
	sub := Subprocess{Exe: slowWorker(t, "0.2"), Timeout: 30 * time.Second, Limit: g}
	p := Registry()[0]

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = sub.Run(p, "", "/x", parsers.ParseContext{})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("parse %d: %v", i, err)
		}
	}
	st := g.Stats()
	if st.PeakRunning > 2 {
		t.Fatalf("%d workers ran at once, limit 2", st.PeakRunning)
	}
	if st.PeakRunning < 2 {
		t.Fatalf("only %d ran at once: the test did not exercise the limit", st.PeakRunning)
	}
	if st.Admitted != 8 || st.Running != 0 {
		t.Fatalf("after the burst: %+v", st)
	}
}

// Waiting for a slot is not running: a parse that queued behind others still
// gets its whole time limit.
func TestSubprocess_QueueingDoesNotUseUpTheTimeLimit(t *testing.T) {
	g := gate.New(1)
	sub := Subprocess{Exe: slowWorker(t, "0.5"), Timeout: 1500 * time.Millisecond, Limit: g}
	p := Registry()[0]

	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = sub.Run(p, "", "/x", parsers.ParseContext{})
		}(i)
	}
	wg.Wait() // four 0.5 s parses in turn take 2 s, past the 1.5 s limit each has
	for i, err := range errs {
		if err != nil {
			t.Fatalf("parse %d was stopped for time it spent waiting: %v", i, err)
		}
	}
}
