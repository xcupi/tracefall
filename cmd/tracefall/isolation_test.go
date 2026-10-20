package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/api"
	"tracefall/internal/ingest"
	"tracefall/internal/parsers"
)

// The test binary doubles as the worker. `parse-worker` is the real worker; the
// other modes misbehave in the ways a hostile file could make a parser behave,
// after applying the same limits the real worker applies.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "parse-worker":
			os.Exit(parseWorkerCmd())
		case "seccompprobe":
			runProbe(true)
			os.Exit(0)
		case "seccompcontrol":
			runProbe(false)
			os.Exit(0)
		case "seccompspawn":
			spawnProbe()
			os.Exit(0)
		case "hog":
			_, _ = ingest.ApplyWorkerLimits()
			b := make([]byte, 16<<30) // far past any limit the tests set
			b[len(b)-1] = 1
			fmt.Println(len(b))
			os.Exit(0)
		case "netcheck":
			_, _ = ingest.ApplyWorkerLimits()
			dev, _ := os.ReadFile("/proc/net/dev")
			var ifaces []string
			for _, l := range strings.Split(string(dev), "\n")[2:] {
				if i := strings.IndexByte(l, ':'); i > 0 {
					ifaces = append(ifaces, strings.TrimSpace(l[:i]))
				}
			}
			resp := map[string]any{"error": map[string]string{"category": "x", "message": "m", "detail": strings.Join(ifaces, ",")}}
			_ = json.NewEncoder(os.Stdout).Encode(resp)
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

// script writes an executable shell script that ignores its arguments and runs
// body, and returns its path. Subprocess always starts `Exe parse-worker`.
func script(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "worker.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func self(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// sampleFiles returns the repository fixtures with the parser that claims each.
func sampleFiles(t *testing.T) (files []string, roots []string) {
	t.Helper()
	for _, dir := range []string{"native_samples", "synthetic_case"} {
		root := filepath.Join("..", "..", "testdata", dir)
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err == nil && info.Mode().IsRegular() {
				files = append(files, p)
				roots = append(roots, root)
			}
			return nil
		})
	}
	return
}

// Running a parser in the child process gives the same events as running it in
// this one, and the same classification of a file that fails to parse.
func TestIsolation_ResultsAreIdenticalToInProcess(t *testing.T) {
	t.Run("process", func(t *testing.T) {
		equivalence(t, ingest.Subprocess{Exe: self(t), MemoryMB: 4096, Timeout: time.Minute})
	})
	t.Run("sandbox", func(t *testing.T) {
		bwrap := ingest.FindSandbox()
		if bwrap == "" {
			t.Skip("bubblewrap is not usable here")
		}
		equivalence(t, ingest.Subprocess{Exe: self(t), MemoryMB: 4096, Timeout: time.Minute, Sandbox: bwrap})
	})
}

func equivalence(t *testing.T, sub ingest.Subprocess) {
	t.Helper()
	files, roots := sampleFiles(t)
	compared, failed := 0, 0
	for i, f := range files {
		rel, _ := filepath.Rel(roots[i], f)
		rel = filepath.ToSlash(rel)
		for _, p := range ingest.Registry() {
			if !p.Detect(rel) {
				continue
			}
			want, werr := inProc(p, f, ingestCtx(rel))
			got, gerr := sub.Run(p, roots[i], f, ingestCtx(rel))
			if (werr == nil) != (gerr == nil) {
				t.Fatalf("%s via %s: in-process err=%v, isolated err=%v", rel, p.Name(), werr, gerr)
			}
			if werr != nil {
				wc, wm := api.ClassifyParseError(werr)
				gc, gm := api.ClassifyParseError(gerr)
				if wc != gc || wm != gm {
					t.Errorf("%s: classification differs: %q/%q vs %q/%q", rel, wc, wm, gc, gm)
				}
				failed++
				continue
			}
			a, _ := json.Marshal(want)
			b, _ := json.Marshal(got)
			if string(a) != string(b) {
				t.Errorf("%s via %s: the events differ after crossing the process boundary", rel, p.Name())
			}
			compared++
		}
	}
	t.Logf("%d parses compared, %d error classifications compared", compared, failed)
	if compared < 5 || failed < 1 {
		t.Fatalf("too little covered: %d parses, %d failing files", compared, failed)
	}
}

func TestIsolation_AMemoryHogOnlyFailsItsOwnParse(t *testing.T) {
	hog := script(t, fmt.Sprintf("exec %s hog", self(t)))
	sub := ingest.Subprocess{Exe: hog, MemoryMB: 512, Timeout: time.Minute}
	_, err := sub.Run(anyParser(t), "", "/nonexistent", ingestCtx(""))
	var pf *ingest.ProcessFailure
	if !errors.As(err, &pf) {
		t.Fatalf("want a ProcessFailure, got %v", err)
	}
	cat, _ := api.ClassifyParseError(err)
	if cat != api.ParseFailureLimit {
		t.Errorf("category %q, want %q", cat, api.ParseFailureLimit)
	}
	// The server is still here, and the next parse works.
	good := ingest.Subprocess{Exe: self(t), MemoryMB: 4096, Timeout: time.Minute}
	files, roots := sampleFiles(t)
	for i, f := range files {
		rel, _ := filepath.Rel(roots[i], f)
		rel = filepath.ToSlash(rel)
		for _, p := range ingest.Registry() {
			if !p.Detect(rel) {
				continue
			}
			if _, err := inProc(p, f, ingestCtx(rel)); err != nil {
				continue // a fixture that fails to parse is not a good control
			}
			if _, err := good.Run(p, roots[i], f, ingestCtx(rel)); err != nil {
				t.Fatalf("a normal parse after the hog failed: %v", err)
			}
			return
		}
	}
	t.Fatal("no fixture parses cleanly to use as the control")
}

func TestIsolation_ATimeoutStopsTheWorker(t *testing.T) {
	sub := ingest.Subprocess{Exe: script(t, "exec sleep 60"), Timeout: time.Second}
	start := time.Now()
	_, err := sub.Run(anyParser(t), "", "/x", ingestCtx(""))
	var pf *ingest.ProcessFailure
	if !errors.As(err, &pf) || !strings.Contains(pf.Reason, "time limit") {
		t.Fatalf("want a time-limit ProcessFailure, got %v", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("took %s to stop a worker with a 1s limit", d)
	}
}

func TestIsolation_GarbageAndHugeOutputAreRefused(t *testing.T) {
	garbage := ingest.Subprocess{Exe: script(t, "echo 'not json at all'"), Timeout: 10 * time.Second}
	if _, err := garbage.Run(anyParser(t), "", "/x", ingestCtx("")); !isProcessFailure(err) {
		t.Fatalf("garbage output: want a ProcessFailure, got %v", err)
	}
	huge := ingest.Subprocess{Exe: script(t, "yes '{' | head -c 3000000"), Timeout: 10 * time.Second, MaxOutputBytes: 1 << 20}
	_, err := huge.Run(anyParser(t), "", "/x", ingestCtx(""))
	var pf *ingest.ProcessFailure
	if !errors.As(err, &pf) {
		t.Fatalf("huge output: want a ProcessFailure, got %v", err)
	}
}

func TestIsolation_WorkerHasNoNetworkInterfaces(t *testing.T) {
	if !ingest.NetworkIsolationAvailable() {
		t.Skip("this kernel does not allow an unprivileged network namespace")
	}
	sub := ingest.Subprocess{Exe: script(t, fmt.Sprintf("exec %s netcheck", self(t))), Timeout: 20 * time.Second, NoNetwork: true}
	_, err := sub.Run(anyParser(t), "", "/x", ingestCtx(""))
	var ce *ingest.ClassifiedError
	if !errors.As(err, &ce) {
		t.Fatalf("want the worker's report, got %v", err)
	}
	if strings.Contains(ce.Detail, "eth") || strings.Contains(ce.Detail, "en") || strings.Contains(ce.Detail, "wl") {
		t.Fatalf("the worker sees network interfaces: %q", ce.Detail)
	}
	t.Logf("interfaces seen by the worker: %q", ce.Detail)
}

func isProcessFailure(err error) bool {
	var pf *ingest.ProcessFailure
	return errors.As(err, &pf)
}

func ingestCtx(rel string) parsers.ParseContext { return parsers.ParseContext{EvidencePath: rel} }

func anyParser(t *testing.T) parsers.ArtifactParser {
	t.Helper()
	return ingest.Registry()[0]
}

// inProc runs a parser the way the in-process runner does.
func inProc(p parsers.ArtifactParser, f string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
	if cp, ok := p.(parsers.ContextualParser); ok {
		return cp.ParseWithContext(f, ctx)
	}
	return p.Parse(f)
}

// Inside the sandbox the worker sees the evidence directory and nothing else of
// the server's files, and has no network interface but a loopback.
func TestIsolation_SandboxConfinesTheWorker(t *testing.T) {
	bwrap := ingest.FindSandbox()
	if bwrap == "" {
		t.Skip("bubblewrap is not usable here")
	}
	root := t.TempDir()
	inside := filepath.Join(root, "evidence.txt")
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "secret.txt")
	for _, f := range []string{inside, outside} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	body := fmt.Sprintf(`seen() { [ -e "$1" ] && echo readable || echo hidden; }
printf '{"error":{"category":"x","message":"m","detail":"inside=%%s outside=%%s parent=%%s net=%%s"}}' \
  "$(seen %s)" "$(seen %s)" "$(ls -1 %s | tr '\n' ,)" "$(tr '\n' ' ' </proc/net/dev | grep -o '[a-z0-9]*:' | tr -d '\n')"
`, inside, outside, filepath.Dir(root))
	exe := script(t, body)
	sub := ingest.Subprocess{Exe: exe, Timeout: 20 * time.Second, Sandbox: bwrap}
	_, err := sub.Run(anyParser(t), root, inside, ingestCtx(""))
	var ce *ingest.ClassifiedError
	if !errors.As(err, &ce) {
		t.Fatalf("want the worker's report, got %v", err)
	}
	t.Logf("worker report: %s", ce.Detail)
	if strings.Contains(ce.Detail, filepath.Base(outsideDir)+",") {
		t.Errorf("a sibling directory outside the evidence root is visible: %q", ce.Detail)
	}
	for _, want := range []string{"inside=readable", "outside=hidden", "parent=" + filepath.Base(root) + ",", "net=lo:"} {
		if !strings.Contains(ce.Detail, want) {
			t.Errorf("report %q lacks %q", ce.Detail, want)
		}
	}
}
