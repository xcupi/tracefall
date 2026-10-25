package ingest

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"tracefall/internal/gate"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

// Artifact parsers read files that an attacker may have crafted. A parser can
// be made to allocate without bound, loop, or crash, and a Go out-of-memory
// error cannot be recovered: it ends the whole process. So parsing can run in
// a short-lived child process of its own, with a memory limit, a time limit, a
// bounded output and (on Linux, where available) no network. If the child
// dies, one file fails and the server carries on.
//
// The in-process path stays the default for tests and tools; the server turns
// the child process on (see cmd/tracefall).

// ParserRunner runs one parser on one file.
type ParserRunner interface {
	// root is the collection's evidence directory, absPath a file inside it.
	// A sandboxed runner makes only root readable to the parser.
	Run(p parsers.ArtifactParser, root, absPath string, ctx parsers.ParseContext) (parsers.ParseResult, error)
}

type inProcess struct{}

func (inProcess) Run(p parsers.ArtifactParser, _, abs string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
	if cp, ok := p.(parsers.ContextualParser); ok {
		return cp.ParseWithContext(abs, ctx)
	}
	return p.Parse(abs)
}

var runner ParserRunner = inProcess{}

// SetParserRunner chooses how parsers run. It is meant to be called once at
// start-up, before any parsing; nil restores the in-process runner.
func SetParserRunner(r ParserRunner) {
	if r == nil {
		r = inProcess{}
	}
	runner = r
}

// ClassifiedError is a parse error the worker has already classified, because
// the sentinel errors the classification depends on do not cross a process
// boundary. Category and Message are what the analyst sees.
type ClassifiedError struct {
	Category string
	Message  string
	Detail   string // the original error text, for logs
}

func (e *ClassifiedError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return e.Message
}

// ProcessFailure means the parser process did not return a result: it was
// killed (memory or time limit), crashed, or produced unusable output. It says
// nothing about the evidence being damaged.
type ProcessFailure struct {
	Reason string
}

func (e *ProcessFailure) Error() string { return "parser process failed: " + e.Reason }

// Subprocess runs each parse in a child process.
type Subprocess struct {
	// Exe is the program to run as the worker (normally os.Executable()). It
	// is started as `Exe parse-worker`.
	Exe string
	// MemoryMB is the child's address-space limit. 0 means 4096.
	MemoryMB int
	// Timeout bounds one parse. 0 means 20 minutes.
	Timeout time.Duration
	// MaxOutputBytes bounds the result the child may return. 0 means 1 GiB.
	MaxOutputBytes int64
	// Sandbox is the path of bubblewrap. When set (and root is known), the
	// worker runs in empty namespaces with a minimal read-only file system:
	// its own executable, the system libraries and the collection's evidence
	// directory. It cannot reach the network, the case database, other
	// cases' evidence or the server's keys. Empty means no sandbox.
	Sandbox string
	// Limit bounds how many workers run at once across the whole server. Every
	// worker may use up to MemoryMB, so without it the memory a burst of
	// imports can take is the number of imports times that. A parse that has
	// to wait holds no process and its time limit does not start until it
	// runs. Nil means unbounded.
	Limit *gate.Gate
	// NoNetwork asks, when there is no Sandbox, for a network namespace with
	// no interfaces, where the kernel allows it.
	NoNetwork bool
}

type workerRequest struct {
	Stream  bool                 `json:"stream,omitempty"`
	Parser  string               `json:"parser"`
	Path    string               `json:"path"`
	Context parsers.ParseContext `json:"context"`
}

type workerError struct {
	Category string `json:"category"`
	Message  string `json:"message"`
	Detail   string `json:"detail"`
}

type workerResponse struct {
	Result *parsers.ParseResult `json:"result,omitempty"`
	Error  *workerError         `json:"error,omitempty"`
}

func (s Subprocess) memoryMB() int {
	if s.MemoryMB > 0 {
		return s.MemoryMB
	}
	return 4096
}

func (s Subprocess) timeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return 20 * time.Minute
}

func (s Subprocess) maxOutput() int64 {
	if s.MaxOutputBytes > 0 {
		return s.MaxOutputBytes
	}
	return 1 << 30
}

// Run implements ParserRunner.
func (s Subprocess) Run(p parsers.ArtifactParser, root, abs string, pctx parsers.ParseContext) (parsers.ParseResult, error) {
	// The sandbox binds absolute paths, and the worker's working directory is
	// not the server's, so neither may be relative.
	if a, err := filepath.Abs(abs); err == nil {
		abs = a
	}
	if root != "" {
		if a, err := filepath.Abs(root); err == nil {
			root = a
		}
	}
	req, err := json.Marshal(workerRequest{Parser: p.Name(), Path: abs, Context: pctx})
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if s.Limit != nil {
		release, err := s.Limit.Acquire(context.Background())
		if err != nil {
			return parsers.ParseResult{}, &ProcessFailure{Reason: "waiting for a worker slot failed: " + err.Error()}
		}
		defer release()
	}
	// Trusted registered adapters may own a mandatory external-runtime sandbox.
	// Do not pass CoreCLR through the Go worker inherited RLIMIT_AS/seccomp.
	if own, ok := p.(interface{ OwnSandbox(string) bool }); ok && own.OwnSandbox(abs) {
		return inProcess{}.Run(p, root, abs, pctx)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout())
	defer cancel()

	name, args := s.Exe, []string{"parse-worker"}
	sandboxed := s.Sandbox != "" && root != ""
	if sandboxed {
		name, args = s.Sandbox, sandboxArgs(s.Exe, root)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = workerEnv(s.memoryMB(), sandboxed)
	cmd.Stdin = bytes.NewReader(req)
	var stderr limitedBuffer
	stderr.max = 8 << 10
	cmd.Stderr = &stderr
	configureChild(cmd, s.NoNetwork && !sandboxed)
	// A child that outlives its parser, or hands its pipes to a descendant,
	// must not hold Wait forever: after the process ends or is cancelled, the
	// pipes are closed by force after this delay.
	cmd.WaitDelay = 3 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if err := cmd.Start(); err != nil {
		return parsers.ParseResult{}, &ProcessFailure{Reason: "could not start the worker: " + err.Error()}
	}

	max := s.maxOutput()
	lr := &io.LimitedReader{R: stdout, N: max + 1}
	var resp workerResponse
	decErr := json.NewDecoder(lr).Decode(&resp)
	overflow := lr.N <= 0
	if decErr != nil || overflow {
		// Stop the child (and anything it started) before reporting.
		cancel()
	}
	waitErr := cmd.Wait()

	switch {
	case overflow:
		return parsers.ParseResult{}, &ProcessFailure{Reason: fmt.Sprintf("the result is larger than %d bytes", max)}
	case ctx.Err() == context.DeadlineExceeded:
		return parsers.ParseResult{}, &ProcessFailure{Reason: fmt.Sprintf("it ran past the %s time limit and was stopped", s.timeout())}
	case decErr != nil:
		return parsers.ParseResult{}, &ProcessFailure{Reason: describeExit(waitErr, stderr.String(), decErr)}
	case waitErr != nil:
		return parsers.ParseResult{}, &ProcessFailure{Reason: describeExit(waitErr, stderr.String(), nil)}
	}
	if resp.Error != nil {
		return parsers.ParseResult{}, &ClassifiedError{Category: resp.Error.Category, Message: resp.Error.Message, Detail: resp.Error.Detail}
	}
	if resp.Result == nil {
		return parsers.ParseResult{}, &ProcessFailure{Reason: "the worker returned neither a result nor an error"}
	}
	return *resp.Result, nil
}

func describeExit(waitErr error, stderr string, decErr error) string {
	var parts []string
	var ee *exec.ExitError
	switch {
	case errors.As(waitErr, &ee):
		parts = append(parts, "the process ended: "+ee.Error())
	case waitErr != nil:
		parts = append(parts, waitErr.Error())
	}
	if decErr != nil {
		parts = append(parts, "no readable result ("+decErr.Error()+")")
	}
	if s := strings.TrimSpace(stderr); s != "" {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[:i]
		}
		if len(s) > 200 {
			s = s[:200]
		}
		parts = append(parts, "worker said: "+s)
	}
	if len(parts) == 0 {
		return "the process ended without a result"
	}
	return strings.Join(parts, "; ")
}

// limitedBuffer keeps the first max bytes written and drops the rest, so a
// noisy child cannot grow the server's memory.
type limitedBuffer struct {
	b   bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.b.Len(); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		l.b.Write(p[:room])
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return l.b.String() }

// WorkerMain is the child's side. It reads one request from in, runs the named
// parser from the registry, and writes one response to out. classify turns a
// parse error into the category and message the analyst sees; it is passed in
// because that logic lives in the API layer.
//
// Anything the parser prints is sent to stderr, so it cannot corrupt the
// response on stdout.
func WorkerMain(in io.Reader, out io.Writer, classify func(error) (category, message string)) error {
	var req workerRequest
	if err := json.NewDecoder(io.LimitReader(in, 16<<20)).Decode(&req); err != nil {
		return fmt.Errorf("reading the request: %w", err)
	}
	var p parsers.ArtifactParser
	for _, c := range Registry() {
		if c.Name() == req.Parser {
			p = c
			break
		}
	}
	enc := json.NewEncoder(out)
	if p == nil {
		return enc.Encode(workerResponse{Error: &workerError{
			Category: "internal_error", Message: "The file could not be parsed.", Detail: "unknown parser " + req.Parser,
		}})
	}
	if req.Stream {
		sp, ok := p.(parsers.StreamingParser)
		if !ok {
			return fmt.Errorf("parser does not support streaming")
		}
		var packed bytes.Buffer
		z := gzip.NewWriter(&packed)
		cov, err := sp.ParseStream(context.Background(), req.Path, req.Context, func(batch parsers.ParseResult) error {
			if p.ArtifactType() == model.ArtifactMFT || p.ArtifactType() == model.ArtifactUsnJournal {
				data, err := json.Marshal(batch)
				if err != nil {
					return err
				}
				if len(data) > 16<<20 {
					return &ProcessFailure{Reason: "decoded stream frame exceeds 16 MiB"}
				}
				packed.Reset()
				z.Reset(&packed)
				if _, err = z.Write(data); err != nil {
					return err
				}
				if err = z.Close(); err != nil {
					return err
				}
				return enc.Encode(streamFrame{CompressedBatch: packed.Bytes()})
			}
			return enc.Encode(streamFrame{Batch: &batch})
		})
		frame := streamFrame{Done: true, Coverage: cov}
		if err != nil {
			cat, msg := classify(err)
			frame.Error = &workerError{Category: cat, Message: msg, Detail: err.Error()}
		}
		return enc.Encode(frame)
	}
	res, err := inProcess{}.Run(p, "", req.Path, req.Context)
	if err != nil {
		cat, msg := classify(err)
		return enc.Encode(workerResponse{Error: &workerError{Category: cat, Message: msg, Detail: err.Error()}})
	}
	return writeResult(out, res)
}

// writeResult writes {"result":{"Events":[...],"Raw":[...]}} one element at a
// time. Encoding the whole result with one Encode call builds all of it in a
// single buffer first, which doubled the worker's memory for a large $MFT and
// ran it out of address space.
func writeResult(out io.Writer, res parsers.ParseResult) error {
	bw := bufio.NewWriterSize(out, 1<<20)
	list := func(name string, isNil bool, n int, elem func(i int) ([]byte, error)) error {
		if isNil { // same as encoding/json: a nil slice is null, an empty one is []
			_, err := fmt.Fprintf(bw, "%q:null", name)
			return err
		}
		if _, err := fmt.Fprintf(bw, "%q:[", name); err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			if i > 0 {
				bw.WriteByte(',')
			}
			b, err := elem(i)
			if err != nil {
				return err
			}
			if _, err := bw.Write(b); err != nil {
				return err
			}
		}
		_, err := bw.WriteString("]")
		return err
	}
	bw.WriteString(`{"result":{`)
	if err := list("Events", res.Events == nil, len(res.Events), func(i int) ([]byte, error) { return json.Marshal(res.Events[i]) }); err != nil {
		return err
	}
	bw.WriteByte(',')
	if err := list("Raw", res.Raw == nil, len(res.Raw), func(i int) ([]byte, error) { return json.Marshal(res.Raw[i]) }); err != nil {
		return err
	}
	if res.Coverage != nil {
		b, err := json.Marshal(res.Coverage)
		if err != nil {
			return err
		}
		bw.WriteString(`,"Coverage":`)
		if _, err := bw.Write(b); err != nil {
			return err
		}
	}
	bw.WriteString("}}\n")
	return bw.Flush()
}

// SelfPath is the running executable, the program to use as the worker.
func SelfPath() (string, error) { return os.Executable() }
