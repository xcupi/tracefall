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
	"os/exec"
	"path/filepath"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

type streamFrame struct {
	CompressedBatch []byte               `json:"compressed_batch,omitempty"`
	Batch           *parsers.ParseResult `json:"batch,omitempty"`
	Coverage        *model.ParseCoverage `json:"coverage,omitempty"`
	Error           *workerError         `json:"error,omitempty"`
	Done            bool                 `json:"done,omitempty"`
}

// RunStream preserves synchronous sink backpressure across the worker pipe.
// Unlike Run, it never collects the complete result. Existing process memory,
// deadline, total-output and sandbox bounds apply unchanged.
func (s Subprocess) RunStream(parent context.Context, p parsers.ArtifactParser, root, abs string, pc parsers.ParseContext, sink parsers.RecordSink) (*model.ParseCoverage, error) {
	if _, ok := p.(parsers.StreamingParser); !ok {
		return nil, fmt.Errorf("parser %s does not support streaming", p.Name())
	}
	var err error
	abs, err = filepath.Abs(abs)
	if err != nil {
		return nil, err
	}
	if root != "" {
		root, err = filepath.Abs(root)
		if err != nil {
			return nil, err
		}
	}
	if s.Limit != nil {
		release, err := s.Limit.Acquire(parent)
		if err != nil {
			return nil, err
		}
		defer release()
	}
	ctx, cancel := context.WithTimeout(parent, s.timeout())
	defer cancel()
	req, err := json.Marshal(workerRequest{Parser: p.Name(), Path: abs, Context: pc, Stream: true})
	if err != nil {
		return nil, err
	}
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
	cmd.WaitDelay = 3 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, &ProcessFailure{Reason: "could not start worker: " + err.Error()}
	}
	max := s.maxOutput()
	lr := &io.LimitedReader{R: stdout, N: max + 1}
	scan := bufio.NewScanner(lr)
	scan.Buffer(make([]byte, 64<<10), 16<<20)
	var cov *model.ParseCoverage
	done := false
	received, undated := 0, 0
	var readErr error
	var consumerErr error
	for scan.Scan() {
		if done {
			readErr = fmt.Errorf("worker returned data after terminal frame")
			break
		}
		var frame streamFrame
		if err = json.Unmarshal(scan.Bytes(), &frame); err != nil {
			readErr = err
			break
		}
		if frame.CompressedBatch != nil {
			if frame.Batch != nil || frame.Done || frame.Error != nil || frame.Coverage != nil {
				readErr = fmt.Errorf("invalid compressed stream frame")
				break
			}
			z, e := gzip.NewReader(bytes.NewReader(frame.CompressedBatch))
			if e != nil {
				readErr = e
				break
			}
			data, e := io.ReadAll(io.LimitReader(z, (16<<20)+1))
			closeErr := z.Close()
			if e != nil {
				readErr = e
				break
			}
			if closeErr != nil {
				readErr = closeErr
				break
			}
			if len(data) > 16<<20 {
				readErr = fmt.Errorf("decoded stream frame exceeds 16 MiB")
				break
			}
			frame.Batch = &parsers.ParseResult{}
			if e = json.Unmarshal(data, frame.Batch); e != nil {
				readErr = e
				break
			}
		}
		if frame.Batch != nil && !frame.Done && frame.Error == nil && frame.Coverage == nil {
			if len(frame.Batch.Events) != len(frame.Batch.Raw) {
				readErr = fmt.Errorf("stream event/raw count mismatch")
				break
			}
			for i, e := range frame.Batch.Events {
				if e.SourceReference == "" || e.SourceReference != frame.Batch.Raw[i].SourceReference {
					readErr = fmt.Errorf("stream event/raw source reference mismatch")
					break
				}
			}
			if readErr != nil {
				break
			}
			if err = sink(*frame.Batch); err != nil {
				consumerErr = err
				readErr = err
				break
			}
			received += len(frame.Batch.Events)
			for _, e := range frame.Batch.Events {
				if e.Timestamp.IsZero() {
					undated++
				}
			}
		} else if frame.Done && frame.Batch == nil {
			done = true
			cov = frame.Coverage
			if frame.Error != nil {
				readErr = &ClassifiedError{Category: frame.Error.Category, Message: frame.Error.Message, Detail: frame.Error.Detail}
			}
		} else {
			readErr = fmt.Errorf("invalid stream frame")
			break
		}
	}
	if readErr == nil {
		readErr = scan.Err()
	}
	overflow := lr.N <= 0
	if readErr != nil || overflow || !done {
		cancel()
	}
	waitErr := cmd.Wait()
	if overflow {
		return cov, &ProcessFailure{Reason: fmt.Sprintf("the result is larger than %d bytes", max)}
	}
	if ctx.Err() != nil && parent.Err() != nil {
		return cov, parent.Err()
	}
	if ctx.Err() == context.DeadlineExceeded {
		return cov, &ProcessFailure{Reason: fmt.Sprintf("it ran past the %s time limit and was stopped", s.timeout())}
	}
	if readErr != nil {
		var classified *ClassifiedError
		if consumerErr != nil || errors.As(readErr, &classified) {
			return cov, readErr
		}
		return cov, &ProcessFailure{Reason: describeExit(waitErr, stderr.String(), readErr)}
	}
	if waitErr != nil || !done {
		return cov, &ProcessFailure{Reason: describeExit(waitErr, stderr.String(), nil)}
	}
	if cov == nil {
		return nil, &ProcessFailure{Reason: "missing stream coverage"}
	}
	emitted := cov.Mapped
	if cov.EmittedEvents != nil {
		emitted = *cov.EmittedEvents
	}
	if emitted != received || (emitted > 0 && cov.Mapped == 0) || emitted < cov.Mapped || cov.RecordsRead < cov.Mapped || cov.Mapped < 0 || cov.Unmapped < 0 || cov.Undated != undated {
		return cov, &ProcessFailure{Reason: "stream coverage does not match received records"}
	}
	if cov.LimitReached || cov.RecordsFailed != 0 || cov.ChunksFailed != 0 {
		return cov, &ProcessFailure{Reason: "worker reported incomplete stream coverage without an error"}
	}
	return cov, nil
}
