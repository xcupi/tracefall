package report

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

// flipCtx reports Canceled from its n-th Err call on. It is deterministic
// because rendering is single goroutine; it proves the template writer checks
// the context while executing, not only before and after.
type flipCtx struct {
	context.Context
	calls atomic.Int64
	after int64
}

func (f *flipCtx) Err() error {
	if f.calls.Add(1) > f.after {
		return context.Canceled
	}
	return nil
}

func TestRenderContext_StopsInsideTemplateExecution(t *testing.T) {
	ctx := &flipCtx{Context: context.Background(), after: 5}
	out, err := RenderContext(ctx, sampleData())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if out != nil {
		t.Fatal("a cancelled render returned a document")
	}
	if ctx.calls.Load() <= 3 {
		t.Fatalf("the context was only checked at the edges (%d calls)", ctx.calls.Load())
	}
}

func TestRenderContext_SuccessIsByteIdenticalToRender(t *testing.T) {
	want, err := Render(sampleData())
	if err != nil {
		t.Fatal(err)
	}
	got, err := RenderContext(context.Background(), sampleData())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("RenderContext output differs from Render")
	}
}
