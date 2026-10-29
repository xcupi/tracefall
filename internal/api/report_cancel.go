package api

import (
	"context"
	"io"
	"net/http"
)

// opCtx is the context a heavy operation runs under: the request it serves, or
// Background outside a request (the pipeline), where there is nothing to cancel.
func (s *Service) opCtx() context.Context {
	if s.reqCtx != nil {
		return s.reqCtx
	}
	return context.Background()
}

// checkpoint marks a phase boundary of a report build. It reports the
// operation's context error, so a build whose client left stops at the next
// boundary instead of running every remaining phase. A phase observer carried
// by the context (never a package variable) lets a test cancel at an exact,
// named point without sleeping.
func (s *Service) checkpoint(phase string) error {
	if fn, ok := s.opCtx().Value(phaseObserverKey{}).(func(string)); ok {
		fn(phase)
	}
	return s.opCtx().Err()
}

type phaseObserverKey struct{}

// ctxWriter stops a long write once ctx is done. It is how a CPU-bound writer
// (template execution, the ZIP stream) notices a departed client.
type ctxWriter struct {
	ctx context.Context
	w   io.Writer
}

func (c ctxWriter) Write(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.w.Write(p)
}

// clientGone reports whether err is the request's own cancellation. It checks
// the request context as well as the error: a renderer deadline also unwraps to
// context.DeadlineExceeded, and that is a failed render to report, not a client
// that left.
func clientGone(r *http.Request, err error) bool {
	return err != nil && isCancelled(err) && r.Context().Err() != nil
}
