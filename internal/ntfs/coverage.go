package ntfs

import (
	"context"
	"errors"

	"tracefall/internal/model"
)

// FailureClass names why an NTFS source stopped, from the error alone. A stop
// forced from outside (limit, cancellation, deadline) is never reported as
// damage, and damage is never reported as a limit.
func FailureClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrLimitExceeded), errors.Is(err, ErrCancelled), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return model.NtfsFailureLimit
	case errors.Is(err, ErrNotUSN):
		return model.NtfsFailureNotAJournal
	case errors.Is(err, ErrNotMFT):
		return model.NtfsFailureNotAnMFT
	case errors.Is(err, ErrNotLogFile):
		return model.NtfsFailureNotALogFile
	case errors.Is(err, ErrUnsupportedUSNVersion):
		return model.NtfsFailureUnsupported
	case errors.Is(err, ErrCorrupt):
		return model.NtfsFailureCorrupt
	}
	return model.NtfsFailureOther
}

// RecordFailure marks the NTFS part of cov as a failed source. offset is the
// best-known byte offset (nil when none is known). It does nothing for a
// failure of the consumer (sink), which says nothing about the source.
func RecordFailure(n *model.NtfsCoverage, err error, offset *int64) {
	if n == nil || err == nil {
		return
	}
	n.Failed = true
	n.FailureClass = FailureClass(err)
	if off, ok := ErrorOffset(err); ok {
		n.FailureOffset = &off
	} else if offset != nil {
		o := *offset
		n.FailureOffset = &o
	}
}
