package wmirepo

import "fmt"

// Project maps a record-relative field range back to physical file extents.
// Overlap, holes, invalid ranges and arithmetic overflow fail closed.
func Project(spans []Span, offset, length int) ([]Span, error) {
	if offset < 0 || length <= 0 || offset > int(^uint(0)>>1)-length {
		return nil, fmt.Errorf("%w: field span range", ErrCorrupt)
	}
	end := offset + length
	covered := offset
	out := []Span{}
	for _, s := range spans {
		if s.RecordOffset < 0 || s.Length <= 0 || s.RecordOffset > int(^uint(0)>>1)-s.Length || s.Offset < 0 || s.Offset > int64(^uint64(0)>>1)-int64(s.Length) {
			return nil, fmt.Errorf("%w: physical extent range", ErrCorrupt)
		}
		lo, hi := max(offset, s.RecordOffset), min(end, s.RecordOffset+s.Length)
		if lo >= hi {
			continue
		}
		if lo != covered {
			return nil, fmt.Errorf("%w: overlapping or incomplete field spans", ErrCorrupt)
		}
		out = append(out, Span{File: s.File, Offset: s.Offset + int64(lo-s.RecordOffset), Length: hi - lo, RecordOffset: lo})
		covered = hi
	}
	if covered != end {
		return nil, fmt.Errorf("%w: incomplete field spans", ErrCorrupt)
	}
	return out, nil
}
