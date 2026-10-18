package image

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// rawImage presents one or more files, in order, as a single disk.
type rawImage struct {
	files []*os.File
	start []int64 // byte offset where each file begins
	size  int64
}

func openRaw(paths []string) (Image, error) {
	r := &rawImage{}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			r.Close()
			return nil, err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			r.Close()
			return nil, err
		}
		if st.IsDir() {
			f.Close()
			r.Close()
			return nil, fmt.Errorf("image: %s is a directory", p)
		}
		r.files = append(r.files, f)
		r.start = append(r.start, r.size)
		r.size += st.Size()
	}
	if r.size == 0 {
		r.Close()
		return nil, fmt.Errorf("%w: the image is empty", ErrCorrupt)
	}
	return r, nil
}

func (r *rawImage) Size() int64 { return r.size }

func (r *rawImage) Info() Info {
	return Info{Format: FormatRaw, Size: r.size, SectorSize: 512, Segments: len(r.files)}
}

func (r *rawImage) Close() error {
	var first error
	for _, f := range r.files {
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (r *rawImage) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("image: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.size {
		return 0, io.EOF
	}
	total := 0
	for total < len(p) && off < r.size {
		// the segment holding off
		i := len(r.files) - 1
		for i > 0 && r.start[i] > off {
			i--
		}
		local := off - r.start[i]
		segEnd := r.size
		if i+1 < len(r.files) {
			segEnd = r.start[i+1]
		}
		want := int64(len(p) - total)
		if avail := segEnd - off; want > avail {
			want = avail
		}
		n, err := r.files[i].ReadAt(p[total:total+int(want)], local)
		total += n
		off += int64(n)
		if err != nil && !(errors.Is(err, io.EOF) && int64(n) == want) {
			if errors.Is(err, io.EOF) {
				err = fmt.Errorf("%w: segment %d is shorter than when it was opened", ErrCorrupt, i)
			}
			return total, err
		}
	}
	if total < len(p) {
		return total, io.EOF
	}
	return total, nil
}
