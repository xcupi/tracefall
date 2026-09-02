package browsercacheindex

import (
	"io"
	"os"

	"tracefall/internal/parsers"
)

// readHead reads the leading bytes needed to tell the two container
// formats apart. Both declare themselves in their first few dozen bytes,
// so the whole file is never loaded just to identify it.
func readHead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, parsers.SniffLength)
	n, err := io.ReadFull(f, buf)
	if n == 0 && err != nil {
		return nil, err
	}
	return buf[:n], nil
}
