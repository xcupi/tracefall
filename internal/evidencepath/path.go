package evidencepath

import (
	"errors"
	"os"
)

var ErrUnsafe = errors.New("unavailable or unsafe evidence path")

func Open(root, rel string) (*os.File, error)   { return open(root, rel, false) }
func Create(root, rel string) (*os.File, error) { return open(root, rel, true) }
