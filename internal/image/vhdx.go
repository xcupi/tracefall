package image

import "fmt"

// openVHDX reads a Hyper-V VHDX (fixed and dynamic). Not implemented yet: say so rather than
// misread it as a raw disk.
func openVHDX(paths []string) (Image, error) {
	return nil, fmt.Errorf("%w: VHDX reading is not implemented", ErrUnsupported)
}
