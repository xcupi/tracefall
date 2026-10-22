package image

import "fmt"

// openVHD reads a Virtual PC / Hyper-V VHD (fixed and dynamic). Not implemented yet: say so rather than
// misread it as a raw disk.
func openVHD(paths []string) (Image, error) {
	return nil, fmt.Errorf("%w: VHD reading is not implemented", ErrUnsupported)
}
