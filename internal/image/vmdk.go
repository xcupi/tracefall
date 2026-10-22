package image

import "fmt"

// openVMDK reads a VMware VMDK (monolithic sparse, stream optimized, flat and split extents). Not implemented yet: say so rather than
// misread it as a raw disk.
func openVMDK(paths []string) (Image, error) {
	return nil, fmt.Errorf("%w: VMDK reading is not implemented", ErrUnsupported)
}
