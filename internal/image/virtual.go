package image

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
)

// Detection of the virtual disk containers. Each is identified from the file's
// contents, never its extension. The readers live in vhd.go, vhdx.go and
// vmdk.go.
const (
	vhdxSignature   = "vhdxfile"
	vmdkSparseMagic = "KDMV"
	vhdCookie       = "conectix"
)

// isVHD reports whether path is a Virtual PC / Hyper-V VHD. A dynamic or
// differencing VHD begins with a copy of its 512-byte footer; a fixed VHD is the
// raw disk followed by the footer, so only the end of the file tells.
func isVHD(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var head [8]byte
	if n, _ := io.ReadFull(f, head[:]); n == 8 && string(head[:]) == vhdCookie {
		return true
	}
	st, err := f.Stat()
	if err != nil || st.Size() < 512 {
		return false
	}
	var foot [512]byte
	if _, err := f.ReadAt(foot[:], st.Size()-512); err != nil {
		return false
	}
	return bytes.HasPrefix(foot[:], []byte(vhdCookie))
}

// isVMDKDescriptor reports whether path is a VMDK text descriptor (a small
// file whose first non-blank line is "# Disk DescriptorFile"). The extents it
// names are separate files.
func isVMDKDescriptor(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 64)
	n, _ := f.Read(buf)
	return bytes.HasPrefix(bytes.TrimLeft(buf[:n], " \t\r\n\xef\xbb\xbf"), []byte("# Disk DescriptorFile"))
}

// IsVirtualDisk reports whether path is a VHD, VHDX or VMDK container, from its
// contents. It claims the file even when the reader would refuse it (a
// differencing disk, say), so the analyst is told why instead of being told the
// file is unrecognised.
func IsVirtualDisk(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	var head [8]byte
	n, _ := io.ReadFull(f, head[:])
	f.Close()
	switch {
	case n == 8 && string(head[:]) == vhdxSignature:
		return true
	case n >= 4 && string(head[:4]) == vmdkSparseMagic:
		return true
	}
	return isVMDKDescriptor(path) || isVHD(path)
}

// vmdkSegments returns the files that make up a VMDK given its descriptor (or
// the first sparse extent of a split set): the descriptor, then every extent it
// names, in order. The evidence fingerprint is taken over this list, so it must
// cover the extents that hold the disk and not only a few hundred bytes of
// descriptor text.
//
// It never invents or skips anything: if the file is not a VMDK, an extent name
// is not a plain file name inside the directory, an extent is missing or the
// layout cannot be reconciled, it returns just the given path, and Open then
// reports the real reason.
func vmdkSegments(first string) []string {
	alone := []string{first}
	f, err := os.Open(first)
	if err != nil {
		return alone
	}
	defer f.Close()
	var magic [4]byte
	f.ReadAt(magic[:], 0)
	var text string
	sparse := string(magic[:]) == vmdkSparseMagic
	switch {
	case sparse:
		ext, err := newSparseExtent(f)
		if err != nil || ext.desc == "" {
			return alone
		}
		text = ext.desc
	case isVMDKDescriptor(first):
		if text, err = readVMDKDescriptorFile(f); err != nil {
			return alone
		}
	default:
		return alone
	}
	d, err := parseVMDKDescriptor(text)
	if err != nil || len(d.extents) == 0 {
		return alone
	}
	dir := filepath.Dir(first)
	realFirst, err := filepath.EvalSymlinks(first)
	if err != nil {
		return alone
	}
	var out []string
	if !sparse {
		out = append(out, first)
	}
	seen := map[string]bool{}
	for i, e := range d.extents {
		p, err := vmdkExtentPath(dir, e.name)
		if err != nil {
			return alone
		}
		if st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() {
			return alone
		}
		if sparse && i == 0 {
			if p != realFirst {
				return alone // the given file is not the first extent; do not guess
			}
			p = first
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	if sparse && len(out) < 2 {
		return alone
	}
	return out
}
