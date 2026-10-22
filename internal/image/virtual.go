package image

import (
	"bytes"
	"io"
	"os"
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
