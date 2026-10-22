// Package image reads forensic disk-image containers: raw (dd) files,
// including split sets, and EWF1 (E01/EnCase) images.
//
// Everything is read-only and presents the same view: a flat, seekable
// byte range (io.ReaderAt) holding the original media, with the
// container's own framing, compression and checksums removed. Whatever
// sits above it (partition tables, file systems) never learns which
// container the bytes came from.
//
// # Honesty about integrity
//
// A decoded read is checked against the container's own per-chunk
// checksums, and a mismatch is an error wrapping ErrCorrupt, never
// silently wrong data. Verify additionally hashes the whole decoded
// image and compares it with the digests the acquisition tool recorded;
// for a raw image there is nothing recorded, and the result says so
// instead of implying a match.
//
// Not supported, and reported as ErrUnsupported rather than misread:
// Ex01 (EWF2), L01 logical evidence, encrypted containers, and EWF
// images whose segments exceed the 31-bit offset range of the table.
package image

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Format names a container format.
type Format string

const (
	FormatRaw Format = "raw"
	FormatEWF Format = "ewf"
	// Virtual disk containers (Hyper-V, VMware). Their framing, block maps and
	// sparse holes are removed, so the view is the guest's disk.
	FormatVHD  Format = "vhd"
	FormatVHDX Format = "vhdx"
	FormatVMDK Format = "vmdk"
)

var (
	// ErrCorrupt means the container is damaged or internally inconsistent.
	ErrCorrupt = errors.New("image is corrupt")
	// ErrUnsupported means the container is valid but of a kind this
	// package deliberately does not read.
	ErrUnsupported = errors.New("image format is not supported")
)

// Info describes an opened image.
type Info struct {
	Format     Format
	Size       int64
	SectorSize int
	Segments   int
	// StoredMD5 and StoredSHA1 are the digests the acquisition tool
	// recorded inside the container, lower-case hex, or "".
	StoredMD5, StoredSHA1 string
	// Meta carries acquisition details recorded in the container
	// (case_number, evidence_number, examiner, description, notes,
	// acquisition_date, system_date, operating_system, software_version).
	Meta map[string]string
}

// Image is a read-only view of the original media.
type Image interface {
	io.ReaderAt
	Size() int64
	Info() Info
	Close() error
}

// Open opens an image given all of its segment files in order, which
// FindSegments produces from the first one. The format is identified from
// the file's contents, not its extension.
func Open(paths ...string) (Image, error) {
	if len(paths) == 0 {
		return nil, errors.New("image: no path given")
	}
	f, err := os.Open(paths[0])
	if err != nil {
		return nil, err
	}
	var magic [8]byte
	n, _ := io.ReadFull(f, magic[:])
	f.Close()
	switch {
	case n == 8 && string(magic[:]) == ewf1Signature:
		return openEWF(paths)
	case n == 8 && string(magic[:4]) == "EVF2":
		return nil, fmt.Errorf("%w: Ex01 (EWF version 2) images are not read yet", ErrUnsupported)
	case n == 8 && string(magic[:3]) == "LVF":
		return nil, fmt.Errorf("%w: L01 logical evidence files are not read yet", ErrUnsupported)
	case n == 8 && string(magic[:]) == vhdxSignature:
		return openVHDX(paths)
	case n >= 4 && string(magic[:4]) == vmdkSparseMagic, n >= 8 && isVMDKDescriptor(paths[0]):
		return openVMDK(paths)
	case isVHD(paths[0]):
		return openVHD(paths)
	}
	return openRaw(paths)
}

// FindSegments returns the full ordered segment list for the first
// segment of a split image: E01, E02 ... E99, EAA ... for EWF, or
// .001, .002 ... for raw. Any other path is returned alone.
func FindSegments(first string) ([]string, error) {
	if _, err := os.Stat(first); err != nil {
		return nil, err
	}
	dir, name := filepath.Split(first)
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	var next func(i int) string
	switch {
	case len(ext) == 4 && (ext[1] == 'E' || ext[1] == 'e') && ext[2:] == "01":
		letter := string(ext[1])
		next = func(i int) string { return stem + "." + letter + ewfSegmentSuffix(i) }
	case ext == ".001":
		next = func(i int) string { return fmt.Sprintf("%s.%03d", stem, i) }
	default:
		return []string{first}, nil
	}
	out := []string{first}
	for i := 2; i < 100000; i++ {
		p := filepath.Join(dir, next(i))
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			break
		}
		out = append(out, p)
	}
	return out, nil
}

// ewfSegmentSuffix returns the two characters after "E": 01..99, then
// AA..ZZ, matching EnCase's naming.
func ewfSegmentSuffix(i int) string {
	if i < 100 {
		return fmt.Sprintf("%02d", i)
	}
	j := i - 100
	return string([]byte{byte('A' + (j/26)%26), byte('A' + j%26)})
}

// VerifyResult is the outcome of hashing a whole image.
type VerifyResult struct {
	Bytes                 int64
	MD5, SHA1, SHA256     string
	StoredMD5, StoredSHA1 string
	// MD5Match and SHA1Match are nil when the container stored no such
	// digest: there was nothing to compare, which is not a match.
	MD5Match, SHA1Match *bool
}

// Verify reads the whole decoded image, hashes it, and compares it with
// the digests recorded at acquisition. progress, if non-nil, receives
// (bytes done, total) after each block. Any chunk that fails its own
// checksum aborts with an error wrapping ErrCorrupt.
func Verify(img Image, progress func(done, total int64)) (VerifyResult, error) {
	var hm, hs1, hs2 hash.Hash = md5.New(), sha1.New(), sha256.New()
	w := io.MultiWriter(hm, hs1, hs2)
	size := img.Size()
	buf := make([]byte, 4<<20)
	var done int64
	for done < size {
		n := int64(len(buf))
		if size-done < n {
			n = size - done
		}
		got, err := img.ReadAt(buf[:n], done)
		if int64(got) != n {
			if err == nil || errors.Is(err, io.EOF) {
				err = fmt.Errorf("%w: short read at %d", ErrCorrupt, done)
			}
			return VerifyResult{}, err
		}
		w.Write(buf[:n])
		done += n
		if progress != nil {
			progress(done, size)
		}
	}
	in := img.Info()
	res := VerifyResult{
		Bytes: done, MD5: hex.EncodeToString(hm.Sum(nil)), SHA1: hex.EncodeToString(hs1.Sum(nil)),
		SHA256: hex.EncodeToString(hs2.Sum(nil)), StoredMD5: in.StoredMD5, StoredSHA1: in.StoredSHA1,
	}
	if in.StoredMD5 != "" {
		m := strings.EqualFold(in.StoredMD5, res.MD5)
		res.MD5Match = &m
	}
	if in.StoredSHA1 != "" {
		m := strings.EqualFold(in.StoredSHA1, res.SHA1)
		res.SHA1Match = &m
	}
	return res, nil
}
