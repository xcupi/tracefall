// Package fsvol is the file-system-neutral view of a volume: the types the
// disk-image catalog and extractor use, shared by every file system reader
// (NTFS, ext2/3/4). A reader implements Volume and lists its in-use files
// with paths that start at "/", the root being "/".
package fsvol

import (
	"errors"
	"time"
)

var (
	// ErrNotFound means the record or stream does not exist.
	ErrNotFound = errors.New("not found")
	// ErrCorrupt means a structure on the volume is damaged or inconsistent.
	ErrCorrupt = errors.New("file system structure is corrupt")
	// ErrUnsupported means the volume or file uses a feature the reader does
	// not implement. It is reported, never guessed around.
	ErrUnsupported = errors.New("file system feature is not supported")
	// ErrEncrypted means the file's content is encrypted and cannot be read.
	ErrEncrypted = errors.New("encrypted content cannot be read")
)

// Info describes a volume.
type Info struct {
	Label       string
	Version     string // the file system's own name or version, e.g. "3.1" or "ext4"
	Serial      uint64
	ClusterSize int   // NTFS cluster or ext block size, in bytes
	Records     int64 // NTFS MFT records or ext inodes
	VolumeBytes int64
}

// Stream describes one data stream of a file.
type Stream struct {
	Name       string // "" for the file's content
	Size       int64
	Resident   bool
	Compressed bool
	Encrypted  bool
	Sparse     bool
}

// File is one in-use entry, or a deleted one where the reader can find it.
type File struct {
	Record  uint64
	Seq     uint16
	Parent  uint64
	Name    string
	Path    string
	IsDir   bool
	InUse   bool
	Orphan  bool
	Size    int64 // length of the unnamed data stream
	Streams []Stream

	Attributes                              uint32
	Created, Modified, MFTChanged, Accessed time.Time

	// ExtensionRecords is how many extra metadata records hold this file
	// (NTFS $ATTRIBUTE_LIST), a sign of heavy fragmentation.
	ExtensionRecords int
}

// WalkStats summarises a walk.
type WalkStats struct {
	Records      int
	InUse        int
	Deleted      int
	CorruptCount int
	Corrupt      []uint64 // the first records that could not be read
}

// Reader reads the content of one file. It is read-only.
type Reader interface {
	ReadAt(p []byte, off int64) (int, error)
	Size() int64
	// AllocatedRanges lists the byte ranges that hold stored data, merged and
	// in order. Everything outside them reads as zeros.
	AllocatedRanges() [][2]int64
}

// Volume is an opened file system.
type Volume interface {
	Info() Info
	// Walk calls fn for every file the reader can name. An error from fn
	// stops the walk and is returned.
	Walk(fn func(File) error) (WalkStats, error)
	// OpenStream opens a stream of a record. "" is the unnamed content.
	OpenStream(record uint64, stream string) (Reader, error)
}
