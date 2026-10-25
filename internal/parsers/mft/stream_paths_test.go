package mft

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"tracefall/internal/ntfs"
	"tracefall/internal/ntfs/mftgen"
)

func TestDirectoryReaderEvictionKeepsFixedCardinality(t *testing.T) {
	files := mftgen.SystemRecords(mftgen.Times{})
	for i := 0; i < 5000; i++ {
		files = append(files, mftgen.File{RecordNumber: uint64(64 + i), SequenceNumber: 1, IsDirectory: true, Names: []mftgen.Name{{Name: "dir", Namespace: 1, ParentRef: 5, ParentSeq: 5}}})
	}
	path := filepath.Join(t.TempDir(), "$MFT")
	if err := os.WriteFile(path, mftgen.Build(files), 0600); err != nil {
		t.Fatal(err)
	}
	d, err := openDirectories(path, ntfs.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer d.f.Close()
	for i := 0; i < 5000; i++ {
		if !d.get(uint64(64 + i)).valid {
			t.Fatal("directory lost")
		}
	}
	if len(d.cache) != 4096 || d.lru.Len() != 4096 {
		t.Fatal("directory state not bounded", len(d.cache), d.lru.Len())
	}
	p, complete, err := d.path(context.Background(), ntfs.FileName{Name: "file.txt", ParentRef: 64, ParentSeq: 1})
	if err != nil || !complete || p != `\dir\file.txt` {
		t.Fatal("evicted parent could not be reread", p, complete, err)
	}
	if len(d.cache) != 4096 || d.lru.Len() != 4096 {
		t.Fatal("reread exceeded bound")
	}
}
