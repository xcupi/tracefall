package ext4

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"tracefall/internal/fsvol"
	"tracefall/internal/image"
	"tracefall/internal/partition"
)

// TestReal_ExtVolumeMatchesDebugfsRdump reads every ext partition of a real
// disk image and compares the listing and every regular file's content with
// debugfs's own extraction of the same partition. debugfs is an independent
// implementation, so this is not the reader checking itself.
//
// Set TRACEFALL_REAL_EXT4 to a disk image (the first segment of an E01 is
// enough). The partition is copied to a scratch file for debugfs, so this
// needs free disk space of the partition's size.
func TestReal_ExtVolumeMatchesDebugfsRdump(t *testing.T) {
	seg := os.Getenv("TRACEFALL_REAL_EXT4")
	if seg == "" {
		t.Skip("set TRACEFALL_REAL_EXT4 to a real disk image with an ext partition")
	}
	if _, err := exec.LookPath("debugfs"); err != nil {
		t.Skip("debugfs not installed")
	}
	paths, err := image.FindSegments(seg)
	if err != nil {
		t.Fatal(err)
	}
	img, err := image.Open(paths...)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	tb, err := partition.Read(img, img.Size(), img.Info().SectorSize)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, p := range tb.Partitions {
		if p.FS != "ext" {
			continue
		}
		checked++
		comparePartition(t, img, p)
	}
	if checked == 0 {
		t.Skip("no ext partition in this image")
	}
}

func comparePartition(t *testing.T, img image.Image, p partition.Partition) {
	t.Helper()
	v, err := Open(p.Reader(img), p.SizeBytes)
	if err != nil {
		t.Fatalf("partition %d: open: %v", p.Index, err)
	}
	ours := map[string]string{} // path -> sha256 for regular files
	links := map[string]bool{}
	st, err := v.Walk(func(f fsvol.File) error {
		if f.IsDir {
			return nil
		}
		r, err := v.OpenStream(f.Record, "")
		if err != nil {
			links[f.Path] = true // symlink, or unreadable: listed but no content
			return nil
		}
		h := sha256.New()
		buf := make([]byte, 1<<20)
		for off := int64(0); ; {
			n, err := r.ReadAt(buf, off)
			h.Write(buf[:n])
			off += int64(n)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("partition %d: %s: read at %d: %v", p.Index, f.Path, off, err)
			}
		}
		ours[f.Path] = hex.EncodeToString(h.Sum(nil))
		return nil
	})
	if err != nil {
		t.Fatalf("partition %d: walk: %v", p.Index, err)
	}
	if st.CorruptCount != 0 {
		t.Fatalf("partition %d: %d corrupt records: %v", p.Index, st.CorruptCount, st.Corrupt)
	}

	// Export the partition for debugfs.
	dir := t.TempDir()
	raw := filepath.Join(dir, "part.raw")
	out, err := os.Create(raw)
	if err != nil {
		t.Fatal(err)
	}
	written, err := sparseCopy(out, io.NewSectionReader(p.Reader(img), 0, p.SizeBytes))
	if err != nil {
		t.Fatal(err)
	}
	if err := out.Truncate(p.SizeBytes); err != nil {
		t.Fatal(err)
	}
	out.Close()
	t.Logf("partition %d: %d of %d bytes are non-zero and were written", p.Index, written, p.SizeBytes)
	dest := filepath.Join(dir, "rdump")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("debugfs", "-R", "rdump / "+dest, raw)
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("debugfs rdump: %v\n%s", err, o)
	}

	theirs := map[string]string{}
	// debugfs cannot restore ownership when run without root, and it leaves
	// some root-only modes behind (for example a snap directory is 000). That
	// is a property of the copy, not of the content, so the owner's read bits
	// are restored before reading.
	err = filepath.WalkDir(dest, func(p2 string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(p2, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if err := os.Chmod(p2, 0o644); err != nil {
			return err
		}
		rel, _ := filepath.Rel(dest, p2)
		b, err := os.ReadFile(p2)
		if err != nil {
			return err
		}
		h := sha256.Sum256(b)
		theirs["/"+filepath.ToSlash(rel)] = hex.EncodeToString(h[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var missing, extra, differ []string
	for path, sum := range ours {
		got, ok := theirs[path]
		switch {
		case !ok:
			extra = append(extra, path)
		case got != sum:
			differ = append(differ, path)
		}
	}
	stale := 0
	for path := range theirs {
		if _, ok := ours[path]; ok || links[path] {
			continue
		}
		// debugfs also dumps a directory entry whose inode is already free
		// (links 0, deletion time set). Walk lists only in-use names, so such
		// an entry is expected to be absent here. Anything else is a bug.
		if v.staleEntry(path) {
			stale++
			continue
		}
		missing = append(missing, path)
	}
	sort.Strings(missing)
	sort.Strings(extra)
	sort.Strings(differ)
	t.Logf("partition %d: %d regular files compared, %d symlinks listed, %d in-use names walked, %d stale entries (free inode) dumped by debugfs only", p.Index, len(ours), len(links), st.InUse, stale)
	if len(missing)+len(extra)+len(differ) > 0 {
		t.Errorf("partition %d differs from debugfs:\n  only in debugfs: %s\n  only in reader: %s\n  content differs: %s",
			p.Index, head(missing), head(extra), head(differ))
	}
}

func head(s []string) string {
	if len(s) > 10 {
		return strings.Join(s[:10], ", ") + ", ..."
	}
	return strings.Join(s, ", ")
}

// sparseCopy copies src to dst but does not write blocks that are entirely
// zero: it seeks past them, so dst is sparse and uses disk only for the
// data. It returns how many bytes of non-zero blocks were written. The copy is
// byte-identical to src.
func sparseCopy(dst *os.File, src io.Reader) (int64, error) {
	const chunk = 1 << 20
	buf := make([]byte, chunk)
	var pos, written int64
	for {
		n, err := io.ReadFull(src, buf)
		if n > 0 {
			if allZero(buf[:n]) {
				if _, serr := dst.Seek(int64(n), io.SeekCurrent); serr != nil {
					return written, serr
				}
			} else {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return written, werr
				}
				written += int64(n)
			}
			pos += int64(n)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return written, nil
		}
		if err != nil {
			return written, err
		}
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// staleEntry reports whether path resolves, through the directory tree, to an
// inode that is not in use.
func (v *Volume) staleEntry(path string) bool {
	cur := uint64(rootIno)
	for _, name := range strings.Split(strings.Trim(path, "/"), "/") {
		dir, err := v.readInode(cur)
		if err != nil || !dir.isDir() {
			return false
		}
		ents, err := v.dirEntries(dir)
		if err != nil {
			return false
		}
		next := uint64(0)
		for _, e := range ents {
			if e.name == name {
				next = e.ino
				break
			}
		}
		if next == 0 {
			return false
		}
		cur = next
	}
	in, err := v.readInode(cur)
	return err == nil && !in.inUse()
}
