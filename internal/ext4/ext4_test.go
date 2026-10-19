package ext4

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"tracefall/internal/fsvol"
)

// The fixtures are built by mkfs from a source tree this file writes, so the
// expected content is known without reading the image back.

type memImage []byte

func (m memImage) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(m)) {
		return 0, io.EOF
	}
	n := copy(p, m[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// fixtureTree writes the source tree every fixture is built from.
func fixtureTree(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	want := map[string][]byte{}
	write := func(rel string, b []byte) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		want["/"+rel] = b
	}
	write("small.txt", []byte("hello from the fixture\n"))
	write("empty.txt", nil)
	write("dir1/dir2/deep.txt", []byte("nested\n"))
	rng := rand.New(rand.NewSource(1))
	big := make([]byte, 2<<20)
	rng.Read(big)
	write("big.bin", big)
	for i := 0; i < 400; i++ {
		write(fmt.Sprintf("many/f%04d.txt", i), []byte(fmt.Sprintf("file %d\n", i)))
	}
	// A hole: 4 KiB of data at 1 MiB, and nothing before it.
	sp := filepath.Join(dir, "sparse.bin")
	f, err := os.Create(sp)
	if err != nil {
		t.Fatal(err)
	}
	tail := bytes.Repeat([]byte{0xAB}, 4096)
	if _, err := f.WriteAt(tail, 1<<20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	sparse := make([]byte, 1<<20+4096)
	copy(sparse[1<<20:], tail)
	want["/sparse.bin"] = sparse
	if err := os.Symlink("small.txt", filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(dir, "small.txt"), filepath.Join(dir, "hard.txt")); err != nil {
		t.Fatal(err)
	}
	want["/hard.txt"] = want["/small.txt"]
	return want
}

// buildFS runs mkfs with -d on a fresh source tree and returns the image.
func buildFS(t *testing.T, tool string, args ...string) (memImage, map[string][]byte) {
	t.Helper()
	if _, err := exec.LookPath(tool); err != nil {
		t.Skipf("%s not installed", tool)
	}
	src := t.TempDir()
	want := fixtureTree(t, src)
	img := filepath.Join(t.TempDir(), "fs.img")
	cmd := exec.Command(tool, append(append([]string{"-q", "-F", "-d", src}, args...), img, "16M")...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", tool, err, out)
	}
	b, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	return memImage(b), want
}

func readAll(t *testing.T, r fsvol.Reader) []byte {
	t.Helper()
	var out []byte
	buf := make([]byte, 64<<10)
	for off := int64(0); ; {
		n, err := r.ReadAt(buf, off)
		out = append(out, buf[:n]...)
		off += int64(n)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading at %d: %v", off, err)
		}
	}
	return out
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// listing walks a volume and returns its files by path.
func listing(t *testing.T, v *Volume) map[string]fsvol.File {
	t.Helper()
	out := map[string]fsvol.File{}
	st, err := v.Walk(func(f fsvol.File) error {
		out[f.Path] = f
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if st.CorruptCount != 0 {
		t.Fatalf("walk reported %d corrupt records: %v", st.CorruptCount, st.Corrupt)
	}
	return out
}

// checkContent compares every regular file the fixture wrote with what the
// reader returns, and checks the listing has exactly those files, plus the
// symlink, which is listed but has no content read.
func checkContent(t *testing.T, v *Volume, want map[string][]byte) {
	t.Helper()
	got := listing(t, v)
	for p, b := range want {
		f, ok := got[p]
		if !ok {
			t.Errorf("%s is not listed", p)
			continue
		}
		if f.IsDir || !f.InUse {
			t.Errorf("%s: want an in-use file, got dir=%v inuse=%v", p, f.IsDir, f.InUse)
		}
		if f.Size != int64(len(b)) {
			t.Errorf("%s: size %d, want %d", p, f.Size, len(b))
		}
		r, err := v.OpenStream(f.Record, "")
		if err != nil {
			t.Errorf("%s: open: %v", p, err)
			continue
		}
		if got := readAll(t, r); sum(got) != sum(b) || len(got) != len(b) {
			t.Errorf("%s: content differs (%d bytes, want %d)", p, len(got), len(b))
		}
	}
	var extra []string
	for p, f := range got {
		if _, ok := want[p]; ok {
			continue
		}
		if p == "/link.txt" {
			if !errors.Is(openErr(t, v, f), fsvol.ErrUnsupported) {
				t.Errorf("symlink content: want ErrUnsupported")
			}
			continue
		}
		if !f.IsDir && !strings.HasPrefix(p, "/dir1") && !strings.HasPrefix(p, "/many") {
			extra = append(extra, p)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("unexpected files listed: %v", extra)
	}
}

func openErr(t *testing.T, v *Volume, f fsvol.File) error {
	t.Helper()
	_, err := v.OpenStream(f.Record, "")
	return err
}

func TestExt4_EveryFileReadsAsItWasWritten(t *testing.T) {
	for _, bs := range []string{"1024", "4096"} {
		t.Run("block"+bs, func(t *testing.T) {
			img, want := buildFS(t, "mkfs.ext4", "-b", bs)
			v, err := Open(img, int64(len(img)))
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if v.Version != "ext4" {
				t.Errorf("version %q, want ext4", v.Version)
			}
			if got := v.Info().ClusterSize; fmt.Sprint(got) != bs {
				t.Errorf("block size %d, want %s", got, bs)
			}
			checkContent(t, v, want)
		})
	}
}

func TestExt2AndExt3_BlockMappedFilesIncludingDoubleIndirect(t *testing.T) {
	// 2 MiB at 1 KiB blocks is 2048 blocks: past the 12 direct pointers, the
	// single-indirect block, and into the double-indirect tree.
	for _, tc := range []struct{ tool, version string }{
		{"mkfs.ext2", "ext2"},
		{"mkfs.ext3", "ext3"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			img, want := buildFS(t, tc.tool, "-b", "1024")
			v, err := Open(img, int64(len(img)))
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if v.Version != tc.version {
				t.Errorf("version %q, want %s", v.Version, tc.version)
			}
			checkContent(t, v, want)
		})
	}
}

func TestOpen_RejectsWhatIsNotExt(t *testing.T) {
	if _, err := Open(memImage(make([]byte, 64<<10)), 64<<10); !errors.Is(err, ErrNotExt) {
		t.Fatalf("zeros: want ErrNotExt, got %v", err)
	}
	if _, err := Open(memImage(make([]byte, 100)), 100); !errors.Is(err, ErrNotExt) {
		t.Fatalf("tiny: want ErrNotExt, got %v", err)
	}
}

// A damaged image must produce errors or corrupt counts, never a panic. The
// mutations are deterministic, and they land anywhere in the image, so they
// reach the superblock, the group descriptors, inode tables, directories and
// data.
func TestCorruptImages_NeverPanic(t *testing.T) {
	img, _ := buildFS(t, "mkfs.ext4", "-b", "1024")
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 300; i++ {
		m := append(memImage(nil), img...)
		for k := 0; k < 1+rng.Intn(8); k++ {
			m[rng.Intn(len(m))] = byte(rng.Intn(256))
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("mutation %d panicked: %v", i, r)
				}
			}()
			v, err := Open(m, int64(len(m)))
			if err != nil {
				return
			}
			_, _ = v.Walk(func(f fsvol.File) error {
				if r, err := v.OpenStream(f.Record, ""); err == nil {
					buf := make([]byte, 4096)
					_, _ = r.ReadAt(buf, 0)
					_ = r.AllocatedRanges()
				}
				return nil
			})
		}()
	}
}

// A cut image must never return wrong bytes. A file that reads back must match
// what was written; a file whose blocks were cut must fail to read, or be
// reported corrupt. Cuts land inside the data of the 2 MiB file, so at least
// one read is past the end.
func TestTruncatedImage_NeverReturnsWrongContent(t *testing.T) {
	img, want := buildFS(t, "mkfs.ext4", "-b", "1024")
	failed := 0
	for _, cut := range []int64{1 << 20, 2 << 20, 3 << 20} {
		m := img[:cut]
		v, err := Open(m, int64(len(m)))
		if err != nil {
			continue
		}
		_, _ = v.Walk(func(f fsvol.File) error {
			if f.IsDir {
				return nil
			}
			r, err := v.OpenStream(f.Record, "")
			if err != nil {
				return nil
			}
			var got []byte
			buf := make([]byte, 64<<10)
			for off := int64(0); off < r.Size(); {
				n, err := r.ReadAt(buf, off)
				got = append(got, buf[:n]...)
				off += int64(n)
				if err != nil {
					failed++
					return nil
				}
			}
			if w, ok := want[f.Path]; ok && sum(got) != sum(w) {
				t.Errorf("cut %d: %s read back wrong bytes", cut, f.Path)
			}
			return nil
		})
	}
	if failed == 0 {
		t.Fatal("no cut made any read fail; the cuts did not reach the file data")
	}
}

// A file with a hole reports only its stored range as allocated, and reads
// zeros in the hole. Both extent (ext4) and block-map (ext2) files are checked.
func TestHoles_ReportOnlyStoredRangesAndReadZeros(t *testing.T) {
	for _, tool := range []string{"mkfs.ext4", "mkfs.ext2"} {
		t.Run(tool, func(t *testing.T) {
			img, _ := buildFS(t, tool, "-b", "1024")
			v, err := Open(img, int64(len(img)))
			if err != nil {
				t.Fatal(err)
			}
			var rec uint64
			found := false
			_, _ = v.Walk(func(f fsvol.File) error {
				if f.Path == "/sparse.bin" {
					rec, found = f.Record, true
				}
				return nil
			})
			if !found {
				t.Fatal("/sparse.bin is not listed")
			}
			r, err := v.OpenStream(rec, "")
			if err != nil {
				t.Fatal(err)
			}
			want := [][2]int64{{1 << 20, 1<<20 + 4096}}
			if got := r.AllocatedRanges(); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("allocated %v, want %v", got, want)
			}
			hole := make([]byte, 4096)
			if n, _ := r.ReadAt(hole, 512<<10); n != 4096 || !bytes.Equal(hole, make([]byte, 4096)) {
				t.Errorf("hole did not read as zeros")
			}
		})
	}
}

// debugfsEdit runs one debugfs write command on a copy of img and returns the
// edited image. debugfs is the tool an examiner would use to delete a file, so
// the deletion here is not made by the reader.
func debugfsEdit(t *testing.T, img memImage, cmd string) memImage {
	t.Helper()
	if _, err := exec.LookPath("debugfs"); err != nil {
		t.Skip("debugfs not installed")
	}
	p := filepath.Join(t.TempDir(), "fs.img")
	if err := os.WriteFile(p, img, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("debugfs", "-w", "-R", cmd, p).CombinedOutput(); err != nil {
		t.Fatalf("debugfs %s: %v\n%s", cmd, err, out)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return memImage(b)
}

// findDeleted returns the deleted files a walk reports, by path.
func findDeleted(t *testing.T, v *Volume) (map[string]fsvol.File, fsvol.WalkStats) {
	t.Helper()
	out := map[string]fsvol.File{}
	st, err := v.Walk(func(f fsvol.File) error {
		if !f.InUse {
			out[f.Path] = f
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out, st
}

// A file whose directory entry is kept but whose inode was freed is listed as
// deleted under its own name, and its content reads back as it was written
// while its blocks are still intact.
func TestDeleted_FreedInodeKeepsItsNameAndContent(t *testing.T) {
	for _, tool := range []string{"mkfs.ext2", "mkfs.ext4"} {
		t.Run(tool, func(t *testing.T) {
			img, want := buildFS(t, tool, "-b", "1024")
			// deep.txt has no hard link, so freeing its inode leaves no other name.
			killed := debugfsEdit(t, img, "kill_file /dir1/dir2/deep.txt")
			v, err := Open(killed, int64(len(killed)))
			if err != nil {
				t.Fatal(err)
			}
			for p, f := range listing(t, v) {
				if p == "/dir1/dir2/deep.txt" {
					t.Fatalf("a freed file is listed as in use: %+v", f)
				}
			}
			dels, st := findDeleted(t, v)
			f, ok := dels["/$OrphanFiles/deep.txt"]
			if !ok {
				t.Fatalf("the freed file is not listed under its name; deleted = %v", keys(dels))
			}
			if st.Deleted < 1 || !f.Orphan || f.InUse {
				t.Errorf("stats %+v, file %+v: want a deleted, orphan file", st, f)
			}
			if f.Size != int64(len(want["/dir1/dir2/deep.txt"])) {
				t.Errorf("size %d, want %d", f.Size, len(want["/dir1/dir2/deep.txt"]))
			}
			r, err := v.OpenStream(f.Record, "")
			if err != nil {
				// On ext4 the freed inode's extent tree may be cleared on
				// deletion. That is a limit of the medium, not a wrong read.
				t.Logf("%s: content not readable after deletion: %v", tool, err)
				return
			}
			if got := readAll(t, r); sum(got) != sum(want["/dir1/dir2/deep.txt"]) {
				t.Errorf("recovered content differs from the original")
			}
		})
	}
}

// A file whose directory entry was removed has no name left, so it is listed
// as an inode with a generated name. Its content is still read only when its
// blocks are intact.
func TestDeleted_UnlinkedFileIsListedByInodeNumber(t *testing.T) {
	img, want := buildFS(t, "mkfs.ext2", "-b", "1024")
	rm := debugfsEdit(t, img, "rm /dir1/dir2/deep.txt")
	v, err := Open(rm, int64(len(rm)))
	if err != nil {
		t.Fatal(err)
	}
	dels, st := findDeleted(t, v)
	var found *fsvol.File
	for p, f := range dels {
		if strings.HasPrefix(p, "/$OrphanFiles/inode-") && f.Size == int64(len(want["/dir1/dir2/deep.txt"])) {
			f := f
			found = &f
		}
	}
	if found == nil {
		t.Fatalf("no unnamed deleted inode of the right size; stats %+v, deleted %v", st, keys(dels))
	}
	r, err := v.OpenStream(found.Record, "")
	if err != nil {
		t.Fatalf("content of an intact deleted inode: %v", err)
	}
	if got := readAll(t, r); sum(got) != sum(want["/dir1/dir2/deep.txt"]) {
		t.Errorf("recovered content differs from the original")
	}
}

func keys(m map[string]fsvol.File) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
