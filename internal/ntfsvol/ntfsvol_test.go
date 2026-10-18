package ntfsvol

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The volume in testdata/images was created by mkntfs and populated through
// the ntfs-3g driver; manifest.json is read back from that mounted file
// system. See testdata/images/gen.py.
const fixtures = "../../testdata/images"

const (
	volStart = 2048 * 512
	volBytes = 49152 * 512
)

type entry struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type manifest struct {
	Volume struct {
		Files   map[string]entry `json:"files"`
		Streams map[string]entry `json:"streams"`
		Dirs    []string         `json:"dirs"`
		Deleted []string         `json:"deleted"`
		Label   string           `json:"volume_label"`
	} `json:"volume"`
}

var (
	loadOnce sync.Once
	volData  []byte
	man      manifest
)

func load(t testing.TB) ([]byte, manifest) {
	t.Helper()
	loadOnce.Do(func() {
		f, err := os.Open(filepath.Join(fixtures, "gpt.dd.gz"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		z, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		disk, err := io.ReadAll(z)
		if err != nil {
			t.Fatal(err)
		}
		volData = disk[volStart : volStart+volBytes]
		b, _ := os.ReadFile(filepath.Join(fixtures, "manifest.json"))
		if err := json.Unmarshal(b, &man); err != nil {
			t.Fatal(err)
		}
	})
	return append([]byte(nil), volData...), man
}

func openVol(t testing.TB, data []byte) *Volume {
	t.Helper()
	v, err := Open(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return v
}

func walkAll(t testing.TB, v *Volume) (map[string]File, WalkStats) {
	t.Helper()
	files := map[string]File{}
	st, err := v.Walk(func(f File) error {
		if f.InUse {
			files[f.Path] = f
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files, st
}

func readStream(t testing.TB, v *Volume, rec uint64, stream string) []byte {
	t.Helper()
	dr, err := v.OpenStream(rec, stream)
	if err != nil {
		t.Fatalf("OpenStream(%d,%q): %v", rec, stream, err)
	}
	b := make([]byte, dr.Size())
	if n, err := dr.ReadAt(b, 0); n != len(b) && err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("reading record %d: %v", rec, err)
	}
	return b
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func TestVolume_ReportsTheGeometryMkntfsWrote(t *testing.T) {
	data, m := load(t)
	in := openVol(t, data).Info()
	if in.Label != m.Volume.Label || in.BytesPerSector != 512 || in.ClusterSize != 4096 || in.RecordSize != 1024 {
		t.Errorf("info = %+v", in)
	}
	// NTFS keeps a backup boot sector in the last sector and does not
	// count it in the volume size.
	if in.VolumeBytes != int64(len(data))-512 || in.MFTRecords < 1200 || in.Serial == 0 {
		t.Errorf("info = %+v", in)
	}
}

func TestWalk_FindsEveryFileWithTheRightSizeAndContent(t *testing.T) {
	data, m := load(t)
	v := openVol(t, data)
	files, stats := walkAll(t, v)
	if len(stats.Corrupt) != 0 {
		t.Errorf("a clean volume reported corrupt records: %v", stats.Corrupt)
	}
	if len(m.Volume.Files) < 1200 {
		t.Fatalf("manifest has only %d files", len(m.Volume.Files))
	}
	for path, want := range m.Volume.Files {
		f, ok := files[path]
		if !ok {
			t.Errorf("missing from the walk: %s", path)
			continue
		}
		if f.IsDir || f.Size != want.Size {
			t.Errorf("%s: dir=%v size=%d, want size %d", path, f.IsDir, f.Size, want.Size)
			continue
		}
		if got := sum(readStream(t, v, f.Record, "")); got != want.SHA256 {
			t.Errorf("%s: content hash %s, want %s", path, got, want.SHA256)
		}
	}
}

func TestWalk_FindsEveryDirectoryAndNothingExtraInTheUserArea(t *testing.T) {
	data, m := load(t)
	files, _ := walkAll(t, openVol(t, data))
	for _, d := range m.Volume.Dirs {
		if f, ok := files[d]; !ok || !f.IsDir {
			t.Errorf("directory %s: found=%v dir=%v", d, ok, f.IsDir)
		}
	}
	// Everything outside the NTFS system metadata ($-names and System
	// Volume Information) must be something the manifest knows.
	known := map[string]bool{}
	for p := range m.Volume.Files {
		known[p] = true
	}
	for _, d := range m.Volume.Dirs {
		known[d] = true
	}
	for p := range files {
		if strings.HasPrefix(p, "/$") || p == "/" || strings.HasPrefix(p, "/System Volume Information") {
			continue
		}
		if !known[p] {
			t.Errorf("the walk invented %s", p)
		}
	}
}

func TestWalk_ResolvesUnicodeNames(t *testing.T) {
	data, _ := load(t)
	files, _ := walkAll(t, openVol(t, data))
	if _, ok := files["/r\u00e9sum\u00e9_\u65e5\u672c\u8a9e.txt"]; !ok {
		t.Error("a non-ASCII file name was not decoded")
	}
}

func TestFragmentedFilesThatNeedAnAttributeListAreReadCorrectly(t *testing.T) {
	data, m := load(t)
	v := openVol(t, data)
	files, _ := walkAll(t, v)
	withList := 0
	for i := 0; i < 8; i++ {
		p := "/frag/f" + string(rune('0'+i)) + ".bin"
		f := files[p]
		if f.ExtensionRecords > 0 {
			withList++
		}
		if got := sum(readStream(t, v, f.Record, "")); got != m.Volume.Files[p].SHA256 {
			t.Errorf("%s (extension records: %d): wrong content", p, f.ExtensionRecords)
		}
	}
	if withList == 0 {
		t.Fatal("no fragmented fixture file uses an $ATTRIBUTE_LIST: this test no longer covers that path")
	}
}

func TestAlternateDataStreamsAreListedAndReadable(t *testing.T) {
	data, m := load(t)
	v := openVol(t, data)
	files, _ := walkAll(t, v)
	f := files["/ads.txt"]
	names := map[string]int64{}
	for _, s := range f.Streams {
		names[s.Name] = s.Size
	}
	if len(f.Streams) != 3 {
		t.Fatalf("streams = %+v, want the unnamed stream and two named ones", f.Streams)
	}
	for key, want := range m.Volume.Streams {
		name := strings.SplitN(key, ":", 2)[1]
		if names[name] != want.Size {
			t.Errorf("stream %q size %d, want %d", name, names[name], want.Size)
		}
		if got := sum(readStream(t, v, f.Record, name)); got != want.SHA256 {
			t.Errorf("stream %q has the wrong content", name)
		}
	}
	if f.Size != 16 {
		t.Errorf("the file's own size must be its unnamed stream (16), got %d", f.Size)
	}
}

func TestSparseFilesReadZerosInHolesAndReportTheirAllocation(t *testing.T) {
	data, m := load(t)
	v := openVol(t, data)
	files, _ := walkAll(t, v)
	f := files["/sparse.bin"]
	if len(f.Streams) == 0 || !f.Streams[0].Sparse {
		t.Fatalf("sparse flag missing: %+v", f.Streams)
	}
	dr, err := v.OpenStream(f.Record, "")
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, dr.Size())
	dr.ReadAt(b, 0)
	if sum(b) != m.Volume.Files["/sparse.bin"].SHA256 {
		t.Error("sparse file content differs")
	}
	var allocated int64
	for _, r := range dr.AllocatedRanges() {
		allocated += r[1] - r[0]
	}
	if allocated <= 0 || allocated >= dr.Size() {
		t.Errorf("allocated %d of %d: a sparse file must allocate less than its size", allocated, dr.Size())
	}
}

func TestDeletedFilesAreFoundMarkedAndStillReadable(t *testing.T) {
	data, m := load(t)
	v := openVol(t, data)
	var found File
	v.Walk(func(f File) error {
		if f.Path == m.Volume.Deleted[0] {
			found = f
		}
		return nil
	})
	if found.Record == 0 || found.InUse {
		t.Fatalf("deleted file = %+v: must be present and flagged not in use", found)
	}
	if got := string(readStream(t, v, found.Record, "")); got != "this file is deleted before imaging\n" {
		t.Errorf("deleted resident content = %q", got)
	}
}

func TestSystemFilesAreReachableByRecordNumber(t *testing.T) {
	data, _ := load(t)
	v := openVol(t, data)
	mft := readStream(t, v, 0, "")
	if int64(len(mft)) != v.Info().MFTRecords*int64(v.Info().RecordSize) {
		t.Errorf("$MFT stream is %d bytes for %d records", len(mft), v.Info().MFTRecords)
	}
	if !bytes.HasPrefix(mft, []byte("FILE")) {
		t.Error("$MFT does not start with a FILE record")
	}
	files, _ := walkAll(t, v)
	if _, ok := files["/$MFT"]; !ok {
		t.Error("/$MFT missing from the walk")
	}
}

func TestTimestampsComeFromStandardInformation(t *testing.T) {
	data, _ := load(t)
	files, _ := walkAll(t, openVol(t, data))
	f := files["/hello.txt"]
	if f.Created.IsZero() || f.Modified.IsZero() || f.Created.Year() != 2026 || f.Created.Location().String() != "UTC" {
		t.Errorf("times = %v %v %v %v", f.Created, f.Modified, f.MFTChanged, f.Accessed)
	}
}

func TestDataReader_FollowsTheReaderAtContract(t *testing.T) {
	data, _ := load(t)
	v := openVol(t, data)
	files, _ := walkAll(t, v)
	dr, err := v.OpenStream(files["/big.bin"].Record, "")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	if n, err := dr.ReadAt(buf, dr.Size()-30); n != 30 || !errors.Is(err, io.EOF) {
		t.Errorf("short read at the end: n=%d err=%v", n, err)
	}
	if n, err := dr.ReadAt(buf, dr.Size()); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("read at Size: n=%d err=%v", n, err)
	}
	if _, err := dr.ReadAt(buf, -1); err == nil {
		t.Error("negative offset accepted")
	}
	want := readStream(t, v, files["/big.bin"].Record, "")
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		off := rng.Intn(len(want) - 1)
		n := 1 + rng.Intn(20000)
		if off+n > len(want) {
			n = len(want) - off
		}
		b := make([]byte, n)
		got, _ := dr.ReadAt(b, int64(off))
		if got != n || !bytes.Equal(b, want[off:off+n]) {
			t.Fatalf("ReadAt(%d,%d) wrong", off, n)
		}
	}
	if _, err := v.OpenStream(files["/hello.txt"].Record, "nosuchstream"); err == nil {
		t.Error("a missing stream opened")
	}
	if _, err := v.OpenStream(1<<40, ""); err == nil {
		t.Error("a record beyond the MFT opened")
	}
}

func TestOpen_RejectsWhatIsNotNtfs(t *testing.T) {
	data, _ := load(t)
	if _, err := Open(bytes.NewReader(make([]byte, 1<<20)), 1<<20); !errors.Is(err, ErrNotNTFS) {
		t.Errorf("zeros: %v", err)
	}
	bad := append([]byte(nil), data...)
	bad[13] = 3 // sectors per cluster not a power of two
	if _, err := Open(bytes.NewReader(bad), int64(len(bad))); err == nil {
		t.Error("an implausible boot sector was accepted")
	}
	bad = append([]byte(nil), data...)
	bad[11], bad[12] = 0, 0 // bytes per sector zero
	if _, err := Open(bytes.NewReader(bad), int64(len(bad))); err == nil {
		t.Error("zero bytes per sector accepted")
	}
	if _, err := Open(bytes.NewReader(data[:4096]), 4096); err == nil {
		t.Error("a truncated volume opened")
	}
}

func TestWalk_ACorruptRecordIsReportedAndTheRestStillWalks(t *testing.T) {
	data, _ := load(t)
	clean := openVol(t, data)
	files, _ := walkAll(t, clean)
	victim := files["/hello.txt"]
	mftOff := int64(clean.mftByteOffsetForTest(victim.Record))
	bad := append([]byte(nil), data...)
	bad[mftOff+510] ^= 0xff // the update-sequence check bytes of sector 1
	bad[mftOff+511] ^= 0xff
	v := openVol(t, bad)
	got, stats := walkAll(t, v)
	if len(stats.Corrupt) == 0 || stats.Corrupt[0] != victim.Record {
		t.Fatalf("corrupt = %v, want [%d]", stats.Corrupt, victim.Record)
	}
	if _, ok := got["/hello.txt"]; ok {
		t.Error("a torn record was returned as if it were valid")
	}
	if len(got) < len(files)-3 {
		t.Errorf("one bad record lost %d files", len(files)-len(got))
	}
}

func TestOpenStream_ARecordWithATornFixupIsAnErrorNotGarbage(t *testing.T) {
	data, _ := load(t)
	clean := openVol(t, data)
	files, _ := walkAll(t, clean)
	rec := files["/hello.txt"].Record
	off := int64(clean.mftByteOffsetForTest(rec))
	bad := append([]byte(nil), data...)
	bad[off+510] ^= 0xff
	if _, err := openVol(t, bad).OpenStream(rec, ""); !errors.Is(err, ErrCorrupt) {
		t.Errorf("err = %v, want ErrCorrupt", err)
	}
}

func TestRandomDamageNeverPanicsOrHangs(t *testing.T) {
	data, _ := load(t)
	clean := openVol(t, data)
	rng := rand.New(rand.NewSource(11))
	mftStart := int(clean.mftByteOffsetForTest(0))
	for i := 0; i < 150; i++ {
		bad := append([]byte(nil), data...)
		for k := 0; k < 1+rng.Intn(40); k++ {
			var pos int
			switch rng.Intn(3) {
			case 0:
				pos = rng.Intn(512) // boot sector
			case 1:
				pos = mftStart + rng.Intn(64*1024) // first MFT records
			default:
				pos = rng.Intn(len(bad))
			}
			bad[pos] = byte(rng.Intn(256))
		}
		v, err := Open(bytes.NewReader(bad), int64(len(bad)))
		if err != nil {
			continue
		}
		v.Walk(func(f File) error {
			if f.InUse && !f.IsDir && f.Size > 0 && f.Size < 1<<20 {
				if dr, err := v.OpenStream(f.Record, ""); err == nil {
					buf := make([]byte, 4096)
					dr.ReadAt(buf, 0)
				}
			}
			return nil
		})
	}
}

func TestWalk_StopsWhenTheCallbackSaysSo(t *testing.T) {
	data, _ := load(t)
	v := openVol(t, data)
	stop := errors.New("enough")
	n := 0
	_, err := v.Walk(func(File) error {
		n++
		if n == 10 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || n != 10 {
		t.Errorf("err=%v n=%d", err, n)
	}
}

func TestWalk_PathsNeverContainTraversalComponents(t *testing.T) {
	data, _ := load(t)
	v := openVol(t, data)
	v.Walk(func(f File) error {
		for _, part := range strings.Split(f.Path, "/") {
			if part == ".." || part == "." {
				t.Errorf("record %d has a traversal component in %q", f.Record, f.Path)
			}
		}
		if !strings.HasPrefix(f.Path, "/") {
			t.Errorf("record %d path %q is not absolute", f.Record, f.Path)
		}
		return nil
	})
}
