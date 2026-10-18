package image

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// The fixtures in testdata/images were written by independent tools
// (ewfacquire from libewf, sgdisk, mkntfs). See testdata/images/gen.py.
const fixtures = "../../testdata/images"

type truth struct {
	Images map[string]struct {
		Size   int64  `json:"size"`
		MD5    string `json:"md5"`
		SHA1   string `json:"sha1"`
		SHA256 string `json:"sha256"`
	} `json:"images"`
}

func loadTruth(t *testing.T) truth {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var tr truth
	if err := json.Unmarshal(b, &tr); err != nil {
		t.Fatal(err)
	}
	return tr
}

// rawDisk returns the bytes of a raw fixture ("gpt", "mbr").
func rawDisk(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open(filepath.Join(fixtures, name+".dd.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hashes(b []byte) (string, string, string) {
	m, s1, s2 := md5.Sum(b), sha1.Sum(b), sha256.Sum256(b)
	return hex.EncodeToString(m[:]), hex.EncodeToString(s1[:]), hex.EncodeToString(s2[:])
}

func readAll(t *testing.T, img Image) []byte {
	t.Helper()
	out := make([]byte, img.Size())
	if _, err := img.ReadAt(out, 0); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("reading the whole image: %v", err)
	}
	return out
}

func TestEWF_ReadsAnImageWrittenByLibewfByteForByte(t *testing.T) {
	disk := rawDisk(t, "gpt")
	for _, c := range []struct {
		name string
		want []byte
	}{{"gpt.E01", disk}, {"gpt-store.E01", disk[:2*1024*1024]}} {
		name, want := c.name, c.want
		paths, err := FindSegments(filepath.Join(fixtures, name))
		if err != nil {
			t.Fatal(err)
		}
		img, err := Open(paths...)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if img.Info().Format != FormatEWF || img.Size() != int64(len(want)) {
			t.Fatalf("%s: info = %+v size %d, want ewf/%d", name, img.Info(), img.Size(), len(want))
		}
		if got := readAll(t, img); !bytes.Equal(got, want) {
			t.Errorf("%s: the decoded image differs from the raw disk it was acquired from", name)
		}
		img.Close()
	}
}

func TestEWF_SegmentedImageIsReallySplit(t *testing.T) {
	paths, err := FindSegments(filepath.Join(fixtures, "gpt-store.E01"))
	if err != nil || len(paths) < 2 {
		t.Fatalf("FindSegments = %v, %v: the fixture must span several segments", paths, err)
	}
	img, err := Open(paths...)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	if img.Info().Segments != len(paths) {
		t.Errorf("segments = %d, want %d", img.Info().Segments, len(paths))
	}
}

func TestEWF_UncompressedChunksAreChecksummed(t *testing.T) {
	tr := loadTruth(t)
	paths, _ := FindSegments(filepath.Join(fixtures, "gpt-store.E01"))
	img, err := Open(paths...)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	got := readAll(t, img)
	_, _, sum := hashes(got)
	if sum != tr.Images["store"].SHA256 || int64(len(got)) != tr.Images["store"].Size {
		t.Errorf("uncompressed image sha256 = %s, want %s", sum, tr.Images["store"].SHA256)
	}
}

func TestEWF_ReportsTheAcquisitionRecordedInTheFile(t *testing.T) {
	tr := loadTruth(t)
	img, err := Open(filepath.Join(fixtures, "gpt.E01"))
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	in := img.Info()
	if in.SectorSize != 512 {
		t.Errorf("sector size = %d", in.SectorSize)
	}
	if in.StoredMD5 != tr.Images["gpt"].MD5 || in.StoredSHA1 != tr.Images["gpt"].SHA1 {
		t.Errorf("stored hashes = %q/%q, want %q/%q", in.StoredMD5, in.StoredSHA1, tr.Images["gpt"].MD5, tr.Images["gpt"].SHA1)
	}
	for k, want := range map[string]string{"case_number": "CASE-0001", "examiner": "Fixture Examiner", "evidence_number": "EV-001"} {
		if in.Meta[k] != want {
			t.Errorf("meta[%s] = %q, want %q", k, in.Meta[k], want)
		}
	}
}

func TestEWF_RandomAndChunkStraddlingReadsMatchTheRawDisk(t *testing.T) {
	want := rawDisk(t, "gpt")
	img, err := Open(filepath.Join(fixtures, "gpt.E01"))
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	rng := rand.New(rand.NewSource(7))
	const chunk = 64 * 512
	cases := [][2]int{{0, 1}, {chunk - 1, 2}, {chunk, chunk}, {chunk - 7, 9000}, {len(want) - 1, 1}, {len(want) - 100, 100}}
	for i := 0; i < 300; i++ {
		off := rng.Intn(len(want) - 1)
		n := 1 + rng.Intn(3*chunk)
		if off+n > len(want) {
			n = len(want) - off
		}
		cases = append(cases, [2]int{off, n})
	}
	for _, c := range cases {
		buf := make([]byte, c[1])
		n, err := img.ReadAt(buf, int64(c[0]))
		if err != nil && !(errors.Is(err, io.EOF) && c[0]+c[1] >= len(want)) {
			t.Fatalf("ReadAt(%d,%d): n=%d err=%v", c[0], c[1], n, err)
		}
		if !bytes.Equal(buf[:n], want[c[0]:c[0]+n]) {
			t.Fatalf("ReadAt(%d,%d) returned different bytes", c[0], c[1])
		}
	}
}

func TestReadAt_FollowsTheIoReaderAtContractAtTheEnd(t *testing.T) {
	img, err := Open(filepath.Join(fixtures, "gpt.E01"))
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	buf := make([]byte, 10)
	if n, err := img.ReadAt(buf, img.Size()-4); n != 4 || !errors.Is(err, io.EOF) {
		t.Errorf("short read at the end: n=%d err=%v, want 4 and io.EOF", n, err)
	}
	if n, err := img.ReadAt(buf, img.Size()); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("read at Size(): n=%d err=%v, want 0 and io.EOF", n, err)
	}
	if n, err := img.ReadAt(buf, img.Size()+1000); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("read past the end: n=%d err=%v", n, err)
	}
	if _, err := img.ReadAt(buf, -1); err == nil {
		t.Error("a negative offset was accepted")
	}
	if n, err := img.ReadAt(nil, 5); n != 0 || err != nil {
		t.Errorf("zero-length read: n=%d err=%v", n, err)
	}
}

func TestEWF_ConcurrentReadersSeeConsistentData(t *testing.T) {
	want := rawDisk(t, "gpt")
	img, err := Open(filepath.Join(fixtures, "gpt.E01"))
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(g)))
			for i := 0; i < 200; i++ {
				off := rng.Intn(len(want) - 100000)
				buf := make([]byte, 1+rng.Intn(100000))
				n, _ := img.ReadAt(buf, int64(off))
				if !bytes.Equal(buf[:n], want[off:off+n]) {
					t.Errorf("goroutine %d: data mismatch at %d", g, off)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestVerify_ChecksTheStoredHashesAgainstTheDecodedData(t *testing.T) {
	img, err := Open(filepath.Join(fixtures, "gpt.E01"))
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	res, err := Verify(img, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := loadTruth(t)
	if res.MD5 != tr.Images["gpt"].MD5 || res.SHA1 != tr.Images["gpt"].SHA1 || res.SHA256 != tr.Images["gpt"].SHA256 {
		t.Errorf("computed digests = %+v", res)
	}
	if res.MD5Match == nil || !*res.MD5Match || res.SHA1Match == nil || !*res.SHA1Match {
		t.Errorf("an untouched image must match its stored hashes: %+v", res)
	}
	if res.Bytes != img.Size() {
		t.Errorf("hashed %d bytes of %d", res.Bytes, img.Size())
	}
}

func TestVerify_ReportsProgress(t *testing.T) {
	img, _ := Open(filepath.Join(fixtures, "gpt.E01"))
	defer img.Close()
	var calls int
	var last int64
	if _, err := Verify(img, func(done, total int64) {
		calls++
		last = done
		if total != img.Size() {
			t.Errorf("total = %d", total)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if calls == 0 || last != img.Size() {
		t.Errorf("progress calls=%d last=%d", calls, last)
	}
}

// copyTo copies the named fixture files into a temp dir for tampering.
func copyTo(t *testing.T, names ...string) []string {
	t.Helper()
	dir := t.TempDir()
	var out []string
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(fixtures, n))
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, n)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

func TestEWF_AFlippedBitInImageDataIsDetectedNeverSilentlyReturned(t *testing.T) {
	for _, set := range [][]string{{"gpt.E01"}, {"gpt-store.E01", "gpt-store.E02", "gpt-store.E03"}} {
		paths := copyTo(t, set...)
		b, _ := os.ReadFile(paths[0])
		b[len(b)/2] ^= 0x40 // somewhere inside the first segment's chunk data
		os.WriteFile(paths[0], b, 0o644)
		img, err := Open(paths...)
		if err != nil {
			t.Errorf("%v: the open itself failed (%v); this test must reach the data", set, err)
			continue
		}
		_, verr := Verify(img, nil)
		img.Close()
		if verr == nil {
			t.Errorf("%v: a corrupted chunk was read without any error", set)
		} else if !errors.Is(verr, ErrCorrupt) {
			t.Errorf("%v: error %v does not wrap ErrCorrupt", set, verr)
		}
	}
}

func TestEWF_TruncatedFilesFailCleanly(t *testing.T) {
	p := copyTo(t, "gpt.E01")[0]
	full, _ := os.ReadFile(p)
	for _, cut := range []int{0, 8, 13, 100, 500, len(full) / 3, len(full) - 200, len(full) - 1} {
		os.WriteFile(p, full[:cut], 0o644)
		img, err := Open(p)
		if err != nil {
			continue
		}
		_, verr := Verify(img, nil)
		img.Close()
		if verr == nil {
			t.Errorf("cut at %d of %d: a truncated image verified successfully", cut, len(full))
		}
	}
}

func TestEWF_GarbageAndMangledHeadersNeverPanic(t *testing.T) {
	p := copyTo(t, "gpt.E01")[0]
	full, _ := os.ReadFile(p)
	rng := rand.New(rand.NewSource(99))
	for i := 0; i < 400; i++ {
		b := append([]byte(nil), full[:4096]...) // headers and the first table region only
		for k := 0; k < 1+rng.Intn(6); k++ {
			b[rng.Intn(len(b))] = byte(rng.Intn(256))
		}
		os.WriteFile(p, b, 0o644)
		if img, err := Open(p); err == nil {
			buf := make([]byte, 4096)
			img.ReadAt(buf, 0)
			img.Close()
		}
	}
	os.WriteFile(p, append([]byte("EVF\x09\x0d\x0a\xff\x00"), bytes.Repeat([]byte{0xff}, 4000)...), 0o644)
	if img, err := Open(p); err == nil {
		img.Close()
		t.Error("an EWF signature followed by garbage opened successfully")
	}
}

func TestEWF_AMissingSegmentIsRefused(t *testing.T) {
	all := copyTo(t, "gpt-store.E01", "gpt-store.E02", "gpt-store.E03")
	if _, err := Open(all[0], all[1]); err == nil {
		t.Error("opening E01+E02 of a three-segment image succeeded: the end of the disk would be silently absent")
	}
	if _, err := Open(all[0], all[2]); err == nil {
		t.Error("opening E01+E03 (E02 missing) succeeded")
	}
	if _, err := Open(all[0]); err == nil {
		t.Error("opening only the first segment succeeded")
	}
	if img, err := Open(all...); err != nil {
		t.Errorf("the complete set must open: %v", err)
	} else {
		img.Close()
	}
}

func TestEWF_Ex01IsReportedUnsupportedNotMisread(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.Ex01")
	os.WriteFile(p, append([]byte("EVF2\x0d\x0a\x81\x00"), make([]byte, 200)...), 0o644)
	if _, err := Open(p); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Ex01 error = %v, want ErrUnsupported", err)
	}
}

func TestRaw_OpensAFileAndASplitSetAsOneDisk(t *testing.T) {
	want := rawDisk(t, "gpt")
	dir := t.TempDir()
	whole := filepath.Join(dir, "disk.dd")
	os.WriteFile(whole, want, 0o644)
	img, err := Open(whole)
	if err != nil {
		t.Fatal(err)
	}
	if img.Info().Format != FormatRaw || img.Size() != int64(len(want)) || !bytes.Equal(readAll(t, img), want) {
		t.Errorf("raw single file read back differently: %+v", img.Info())
	}
	img.Close()

	third := len(want) / 3
	parts := [][]byte{want[:third], want[third : 2*third+777], want[2*third+777:]}
	var paths []string
	for i, p := range parts {
		name := filepath.Join(dir, "split.00"+string(rune('1'+i)))
		os.WriteFile(name, p, 0o644)
		paths = append(paths, name)
	}
	found, err := FindSegments(paths[0])
	if err != nil || len(found) != 3 {
		t.Fatalf("FindSegments = %v, %v", found, err)
	}
	img, err = Open(found...)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	if !bytes.Equal(readAll(t, img), want) {
		t.Error("a split raw image does not read back as the concatenation")
	}
	buf := make([]byte, 50)
	if n, err := img.ReadAt(buf, int64(third-25)); err != nil || n != 50 || !bytes.Equal(buf, want[third-25:third+25]) {
		t.Errorf("a read across a segment boundary is wrong: n=%d err=%v", n, err)
	}
}

func TestRaw_VerifyHasNothingStoredToCompareAndSaysSo(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d.dd")
	os.WriteFile(p, rawDisk(t, "mbr"), 0o644)
	img, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	res, err := Verify(img, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := loadTruth(t)
	if res.SHA256 != tr.Images["mbr"].SHA256 {
		t.Errorf("sha256 = %s", res.SHA256)
	}
	if res.MD5Match != nil || res.SHA1Match != nil {
		t.Errorf("a raw image has no stored hash; claiming a match would be false assurance: %+v", res)
	}
}

func TestOpen_RefusesNothingAndEmptyInput(t *testing.T) {
	if _, err := Open(); err == nil {
		t.Error("Open() with no path succeeded")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "absent.dd")); err == nil {
		t.Error("a missing file opened")
	}
	empty := filepath.Join(t.TempDir(), "empty.dd")
	os.WriteFile(empty, nil, 0o644)
	if _, err := Open(empty); err == nil {
		t.Error("an empty file opened as an image")
	}
}
