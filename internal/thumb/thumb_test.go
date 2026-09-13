package thumb_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"image"
	"image/jpeg"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/exif/exifgen"
	"tracefall/internal/thumb"
)

func write(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// realJPEG builds an image with actual pixel data, so the downscale path
// has something to decode. exifgen writes marker structure rather than a
// real scan, which is right for parser tests and useless here.
func realJPEG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			i := img.PixOffset(x, y)
			img.Pix[i] = uint8(x % 256)
			img.Pix[i+1] = uint8(y % 256)
			img.Pix[i+2] = 128
			img.Pix[i+3] = 255
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The forensic requirement, stated as a test: producing a preview must
// not change one byte of the evidence.
func TestGenerate_LeavesTheOriginalByteIdentical(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"with embedded thumbnail", exifgen.Build(withThumbnail())},
		{"needing a downscale", realJPEG(t, 900, 600)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := write(t, "evidence.jpg", tc.data)
			before := sha256.Sum256(tc.data)

			if _, err := thumb.Generate(path, thumb.DefaultLimits()); err != nil {
				t.Fatalf("Generate: %v", err)
			}

			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := sha256.Sum256(after); got != before {
				t.Errorf("the evidence file changed:\n before %x\n after  %x", before, got)
			}
			if len(after) != len(tc.data) {
				t.Errorf("evidence size changed from %d to %d bytes", len(tc.data), len(after))
			}
		})
	}
}

// The embedded thumbnail must be COPIED, not re-rendered: the bytes
// served have to be the bytes in the file.
func TestGenerate_EmbeddedThumbnailIsCopiedVerbatim(t *testing.T) {
	spec := withThumbnail()
	data := exifgen.Build(spec)
	path := write(t, "photo.jpg", data)

	res, err := thumb.Generate(path, thumb.DefaultLimits())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if res.Source != thumb.SourceEmbedded {
		t.Fatalf("Source = %q, want %q", res.Source, thumb.SourceEmbedded)
	}
	if res.Length != len(res.JPEG) {
		t.Errorf("Length = %d but %d bytes returned", res.Length, len(res.JPEG))
	}
	if res.Offset <= 0 {
		t.Errorf("Offset = %d; the byte range must be reported so the copy can be checked", res.Offset)
	}
	// The claim the Note makes must hold: those bytes, at that offset,
	// in that file.
	if int(res.Offset)+res.Length > len(data) {
		t.Fatalf("the reported range %d+%d lies outside the %d-byte file", res.Offset, res.Length, len(data))
	}
	inFile := data[res.Offset : int(res.Offset)+res.Length]
	if !bytes.Equal(inFile, res.JPEG) {
		t.Error("the returned preview is not byte-identical to the range it says it came from")
	}
	if !strings.Contains(res.Note, "unchanged") {
		t.Errorf("Note = %q; it must say the bytes were copied unchanged", res.Note)
	}
}

func TestGenerate_FallsBackToADownscaleWhenNoThumbnailIsEmbedded(t *testing.T) {
	path := write(t, "photo.jpg", realJPEG(t, 1200, 800))

	res, err := thumb.Generate(path, thumb.DefaultLimits())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if res.Source != thumb.SourceDownscaled {
		t.Fatalf("Source = %q, want %q", res.Source, thumb.SourceDownscaled)
	}
	// A rendering must never claim to be a copy of a byte range.
	if res.Offset != 0 || res.Length != 0 {
		t.Errorf("a downscale reported a source byte range (%d+%d); it is not a copy of one",
			res.Offset, res.Length)
	}
	if !strings.Contains(res.Note, "unchanged") {
		t.Errorf("Note = %q; it must state that the evidence is unchanged", res.Note)
	}

	cfg, err := jpeg.DecodeConfig(bytes.NewReader(res.JPEG))
	if err != nil {
		t.Fatalf("the downscale is not a decodable JPEG: %v", err)
	}
	if cfg.Width > 256 || cfg.Height > 256 {
		t.Errorf("downscale is %dx%d, over the 256px limit", cfg.Width, cfg.Height)
	}
	// Aspect ratio preserved: 1200x800 is 3:2.
	if got := float64(cfg.Width) / float64(cfg.Height); got < 1.4 || got > 1.6 {
		t.Errorf("aspect ratio = %v, want about 1.5", got)
	}
}

// A preview must never invent detail by enlarging.
func TestGenerate_SmallImageIsNotEnlarged(t *testing.T) {
	path := write(t, "small.jpg", realJPEG(t, 80, 60))
	res, err := thumb.Generate(path, thumb.DefaultLimits())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(res.JPEG))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Width != 80 || cfg.Height != 60 {
		t.Errorf("an 80x60 image became %dx%d; a preview must not upscale", cfg.Width, cfg.Height)
	}
}

func TestGenerate_NonImageIsNotRenderable(t *testing.T) {
	path := write(t, "notes.jpg", []byte("MZ this is a PE binary, not a picture"))
	_, err := thumb.Generate(path, thumb.DefaultLimits())
	if !errors.Is(err, thumb.ErrNotRenderable) {
		t.Errorf("err = %v, want ErrNotRenderable", err)
	}
}

func TestGenerate_TruncatedImageNeverPanics(t *testing.T) {
	full := realJPEG(t, 400, 300)
	for _, cut := range []int{0, 2, 10, 100, len(full) / 2, len(full) - 1} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic at cut %d: %v", cut, r)
				}
			}()
			path := write(t, "cut.jpg", full[:cut])
			_, _ = thumb.Generate(path, thumb.DefaultLimits())
		}()
	}
}

// Decoding is the only unbounded-memory step here, so a declared size
// must be refused before any pixel buffer is allocated.
func TestGenerate_RefusesAnImageOverThePixelLimit(t *testing.T) {
	path := write(t, "big.jpg", realJPEG(t, 900, 900))
	lim := thumb.DefaultLimits()
	lim.MaxSourcePixels = 1000

	_, err := thumb.Generate(path, lim)
	if err == nil {
		t.Fatal("an image over the pixel limit was decoded")
	}
	if !strings.Contains(err.Error(), "decode limit") {
		t.Errorf("err = %v; it should name the limit", err)
	}
}

func TestGenerate_IsDeterministic(t *testing.T) {
	path := write(t, "photo.jpg", realJPEG(t, 640, 480))
	first, err := thumb.Generate(path, thumb.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		got, err := thumb.Generate(path, thumb.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.JPEG, first.JPEG) {
			t.Fatalf("run %d produced different bytes", i)
		}
	}
}

func withThumbnail() exifgen.Spec {
	return exifgen.Spec{
		Width: 4160, Height: 3120,
		Make: "LG Electronics", Model: "LM-Q725K",
		DateTimeOriginal: "2021:04:29 15:20:43",
		GPS: &exifgen.GPS{
			LatRef: "S", Lat: exifgen.DMS(16, 0, 0),
			LonRef: "E", Lon: exifgen.DMS(23, 0, 0),
		},
		Thumbnail: exifgen.MinimalJPEG(),
	}
}
