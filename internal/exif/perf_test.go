package exif_test

import (
	"bytes"
	"testing"

	"tracefall/internal/exif"
	"tracefall/internal/exif/exifgen"
)

// A real photograph is megabytes of pixel data. Reading its metadata
// must cost the marker segments and nothing more -- so the benchmark
// pads the fixture to the size of a real phone photo and the cost must
// not move with the padding.
func BenchmarkParse_LargeImage(b *testing.B) {
	small := exifgen.Build(photo())
	large := append(append([]byte{}, small...), bytes.Repeat([]byte{0xAB}, 8<<20)...)

	b.Run("small", func(b *testing.B) {
		b.SetBytes(int64(len(small)))
		for i := 0; i < b.N; i++ {
			if _, err := exif.Parse(bytes.NewReader(small), exif.DefaultLimits()); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("8MB", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := exif.Parse(bytes.NewReader(large), exif.DefaultLimits()); err != nil {
				b.Fatal(err)
			}
		}
	})
}
