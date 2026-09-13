// Package thumb produces small preview images for display, without ever
// touching the evidence they are derived from.
//
// # Two sources, in order of preference
//
//  1. The thumbnail the camera already embedded in the image's EXIF
//     block. This costs a byte-range read: nothing is decoded, scaled or
//     re-encoded, so the preview a viewer sees is literally a range of
//     bytes present in the evidence file, and the result says which
//     range. 14 of the 26 images in one real triage image carry one.
//
//  2. A downscale of the image itself, for the ones that do not. This
//     does decode and re-encode -- into a NEW buffer. The source file is
//     opened read-only and is never written to, moved, renamed or
//     re-saved.
//
// # A thumbnail is not evidence
//
// Everything this package returns is a DERIVED DISPLAY ARTIFACT. It is
// never hashed as evidence, never presented as the source file's hash,
// and never replaces the original. Result.Source and Result.Note say
// where each preview came from so a viewer can state what it is showing.
package thumb

import (
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
	"os"

	"tracefall/internal/exif"
)

// Source names where a preview came from. It travels with the bytes
// because "this is the camera's own thumbnail" and "this is a picture
// Tracefall rendered" are different claims.
const (
	// SourceEmbedded: copied verbatim out of the evidence file's EXIF
	// block. Byte-for-byte what the camera wrote.
	SourceEmbedded = "embedded_exif_thumbnail"
	// SourceDownscaled: decoded from the evidence and re-encoded smaller
	// by Tracefall. A rendering of the evidence, not a copy of it.
	SourceDownscaled = "downscaled_by_tracefall"
)

// Limits bound what generating one preview may cost. Every one of them
// caps work driven by a number inside an attacker-supplied file.
type Limits struct {
	// MaxEdge is the longest edge of a generated thumbnail, in pixels.
	MaxEdge int
	// MaxSourcePixels refuses to decode an image larger than this.
	// Decoding is the only step here with unbounded memory cost, and a
	// declared 60000x60000 JPEG is a few hundred bytes on disk.
	MaxSourcePixels int
	// MaxEmbeddedBytes caps the embedded thumbnail accepted from EXIF.
	MaxEmbeddedBytes int
	// Quality is the JPEG quality used for a downscale.
	Quality int
}

// DefaultLimits are sized for a marker preview and a popup card: 256px
// matches the edge cameras themselves use for EXIF thumbnails, so the
// two sources look alike.
func DefaultLimits() Limits {
	return Limits{
		MaxEdge:          256,
		MaxSourcePixels:  80_000_000,
		MaxEmbeddedBytes: 4 << 20,
		Quality:          82,
	}
}

// Result is one generated preview.
type Result struct {
	JPEG   []byte
	Source string // SourceEmbedded or SourceDownscaled
	Width  int
	Height int
	// Offset and Length are the byte range in the SOURCE FILE the
	// preview was copied from, set only for SourceEmbedded. They make
	// the claim checkable: an analyst can read those bytes out of the
	// evidence and get the same image.
	Offset int64
	Length int
	// Note states, in one line, what this preview is.
	Note string
}

// ErrNotRenderable reports that no preview could be produced -- the file
// is not a JPEG, or its pixel data cannot be decoded. It is deliberately
// distinct from an I/O failure: "this evidence has no preview" is a fact
// to display, not an error to retry.
var ErrNotRenderable = fmt.Errorf("thumb: no preview can be produced from this file")

// Generate produces a preview of absPath.
//
// absPath is opened READ-ONLY and is never modified. The caller is
// responsible for having resolved absPath from an authorized evidence
// record -- this package does no authorization and accepts no
// browser-supplied path.
func Generate(absPath string, lim Limits) (Result, error) {
	if lim.MaxEdge <= 0 {
		lim = DefaultLimits()
	}

	// 1. The camera's own thumbnail, if there is one. No decode.
	jpegBytes, off, ok, err := exif.EmbeddedThumbnail(absPath, exif.DefaultLimits())
	if err == nil && ok && len(jpegBytes) <= lim.MaxEmbeddedBytes {
		w, h := jpegDimensions(jpegBytes)
		return Result{
			JPEG:   jpegBytes,
			Source: SourceEmbedded,
			Width:  w, Height: h,
			Offset: off,
			Length: len(jpegBytes),
			Note: fmt.Sprintf("the thumbnail the camera embedded in this image's EXIF block, copied "+
				"unchanged from bytes %d-%d of the evidence file", off, off+int64(len(jpegBytes))),
		}, nil
	}

	// 2. Downscale the image itself.
	return downscale(absPath, lim)
}

func downscale(absPath string, lim Limits) (Result, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()

	// The header is read first so an absurd declared size is refused
	// BEFORE any pixel buffer is allocated.
	cfg, _, err := image.DecodeConfig(f)
	if err != nil {
		return Result{}, ErrNotRenderable
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return Result{}, ErrNotRenderable
	}
	if lim.MaxSourcePixels > 0 && cfg.Width*cfg.Height > lim.MaxSourcePixels {
		return Result{}, fmt.Errorf("thumb: image declares %dx%d pixels, over the %d-pixel decode limit",
			cfg.Width, cfg.Height, lim.MaxSourcePixels)
	}
	if _, err := f.Seek(0, 0); err != nil {
		return Result{}, err
	}

	src, err := jpeg.Decode(f)
	if err != nil {
		return Result{}, ErrNotRenderable
	}

	dst := boxDownscale(src, lim.MaxEdge)
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, dst, &jpeg.Options{Quality: lim.Quality}); err != nil {
		return Result{}, err
	}
	b := dst.Bounds()
	return Result{
		JPEG:   buf.Bytes(),
		Source: SourceDownscaled,
		Width:  b.Dx(), Height: b.Dy(),
		Note: fmt.Sprintf("rendered by Tracefall: this image embeds no EXIF thumbnail, so its pixels were "+
			"decoded and re-encoded at %dx%d for display. The evidence file itself is unchanged",
			b.Dx(), b.Dy()),
	}, nil
}

// boxDownscale reduces src so its longest edge is at most maxEdge, by
// averaging each destination pixel's source box.
//
// A box filter rather than nearest-neighbour because nearest-neighbour
// aliases badly on photographs at these ratios -- a preview an analyst
// cannot recognize is not doing its job. It is written here rather than
// pulled from a library because it is twenty lines and the alternative
// is a dependency in a tool that has none.
//
// An image already within maxEdge is returned scaled 1:1 rather than
// enlarged: a preview must never invent detail.
func boxDownscale(src image.Image, maxEdge int) *image.RGBA {
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()

	dw, dh := sw, sh
	if sw > maxEdge || sh > maxEdge {
		if sw >= sh {
			dw = maxEdge
			dh = max(1, sh*maxEdge/sw)
		} else {
			dh = maxEdge
			dw = max(1, sw*maxEdge/sh)
		}
	}

	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for dy := 0; dy < dh; dy++ {
		y0 := b.Min.Y + dy*sh/dh
		y1 := b.Min.Y + (dy+1)*sh/dh
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for dx := 0; dx < dw; dx++ {
			x0 := b.Min.X + dx*sw/dw
			x1 := b.Min.X + (dx+1)*sw/dw
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var r, g, bl, n uint64
			for y := y0; y < y1; y++ {
				for x := x0; x < x1; x++ {
					cr, cg, cb, _ := src.At(x, y).RGBA()
					r += uint64(cr >> 8)
					g += uint64(cg >> 8)
					bl += uint64(cb >> 8)
					n++
				}
			}
			if n == 0 {
				n = 1
			}
			i := dst.PixOffset(dx, dy)
			dst.Pix[i+0] = uint8(r / n)
			dst.Pix[i+1] = uint8(g / n)
			dst.Pix[i+2] = uint8(bl / n)
			dst.Pix[i+3] = 0xFF
		}
	}
	return dst
}

// jpegDimensions reads a JPEG's frame header without decoding it. Used
// only to describe an embedded thumbnail whose IFD1 omitted its size
// tags, which is most of them.
func jpegDimensions(b []byte) (int, int) {
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return 0, 0
	}
	return cfg.Width, cfg.Height
}
