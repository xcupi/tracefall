package lzxpress

import (
	"encoding/binary"
	"fmt"
)

// bitReader reads the Xpress Huffman bit stream.
//
// The bit order is the format's, not a conventional one: bits are taken
// most-significant-first out of a 32-bit window that is refilled from
// LITTLE-endian 16-bit words. Getting either half of that wrong decodes
// plausible-looking garbage rather than failing, which is why it is
// isolated here and tested directly.
//
// pos doubles as the raw-byte cursor. Extended match lengths are read as
// whole bytes from the same position the bit stream refills from, so the
// two are deliberately not separate streams.
type bitReader struct {
	src  []byte
	pos  int    // next byte to read, for refills and raw reads
	mask uint32 // bit window, most-significant bit next
	bits int    // how many bits of mask are valid

	// exhausted records that a refill ran past the end and zero bits
	// were substituted. The stream is padded rather than failed at that
	// moment because a chunk's final symbols legitimately sit against
	// the end of the buffer; a decode that actually depends on the
	// padding fails on its own terms instead.
	exhausted bool
}

func newBitReader(src []byte, off int) (*bitReader, error) {
	if off < 0 || off+4 > len(src) {
		return nil, fmt.Errorf("%w: need 4 bytes to prime the bit stream at offset %d", ErrTruncated, off)
	}
	r := &bitReader{src: src, pos: off}
	r.mask = uint32(binary.LittleEndian.Uint16(src[off:off+2]))<<16 |
		uint32(binary.LittleEndian.Uint16(src[off+2:off+4]))
	r.pos += 4
	r.bits = 32
	return r, nil
}

// peek returns the next n bits without consuming them.
func (r *bitReader) peek(n int) uint32 {
	if n <= 0 {
		return 0
	}
	return r.mask >> (32 - uint(n))
}

// skip consumes n bits, refilling from the source when the window drops
// below one word.
func (r *bitReader) skip(n int) error {
	if n < 0 || n > r.bits {
		// Only reachable on a code length the table should never have
		// produced; refusing beats decoding past the window.
		return fmt.Errorf("%w: tried to consume %d bits with %d available", ErrCorrupt, n, r.bits)
	}
	r.mask <<= uint(n)
	r.bits -= n
	if r.bits < 16 {
		if r.pos+2 > len(r.src) {
			// Pad with zeros. See exhausted.
			r.exhausted = true
			r.bits += 16
			return nil
		}
		r.mask |= uint32(binary.LittleEndian.Uint16(r.src[r.pos:r.pos+2])) << uint(16-r.bits)
		r.pos += 2
		r.bits += 16
	}
	return nil
}

func (r *bitReader) readByte() (byte, bool) {
	if r.pos >= len(r.src) {
		return 0, false
	}
	b := r.src[r.pos]
	r.pos++
	return b, true
}

func (r *bitReader) readUint16() (uint16, bool) {
	if r.pos+2 > len(r.src) {
		return 0, false
	}
	v := binary.LittleEndian.Uint16(r.src[r.pos : r.pos+2])
	r.pos += 2
	return v, true
}

func (r *bitReader) readUint32() (uint32, bool) {
	if r.pos+4 > len(r.src) {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(r.src[r.pos : r.pos+4])
	r.pos += 4
	return v, true
}
