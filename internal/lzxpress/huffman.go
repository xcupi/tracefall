// Package lzxpress implements LZXPRESS Huffman decompression -- the
// algorithm Microsoft documents as "Xpress Huffman" in MS-XCA, and the
// one Windows 10 and 11 use to store Prefetch files.
//
// It exists because Tracefall must read the ORIGINAL evidence. A modern
// Windows host writes every .pf compressed, so without this the most
// valuable execution artifact on the system is unreadable unless an
// analyst first runs a second tool over it by hand -- which is both a
// workflow burden and a chain-of-custody problem, since it puts a
// derived file into the case in place of the collected one.
//
// # Format
//
// The stream is a sequence of independently-Huffman-coded chunks, each
// producing at most 65,536 bytes of output. A chunk is:
//
//	256 bytes  code lengths: 512 symbols, one 4-bit length each,
//	           low nibble first
//	...        a bit stream, read as little-endian 16-bit words,
//	           most-significant bit first
//
// Symbols 0-255 are literal bytes. Symbols 256-511 encode an LZ77 match:
// the low 4 bits are a length, the high 4 bits are how many extra bits
// carry the match offset.
//
// Matches may reference anything already produced, including across a
// chunk boundary -- the offset field reaches 65,535 bytes, further back
// than one chunk.
//
// # Hostile input
//
// Every byte here comes from evidence and none of it is trusted. The
// declared output size is checked against a ceiling BEFORE anything is
// allocated, so a header claiming four gigabytes costs nothing; every
// read is bounds-checked; a match offset pointing before the start of
// the output is rejected rather than wrapped; and output is written into
// a buffer of exactly the declared size, so no sequence of symbols can
// grow it. The result is that a malformed or deliberately hostile stream
// returns an error -- it does not panic, spin, or allocate without
// bound.
package lzxpress

import (
	"errors"
	"fmt"
)

var (
	// ErrTruncated means the compressed stream ended before the declared
	// output was produced.
	ErrTruncated = errors.New("lzxpress: compressed stream is truncated")
	// ErrCorrupt means the stream is structurally invalid: an undefined
	// Huffman code, or a match reaching back past the start of the
	// output.
	ErrCorrupt = errors.New("lzxpress: compressed stream is corrupt")
	// ErrLimitExceeded means the declared output size is above the
	// caller's ceiling. Reported before allocating anything.
	ErrLimitExceeded = errors.New("lzxpress: declared output size exceeds the limit")
)

const (
	// chunkSize is the output produced by one Huffman-coded chunk.
	chunkSize = 65536
	// symbolCount is 256 literals plus 256 match descriptors.
	symbolCount = 512
	// tableBits is the longest possible code, since lengths are 4 bits.
	tableBits = 15
	// invalidSymbol marks a decoding-table slot no code reaches. Looking
	// one up means the stream used a code the table never defined.
	invalidSymbol = uint16(0xFFFF)
)

// HuffmanDecompress decompresses src into exactly declaredSize bytes.
//
// declaredSize comes from the container (for Prefetch, the MAM header)
// and is authoritative: the result is allocated at that size and decoding
// stops when it is full. maxSize is the caller's ceiling; a declaredSize
// above it is refused without allocating.
func HuffmanDecompress(src []byte, declaredSize int, maxSize int) (out []byte, err error) {
	// A backstop, not the safety mechanism. Every index below is
	// bounds-checked; this guarantees the package's promise even if one
	// of those checks is ever wrong.
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("%w: recovered from %v", ErrCorrupt, r)
		}
	}()

	if declaredSize < 0 {
		return nil, fmt.Errorf("%w: negative declared size %d", ErrCorrupt, declaredSize)
	}
	if maxSize > 0 && declaredSize > maxSize {
		return nil, fmt.Errorf("%w: declared %d bytes, limit is %d", ErrLimitExceeded, declaredSize, maxSize)
	}
	if declaredSize == 0 {
		return []byte{}, nil
	}
	if len(src) == 0 {
		return nil, fmt.Errorf("%w: no compressed data", ErrTruncated)
	}

	// Allocated once, at exactly the declared size. Nothing in the
	// decode loop can grow it, which is what makes a decompression bomb
	// impossible rather than merely unlikely.
	out = make([]byte, declaredSize)

	srcPos, outPos := 0, 0
	for outPos < declaredSize {
		if srcPos+256 > len(src) {
			return nil, fmt.Errorf("%w: need a 256-byte code-length table at offset %d", ErrTruncated, srcPos)
		}
		lengths := decodeCodeLengths(src[srcPos : srcPos+256])
		table, err := buildDecodingTable(lengths)
		if err != nil {
			return nil, err
		}

		br, err := newBitReader(src, srcPos+256)
		if err != nil {
			return nil, err
		}

		target := outPos + chunkSize
		if target > declaredSize {
			target = declaredSize
		}
		if outPos, err = decodeChunk(br, table, lengths, out, outPos, target); err != nil {
			return nil, err
		}

		// The next chunk's 256-byte table begins exactly at the reader's
		// cursor.
		//
		// No lookahead is given back, which is initially surprising: the
		// reader primes 32 bits and keeps up to two words buffered ahead
		// of the bits it has actually consumed. It works because the
		// ENCODER flushes its own 32-bit register when it closes a chunk,
		// so those trailing words are padding the encoder wrote, not data
		// the next chunk needs. Determined against real Windows 10
		// evidence: giving the lookahead back decoded 54 of 81 files,
		// while starting at the cursor decoded all 81.
		next := br.pos
		if next <= srcPos {
			// No forward progress: a malformed stream would otherwise
			// loop here forever.
			return nil, fmt.Errorf("%w: chunk at offset %d consumed no input", ErrCorrupt, srcPos)
		}
		srcPos = next
	}
	return out, nil
}

// decodeCodeLengths expands the 256-byte table into 512 code lengths.
// The low nibble of each byte is the even-numbered symbol.
func decodeCodeLengths(raw []byte) []uint8 {
	lengths := make([]uint8, symbolCount)
	for i := 0; i < 256; i++ {
		lengths[2*i] = raw[i] & 0x0F
		lengths[2*i+1] = raw[i] >> 4
	}
	return lengths
}

// buildDecodingTable turns canonical code lengths into a flat lookup
// keyed by the next 15 bits.
//
// Codes are assigned shortest-first, in symbol order, exactly as the
// canonical construction requires. A symbol of length L occupies
// 2^(15-L) consecutive slots, so one indexed read decodes any symbol.
//
// An INCOMPLETE table (one whose slots are not all claimed) is accepted
// rather than rejected outright: unclaimed slots keep invalidSymbol and
// fail only if the stream actually uses one. Rejecting the whole file up
// front would discard evidence a conforming decoder would read.
func buildDecodingTable(lengths []uint8) ([]uint16, error) {
	table := make([]uint16, 1<<tableBits)
	for i := range table {
		table[i] = invalidSymbol
	}
	slot := 0
	for bitLen := 1; bitLen <= tableBits; bitLen++ {
		for sym := 0; sym < symbolCount; sym++ {
			if lengths[sym] != uint8(bitLen) {
				continue
			}
			span := 1 << (tableBits - bitLen)
			if slot+span > len(table) {
				// The lengths over-subscribe the code space, so they
				// cannot describe a prefix-free code.
				return nil, fmt.Errorf("%w: Huffman code lengths over-subscribe the code space", ErrCorrupt)
			}
			for i := 0; i < span; i++ {
				table[slot+i] = uint16(sym)
			}
			slot += span
		}
	}
	if slot == 0 {
		return nil, fmt.Errorf("%w: Huffman table defines no symbols", ErrCorrupt)
	}
	return table, nil
}

// decodeChunk decodes symbols into out[outPos:target] and returns the
// new output position.
func decodeChunk(br *bitReader, table []uint16, lengths []uint8, out []byte, outPos, target int) (int, error) {
	for outPos < target {
		sym := table[br.peek(tableBits)]
		if sym == invalidSymbol {
			return 0, fmt.Errorf("%w: undefined Huffman code at output offset %d", ErrCorrupt, outPos)
		}
		if err := br.skip(int(lengths[sym])); err != nil {
			return 0, err
		}

		if sym < 256 {
			out[outPos] = byte(sym)
			outPos++
			continue
		}

		// A match: low 4 bits are the length, high 4 the offset width.
		desc := sym - 256
		matchLen := int(desc & 0x0F)
		offsetBits := int(desc >> 4)

		// ORDER MATTERS, and it is the opposite of what the field layout
		// suggests: the extended-length bytes are consumed BEFORE the
		// offset's extra bits.
		//
		// Both come from the same buffer, so the order decides which
		// bytes each one gets. Reading the offset first lets its skip
		// pull another 16-bit word, moving the byte cursor two bytes on,
		// and the length escape then reads the wrong byte -- after which
		// the whole stream is silently garbage rather than obviously
		// broken. Determined against real Windows 10 evidence: offset
		// first decoded 4 of 81 files, length first decoded all 81.
		if matchLen == 15 {
			b, ok := br.readByte()
			if !ok {
				return 0, fmt.Errorf("%w: match length escape past end of stream", ErrTruncated)
			}
			matchLen = int(b) + 15
			if matchLen == 270 {
				w, ok := br.readUint16()
				if !ok {
					return 0, fmt.Errorf("%w: 16-bit match length past end of stream", ErrTruncated)
				}
				matchLen = int(w)
				if matchLen == 0 {
					d, ok := br.readUint32()
					if !ok {
						return 0, fmt.Errorf("%w: 32-bit match length past end of stream", ErrTruncated)
					}
					if d > uint32(len(out)) {
						return 0, fmt.Errorf("%w: match length %d exceeds the declared output size", ErrCorrupt, d)
					}
					matchLen = int(d)
				}
			}
		}
		matchLen += 3

		// The offset's high bit is implied by its width, so a width of n
		// describes offsets [2^n, 2^(n+1)-1]. An offset is never zero.
		matchOffset := 1 << offsetBits
		if offsetBits > 0 {
			extra := int(br.peek(offsetBits))
			if err := br.skip(offsetBits); err != nil {
				return 0, err
			}
			matchOffset += extra
		}

		if matchOffset > outPos {
			// Reaching back before the first byte ever produced.
			return 0, fmt.Errorf("%w: match offset %d reaches before the start of the output at %d",
				ErrCorrupt, matchOffset, outPos)
		}
		// Byte at a time, deliberately: an overlapping match (offset
		// smaller than length) is legal and is how runs are encoded, so
		// a bulk copy would produce the wrong bytes.
		for i := 0; i < matchLen && outPos < target; i++ {
			out[outPos] = out[outPos-matchOffset]
			outPos++
		}
	}
	return outPos, nil
}
