package prefetchgen

import "encoding/binary"

// MAM fixture generation.
//
// Builds a genuine Windows 10/11 MAM container around SCCA bytes:
// a real 256-byte Huffman code-length table and a real LZXPRESS Huffman
// bit stream that internal/lzxpress decodes.
//
// It is deliberately a LITERALS-ONLY encoder. Every byte is emitted as
// its own 8-bit Huffman symbol and no LZ77 match is ever produced, which
// makes the fixture trivially auditable and keeps this file short. The
// consequence is that it exercises the decoder's table construction, bit
// order, chunking and container handling, but NOT its match paths.
//
// That limitation is deliberate and safe, because the match paths are
// validated against real Windows 10 evidence rather than against this
// encoder -- see TestDecompress_RealWindowsCorpus. A fixture generator
// that shared a misunderstanding with the decoder would round-trip
// perfectly while both were wrong, so it is not relied on for
// correctness of the format.

// literalOnlyTable is the 256-byte code-length table for a code where
// all 256 literals have length 8 and no match symbol is defined.
//
// 256 symbols x 2^(15-8) slots = 2^15 exactly, so the code is complete,
// and with equal lengths the canonical code for symbol i is simply i.
func literalOnlyTable() []byte {
	table := make([]byte, 256)
	for i := 0; i < 128; i++ {
		table[i] = 0x88 // two symbols per byte, each length 8
	}
	// Bytes 128..255 cover symbols 256..511: length 0, undefined.
	return table
}

// bitWriter accumulates bits most-significant-first and flushes them as
// little-endian 16-bit words, mirroring the reader in internal/lzxpress.
type bitWriter struct {
	out  []byte
	acc  uint32
	bits int
}

func (w *bitWriter) write(value uint32, n int) {
	for i := n - 1; i >= 0; i-- {
		w.acc = (w.acc << 1) | ((value >> uint(i)) & 1)
		w.bits++
		if w.bits == 16 {
			var word [2]byte
			binary.LittleEndian.PutUint16(word[:], uint16(w.acc))
			w.out = append(w.out, word[:]...)
			w.acc, w.bits = 0, 0
		}
	}
}

// flush pads the chunk to exactly the number of bytes a reader will have
// consumed by the time the chunk's output is complete.
//
// A reader primes 32 bits and then pulls a 16-bit word whenever fewer
// than 16 remain, so when a chunk ends it has always read AHEAD of the
// bits it actually used. In a multi-chunk stream the next code-length
// table begins at that read-ahead position, so the encoder has to leave
// exactly that much padding -- too little and the reader starts the next
// table late, too much and it starts early.
//
// The amount is computed by replaying the reader's refill schedule over
// the bits just written, which is exact for any content rather than a
// constant that happens to work for one case.
func (w *bitWriter) flush(symbolBits []int) {
	if w.bits > 0 {
		w.write(0, 16-w.bits)
	}
	written := len(w.out)

	consumed := 4 // the reader primes two words
	bits := 32
	for _, n := range symbolBits {
		bits -= n
		if bits < 16 {
			bits += 16
			consumed += 2
		}
	}
	for written < consumed {
		w.out = append(w.out, 0, 0)
		written += 2
	}
}

// CompressMAM wraps plain SCCA bytes in a MAM container, as Windows
// 10/11 stores Prefetch.
func CompressMAM(plain []byte) []byte {
	const chunk = 65536

	out := make([]byte, 8)
	copy(out[0:3], "MAM")
	out[3] = 0x04 // LZXPRESS Huffman
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(plain)))

	for start := 0; start < len(plain); start += chunk {
		end := start + chunk
		if end > len(plain) {
			end = len(plain)
		}
		out = append(out, literalOnlyTable()...)
		w := &bitWriter{}
		symbolBits := make([]int, 0, end-start)
		for _, b := range plain[start:end] {
			w.write(uint32(b), 8)
			symbolBits = append(symbolBits, 8)
		}
		w.flush(symbolBits)
		out = append(out, w.out...)
	}
	// An empty input still needs a chunk for the decoder to find.
	if len(plain) == 0 {
		out = append(out, literalOnlyTable()...)
		w := &bitWriter{}
		w.flush(nil)
		out = append(out, w.out...)
	}
	return out
}

// Compressed wraps arbitrary bytes in a MAM header WITHOUT a valid
// compressed stream, for testing the failure path: a container that
// announces LZXPRESS Huffman and then carries nothing decodable.
func Compressed(uncompressedSize uint32) []byte {
	out := make([]byte, 8, 64)
	copy(out[0:3], "MAM")
	out[3] = 0x04
	binary.LittleEndian.PutUint32(out[4:8], uncompressedSize)
	return append(out, make([]byte, 32)...)
}

// CompressedMethod builds a MAM container declaring some other
// compression method, for the unsupported-method path.
func CompressedMethod(uncompressedSize uint32, method byte) []byte {
	out := Compressed(uncompressedSize)
	out[3] = method
	return out
}
