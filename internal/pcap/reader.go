// Package pcap reads packet captures and extracts what they can prove:
// who talked to whom and when, which names were looked up, which HTTP
// objects crossed the wire and their hashes, which hosts' clocks were
// observed, and which connections were Remote Desktop.
//
// # Formats
//
// Classic pcap (both byte orders, microsecond and nanosecond timestamps) and
// pcapng (section header, interface description, enhanced and simple packet
// blocks). Link types Ethernet, Linux cooked capture (v1 and v2), raw IP and
// the BSD loopback header are decoded; a capture on any other link type is
// reported as unsupported rather than guessed at.
//
// # Time
//
// A packet's time is the capture machine's clock. It is not any observed
// host's clock, and the two can differ. Package clockskew is where the two
// are compared; nothing in this package adjusts a time.
//
// # Bounds
//
// A capture is untrusted input and can be gigabytes. Every table here has a
// cap, packets are read as a stream, HTTP bodies are hashed and never kept,
// and a record claiming a length beyond the format limit ends the read with
// an error instead of an allocation.
package pcap

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Link types (LINKTYPE_*).
const (
	LinkNull        = 0
	LinkEthernet    = 1
	LinkRaw         = 101
	LinkRawIPv4     = 228
	LinkRawIPv6     = 229
	LinkLinuxSLL    = 113
	LinkLinuxSLL2   = 276
	LinkLoop        = 108
	maxPacketBytes  = 1 << 20 // a record longer than this is not a packet
	maxBlockBytes   = 16 << 20
	maxInterfaces   = 4096
	pcapMagicMicro  = 0xa1b2c3d4
	pcapMagicNano   = 0xa1b23c4d
	pcapngSHB       = 0x0A0D0D0A
	pcapngByteOrder = 0x1A2B3C4D
)

// Packet is one captured frame.
type Packet struct {
	Time     time.Time // capture clock, UTC
	LinkType int
	Data     []byte // valid until the next call to Next
	OrigLen  int    // length on the wire; larger than len(Data) when truncated
}

// ErrUnsupported is returned for input that is not a capture this package reads.
var ErrUnsupported = errors.New("pcap: not a supported capture format")

// Reader yields the packets of a capture in file order.
type Reader struct {
	r        *bufio.Reader
	order    binary.ByteOrder
	ng       bool
	nano     bool
	linkType int
	ifaces   []iface // pcapng
	buf      []byte
	count    uint64
}

type iface struct {
	link  int
	units time.Duration // duration of one timestamp tick
}

// NewReader reads the file header and returns a Reader.
func NewReader(src io.Reader) (*Reader, error) {
	br := bufio.NewReaderSize(src, 1<<20)
	head, err := br.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("pcap: reading header: %w", err)
	}
	rd := &Reader{r: br}
	le := binary.LittleEndian.Uint32(head)
	be := binary.BigEndian.Uint32(head)
	switch {
	case le == pcapngSHB:
		rd.ng = true
		return rd, nil
	case le == pcapMagicMicro:
		rd.order = binary.LittleEndian
	case le == pcapMagicNano:
		rd.order, rd.nano = binary.LittleEndian, true
	case be == pcapMagicMicro:
		rd.order = binary.BigEndian
	case be == pcapMagicNano:
		rd.order, rd.nano = binary.BigEndian, true
	default:
		return nil, ErrUnsupported
	}
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, fmt.Errorf("pcap: short file header: %w", err)
	}
	rd.linkType = int(rd.order.Uint32(hdr[20:24]) & 0x0fffffff)
	return rd, nil
}

// Next returns the next packet, io.EOF at a clean end, or an error describing
// why the rest of the file could not be read. A capture cut off mid-record
// (common for a capture stopped by killing the tool) is io.ErrUnexpectedEOF:
// the packets before it are valid.
func (r *Reader) Next() (Packet, error) {
	if r.ng {
		return r.nextNG()
	}
	var h [16]byte
	if _, err := io.ReadFull(r.r, h[:]); err != nil {
		if err == io.EOF {
			return Packet{}, io.EOF
		}
		return Packet{}, io.ErrUnexpectedEOF
	}
	sec, frac := r.order.Uint32(h[0:4]), r.order.Uint32(h[4:8])
	incl, orig := r.order.Uint32(h[8:12]), r.order.Uint32(h[12:16])
	if incl > maxPacketBytes {
		return Packet{}, fmt.Errorf("pcap: record %d claims %d captured bytes", r.count+1, incl)
	}
	data, err := r.read(int(incl))
	if err != nil {
		return Packet{}, err
	}
	nsec := int64(frac) * 1000
	if r.nano {
		nsec = int64(frac)
	}
	r.count++
	return Packet{
		Time: time.Unix(int64(sec), nsec).UTC(), LinkType: r.linkType, Data: data, OrigLen: int(orig),
	}, nil
}

func (r *Reader) read(n int) ([]byte, error) {
	if cap(r.buf) < n {
		r.buf = make([]byte, n)
	}
	r.buf = r.buf[:n]
	if _, err := io.ReadFull(r.r, r.buf); err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	return r.buf, nil
}

func (r *Reader) nextNG() (Packet, error) {
	for {
		var h [8]byte
		if _, err := io.ReadFull(r.r, h[:]); err != nil {
			if err == io.EOF {
				return Packet{}, io.EOF
			}
			return Packet{}, io.ErrUnexpectedEOF
		}
		// The section header sets the byte order for its blocks, and its own
		// type field is a palindrome, so it can be recognised before the
		// order is known.
		if binary.LittleEndian.Uint32(h[0:4]) == pcapngSHB {
			var bom [4]byte
			if _, err := io.ReadFull(r.r, bom[:]); err != nil {
				return Packet{}, io.ErrUnexpectedEOF
			}
			switch {
			case binary.LittleEndian.Uint32(bom[:]) == pcapngByteOrder:
				r.order = binary.LittleEndian
			case binary.BigEndian.Uint32(bom[:]) == pcapngByteOrder:
				r.order = binary.BigEndian
			default:
				return Packet{}, errors.New("pcap: pcapng section header has no byte-order magic")
			}
			total := r.order.Uint32(h[4:8])
			if total < 12 || total > maxBlockBytes {
				return Packet{}, fmt.Errorf("pcap: section header length %d", total)
			}
			if _, err := io.CopyN(io.Discard, r.r, int64(total)-12); err != nil {
				return Packet{}, io.ErrUnexpectedEOF
			}
			r.ifaces = r.ifaces[:0] // interfaces are per section
			continue
		}
		if r.order == nil {
			return Packet{}, errors.New("pcap: pcapng block before a section header")
		}
		typ, total := r.order.Uint32(h[0:4]), r.order.Uint32(h[4:8])
		if total < 12 || total > maxBlockBytes || total%4 != 0 {
			return Packet{}, fmt.Errorf("pcap: block type %#x has length %d", typ, total)
		}
		body, err := r.read(int(total) - 8)
		if err != nil {
			return Packet{}, err
		}
		body = body[:len(body)-4] // trailing length
		switch typ {
		case 1: // interface description
			if len(body) < 8 || len(r.ifaces) >= maxInterfaces {
				continue
			}
			r.ifaces = append(r.ifaces, iface{
				link:  int(r.order.Uint16(body[0:2])),
				units: tsUnits(r.order, body[8:]),
			})
		case 6: // enhanced packet
			if len(body) < 20 {
				continue
			}
			id := int(r.order.Uint32(body[0:4]))
			if id >= len(r.ifaces) {
				continue
			}
			ts := uint64(r.order.Uint32(body[4:8]))<<32 | uint64(r.order.Uint32(body[8:12]))
			capLen, orig := int(r.order.Uint32(body[12:16])), int(r.order.Uint32(body[16:20]))
			if capLen < 0 || 20+capLen > len(body) || capLen > maxPacketBytes {
				return Packet{}, fmt.Errorf("pcap: enhanced packet claims %d bytes", capLen)
			}
			ifc := r.ifaces[id]
			r.count++
			return Packet{
				Time:     time.Unix(0, 0).UTC().Add(time.Duration(ts) * ifc.units),
				LinkType: ifc.link, Data: body[20 : 20+capLen], OrigLen: orig,
			}, nil
		}
		// Simple packets carry no time and statistics blocks no packet: skipped.
	}
}

// tsUnits reads if_tsresol from an interface description's options. The
// default is microseconds.
func tsUnits(o binary.ByteOrder, opts []byte) time.Duration {
	for len(opts) >= 4 {
		code, ln := o.Uint16(opts[0:2]), int(o.Uint16(opts[2:4]))
		if code == 0 {
			break
		}
		pad := (ln + 3) &^ 3
		if 4+ln > len(opts) {
			break
		}
		if code == 9 && ln >= 1 {
			v := opts[4]
			if v&0x80 == 0 { // power of ten
				d := time.Second
				for i := byte(0); i < v && d > 0; i++ {
					d /= 10
				}
				if d > 0 {
					return d
				}
			}
			return time.Microsecond // a power-of-two resolution is rare; fall back
		}
		if 4+pad > len(opts) {
			break
		}
		opts = opts[4+pad:]
	}
	return time.Microsecond
}
