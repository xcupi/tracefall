package pcap

import (
	"encoding/binary"
	"net/netip"
)

// Decoded is a packet reduced to the fields the analysis uses.
type Decoded struct {
	Src, Dst         netip.Addr
	Proto            uint8 // 6 TCP, 17 UDP, 1 ICMP, ...
	SrcPort, DstPort uint16
	Seq, Ack         uint32
	Flags            uint8 // TCP flags
	Payload          []byte
	Fragment         bool // a non-first IPv4 fragment: no transport header
}

// TCP flag bits.
const (
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x04
	FlagACK = 0x10
)

// IP protocol numbers.
const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

// Decode reduces a frame to its IP and transport fields. It returns false for
// a frame that is not IP, is too short to hold what it claims, or sits on a
// link type this package does not read.
func Decode(linkType int, data []byte) (Decoded, bool) {
	ip, etherType, ok := stripLink(linkType, data)
	if !ok {
		return Decoded{}, false
	}
	switch etherType {
	case 0x0800:
		return decodeIPv4(ip)
	case 0x86DD:
		return decodeIPv6(ip)
	}
	return Decoded{}, false
}

// stripLink removes the link-layer header and returns the IP packet and its
// EtherType (0x0800 or 0x86DD).
func stripLink(linkType int, d []byte) ([]byte, uint16, bool) {
	switch linkType {
	case LinkEthernet:
		if len(d) < 14 {
			return nil, 0, false
		}
		et := binary.BigEndian.Uint16(d[12:14])
		off := 14
		// 802.1Q and 802.1ad tags, any depth up to a sane limit.
		for i := 0; i < 4 && (et == 0x8100 || et == 0x88A8 || et == 0x9100); i++ {
			if len(d) < off+4 {
				return nil, 0, false
			}
			et = binary.BigEndian.Uint16(d[off+2 : off+4])
			off += 4
		}
		return d[off:], et, true
	case LinkLinuxSLL:
		if len(d) < 16 {
			return nil, 0, false
		}
		return d[16:], binary.BigEndian.Uint16(d[14:16]), true
	case LinkLinuxSLL2:
		if len(d) < 20 {
			return nil, 0, false
		}
		return d[20:], binary.BigEndian.Uint16(d[0:2]), true
	case LinkRaw, LinkRawIPv4, LinkRawIPv6:
		if len(d) < 1 {
			return nil, 0, false
		}
		switch d[0] >> 4 {
		case 4:
			return d, 0x0800, true
		case 6:
			return d, 0x86DD, true
		}
		return nil, 0, false
	case LinkNull, LinkLoop:
		if len(d) < 5 {
			return nil, 0, false
		}
		// The 4-byte address family is in the capturing host's byte order;
		// the IP version nibble after it says what follows without needing it.
		switch d[4] >> 4 {
		case 4:
			return d[4:], 0x0800, true
		case 6:
			return d[4:], 0x86DD, true
		}
		return nil, 0, false
	}
	return nil, 0, false
}

func decodeIPv4(p []byte) (Decoded, bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return Decoded{}, false
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl {
		return Decoded{}, false
	}
	total := int(binary.BigEndian.Uint16(p[2:4]))
	if total >= ihl && total <= len(p) {
		p = p[:total] // drop Ethernet padding
	}
	d := Decoded{Proto: p[9]}
	d.Src, _ = netip.AddrFromSlice(p[12:16])
	d.Dst, _ = netip.AddrFromSlice(p[16:20])
	fragOff := binary.BigEndian.Uint16(p[6:8]) & 0x1fff
	if fragOff != 0 {
		d.Fragment = true
		return d, true
	}
	return transport(d, p[ihl:])
}

func decodeIPv6(p []byte) (Decoded, bool) {
	if len(p) < 40 || p[0]>>4 != 6 {
		return Decoded{}, false
	}
	d := Decoded{}
	d.Src, _ = netip.AddrFromSlice(p[8:24])
	d.Dst, _ = netip.AddrFromSlice(p[24:40])
	next := p[6]
	body := p[40:]
	if pl := int(binary.BigEndian.Uint16(p[4:6])); pl > 0 && pl <= len(body) {
		body = body[:pl]
	}
	// Extension headers that carry a next-header and a length in 8-byte units.
	for i := 0; i < 8; i++ {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(body) < 8 {
				return Decoded{}, false
			}
			n := 8 + int(body[1])*8
			if len(body) < n {
				return Decoded{}, false
			}
			next, body = body[0], body[n:]
		case 44: // fragment
			if len(body) < 8 {
				return Decoded{}, false
			}
			if binary.BigEndian.Uint16(body[2:4])&0xfff8 != 0 {
				d.Proto, d.Fragment = body[0], true
				return d, true
			}
			next, body = body[0], body[8:]
		default:
			d.Proto = next
			return transport(d, body)
		}
	}
	return Decoded{}, false
}

func transport(d Decoded, t []byte) (Decoded, bool) {
	switch d.Proto {
	case ProtoTCP:
		if len(t) < 20 {
			return d, true // header cut off by the snap length: addresses still count
		}
		off := int(t[12]>>4) * 4
		d.SrcPort, d.DstPort = binary.BigEndian.Uint16(t[0:2]), binary.BigEndian.Uint16(t[2:4])
		d.Seq, d.Ack, d.Flags = binary.BigEndian.Uint32(t[4:8]), binary.BigEndian.Uint32(t[8:12]), t[13]
		if off >= 20 && off <= len(t) {
			d.Payload = t[off:]
		}
	case ProtoUDP:
		if len(t) < 8 {
			return d, true
		}
		d.SrcPort, d.DstPort = binary.BigEndian.Uint16(t[0:2]), binary.BigEndian.Uint16(t[2:4])
		d.Payload = t[8:]
		if l := int(binary.BigEndian.Uint16(t[4:6])); l >= 8 && l-8 < len(d.Payload) {
			d.Payload = d.Payload[:l-8]
		}
	}
	return d, true
}
