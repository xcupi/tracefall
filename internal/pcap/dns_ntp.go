package pcap

import (
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type dnsKey struct {
	client   netip.Addr
	resolver netip.Addr
	id       uint16
	name     string
	proto    string
}

var dnsTypes = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY", 252: "AXFR",
	65: "HTTPS",
}

func qtypeName(t uint16) string {
	if n, ok := dnsTypes[t]; ok {
		return n
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// dns parses a UDP payload as a DNS, mDNS or LLMNR message and records it. It
// returns true when the bytes really were such a message.
func (a *analyzer) dns(t time.Time, d Decoded, cl, sv endpoint) bool {
	p := d.Payload
	if len(p) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(p[2:4])
	qd, an := int(binary.BigEndian.Uint16(p[4:6])), int(binary.BigEndian.Uint16(p[6:8]))
	if qd < 1 || qd > 8 || an > 64 || flags&0x7800 != 0 { // opcode 0 (standard query) only
		return false
	}
	proto := map[uint16]string{53: "dns", 5353: "mdns", 5355: "llmnr"}[sv.port]
	isResp := flags&0x8000 != 0
	off := 12
	name, n, ok := dnsName(p, off)
	if !ok || off+n+4 > len(p) {
		return false
	}
	off += n
	qtype := binary.BigEndian.Uint16(p[off : off+2])
	off += 4
	for i := 1; i < qd; i++ { // further questions are legal and unused
		_, n, ok := dnsName(p, off)
		if !ok || off+n+4 > len(p) {
			return false
		}
		off += n + 4
	}
	key := dnsKey{client: cl.ip, resolver: sv.ip, id: binary.BigEndian.Uint16(p[0:2]), name: strings.ToLower(name), proto: proto}

	if !isResp {
		if r, dup := a.pendDNS[key]; dup && !r.Responded {
			return true // a retransmitted query
		}
		if len(a.pendDNS) >= a.lim.MaxPendingDNS {
			a.evictDNS()
		}
		a.pendDNS[key] = &DNSRecord{Time: t, Client: cl.ip, Resolver: sv.ip, Protocol: proto, ID: key.id, Name: name, QType: qtypeName(qtype)}
		a.pendOrder = append(a.pendOrder, key)
		return true
	}

	var answers []string
	for i := 0; i < an && off < len(p); i++ {
		_, n, ok := dnsName(p, off)
		if !ok || off+n+10 > len(p) {
			break
		}
		off += n
		typ := binary.BigEndian.Uint16(p[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(p[off+8 : off+10]))
		off += 10
		if off+rdlen > len(p) {
			break
		}
		rd := p[off : off+rdlen]
		switch typ {
		case 1:
			if rdlen == 4 {
				if ip, ok := netip.AddrFromSlice(rd); ok {
					answers = append(answers, ip.String())
				}
			}
		case 28:
			if rdlen == 16 {
				if ip, ok := netip.AddrFromSlice(rd); ok {
					answers = append(answers, ip.String())
				}
			}
		case 5, 2, 12:
			if target, _, ok := dnsName(p, off); ok {
				answers = append(answers, qtypeName(typ)+":"+target)
			}
		}
		off += rdlen
	}
	rcode := int(flags & 0x000f)
	if r, ok := a.pendDNS[key]; ok && !r.Responded {
		r.Responded, r.ResponseAt, r.Answers, r.RCode = true, t, answers, rcode
		return true
	}
	rec := &DNSRecord{Time: t, Client: cl.ip, Resolver: sv.ip, Protocol: proto, ID: key.id, Name: name, QType: qtypeName(qtype),
		Responded: true, ResponseAt: t, Answers: answers, RCode: rcode, QueryAbsent: true}
	a.emitDNS(rec)
	return true
}

func (a *analyzer) evictDNS() {
	// Emit the oldest quarter as unanswered, in the order they were asked.
	n := len(a.pendOrder) / 4
	if n < 1 {
		n = 1
	}
	kept := a.pendOrder[:0]
	for i, k := range a.pendOrder {
		if i < n {
			if r, ok := a.pendDNS[k]; ok {
				a.emitDNS(r)
				delete(a.pendDNS, k)
			}
			continue
		}
		kept = append(kept, k)
	}
	a.pendOrder = kept
	a.note("DNS queries still waiting for an answer when the table filled were reported as unanswered")
}

func (a *analyzer) emitDNS(r *DNSRecord) {
	if len(a.an.DNS) >= a.lim.MaxDNS {
		a.note("DNS record table full: further lookups are not reported")
		return
	}
	a.an.DNS = append(a.an.DNS, *r)
}

// dnsName reads a possibly compressed name at off and returns it with the
// number of bytes it occupies at off (a pointer is two bytes, however long
// the name it points to).
func dnsName(p []byte, off int) (string, int, bool) {
	var labels []string
	consumed, jumped, hops := 0, false, 0
	total := 0
	for {
		if off >= len(p) {
			return "", 0, false
		}
		l := int(p[off])
		switch {
		case l == 0:
			if !jumped {
				consumed++
			}
			return strings.Join(labels, "."), consumed, true
		case l&0xC0 == 0xC0:
			if off+1 >= len(p) {
				return "", 0, false
			}
			if !jumped {
				consumed += 2
			}
			jumped = true
			if hops++; hops > 16 { // a pointer loop
				return "", 0, false
			}
			off = (l&0x3F)<<8 | int(p[off+1])
		case l&0xC0 != 0:
			return "", 0, false
		default:
			if off+1+l > len(p) {
				return "", 0, false
			}
			total += l + 1
			if total > 255 {
				return "", 0, false
			}
			labels = append(labels, string(p[off+1:off+1+l]))
			if !jumped {
				consumed += 1 + l
			}
			off += 1 + l
		}
	}
}

// ---------------- NTP ----------------

type ntpKey struct {
	client, server netip.Addr
	port           uint16
	origin         uint64 // the client's transmit timestamp, echoed by the server
}

const ntpEpochOffset = 2208988800 // seconds from 1900 to 1970

func ntpTime(p []byte) (time.Time, uint64, bool) {
	sec := binary.BigEndian.Uint32(p[0:4])
	frac := binary.BigEndian.Uint32(p[4:8])
	raw := uint64(sec)<<32 | uint64(frac)
	if sec == 0 {
		return time.Time{}, raw, false
	}
	// Era 0 runs to 2036; a value below the 1970 epoch is era 1.
	unix := int64(sec) - ntpEpochOffset
	if sec < ntpEpochOffset {
		unix = int64(sec) + (1 << 32) - ntpEpochOffset
	}
	ns := (int64(frac) * 1_000_000_000) >> 32
	return time.Unix(unix, ns).UTC(), raw, true
}

// ntp records the clock values in an NTP packet. A client's transmit time is
// the client's own clock (when it is not randomised); a server's transmit time
// is the server's. Neither is the capture machine's.
func (a *analyzer) ntp(t time.Time, d Decoded) bool {
	p := d.Payload
	if len(p) < 48 {
		return false
	}
	vn, mode := int(p[0]>>3)&7, int(p[0]&7)
	if vn < 1 || vn > 4 || mode < 1 || mode > 5 {
		return false
	}
	obs := ClockObservation{Source: "ntp", CaptureAt: t, Version: vn, Stratum: int(p[1])}
	origin, originRaw, hasOrigin := ntpTime(p[24:32])
	recv, _, hasRecv := ntpTime(p[32:40])
	xmit, xmitRaw, hasXmit := ntpTime(p[40:48])
	if !hasXmit {
		return true // a packet that carries no time (a kiss-o'-death, an empty probe)
	}
	switch mode {
	case 3, 1: // client request
		obs.Role, obs.Subject, obs.Peer = "client", d.Src, d.Dst
		obs.Observed, obs.Transmit = xmit, xmit
		// Recent clients put random bits in the low half of the timestamp so
		// that a spoofed reply can be rejected. The seconds are still the
		// client's clock; the fraction is not meaningful, which is why the
		// clock model treats an NTP client value as accurate to a second.
		if len(a.ntpReq) < 100_000 {
			a.ntpReq[ntpKey{d.Src, d.Dst, d.DstPort, xmitRaw}] = t
		}
	case 4, 2: // server reply
		obs.Role, obs.Subject, obs.Peer = "server", d.Src, d.Dst
		obs.Observed, obs.Transmit = xmit, xmit
		if hasOrigin {
			obs.Origin, obs.HasOrigin = origin, true
			if rt, ok := a.ntpReq[ntpKey{d.Dst, d.Src, d.SrcPort, originRaw}]; ok {
				obs.RequestAt = rt
				delete(a.ntpReq, ntpKey{d.Dst, d.Src, d.SrcPort, originRaw})
			}
		}
		if hasRecv {
			obs.Receive = recv
		}
	default:
		return true
	}
	if len(a.an.Clock) >= a.lim.MaxClock {
		a.note("clock observation table full: further NTP and HTTP Date values are not reported")
		return true
	}
	a.an.Clock = append(a.an.Clock, obs)
	return true
}
