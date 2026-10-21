package pcap

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// ---- a small capture writer: frames are built from the documented layouts,
// not by the decoder under test.

type frame struct {
	t    time.Time
	data []byte
}

func ip4(s string) [4]byte { return netip.MustParseAddr(s).As4() }

func ipv4Packet(src, dst string, proto byte, payload []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(payload)))
	h[8], h[9] = 64, proto
	s, d := ip4(src), ip4(dst)
	copy(h[12:], s[:])
	copy(h[16:], d[:])
	return append(h, payload...)
}

func ether(ip []byte) []byte {
	h := make([]byte, 14)
	h[12], h[13] = 0x08, 0x00
	return append(h, ip...)
}

func tcpSeg(sport, dport uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:], sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	binary.BigEndian.PutUint32(h[4:], seq)
	binary.BigEndian.PutUint32(h[8:], ack)
	h[12], h[13] = 5<<4, flags
	return append(h, payload...)
}

func udpDgram(sport, dport uint16, payload []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:], sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(payload)))
	return append(h, payload...)
}

func writePcap(frames []frame, nano bool, order binary.ByteOrder) []byte {
	var b bytes.Buffer
	hdr := make([]byte, 24)
	magic := uint32(pcapMagicMicro)
	if nano {
		magic = pcapMagicNano
	}
	order.PutUint32(hdr[0:], magic)
	order.PutUint16(hdr[4:], 2)
	order.PutUint16(hdr[6:], 4)
	order.PutUint32(hdr[16:], 65535)
	order.PutUint32(hdr[20:], LinkEthernet)
	b.Write(hdr)
	for _, f := range frames {
		rec := make([]byte, 16)
		order.PutUint32(rec[0:], uint32(f.t.Unix()))
		frac := uint32(f.t.Nanosecond() / 1000)
		if nano {
			frac = uint32(f.t.Nanosecond())
		}
		order.PutUint32(rec[4:], frac)
		order.PutUint32(rec[8:], uint32(len(f.data)))
		order.PutUint32(rec[12:], uint32(len(f.data)))
		b.Write(rec)
		b.Write(f.data)
	}
	return b.Bytes()
}

func analyze(t *testing.T, frames []frame) *Analysis {
	t.Helper()
	rd, err := NewReader(bytes.NewReader(writePcap(frames, false, binary.LittleEndian)))
	if err != nil {
		t.Fatal(err)
	}
	return Analyze(rd, DefaultLimits())
}

var t0 = time.Date(2020, 9, 19, 2, 21, 47, 0, time.UTC)

// conn builds one TCP connection's frames between a client and a server.
type conn struct {
	c, s         string
	cp, sp       uint16
	cseq, sseq   uint32
	at           time.Time
	frames       []frame
	step         time.Duration
	reorder      bool
	cOff, sOff   uint32
	handshakeAck bool
}

func newConn(c, s string, cp, sp uint16) *conn {
	k := &conn{c: c, s: s, cp: cp, sp: sp, cseq: 1000, sseq: 5000, at: t0, step: 10 * time.Millisecond}
	k.send(true, FlagSYN, nil)
	k.cseq++
	k.send(false, FlagSYN|FlagACK, nil)
	k.sseq++
	k.send(true, FlagACK, nil)
	return k
}

func (k *conn) send(fromClient bool, flags byte, p []byte) {
	var pkt []byte
	if fromClient {
		pkt = tcpSeg(k.cp, k.sp, k.cseq, k.sseq, flags, p)
		k.frames = append(k.frames, frame{k.at, ether(ipv4Packet(k.c, k.s, ProtoTCP, pkt))})
	} else {
		pkt = tcpSeg(k.sp, k.cp, k.sseq, k.cseq, flags, p)
		k.frames = append(k.frames, frame{k.at, ether(ipv4Packet(k.s, k.c, ProtoTCP, pkt))})
	}
	k.at = k.at.Add(k.step)
}

func (k *conn) data(fromClient bool, p []byte) {
	k.send(fromClient, FlagACK|0x08, p)
	if fromClient {
		k.cseq += uint32(len(p))
	} else {
		k.sseq += uint32(len(p))
	}
}

func hexSHA(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func exeBody(n int) []byte {
	b := make([]byte, n)
	copy(b, "MZ\x90\x00")
	for i := 4; i < n; i++ {
		b[i] = byte(i * 7)
	}
	return b
}

// ---------------- reader ----------------

func TestReader_ClassicVariants(t *testing.T) {
	pkt := ether(ipv4Packet("10.0.0.1", "10.0.0.2", ProtoUDP, udpDgram(1000, 2000, []byte("x"))))
	when := time.Date(2020, 1, 2, 3, 4, 5, 123456000, time.UTC)
	for _, c := range []struct {
		name  string
		nano  bool
		order binary.ByteOrder
	}{{"le-micro", false, binary.LittleEndian}, {"be-micro", false, binary.BigEndian}, {"le-nano", true, binary.LittleEndian}, {"be-nano", true, binary.BigEndian}} {
		rd, err := NewReader(bytes.NewReader(writePcap([]frame{{when, pkt}}, c.nano, c.order)))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		p, err := rd.Next()
		if err != nil || !p.Time.Equal(when) || p.LinkType != LinkEthernet || !bytes.Equal(p.Data, pkt) {
			t.Fatalf("%s: %v %v", c.name, p.Time, err)
		}
		if _, err := rd.Next(); err != io.EOF {
			t.Fatalf("%s: want EOF, got %v", c.name, err)
		}
	}
}

func TestReader_CutOffCaptureKeepsThePacketsBeforeIt(t *testing.T) {
	pkt := ether(ipv4Packet("10.0.0.1", "10.0.0.2", ProtoUDP, udpDgram(1000, 2000, []byte("x"))))
	full := writePcap([]frame{{t0, pkt}, {t0.Add(time.Second), pkt}}, false, binary.LittleEndian)
	a := analyze2(t, full[:len(full)-5])
	if a.Stats.Packets != 1 {
		t.Fatalf("packets %d, want the 1 complete one", a.Stats.Packets)
	}
	if a.Err == nil {
		t.Fatal("a truncated capture must say so")
	}
}

func analyze2(t *testing.T, b []byte) *Analysis {
	t.Helper()
	rd, err := NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return Analyze(rd, DefaultLimits())
}

func TestReader_RefusesWhatItCannotRead(t *testing.T) {
	if _, err := NewReader(strings.NewReader("this is not a capture")); err != ErrUnsupported {
		t.Errorf("got %v", err)
	}
	// A record that claims 4 GiB must not be allocated.
	b := writePcap(nil, false, binary.LittleEndian)
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[8:], 0xFFFFFFFF)
	rd, _ := NewReader(bytes.NewReader(append(b, rec...)))
	if _, err := rd.Next(); err == nil || err == io.EOF {
		t.Errorf("an absurd record length must be an error, got %v", err)
	}
}

func TestReader_Pcapng(t *testing.T) {
	var b bytes.Buffer
	le := binary.LittleEndian
	block := func(typ uint32, body []byte) {
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		total := uint32(12 + len(body))
		hdr := make([]byte, 8)
		le.PutUint32(hdr[0:], typ)
		le.PutUint32(hdr[4:], total)
		b.Write(hdr)
		b.Write(body)
		tail := make([]byte, 4)
		le.PutUint32(tail, total)
		b.Write(tail)
	}
	shb := make([]byte, 16)
	le.PutUint32(shb[0:], pcapngByteOrder)
	le.PutUint16(shb[4:], 1)
	for i := 8; i < 16; i++ {
		shb[i] = 0xff
	}
	block(pcapngSHB, shb)
	idb := make([]byte, 8)
	le.PutUint16(idb[0:], LinkEthernet)
	opt := make([]byte, 8) // if_tsresol = 9 (nanoseconds), then end of options
	le.PutUint16(opt[0:], 9)
	le.PutUint16(opt[2:], 1)
	opt[4] = 9
	block(1, append(idb, append(opt, 0, 0, 0, 0)...))
	pkt := ether(ipv4Packet("10.0.0.1", "10.0.0.2", ProtoUDP, udpDgram(1000, 2000, []byte("hello"))))
	when := time.Date(2021, 5, 6, 7, 8, 9, 987654321, time.UTC)
	ts := uint64(when.UnixNano())
	epb := make([]byte, 20)
	le.PutUint32(epb[4:], uint32(ts>>32))
	le.PutUint32(epb[8:], uint32(ts))
	le.PutUint32(epb[12:], uint32(len(pkt)))
	le.PutUint32(epb[16:], uint32(len(pkt)))
	block(6, append(epb, pkt...))

	rd, err := NewReader(&b)
	if err != nil {
		t.Fatal(err)
	}
	p, err := rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	if !p.Time.Equal(when) {
		t.Errorf("time %v, want %v (nanosecond resolution)", p.Time, when)
	}
	if !bytes.Equal(p.Data, pkt) {
		t.Error("data differs")
	}
}

// ---------------- decode ----------------

func TestDecode_VLANAndPaddingAndIPv6(t *testing.T) {
	udp := udpDgram(1234, 53, []byte("abc"))
	ip := ipv4Packet("10.0.0.1", "10.0.0.2", ProtoUDP, udp)
	tagged := append([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x81, 0x00, 0, 5, 0x08, 0x00}, ip...)
	tagged = append(tagged, 0, 0, 0, 0, 0, 0) // Ethernet padding after the IP packet
	d, ok := Decode(LinkEthernet, tagged)
	if !ok || d.Proto != ProtoUDP || d.DstPort != 53 || string(d.Payload) != "abc" {
		t.Fatalf("vlan frame: %+v ok=%v", d, ok)
	}
	v6 := make([]byte, 40)
	v6[0] = 0x60
	binary.BigEndian.PutUint16(v6[4:], uint16(len(udp)))
	v6[6], v6[7] = ProtoUDP, 64
	a, b := netip.MustParseAddr("2001:db8::1").As16(), netip.MustParseAddr("2001:db8::2").As16()
	copy(v6[8:], a[:])
	copy(v6[24:], b[:])
	d, ok = Decode(LinkRaw, append(v6, udp...))
	if !ok || d.Src.String() != "2001:db8::1" || string(d.Payload) != "abc" {
		t.Fatalf("ipv6: %+v ok=%v", d, ok)
	}
}

func TestDecode_RefusesShortAndUnknown(t *testing.T) {
	for _, c := range []struct {
		link int
		data []byte
	}{{LinkEthernet, []byte{1, 2, 3}}, {LinkEthernet, make([]byte, 14)}, {LinkRaw, nil}, {LinkNull, []byte{2, 0, 0, 0}}, {99, make([]byte, 64)}} {
		if _, ok := Decode(c.link, c.data); ok {
			t.Errorf("link %d len %d should not decode", c.link, len(c.data))
		}
	}
}

// ---------------- HTTP ----------------

func TestHTTP_ContentLengthBodyIsHashedAndIdentified(t *testing.T) {
	body := exeBody(3000)
	k := newConn("10.0.0.5", "203.0.113.9", 50000, 80)
	k.data(true, []byte("GET /files/update.exe HTTP/1.1\r\nHost: dl.example\r\nUser-Agent: UA/1\r\n\r\n"))
	resp := "HTTP/1.1 200 OK\r\nDate: Sat, 19 Sep 2020 02:21:48 GMT\r\nContent-Type: application/octet-stream\r\nContent-Length: 3000\r\n\r\n"
	all := append([]byte(resp), body...)
	// the response is split across three segments
	k.data(false, all[:100])
	k.data(false, all[100:1500])
	k.data(false, all[1500:])
	a := analyze(t, k.frames)
	if len(a.HTTP) != 1 {
		t.Fatalf("got %d transactions", len(a.HTTP))
	}
	h := a.HTTP[0]
	if h.Method != "GET" || h.URI != "/files/update.exe" || h.Host != "dl.example" || h.UserAgent != "UA/1" || h.Status != 200 {
		t.Errorf("transaction %+v", h)
	}
	if !h.Complete || h.BodySize != 3000 || h.BodySHA256 != hexSHA(body) {
		t.Errorf("body: complete=%v size=%d sha=%s", h.Complete, h.BodySize, h.BodySHA256)
	}
	if h.Signature != "Windows executable (MZ)" {
		t.Errorf("signature %q", h.Signature)
	}
	if h.Client.String() != "10.0.0.5" || h.Server.String() != "203.0.113.9" || h.ClientPort != 50000 {
		t.Errorf("endpoints %+v", h)
	}
	if len(a.Clock) != 1 || a.Clock[0].Source != "http_date" || a.Clock[0].Subject.String() != "203.0.113.9" {
		t.Errorf("the Date header should give a clock observation: %+v", a.Clock)
	}
	if len(a.Conversations) != 1 || a.Conversations[0].Application != "http" || a.Conversations[0].Connections != 1 || a.Conversations[0].Established != 1 {
		t.Errorf("conversation %+v", a.Conversations)
	}
}

func TestHTTP_ChunkedPipelinedAndHEAD(t *testing.T) {
	k := newConn("10.0.0.5", "203.0.113.9", 50001, 8080)
	k.data(true, []byte("GET /a HTTP/1.1\r\nHost: h\r\n\r\nHEAD /b HTTP/1.1\r\nHost: h\r\n\r\n"))
	chunked := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nTrailer: x\r\n\r\n"
	head := "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n" // a HEAD response carries no body
	k.data(false, []byte(chunked+head))
	a := analyze(t, k.frames)
	if len(a.HTTP) != 2 {
		t.Fatalf("got %d transactions: %+v", len(a.HTTP), a.HTTP)
	}
	if a.HTTP[0].URI != "/a" || a.HTTP[0].BodySize != 11 || a.HTTP[0].BodySHA256 != hexSHA([]byte("hello world")) {
		t.Errorf("chunked: %+v", a.HTTP[0])
	}
	if a.HTTP[1].Method != "HEAD" || a.HTTP[1].BodySize != 0 || !a.HTTP[1].Complete {
		t.Errorf("HEAD must not be given a body: %+v", a.HTTP[1])
	}
}

func TestHTTP_OutOfOrderAndRetransmission(t *testing.T) {
	body := exeBody(2000)
	k := newConn("10.0.0.5", "203.0.113.9", 50002, 80)
	k.data(true, []byte("GET /x HTTP/1.1\r\nHost: h\r\n\r\n"))
	full := append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2000\r\n\r\n"), body...)
	segs := [][]byte{full[:500], full[500:1000], full[1000:1500], full[1500:]}
	base := k.sseq
	off := uint32(0)
	offs := make([]uint32, len(segs))
	for i, s := range segs {
		offs[i] = off
		off += uint32(len(s))
	}
	emit := func(i int) {
		pkt := tcpSeg(80, 50002, base+offs[i], k.cseq, FlagACK, segs[i])
		k.frames = append(k.frames, frame{k.at, ether(ipv4Packet("203.0.113.9", "10.0.0.5", ProtoTCP, pkt))})
		k.at = k.at.Add(k.step)
	}
	for _, i := range []int{0, 2, 1, 1, 3} { // segment 2 early, segment 1 sent twice
		emit(i)
	}
	a := analyze(t, k.frames)
	if len(a.HTTP) != 1 || !a.HTTP[0].Complete || a.HTTP[0].BodySHA256 != hexSHA(body) {
		t.Fatalf("reordered and retransmitted segments must give the same object: %+v", a.HTTP)
	}
}

func TestHTTP_AGapMeansNoHash(t *testing.T) {
	body := exeBody(2000)
	k := newConn("10.0.0.5", "203.0.113.9", 50003, 80)
	k.data(true, []byte("GET /x HTTP/1.1\r\nHost: h\r\n\r\n"))
	full := append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2000\r\n\r\n"), body...)
	base := k.sseq
	send := func(off int, p []byte) {
		pkt := tcpSeg(80, 50003, base+uint32(off), k.cseq, FlagACK, p)
		k.frames = append(k.frames, frame{k.at, ether(ipv4Packet("203.0.113.9", "10.0.0.5", ProtoTCP, pkt))})
		k.at = k.at.Add(k.step)
	}
	send(0, full[:500])
	// Bytes 500-1000 never appear. Enough later segments arrive to give up on them.
	off := 1000
	for i := 0; i < maxReorderSegs+2; i++ {
		send(off, full[off:off+10])
		off += 20
	}
	a := analyze(t, k.frames)
	if len(a.HTTP) != 1 {
		t.Fatalf("got %d transactions", len(a.HTTP))
	}
	if h := a.HTTP[0]; h.Complete || h.BodySHA256 != "" || h.Incomplete == "" {
		t.Errorf("a body with a hole must not be given a hash: %+v", h)
	}
	if a.Stats.HTTPBroken != 1 {
		t.Errorf("HTTPBroken = %d", a.Stats.HTTPBroken)
	}
}

func TestHTTP_CloseDelimitedAndRequestWithoutResponse(t *testing.T) {
	k := newConn("10.0.0.5", "203.0.113.9", 50004, 80)
	k.data(true, []byte("GET /stream HTTP/1.0\r\n\r\n"))
	k.data(false, []byte("HTTP/1.0 200 OK\r\n\r\npart one "))
	k.data(false, []byte("part two"))
	k.send(false, FlagFIN|FlagACK, nil)
	k2 := newConn("10.0.0.5", "203.0.113.9", 50005, 80)
	k2.data(true, []byte("POST /upload HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nabcd"))
	a := analyze(t, append(k.frames, k2.frames...))
	if len(a.HTTP) != 2 {
		t.Fatalf("got %d: %+v", len(a.HTTP), a.HTTP)
	}
	var stream, post HTTPTransaction
	for _, h := range a.HTTP {
		if h.Method == "GET" {
			stream = h
		} else {
			post = h
		}
	}
	if !stream.Complete || stream.BodySHA256 != hexSHA([]byte("part one part two")) {
		t.Errorf("a body ended by the server closing is complete: %+v", stream)
	}
	if !post.ResponseAbsent || post.RequestBodySHA256 != hexSHA([]byte("abcd")) || post.RequestBodySize != 4 {
		t.Errorf("an upload with no response is still reported, with its body hash: %+v", post)
	}
}

func TestHTTP_NotHTTPIsNotParsed(t *testing.T) {
	k := newConn("10.0.0.5", "203.0.113.9", 50006, 80)
	k.data(true, []byte("\x16\x03\x01\x00\x10garbage-not-http"))
	a := analyze(t, k.frames)
	if len(a.HTTP) != 0 || a.Conversations[0].Application == "http" {
		t.Errorf("port 80 does not make it HTTP: %+v", a.Conversations[0])
	}
}

// ---------------- DNS / NTP / RDP / TLS ----------------

func dnsQuery(id uint16, name string, qtype uint16) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], id)
	b[2] = 0x01 // recursion desired
	binary.BigEndian.PutUint16(b[4:], 1)
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return b
}

func dnsResponse(q []byte, ips ...string) []byte {
	r := append([]byte(nil), q...)
	r[2] = 0x81
	r[3] = 0x80
	binary.BigEndian.PutUint16(r[6:], uint16(len(ips)))
	for _, s := range ips {
		a := ip4(s)
		r = append(r, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		r = append(r, a[:]...)
	}
	return r
}

func TestDNS_QueryAnswerAndCompression(t *testing.T) {
	q := dnsQuery(0x1234, "Evil.Example.com", 1)
	resp := dnsResponse(q, "198.51.100.7", "198.51.100.8")
	stray := dnsResponse(dnsQuery(0x9999, "other.example", 1), "192.0.2.1") // its query is not in the capture
	frames := []frame{
		{t0, ether(ipv4Packet("10.0.0.5", "10.0.0.2", ProtoUDP, udpDgram(53124, 53, q)))},
		{t0.Add(20 * time.Millisecond), ether(ipv4Packet("10.0.0.2", "10.0.0.5", ProtoUDP, udpDgram(53, 53124, resp)))},
		{t0.Add(time.Second), ether(ipv4Packet("10.0.0.2", "10.0.0.6", ProtoUDP, udpDgram(53, 40000, stray)))},
	}
	a := analyze(t, frames)
	if len(a.DNS) != 2 {
		t.Fatalf("got %d records: %+v", len(a.DNS), a.DNS)
	}
	r := a.DNS[0]
	if r.Name != "Evil.Example.com" || r.QType != "A" || !r.Responded || strings.Join(r.Answers, ",") != "198.51.100.7,198.51.100.8" || r.Client.String() != "10.0.0.5" {
		t.Errorf("record %+v", r)
	}
	if !r.Time.Equal(t0) || !r.ResponseAt.Equal(t0.Add(20*time.Millisecond)) {
		t.Errorf("times %v %v", r.Time, r.ResponseAt)
	}
	if !a.DNS[1].QueryAbsent {
		t.Errorf("a response with no query must say so: %+v", a.DNS[1])
	}
}

func TestDNS_MalformedIsNotClaimed(t *testing.T) {
	loop := append([]byte(nil), dnsQuery(1, "a.b", 1)...)
	loop[12] = 0xC0 // a pointer to itself
	loop[13] = 0x0C
	for _, payload := range [][]byte{nil, {1, 2, 3}, loop, bytes.Repeat([]byte{0xff}, 100)} {
		a := analyze(t, []frame{{t0, ether(ipv4Packet("10.0.0.5", "10.0.0.2", ProtoUDP, udpDgram(53124, 53, payload)))}})
		if len(a.DNS) != 0 || (len(a.Conversations) > 0 && a.Conversations[0].Application == "dns") {
			t.Errorf("garbage on port 53 was taken for DNS: %+v", a.DNS)
		}
	}
}

func ntpPacket(mode byte, orig, recv, xmit time.Time) []byte {
	p := make([]byte, 48)
	p[0] = 4<<3 | mode
	p[1] = 2
	put := func(off int, t time.Time) {
		if t.IsZero() {
			return
		}
		sec := uint32(t.Unix() + ntpEpochOffset)
		frac := uint32((uint64(t.Nanosecond()) << 32) / 1_000_000_000)
		binary.BigEndian.PutUint32(p[off:], sec)
		binary.BigEndian.PutUint32(p[off+4:], frac)
	}
	put(24, orig)
	put(32, recv)
	put(40, xmit)
	return p
}

func TestNTP_ClientClockAndServerReply(t *testing.T) {
	clientClock := t0.Add(-time.Hour).Add(250 * time.Millisecond) // the client believes it is an hour earlier
	req := ntpPacket(3, time.Time{}, time.Time{}, clientClock)
	serverRecv, serverXmit := t0.Add(110*time.Millisecond), t0.Add(111*time.Millisecond)
	resp := ntpPacket(4, clientClock, serverRecv, serverXmit)
	frames := []frame{
		{t0.Add(100 * time.Millisecond), ether(ipv4Packet("10.0.0.5", "10.0.0.2", ProtoUDP, udpDgram(123, 123, req)))},
		{t0.Add(120 * time.Millisecond), ether(ipv4Packet("10.0.0.2", "10.0.0.5", ProtoUDP, udpDgram(123, 123, resp)))},
	}
	a := analyze(t, frames)
	if len(a.Clock) != 2 {
		t.Fatalf("got %d observations: %+v", len(a.Clock), a.Clock)
	}
	c, s := a.Clock[0], a.Clock[1]
	if c.Role != "client" || c.Subject.String() != "10.0.0.5" || c.Observed.Sub(clientClock).Abs() > time.Millisecond {
		t.Errorf("client observation %+v", c)
	}
	if s.Role != "server" || !s.HasOrigin || s.RequestAt.IsZero() || !s.RequestAt.Equal(t0.Add(100*time.Millisecond)) {
		t.Errorf("the reply must be joined to the request it answers: %+v", s)
	}
	if a.Conversations[0].Application != "ntp" {
		t.Errorf("application %q", a.Conversations[0].Application)
	}
}

func TestRDP_ConnectionRequestCookieAndProtocols(t *testing.T) {
	cookie := "Cookie: mstshash=alice\r\n"
	neg := []byte{0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00} // TLS + CredSSP requested
	x224 := append([]byte{byte(6 + len(cookie) + len(neg)), 0xE0, 0, 0, 0, 0, 0}, cookie...)
	x224 = append(x224, neg...)
	tpkt := append([]byte{3, 0, byte((4 + len(x224)) >> 8), byte(4 + len(x224))}, x224...)
	k := newConn("10.0.0.5", "10.0.0.9", 51000, 3389)
	k.data(true, tpkt)
	a := analyze(t, k.frames)
	c := a.Conversations[0]
	if c.Application != "rdp" || c.RDPCookie != "alice" || c.RDPProtocols != "tls+credssp" {
		t.Errorf("rdp: %+v", c)
	}
	// The same port with other bytes is not RDP.
	k2 := newConn("10.0.0.5", "10.0.0.9", 51001, 3389)
	k2.data(true, []byte("hello"))
	if c2 := analyze(t, k2.frames).Conversations[0]; c2.Application != "" || c2.ServiceHint != "rdp" {
		t.Errorf("a port is a hint, not proof: %+v", c2)
	}
}

func TestTLS_ServerNameIndication(t *testing.T) {
	name := "klient-293.example"
	sni := append([]byte{0, 0, 0, byte(len(name) + 5), 0, byte(len(name) + 3), 0, 0, byte(len(name))}, name...)
	ext := append([]byte{byte(len(sni) >> 8), byte(len(sni))}, sni...)
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                // session id length
	body = append(body, 0, 2, 0xc0, 0x2f) // cipher suites
	body = append(body, 1, 0)             // compression
	body = append(body, ext...)           // ext already begins with the extensions block length
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	k := newConn("10.0.0.5", "203.0.113.50", 52000, 443)
	k.data(true, rec)
	c := analyze(t, k.frames).Conversations[0]
	if c.Application != "tls" || c.TLSServerName != name {
		t.Errorf("tls: %+v", c)
	}
}

// ---------------- bounds ----------------

func TestLimits_AreReportedNotSilent(t *testing.T) {
	var frames []frame
	for i := 0; i < 20; i++ {
		ip := "10.0.1." + string(rune('1'+i%9))
		frames = append(frames, frame{t0, ether(ipv4Packet("10.0.0.1", ip, ProtoUDP, udpDgram(1000+uint16(i), 9000+uint16(i), []byte("x"))))})
	}
	rd, _ := NewReader(bytes.NewReader(writePcap(frames, false, binary.LittleEndian)))
	lim := DefaultLimits()
	lim.MaxConversations = 3
	a := Analyze(rd, lim)
	if len(a.Conversations) != 3 || len(a.Notes) == 0 {
		t.Errorf("conversations=%d notes=%v", len(a.Conversations), a.Notes)
	}
	if a.Stats.Packets != 20 {
		t.Errorf("packets are counted even when the table is full: %d", a.Stats.Packets)
	}
}

// ---------------- fuzz ----------------

func FuzzDecode(f *testing.F) {
	f.Add(LinkEthernet, ether(ipv4Packet("10.0.0.1", "10.0.0.2", ProtoTCP, tcpSeg(1, 2, 3, 4, FlagSYN, nil))))
	f.Add(LinkRaw, []byte{0x60, 0, 0, 0, 0, 8, 17, 64})
	f.Fuzz(func(t *testing.T, link int, data []byte) { Decode(link, data) })
}

func FuzzProtocols(f *testing.F) {
	f.Add(dnsQuery(1, "a.example", 1))
	f.Add(ntpPacket(3, time.Time{}, time.Time{}, t0))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	f.Add([]byte{3, 0, 0, 11, 6, 0xE0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, p []byte) {
		dnsName(p, 0)
		parseSNI(p)
		parseRDPRequest(p)
		a := &analyzer{lim: DefaultLimits(), an: &Analysis{Stats: Stats{LinkTypes: map[int]uint64{}}}, convs: map[convKey]*Conversation{},
			flows: map[pair]*flow{}, pendDNS: map[dnsKey]*DNSRecord{}, ntpReq: map[ntpKey]time.Time{}, notes: map[string]bool{}}
		d := Decoded{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"), Proto: ProtoUDP, SrcPort: 4000, DstPort: 53, Payload: p}
		a.udp(t0, d)
		d.DstPort = 123
		a.udp(t0, d)
		d.Proto, d.DstPort, d.Seq = ProtoTCP, 80, 1
		a.tcp(t0, d)
		a.tcp(t0, Decoded{Src: d.Dst, Dst: d.Src, Proto: ProtoTCP, SrcPort: 80, DstPort: 4000, Seq: 1, Payload: p})
		a.finish()
	})
}

// FuzzHTTPStream feeds arbitrary bytes to the HTTP parsers as a request stream
// and a response stream, in two pieces so message boundaries fall anywhere.
func FuzzHTTPStream(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"), 7)
	f.Add([]byte("POST /u HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"), []byte("HTTP/1.0 200 OK\r\n\r\nbody"), 3)
	f.Fuzz(func(t *testing.T, req, resp []byte, split int) {
		a := &analyzer{lim: DefaultLimits(), an: &Analysis{Stats: Stats{LinkTypes: map[int]uint64{}}}, convs: map[convKey]*Conversation{},
			flows: map[pair]*flow{}, pendDNS: map[dnsKey]*DNSRecord{}, ntpReq: map[ntpKey]time.Time{}, notes: map[string]bool{}}
		fl := &flow{isHTTP: true, req: newHTTPDir(true), resp: newHTTPDir(false),
			client: endpoint{netip.MustParseAddr("10.0.0.1"), 4000}, server: endpoint{netip.MustParseAddr("10.0.0.2"), 80}}
		cut := func(b []byte) ([]byte, []byte) {
			if split < 0 {
				split = -split
			}
			i := split % (len(b) + 1)
			return b[:i], b[i:]
		}
		r1, r2 := cut(req)
		s1, s2 := cut(resp)
		for _, c := range [][]byte{r1, r2} {
			a.httpBytes(fl, fl.req, t0, c)
		}
		for _, c := range [][]byte{s1, s2} {
			a.httpBytes(fl, fl.resp, t0, c)
		}
		a.endFlow(fl, t0, "fuzz")
	})
}

// A client that reuses a source port starts a new connection on the same
// four-tuple. The new connection must be read as its own: a probe on that port
// earlier must not hide the Remote Desktop session that follows it.
func TestTCP_ASourcePortReusedByANewConnectionIsANewConnection(t *testing.T) {
	probe := newConn("10.0.0.5", "10.0.0.9", 40238, 3389)
	probe.data(true, []byte("hello")) // not RDP
	probe.send(false, FlagRST|FlagACK, nil)

	cookie := "Cookie: mstshash=carol\r\n"
	x224 := append([]byte{byte(6 + len(cookie)), 0xE0, 0, 0, 0, 0, 0}, cookie...)
	tpkt := append([]byte{3, 0, byte((4 + len(x224)) >> 8), byte(4 + len(x224))}, x224...)
	sess := &conn{c: "10.0.0.5", s: "10.0.0.9", cp: 40238, sp: 3389, cseq: 777000, sseq: 9000, at: probe.at.Add(time.Minute), step: 10 * time.Millisecond}
	sess.send(true, FlagSYN, nil)
	sess.cseq++
	sess.send(false, FlagSYN|FlagACK, nil)
	sess.sseq++
	sess.send(true, FlagACK, nil)
	sess.data(true, tpkt)
	for i := 0; i < 30; i++ {
		sess.data(i%2 == 0, []byte("encrypted-looking-bytes"))
	}
	a := analyze(t, append(probe.frames, sess.frames...))
	if len(a.Conversations) != 1 {
		t.Fatalf("conversations: %d", len(a.Conversations))
	}
	c := a.Conversations[0]
	if c.Connections != 2 || c.Application != "rdp" || c.RDPCookie != "carol" {
		t.Fatalf("two connections, the second one RDP: %+v", c)
	}
	if len(c.Sessions) != 1 || c.Sessions[0].ClientPort != 40238 || c.Sessions[0].Packets < 30 {
		t.Fatalf("the session after the probe: %+v", c.Sessions)
	}
	// A retransmitted SYN is the same connection, not a new one.
	k := newConn("10.0.0.5", "10.0.0.9", 40300, 3389)
	k.cseq = 1000
	k.send(true, FlagSYN, nil)
	if a := analyze(t, k.frames); a.Conversations[0].Connections != 1 {
		t.Errorf("a repeated SYN with the same sequence number is one connection: %d", a.Conversations[0].Connections)
	}
}
