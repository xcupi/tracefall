package pcap

import (
	"bytes"
	"encoding/binary"
	"strings"
	"time"
)

func (a *analyzer) tcp(t time.Time, d Decoded) {
	src, dst := endpoint{d.Src, d.SrcPort}, endpoint{d.Dst, d.DstPort}
	key := tupleKey(src, dst)
	f := a.flows[key]
	syn := d.Flags&FlagSYN != 0
	ack := d.Flags&FlagACK != 0
	// A client that reuses a source port starts a new connection on the same
	// four-tuple. A SYN with a different initial sequence number (a repeat of
	// the same SYN is a retransmission) ends the old connection, so that what
	// the new one does is read as its own rather than as the old one's tail.
	if f != nil && syn && !ack && src == f.client && ((f.hasSyn && d.Seq != f.synSeq) || (!f.hasSyn && f.pkts > 0)) {
		a.finishFlow(f, t, "the source port was reused by a new connection")
		f = nil
	}
	if f == nil {
		if len(a.flows) >= a.lim.MaxFlows {
			a.note("TCP flow table full: further connections are not tracked")
			return
		}
		cl, sv := orientTCP(src, dst, d)
		conv := a.conversation(t, ProtoTCP, cl, sv)
		f = &flow{conv: conv, client: cl, server: sv, first: t}
		a.flows[key] = f
		if conv != nil {
			conv.Connections++
		}
	}
	if syn && !ack && src == f.client && !f.hasSyn {
		f.hasSyn, f.synSeq = true, d.Seq
	}
	f.last = t
	f.pkts++
	f.bytes += uint64(len(d.Payload))
	toServer := src == f.client
	if f.conv != nil {
		f.conv.add(t, toServer, len(d.Payload))
		if syn && ack && !toServer {
			f.conv.Established++
		}
	}
	if d.Flags&FlagFIN != 0 || d.Flags&FlagRST != 0 {
		if toServer {
			f.finC = true
		} else {
			f.finS = true
		}
	}

	if !f.checked && len(d.Payload) > 0 {
		a.classify(f, toServer, d.Payload)
	}
	if f.isHTTP && !f.httpBroken {
		dir := f.resp
		if toServer {
			dir = f.req
		}
		a.feedHTTP(f, dir, toServer, t, d)
	}
	if d.Flags&(FlagFIN|FlagRST) != 0 && f.isHTTP && !toServer {
		a.endFlow(f, t, "the connection closed before the response was complete")
	}
}

// orientTCP names the client and the server. A SYN without ACK is the client's
// opening; a SYN-ACK is the server's answer. For a capture that starts
// mid-connection the server is the end with a well-known port, then the end
// with the lower port, then the receiver of the first packet seen.
func orientTCP(src, dst endpoint, d Decoded) (client, server endpoint) {
	syn, ack := d.Flags&FlagSYN != 0, d.Flags&FlagACK != 0
	switch {
	case syn && !ack:
		return src, dst
	case syn && ack:
		return dst, src
	}
	sKnown, dKnown := tcpServerPorts[src.port], tcpServerPorts[dst.port]
	switch {
	case dKnown && !sKnown:
		return src, dst
	case sKnown && !dKnown:
		return dst, src
	case src.port < dst.port && src.port < 1024:
		return dst, src
	}
	return src, dst
}

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("DELETE "), []byte("OPTIONS "),
	[]byte("PATCH "), []byte("CONNECT "), []byte("TRACE "), []byte("PROPFIND "),
}

func looksLikeRequest(p []byte) bool {
	for _, m := range httpMethods {
		if bytes.HasPrefix(p, m) {
			// The request line ends with HTTP/1.x within the first packet.
			end := bytes.IndexByte(p, '\n')
			if end < 0 {
				end = len(p)
			}
			return bytes.Contains(p[:end], []byte(" HTTP/1."))
		}
	}
	return false
}

// classify looks at the first payload of a connection, once. It identifies
// protocols from their bytes, never from the port: RDP's connection request,
// a TLS client hello, an HTTP request.
func (a *analyzer) classify(f *flow, toServer bool, p []byte) {
	f.checked = true
	switch {
	case toServer && looksLikeRequest(p):
		f.isHTTP = true
		f.req, f.resp = newHTTPDir(true), newHTTPDir(false)
		if f.conv != nil && f.conv.Application == "" {
			f.conv.Application = "http"
		}
	case !toServer && bytes.HasPrefix(p, []byte("HTTP/1.")):
		f.isHTTP = true
		f.req, f.resp = newHTTPDir(true), newHTTPDir(false)
		if f.conv != nil && f.conv.Application == "" {
			f.conv.Application = "http"
		}
	case toServer:
		if cookie, protos, ok := parseRDPRequest(p); ok && f.conv != nil {
			f.conv.Application = "rdp"
			f.rdp = true
			if f.conv.RDPCookie == "" {
				f.conv.RDPCookie = cookie
			}
			f.conv.RDPProtocols = protos
		} else if sni, ok := parseSNI(p); ok && f.conv != nil {
			if f.conv.Application == "" {
				f.conv.Application = "tls"
			}
			if f.conv.TLSServerName == "" {
				f.conv.TLSServerName = sni
			}
		}
	}
}

// parseRDPRequest recognises the X.224 Connection Request that starts a Remote
// Desktop connection: a TPKT header (version 3), an X.224 CR (0xE0), an
// optional "Cookie: mstshash=<name>" line and an optional negotiation request.
// The cookie is the user name the client typed or was configured with; it is a
// hint written by the client, not an authenticated identity.
func parseRDPRequest(p []byte) (cookie, protocols string, ok bool) {
	if len(p) < 11 || p[0] != 3 || p[1] != 0 {
		return "", "", false
	}
	tpktLen := int(binary.BigEndian.Uint16(p[2:4]))
	li := int(p[4])
	if p[5] != 0xE0 || tpktLen < 11 || tpktLen > 4096 || li+5 > tpktLen {
		return "", "", false
	}
	body := p[11:]
	if tpktLen <= len(p) {
		body = p[11:tpktLen]
	}
	const cookiePrefix = "Cookie: mstshash="
	if bytes.HasPrefix(body, []byte(cookiePrefix)) {
		end := bytes.Index(body, []byte("\r\n"))
		if end < 0 {
			end = len(body)
		}
		cookie = string(body[len(cookiePrefix):end])
		if len(cookie) > 128 {
			cookie = cookie[:128]
		}
		body = body[min(end+2, len(body)):]
	}
	if len(body) >= 8 && body[0] == 0x01 { // RDP_NEG_REQ
		want := binary.LittleEndian.Uint32(body[4:8])
		var names []string
		for _, n := range []struct {
			bit  uint32
			name string
		}{{0x1, "tls"}, {0x2, "credssp"}, {0x4, "rdstls"}, {0x8, "credssp-ex"}} {
			if want&n.bit != 0 {
				names = append(names, n.name)
			}
		}
		if want == 0 {
			names = append(names, "standard-rdp-security")
		}
		protocols = strings.Join(names, "+")
	}
	return cookie, protocols, true
}

// parseSNI returns the server name from a TLS ClientHello, with every length
// checked against the bytes available.
func parseSNI(p []byte) (string, bool) {
	if len(p) < 43 || p[0] != 0x16 || p[1] != 0x03 || p[5] != 0x01 {
		return "", false
	}
	b := p[43:]
	// session id
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return "", false
	}
	b = b[1+int(b[0]):]
	// cipher suites
	if len(b) < 2 {
		return "", false
	}
	n := int(binary.BigEndian.Uint16(b))
	if len(b) < 2+n {
		return "", false
	}
	b = b[2+n:]
	// compression
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return "", false
	}
	b = b[1+int(b[0]):]
	// extensions
	if len(b) < 2 {
		return "", false
	}
	n = int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if n < len(b) {
		b = b[:n]
	}
	for len(b) >= 4 {
		typ, ln := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		if len(b) < 4+ln {
			return "", false
		}
		ext := b[4 : 4+ln]
		b = b[4+ln:]
		if typ != 0 { // server_name
			continue
		}
		if len(ext) < 5 || ext[2] != 0 {
			return "", false
		}
		nameLen := int(binary.BigEndian.Uint16(ext[3:5]))
		if len(ext) < 5+nameLen || nameLen == 0 || nameLen > 255 {
			return "", false
		}
		name := string(ext[5 : 5+nameLen])
		for _, c := range name {
			if c < 0x21 || c > 0x7e {
				return "", false
			}
		}
		return strings.ToLower(name), true
	}
	return "", false
}
