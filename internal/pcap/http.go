package pcap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/payload"
)

const (
	maxHeaderBytes   = 64 << 10
	maxPendingReqs   = 64
	maxReorderSegs   = 32
	maxReorderBytes  = 256 << 10
	maxHeaderValue   = 2048
	httpDateLayout   = "Mon, 02 Jan 2006 15:04:05 GMT"
	chunkLineMaxSize = 256
)

type httpState int

const (
	stHeaders httpState = iota
	stLength
	stChunkSize
	stChunkData
	stChunkCRLF
	stTrailers
	stUntilClose
	stDead
)

type msg struct {
	start time.Time // capture time of the first packet of the message

	// request
	method, uri, host, ua, ref string

	// response
	status               int
	ctype, cenc, disp    string
	date                 time.Time
	req                  *msg // the request this response answers, if known
	noBody, chunked      bool
	contentLen           int64
	hasher               hash.Hash
	size                 uint64
	sniff                []byte
	complete             bool
	incomplete           string
	bodyHash, reqBodyHex string
}

func (m *msg) bodyWrite(p []byte) {
	if len(p) == 0 {
		return
	}
	if m.hasher == nil {
		m.hasher = sha256.New()
	}
	m.hasher.Write(p)
	if len(m.sniff) < 16 {
		m.sniff = append(m.sniff, p[:min(len(p), 16-len(m.sniff))]...)
	}
	m.size += uint64(len(p))
}

func (m *msg) bodyHex() string {
	h := m.hasher
	if h == nil {
		h = sha256.New() // the hash of nothing: an empty body is a fact too
	}
	return hex.EncodeToString(h.Sum(nil))
}

type pendingRequest struct{ m *msg }

type httpDir struct {
	isReq bool

	// TCP reassembly
	init      bool
	next      uint32
	pending   map[uint32][]byte
	pendBytes int

	// message parsing
	state     httpState
	hdr       []byte
	hdrStart  time.Time
	cur       *msg
	remaining uint64
	line      []byte
}

func newHTTPDir(isReq bool) *httpDir {
	return &httpDir{isReq: isReq, pending: map[uint32][]byte{}}
}

func (a *analyzer) feedHTTP(f *flow, dir *httpDir, toServer bool, t time.Time, d Decoded) {
	if d.Flags&FlagSYN != 0 {
		dir.init, dir.next = true, d.Seq+1
		return
	}
	if len(d.Payload) == 0 || dir.state == stDead {
		return
	}
	dir.push(d.Seq, d.Payload,
		func(chunk []byte) { a.httpBytes(f, dir, t, chunk) },
		func() { a.httpGap(f, dir, t) })
}

// push delivers TCP payload in sequence order. Retransmitted bytes are
// dropped, a short run of out-of-order segments is held until the hole fills,
// and a hole that does not fill is declared a gap.
func (d *httpDir) push(seq uint32, p []byte, deliver func([]byte), gap func()) {
	if !d.init {
		d.init, d.next = true, seq
	}
	diff := int32(seq - d.next)
	switch {
	case diff == 0:
		deliver(p)
		d.next += uint32(len(p))
		d.drain(deliver)
	case diff < 0:
		skip := int(-diff)
		if skip >= len(p) {
			return // a retransmission of bytes already delivered
		}
		p = p[skip:]
		deliver(p)
		d.next += uint32(len(p))
		d.drain(deliver)
	default:
		if len(d.pending) >= maxReorderSegs || d.pendBytes+len(p) > maxReorderBytes {
			gap()
			return
		}
		if _, dup := d.pending[seq]; !dup {
			d.pending[seq] = append([]byte(nil), p...)
			d.pendBytes += len(p)
		}
	}
}

func (d *httpDir) drain(deliver func([]byte)) {
	for progress := true; progress && len(d.pending) > 0; {
		progress = false
		for seq, p := range d.pending {
			diff := int32(seq - d.next)
			if diff > 0 {
				continue
			}
			delete(d.pending, seq)
			d.pendBytes -= len(p)
			progress = true
			if skip := int(-diff); skip < len(p) {
				deliver(p[skip:])
				d.next += uint32(len(p) - skip)
			}
		}
	}
}

func (a *analyzer) httpGap(f *flow, dir *httpDir, t time.Time) {
	if dir.state == stDead {
		return
	}
	a.an.Stats.OutOfOrderLost++
	if !dir.isReq && dir.cur != nil {
		dir.cur.incomplete = "bytes missing from the capture"
		a.emitResponse(f, dir.cur, t)
		dir.cur = nil
	}
	dir.state = stDead
	f.httpBroken = true
	a.an.Stats.HTTPBroken++
}

func (a *analyzer) httpBroke(f *flow, dir *httpDir, t time.Time, why string) {
	if !dir.isReq && dir.cur != nil {
		dir.cur.incomplete = why
		a.emitResponse(f, dir.cur, t)
		dir.cur = nil
	}
	dir.state = stDead
	f.httpBroken = true
	a.an.Stats.HTTPBroken++
}

func (a *analyzer) httpBytes(f *flow, dir *httpDir, t time.Time, chunk []byte) {
	for len(chunk) > 0 && dir.state != stDead {
		switch dir.state {
		case stHeaders:
			if len(dir.hdr) == 0 {
				dir.hdrStart = t
			}
			dir.hdr = append(dir.hdr, chunk...)
			chunk = nil
			if len(dir.hdr) > maxHeaderBytes && !bytes.Contains(dir.hdr, []byte("\r\n\r\n")) {
				a.httpBroke(f, dir, t, "HTTP header larger than the parser accepts")
				return
			}
			end, sep := headerEnd(dir.hdr)
			if end < 0 {
				continue
			}
			head, rest := dir.hdr[:end], append([]byte(nil), dir.hdr[end+sep:]...)
			dir.hdr = nil
			if !a.httpHeaders(f, dir, head) {
				a.httpBroke(f, dir, t, "not a well-formed HTTP message")
				return
			}
			chunk = rest
		case stLength, stChunkData:
			n := uint64(len(chunk))
			if n > dir.remaining {
				n = dir.remaining
			}
			dir.cur.bodyWrite(chunk[:n])
			dir.remaining -= n
			chunk = chunk[n:]
			if dir.remaining == 0 {
				if dir.state == stLength {
					a.httpDone(f, dir, t)
				} else {
					dir.state = stChunkCRLF
				}
			}
		case stChunkCRLF:
			i := bytes.IndexByte(chunk, '\n')
			if i < 0 {
				return
			}
			chunk = chunk[i+1:]
			dir.state = stChunkSize
		case stChunkSize, stTrailers:
			i := bytes.IndexByte(chunk, '\n')
			if i < 0 {
				dir.line = append(dir.line, chunk...)
				chunk = nil
				if len(dir.line) > chunkLineMaxSize {
					a.httpBroke(f, dir, t, "chunk framing is malformed")
				}
				continue
			}
			dir.line = append(dir.line, chunk[:i]...)
			chunk = chunk[i+1:]
			line := strings.TrimSpace(string(dir.line))
			dir.line = dir.line[:0]
			if dir.state == stTrailers {
				if line == "" {
					a.httpDone(f, dir, t)
				}
				continue
			}
			if j := strings.IndexByte(line, ';'); j >= 0 {
				line = line[:j]
			}
			size, err := strconv.ParseUint(strings.TrimSpace(line), 16, 40)
			if err != nil {
				a.httpBroke(f, dir, t, "chunk framing is malformed")
				return
			}
			if size == 0 {
				dir.state = stTrailers
			} else {
				dir.remaining, dir.state = size, stChunkData
			}
		case stUntilClose:
			dir.cur.bodyWrite(chunk)
			chunk = nil
		}
	}
}

func headerEnd(b []byte) (end, sepLen int) {
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		return i, 4
	}
	if i := bytes.Index(b, []byte("\n\n")); i >= 0 {
		return i, 2
	}
	return -1, 0
}

// httpHeaders parses a complete header block and moves the parser to the
// state its framing calls for. It returns false for something that is not
// HTTP/1.x.
func (a *analyzer) httpHeaders(f *flow, dir *httpDir, head []byte) bool {
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	first := strings.TrimSpace(lines[0])
	m := &msg{start: dir.hdrStart, contentLen: -1}
	if dir.isReq {
		parts := strings.SplitN(first, " ", 3)
		if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") {
			return false
		}
		m.method, m.uri = parts[0], clipHTTP(parts[1])
	} else {
		parts := strings.SplitN(first, " ", 3)
		if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/1.") {
			return false
		}
		code, err := strconv.Atoi(parts[1])
		if err != nil || code < 100 || code > 599 {
			return false
		}
		m.status = code
	}
	for _, l := range lines[1:] {
		i := strings.IndexByte(l, ':')
		if i <= 0 {
			continue
		}
		name, val := strings.ToLower(strings.TrimSpace(l[:i])), strings.TrimSpace(l[i+1:])
		switch name {
		case "host":
			m.host = clipHTTP(val)
		case "user-agent":
			m.ua = clipHTTP(val)
		case "referer":
			m.ref = clipHTTP(val)
		case "content-type":
			m.ctype = clipHTTP(val)
		case "content-encoding":
			m.cenc = clipHTTP(val)
		case "content-disposition":
			m.disp = clipHTTP(val)
		case "date":
			if tm, err := time.Parse(httpDateLayout, val); err == nil {
				m.date = tm.UTC()
			}
		case "content-length":
			n, err := strconv.ParseInt(val, 10, 64)
			if err != nil || n < 0 {
				return false
			}
			m.contentLen = n
		case "transfer-encoding":
			if strings.Contains(strings.ToLower(val), "chunked") {
				m.chunked = true
			}
		}
	}
	dir.cur = m

	if dir.isReq {
		switch {
		case m.chunked:
			dir.state = stChunkSize
		case m.contentLen > 0:
			dir.state, dir.remaining = stLength, uint64(m.contentLen)
		default:
			a.httpDone(f, dir, dir.hdrStart)
		}
		return true
	}

	// A response. Informational responses precede the real one.
	if m.status >= 100 && m.status < 200 {
		if m.status == 101 {
			dir.state = stDead // the connection is no longer HTTP
		}
		dir.cur = nil
		return true
	}
	if len(f.reqs) > 0 {
		m.req = f.reqs[0].m
		f.reqs = f.reqs[1:]
	}
	m.noBody = m.status == 204 || m.status == 304 || (m.req != nil && m.req.method == "HEAD")
	switch {
	case m.noBody:
		a.httpDone(f, dir, dir.hdrStart)
	case m.chunked:
		dir.state = stChunkSize
	case m.contentLen == 0:
		a.httpDone(f, dir, dir.hdrStart)
	case m.contentLen > 0:
		dir.state, dir.remaining = stLength, uint64(m.contentLen)
	default:
		dir.state = stUntilClose
	}
	return true
}

func clipHTTP(s string) string {
	if len(s) > maxHeaderValue {
		return s[:maxHeaderValue]
	}
	return s
}

// httpDone finishes the message being parsed.
func (a *analyzer) httpDone(f *flow, dir *httpDir, t time.Time) {
	m := dir.cur
	dir.cur, dir.state = nil, stHeaders
	if m == nil {
		return
	}
	m.complete = true
	if dir.isReq {
		m.reqBodyHex = ""
		if m.size > 0 || m.hasher != nil {
			m.reqBodyHex = m.bodyHex()
		}
		if len(f.reqs) >= maxPendingReqs {
			f.reqs = f.reqs[1:]
		}
		f.reqs = append(f.reqs, &pendingRequest{m})
		return
	}
	a.emitResponse(f, m, t)
}

func (a *analyzer) emitResponse(f *flow, m *msg, t time.Time) {
	if len(a.an.HTTP) >= a.lim.MaxHTTP {
		a.note("HTTP transaction table full: further transactions are not reported")
		return
	}
	tx := HTTPTransaction{
		ResponseAt: m.start, Client: f.client.ip, Server: f.server.ip, ClientPort: f.client.port, ServerPort: f.server.port,
		Status: m.status, ContentType: m.ctype, ContentEncoding: m.cenc, ServerDate: m.date,
		BodySize: m.size, Signature: payload.SniffType(m.sniff), Complete: m.complete && m.incomplete == "",
		Incomplete: m.incomplete,
	}
	tx.Disposition = dispositionFilename(m.disp)
	if m.req != nil {
		r := m.req
		tx.RequestAt, tx.Method, tx.URI, tx.Host, tx.UserAgent, tx.Referrer = r.start, r.method, r.uri, r.host, r.ua, r.ref
		tx.RequestBodySize = r.size
		tx.RequestBodySHA256 = r.reqBodyHex
	} else {
		tx.RequestAt, tx.RequestAbsent = m.start, true
	}
	// The hash names an object only when every byte of it was seen. A hash of
	// part of a body would match nothing and mislead anyone who searched for it.
	if tx.Complete {
		tx.BodySHA256 = m.bodyHex()
	}
	a.an.HTTP = append(a.an.HTTP, tx)
	if !m.date.IsZero() && len(a.an.Clock) < a.lim.MaxClock {
		a.an.Clock = append(a.an.Clock, ClockObservation{
			Source: "http_date", Role: "server", Subject: f.server.ip, Peer: f.client.ip,
			CaptureAt: m.start, Observed: m.date,
		})
	}
}

// endFlow flushes what a connection still holds: a close-delimited body that
// the server finished by closing, requests that never got a response.
func (a *analyzer) endFlow(f *flow, t time.Time, why string) {
	if !f.isHTTP || f.ended {
		return
	}
	f.ended = true
	if f.resp != nil && f.resp.cur != nil && f.resp.state != stDead {
		m := f.resp.cur
		if f.resp.state == stUntilClose && f.finS {
			m.complete = true // the server ended the body by closing the connection
		} else {
			m.incomplete = why
		}
		a.emitResponse(f, m, t)
		f.resp.cur = nil
	}
	for _, p := range f.reqs {
		if len(a.an.HTTP) >= a.lim.MaxHTTP {
			break
		}
		r := p.m
		a.an.HTTP = append(a.an.HTTP, HTTPTransaction{
			RequestAt: r.start, Client: f.client.ip, Server: f.server.ip, ClientPort: f.client.port, ServerPort: f.server.port,
			Method: r.method, URI: r.uri, Host: r.host, UserAgent: r.ua, Referrer: r.ref,
			RequestBodySize: r.size, RequestBodySHA256: r.reqBodyHex, ResponseAbsent: true,
			Incomplete: "no response in the capture",
		})
	}
	f.reqs = nil
}

func dispositionFilename(v string) string {
	i := strings.Index(strings.ToLower(v), "filename=")
	if i < 0 {
		return ""
	}
	name := strings.TrimSpace(v[i+len("filename="):])
	if j := strings.IndexByte(name, ';'); j >= 0 {
		name = name[:j]
	}
	name = strings.Trim(name, `" `)
	if k := strings.LastIndexAny(name, `/\`); k >= 0 {
		name = name[k+1:]
	}
	if len(name) > 255 {
		name = name[:255]
	}
	return name
}
