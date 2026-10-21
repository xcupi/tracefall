package pcap

import (
	"io"
	"net/netip"
	"sort"
	"time"
)

// Limits bound every table. A capture is untrusted and can be gigabytes of
// scanning noise; reaching a limit is reported in Analysis.Notes, never
// silent.
type Limits struct {
	MaxFlows         int // concurrent TCP flows tracked
	MaxConversations int
	MaxDNS           int
	MaxHTTP          int
	MaxClock         int
	MaxPendingDNS    int
}

// DefaultLimits suit a capture of a few hundred megabytes.
func DefaultLimits() Limits {
	return Limits{MaxFlows: 200_000, MaxConversations: 200_000, MaxDNS: 200_000, MaxHTTP: 100_000, MaxClock: 50_000, MaxPendingDNS: 20_000}
}

// Conversation is all traffic between one client and one service: the same
// client address, server address, server port and protocol, however many
// connections that took.
type Conversation struct {
	Proto       uint8
	Client      netip.Addr
	Server      netip.Addr
	ServerPort  uint16
	First, Last time.Time

	PktsToServer, PktsToClient   uint64
	BytesToServer, BytesToClient uint64 // transport payload bytes
	Connections                  int    // distinct TCP connections (SYNs seen, or flows begun mid-stream)
	Established                  int    // connections whose SYN-ACK was seen

	// Application is set only from the content of the traffic: the bytes
	// were parsed as that protocol. ServiceHint comes from the port alone
	// and proves nothing.
	Application string
	ServiceHint string

	// Sessions are the Remote Desktop connections that carried real traffic
	// (not a bare handshake or a probe), each with its client port, which is
	// what ties a connection to a logon event that names the same port.
	Sessions      []Session
	RDPCookie     string // mstshash from the connection request, if present
	RDPProtocols  string // protocols the client offered
	TLSServerName string // SNI from the first client hello seen

	order int // creation order, for stable output
}

// Session is one TCP connection.
type Session struct {
	ClientPort  uint16
	First, Last time.Time
	Packets     uint64
	Bytes       uint64
}

// recordSession writes a finished Remote Desktop connection that carried real
// traffic into its conversation, once.
func (a *analyzer) recordSession(f *flow) {
	if f.recorded {
		return
	}
	f.recorded = true
	if f.rdp && f.conv != nil && f.pkts >= minSessionPackets && len(f.conv.Sessions) < maxSessions*4 {
		f.conv.Sessions = append(f.conv.Sessions, Session{ClientPort: f.client.port, First: f.first, Last: f.last, Packets: f.pkts, Bytes: f.bytes})
	}
}

// finishFlow ends a connection that a newer one on the same four-tuple has
// replaced.
func (a *analyzer) finishFlow(f *flow, t time.Time, why string) {
	a.endFlow(f, f.last, why)
	a.recordSession(f)
}

// minSessionPackets separates a connection that did something from a
// handshake or a probe.
const minSessionPackets = 20

const maxSessions = 512

// DNSRecord is one name lookup.
type DNSRecord struct {
	Time        time.Time // the query; the response time when the query is not in the capture
	Client      netip.Addr
	Resolver    netip.Addr
	Protocol    string // dns, mdns, llmnr
	ID          uint16
	Name        string
	QType       string
	Answers     []string
	RCode       int
	Responded   bool
	ResponseAt  time.Time
	QueryAbsent bool // a response whose query is not in the capture
}

// HTTPTransaction is one request and the response that answered it.
type HTTPTransaction struct {
	RequestAt  time.Time
	ResponseAt time.Time
	Client     netip.Addr
	Server     netip.Addr
	ClientPort uint16
	ServerPort uint16

	Method, URI, Host, UserAgent, Referrer string
	RequestBodySize                        uint64
	RequestBodySHA256                      string

	Status          int
	ContentType     string
	ContentEncoding string
	Disposition     string // filename from Content-Disposition, if any
	ServerDate      time.Time
	BodySize        uint64
	BodySHA256      string
	Signature       string // what the first bytes of the body are, by magic number
	Complete        bool   // body fully reassembled; false after a gap or when the capture ended
	Incomplete      string // why not
	ResponseAbsent  bool   // request without a response
	RequestAbsent   bool   // response without a request
}

// ClockObservation is a clock value seen on the wire together with the
// capture time of the packet that carried it.
type ClockObservation struct {
	Source    string // "ntp" or "http_date"
	Role      string // "client" or "server" for ntp; "server" for http_date
	Subject   netip.Addr
	Peer      netip.Addr
	CaptureAt time.Time // capture clock
	Observed  time.Time // the subject's clock as it wrote it
	Version   int
	Stratum   int
	Origin    time.Time // ntp reply: the client's transmit time, echoed
	Receive   time.Time // ntp reply: when the server received the request
	Transmit  time.Time
	HasOrigin bool
	RequestAt time.Time // ntp reply: capture time of the request it answers, when seen
}

// Stats counts what the capture held.
type Stats struct {
	Packets        uint64
	Bytes          uint64
	First, Last    time.Time
	LinkTypes      map[int]uint64
	NotDecoded     uint64 // frames that were not IP or whose link type is unsupported
	Fragments      uint64
	Truncated      uint64 // frames captured shorter than on the wire
	TCPFlows       int
	HTTPBroken     int // HTTP flows abandoned after a gap or a malformed message
	OutOfOrderLost uint64
}

// Analysis is everything extracted from one capture.
type Analysis struct {
	Stats         Stats
	Conversations []*Conversation
	DNS           []DNSRecord
	HTTP          []HTTPTransaction
	Clock         []ClockObservation
	Notes         []string
	Err           error // set when the read ended early; everything before it is valid
}

type pair struct{ a, b endpoint }

type endpoint struct {
	ip   netip.Addr
	port uint16
}

func less(x, y endpoint) bool {
	if c := x.ip.Compare(y.ip); c != 0 {
		return c < 0
	}
	return x.port < y.port
}

func tupleKey(src, dst endpoint) pair {
	if less(src, dst) {
		return pair{src, dst}
	}
	return pair{dst, src}
}

type convKey struct {
	proto      uint8
	client     netip.Addr
	server     netip.Addr
	serverPort uint16
}

type flow struct {
	conv       *Conversation
	client     endpoint
	server     endpoint
	checked    bool // first client payload examined for RDP / TLS / HTTP
	isHTTP     bool
	httpBroken bool
	req, resp  *httpDir
	reqs       []*pendingRequest
	finC, finS bool
	ended      bool
	rdp        bool
	recorded   bool // its session, if any, has been written to the conversation
	hasSyn     bool
	synSeq     uint32
	first      time.Time
	last       time.Time
	pkts       uint64
	bytes      uint64
}

type analyzer struct {
	lim       Limits
	an        *Analysis
	convs     map[convKey]*Conversation
	flows     map[pair]*flow
	pendDNS   map[dnsKey]*DNSRecord
	pendOrder []dnsKey
	ntpReq    map[ntpKey]time.Time
	notes     map[string]bool
}

// Analyze reads the whole capture. A read error after some packets does not
// discard them: the Analysis is returned with Err set.
func Analyze(rd *Reader, lim Limits) *Analysis {
	a := &analyzer{
		lim:     lim,
		an:      &Analysis{Stats: Stats{LinkTypes: map[int]uint64{}}},
		convs:   map[convKey]*Conversation{},
		flows:   map[pair]*flow{},
		pendDNS: map[dnsKey]*DNSRecord{},
		ntpReq:  map[ntpKey]time.Time{},
		notes:   map[string]bool{},
	}
	for {
		pkt, err := rd.Next()
		if err != nil {
			if err != io.EOF {
				a.an.Err = err
			}
			break
		}
		a.packet(pkt)
	}
	a.finish()
	return a.an
}

func (a *analyzer) note(s string) {
	if !a.notes[s] {
		a.notes[s] = true
		a.an.Notes = append(a.an.Notes, s)
	}
}

func (a *analyzer) packet(p Packet) {
	st := &a.an.Stats
	st.Packets++
	st.Bytes += uint64(p.OrigLen)
	if st.First.IsZero() || p.Time.Before(st.First) {
		st.First = p.Time
	}
	if p.Time.After(st.Last) {
		st.Last = p.Time
	}
	st.LinkTypes[p.LinkType]++
	if p.OrigLen > len(p.Data) {
		st.Truncated++
	}
	d, ok := Decode(p.LinkType, p.Data)
	if !ok {
		st.NotDecoded++
		return
	}
	if d.Fragment {
		st.Fragments++
		return
	}
	switch d.Proto {
	case ProtoTCP:
		a.tcp(p.Time, d)
	case ProtoUDP:
		a.udp(p.Time, d)
	}
}

var udpServerPorts = map[uint16]bool{
	53: true, 67: true, 68: false, 123: true, 137: true, 138: true, 161: true, 389: true, 443: true, 500: true,
	514: true, 1900: true, 4500: true, 5353: true, 5355: true,
}

var tcpServerPorts = map[uint16]bool{
	20: true, 21: true, 22: true, 23: true, 25: true, 53: true, 80: true, 88: true, 110: true, 135: true, 139: true,
	143: true, 389: true, 443: true, 445: true, 465: true, 587: true, 636: true, 993: true, 995: true, 1433: true,
	3306: true, 3389: true, 5432: true, 5985: true, 5986: true, 8080: true, 8443: true,
}

func hintFor(proto uint8, port uint16) string {
	names := map[uint16]string{
		22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 88: "kerberos", 110: "pop3", 123: "ntp", 135: "msrpc",
		137: "netbios-ns", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https", 445: "smb", 636: "ldaps", 1433: "mssql",
		3306: "mysql", 3389: "rdp", 5353: "mdns", 5355: "llmnr", 5432: "postgres", 5985: "winrm", 5986: "winrm-tls", 8080: "http-alt",
	}
	return names[port]
}

// serverSide decides which end of a UDP packet is the service, from the ports
// alone, symmetrically: both directions of an exchange give the same answer.
func serverSide(src, dst endpoint) (client, server endpoint) {
	sKnown, dKnown := udpServerPorts[src.port], udpServerPorts[dst.port]
	switch {
	case dKnown && !sKnown:
		return src, dst
	case sKnown && !dKnown:
		return dst, src
	case src.port < dst.port:
		return dst, src
	case dst.port < src.port:
		return src, dst
	}
	return src, dst
}

func (a *analyzer) conversation(t time.Time, proto uint8, client, server endpoint) *Conversation {
	k := convKey{proto, client.ip, server.ip, server.port}
	c := a.convs[k]
	if c != nil {
		return c
	}
	if len(a.convs) >= a.lim.MaxConversations {
		a.note("conversation table full: further conversations are counted in packets and bytes only")
		return nil
	}
	c = &Conversation{Proto: proto, Client: client.ip, Server: server.ip, ServerPort: server.port, First: t, Last: t,
		ServiceHint: hintFor(proto, server.port), order: len(a.convs)}
	a.convs[k] = c
	a.an.Conversations = append(a.an.Conversations, c)
	return c
}

func (c *Conversation) add(t time.Time, toServer bool, payload int) {
	if t.Before(c.First) {
		c.First = t
	}
	if t.After(c.Last) {
		c.Last = t
	}
	if toServer {
		c.PktsToServer++
		c.BytesToServer += uint64(payload)
	} else {
		c.PktsToClient++
		c.BytesToClient += uint64(payload)
	}
}

func (a *analyzer) udp(t time.Time, d Decoded) {
	src, dst := endpoint{d.Src, d.SrcPort}, endpoint{d.Dst, d.DstPort}
	cl, sv := serverSide(src, dst)
	if c := a.conversation(t, ProtoUDP, cl, sv); c != nil {
		c.add(t, src == cl, len(d.Payload))
		switch sv.port {
		case 53, 5353, 5355:
			if a.dns(t, d, cl, sv) {
				c.Application = map[uint16]string{53: "dns", 5353: "mdns", 5355: "llmnr"}[sv.port]
			}
		case 123:
			if a.ntp(t, d) {
				c.Application = "ntp"
			}
		}
	}
}

func (a *analyzer) finish() {
	// Close-delimited HTTP bodies end with the capture.
	for _, f := range a.flows {
		a.endFlow(f, f.last, "the capture ended before the response ended")
	}
	for _, k := range a.pendOrder {
		if r, ok := a.pendDNS[k]; ok {
			a.emitDNS(r)
			delete(a.pendDNS, k)
		}
	}
	a.an.Stats.TCPFlows = len(a.flows)
	for _, f := range a.flows {
		a.recordSession(f)
	}
	for _, c := range a.an.Conversations {
		sort.Slice(c.Sessions, func(i, j int) bool {
			if !c.Sessions[i].First.Equal(c.Sessions[j].First) {
				return c.Sessions[i].First.Before(c.Sessions[j].First)
			}
			return c.Sessions[i].ClientPort < c.Sessions[j].ClientPort
		})
		if len(c.Sessions) > maxSessions {
			// Keep the busiest: a long session is what a reader needs, and a
			// run of short probes must not push it out.
			sort.SliceStable(c.Sessions, func(i, j int) bool { return c.Sessions[i].Packets > c.Sessions[j].Packets })
			c.Sessions = c.Sessions[:maxSessions]
			sort.Slice(c.Sessions, func(i, j int) bool {
				if !c.Sessions[i].First.Equal(c.Sessions[j].First) {
					return c.Sessions[i].First.Before(c.Sessions[j].First)
				}
				return c.Sessions[i].ClientPort < c.Sessions[j].ClientPort
			})
			a.note("more Remote Desktop sessions than the limit: the busiest are kept")
		}
	}
	sort.SliceStable(a.an.HTTP, func(i, j int) bool { return a.an.HTTP[i].RequestAt.Before(a.an.HTTP[j].RequestAt) })
	sort.SliceStable(a.an.DNS, func(i, j int) bool { return a.an.DNS[i].Time.Before(a.an.DNS[j].Time) })
	sort.SliceStable(a.an.Clock, func(i, j int) bool { return a.an.Clock[i].CaptureAt.Before(a.an.Clock[j].CaptureAt) })
	sort.SliceStable(a.an.Conversations, func(i, j int) bool {
		x, y := a.an.Conversations[i], a.an.Conversations[j]
		if !x.First.Equal(y.First) {
			return x.First.Before(y.First)
		}
		return x.order < y.order
	})
	sort.Strings(a.an.Notes)
}
