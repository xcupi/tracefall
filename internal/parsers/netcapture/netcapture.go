// Package netcapture parses packet captures (pcap and pcapng) into events.
//
// The analysis itself lives in package pcap; this package only maps its
// results to Tracefall's event model and states what each event does and does
// not prove.
//
// # What is emitted
//
//   - network_connection: one per conversation (a client, a server address, a
//     server port and a protocol, however many connections that took), with
//     packet and byte counts both ways. A conversation is called RDP, HTTP,
//     TLS, DNS or NTP only when its bytes were parsed as that protocol; a port
//     number alone appears as service_hint and proves nothing. One further
//     event per Remote Desktop connection that carried real traffic, with its
//     client port.
//   - dns_query: one per lookup (DNS, mDNS and LLMNR) with the answers. NetworkDest
//     is the name asked about, as for Sysmon's DNS events.
//   - web_request: one per HTTP transaction, with the response body's SHA-256
//     and size and what the body is by its magic number. The hash is present
//     only when every byte of the body was in the capture.
//   - clock_observation: one per NTP packet and per HTTP Date header, input to
//     package clockskew.
//   - capture_summary: one, describing the capture and every limit it reached.
//
// # Time
//
// Every timestamp is the capturing machine's clock. It is not the clock of
// any host that appears in the capture, and nothing here corrects it.
//
// # What a capture does not show
//
// Encrypted traffic (TLS, the body of an RDP session) is not read; only its
// metadata is. An HTTP object is identified by hash and type and is not
// stored. A capture taken on one machine shows only what reached that
// machine's interface.
package netcapture

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/pcap"
)

const parserName = "netcapture@1"

const maxFileBytes = 8 << 30

// maxConversationEvents bounds the conversation events of a scan-heavy
// capture. The busiest conversations are kept and the rest are counted in the
// summary event.
const maxConversationEvents = 50_000

// Parser implements parsers.ArtifactParser.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactNetworkCapture }

// Detect matches the usual capture extensions.
func (Parser) Detect(relPath string) bool {
	switch strings.ToLower(filepath.Ext(strings.ReplaceAll(relPath, `\`, "/"))) {
	case ".pcap", ".pcapng", ".cap":
		return true
	}
	return false
}

// DetectContent recognises a capture by its magic number.
func (Parser) DetectContent(header []byte) bool { return hasMagic(header) }

// ConfirmContent confirms a name match: a file called .pcap that does not
// begin with a capture magic number is not handed to this parser.
func (Parser) ConfirmContent(header []byte) bool { return hasMagic(header) }

func hasMagic(h []byte) bool {
	if len(h) < 4 {
		return false
	}
	switch [4]byte{h[0], h[1], h[2], h[3]} {
	case [4]byte{0xd4, 0xc3, 0xb2, 0xa1}, [4]byte{0xa1, 0xb2, 0xc3, 0xd4}, // classic, microsecond
		[4]byte{0x4d, 0x3c, 0xb2, 0xa1}, [4]byte{0xa1, 0xb2, 0x3c, 0x4d}: // classic, nanosecond
		return true
	case [4]byte{0x0a, 0x0d, 0x0d, 0x0a}: // pcapng section header; its byte-order magic follows
		return len(h) >= 12 && (string(h[8:12]) == "\x4d\x3c\x2b\x1a" || string(h[8:12]) == "\x1a\x2b\x3c\x4d")
	}
	return false
}

// Parse reads a capture with no evidence path.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	return p.ParseWithContext(absPath, parsers.ParseContext{})
}

// ParseWithContext reads the capture as a stream.
func (p Parser) ParseWithContext(absPath string, ctx parsers.ParseContext) (parsers.ParseResult, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return parsers.ParseResult{}, err
	}
	if st.Size() > maxFileBytes {
		return parsers.ParseResult{}, fmt.Errorf("netcapture: file exceeds %d bytes", int64(maxFileBytes))
	}
	rd, err := pcap.NewReader(f)
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("netcapture: %w", err)
	}
	an := pcap.Analyze(rd, pcap.DefaultLimits())
	return mapAnalysis(an, filepath.Base(absPath)), nil
}

type builder struct {
	out    parsers.ParseResult
	source string
}

func (b *builder) add(ev model.Event, ref, raw string) {
	ev.ArtifactType, ev.Parser, ev.SourceReference = model.ArtifactNetworkCapture, parserName, ref
	ev.FilePath = b.source
	if ev.Confidence == 0 {
		ev.Confidence = 0.95
	}
	if ev.Extra == nil {
		ev.Extra = map[string]string{}
	}
	ev.Extra["evidence_clock"] = "capture"
	ev.Extra["capture_file"] = b.source
	b.out.Events = append(b.out.Events, ev)
	b.out.Raw = append(b.out.Raw, model.RawEvidence{SourceReference: ref, Raw: raw})
}

func rfc(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func port(p uint16) string { return strconv.Itoa(int(p)) }

func proto(p uint8) string {
	switch p {
	case pcap.ProtoTCP:
		return "tcp"
	case pcap.ProtoUDP:
		return "udp"
	}
	return strconv.Itoa(int(p))
}

func mapAnalysis(an *pcap.Analysis, source string) parsers.ParseResult {
	b := &builder{source: source}

	// ---- summary first: it carries the limits that qualify everything below
	convs := an.Conversations
	omitted := 0
	if len(convs) > maxConversationEvents {
		sorted := append([]*pcap.Conversation(nil), convs...)
		sort.SliceStable(sorted, func(i, j int) bool {
			return sorted[i].PktsToServer+sorted[i].PktsToClient > sorted[j].PktsToServer+sorted[j].PktsToClient
		})
		omitted = len(convs) - maxConversationEvents
		convs = sorted[:maxConversationEvents]
		sort.SliceStable(convs, func(i, j int) bool { return convs[i].First.Before(convs[j].First) })
	}
	links := make([]string, 0, len(an.Stats.LinkTypes))
	for lt, n := range an.Stats.LinkTypes {
		links = append(links, fmt.Sprintf("%d:%d", lt, n))
	}
	sort.Strings(links)
	sum := map[string]string{
		"packets": strconv.FormatUint(an.Stats.Packets, 10), "wire_bytes": strconv.FormatUint(an.Stats.Bytes, 10),
		"first_packet_utc": rfc(an.Stats.First), "last_packet_utc": rfc(an.Stats.Last),
		"link_types":             strings.Join(links, ","),
		"not_decoded":            strconv.FormatUint(an.Stats.NotDecoded, 10),
		"ip_fragments_unread":    strconv.FormatUint(an.Stats.Fragments, 10),
		"truncated_frames":       strconv.FormatUint(an.Stats.Truncated, 10),
		"tcp_connections":        strconv.Itoa(an.Stats.TCPFlows),
		"conversations":          strconv.Itoa(len(an.Conversations)),
		"http_transactions":      strconv.Itoa(len(an.HTTP)),
		"dns_lookups":            strconv.Itoa(len(an.DNS)),
		"clock_observations":     strconv.Itoa(len(an.Clock)),
		"http_streams_abandoned": strconv.Itoa(an.Stats.HTTPBroken),
		"timestamps_are":         "the capturing machine's clock; not corrected and not the clock of any host in the capture",
	}
	if omitted > 0 {
		sum["conversations_omitted"] = strconv.Itoa(omitted)
	}
	if len(an.Notes) > 0 {
		sum["limits_reached"] = strings.Join(an.Notes, "; ")
	}
	if an.Err != nil {
		sum["read_stopped_early"] = an.Err.Error()
	}
	if an.Stats.Packets > 0 {
		b.add(model.Event{Timestamp: an.Stats.First.UTC(), EventType: model.EventCaptureSummary, Extra: sum}, "summary",
			fmt.Sprintf("capture %s: %d packets, %s to %s", source, an.Stats.Packets, rfc(an.Stats.First), rfc(an.Stats.Last)))
	}

	// ---- conversations
	for i, c := range convs {
		ref := fmt.Sprintf("conversation:%d", i+1)
		ex := map[string]string{
			"protocol": proto(c.Proto), "last_seen_utc": rfc(c.Last),
			"packets_to_server": strconv.FormatUint(c.PktsToServer, 10), "packets_to_client": strconv.FormatUint(c.PktsToClient, 10),
			"bytes_to_server": strconv.FormatUint(c.BytesToServer, 10), "bytes_to_client": strconv.FormatUint(c.BytesToClient, 10),
			"connections": strconv.Itoa(c.Connections), "established": strconv.Itoa(c.Established),
			"meaning": "traffic between this client and this server port was seen; a count of packets is not a count of successful sessions",
		}
		set := func(k, v string) {
			if v != "" {
				ex[k] = v
			}
		}
		set("application", c.Application)
		set("service_hint", c.ServiceHint)
		set("rdp_cookie_user", c.RDPCookie)
		set("rdp_protocols_requested", c.RDPProtocols)
		set("tls_server_name", c.TLSServerName)
		if c.Application == "rdp" {
			ex["rdp_note"] = "the cookie is the user name the client sent in its connection request: a hint written by the client, not an authenticated identity"
		}
		b.add(model.Event{
			Timestamp: c.First.UTC(), EventType: model.EventNetworkConnection,
			NetworkSource: c.Client.String(), NetworkDest: c.Server.String(), NetworkDestPort: int(c.ServerPort), Extra: ex,
		}, ref, fmt.Sprintf("%s %s -> %s:%d pkts=%d/%d bytes=%d/%d", proto(c.Proto), c.Client, c.Server, c.ServerPort,
			c.PktsToServer, c.PktsToClient, c.BytesToServer, c.BytesToClient))
		for _, s := range c.Sessions {
			sref := fmt.Sprintf("%s:session:%d", ref, s.ClientPort)
			b.add(model.Event{
				Timestamp: s.First.UTC(), EventType: model.EventNetworkConnection,
				NetworkSource: c.Client.String(), NetworkDest: c.Server.String(), NetworkDestPort: int(c.ServerPort),
				Extra: map[string]string{
					"protocol": "tcp", "application": c.Application, "session": "true",
					"client_port": port(s.ClientPort), "last_seen_utc": rfc(s.Last),
					"packets": strconv.FormatUint(s.Packets, 10), "bytes": strconv.FormatUint(s.Bytes, 10),
					"meaning": "one TCP connection that carried real traffic; its client port is what a logon event naming the same port refers to",
				},
			}, sref, fmt.Sprintf("tcp %s:%d -> %s:%d pkts=%d", c.Client, s.ClientPort, c.Server, c.ServerPort, s.Packets))
		}
	}

	// ---- DNS
	for i, d := range an.DNS {
		ex := map[string]string{
			"dns_query": d.Name, "query_type": d.QType, "protocol": d.Protocol, "resolver": d.Resolver.String(),
			"answered": strconv.FormatBool(d.Responded),
			"meaning":  "a lookup seen on the wire; the answers are what the resolver returned then, not what the name resolves to now",
		}
		if len(d.Answers) > 0 {
			ex["answers"] = strings.Join(d.Answers, ",")
		}
		if d.Responded {
			ex["rcode"] = strconv.Itoa(d.RCode)
			ex["response_utc"] = rfc(d.ResponseAt)
		}
		if d.QueryAbsent {
			ex["query_in_capture"] = "false: only the response was captured"
		}
		b.add(model.Event{
			Timestamp: d.Time.UTC(), EventType: model.EventDNSQuery, NetworkSource: d.Client.String(), NetworkDest: d.Name, Extra: ex,
		}, fmt.Sprintf("dns:%d", i+1), fmt.Sprintf("%s %s? %s -> %s", d.Protocol, d.QType, d.Name, strings.Join(d.Answers, ",")))
	}

	// ---- HTTP
	for i, h := range an.HTTP {
		ex := map[string]string{
			"method": h.Method, "uri": h.URI, "status": statusText(h.Status), "http_host": h.Host, "user_agent": h.UserAgent,
			"client_port": port(h.ClientPort), "server_port": port(h.ServerPort),
			"records_outcome": "false: the capture shows the status the server returned, not what the client or the application did with the response",
		}
		set := func(k, v string) {
			if v != "" {
				ex[k] = v
			}
		}
		set("referrer", h.Referrer)
		set("content_type", h.ContentType)
		set("content_encoding", h.ContentEncoding)
		set("filename", firstNonEmpty(h.Disposition, urlFileName(h.URI)))
		set("server_date", rfc(h.ServerDate))
		set("response_utc", rfc(h.ResponseAt))
		set("file_signature", h.Signature)
		if h.RequestBodySize > 0 {
			ex["request_body_size"] = strconv.FormatUint(h.RequestBodySize, 10)
			set("request_body_sha256", h.RequestBodySHA256)
		}
		switch {
		case h.ResponseAbsent:
			ex["reassembly"] = "no_response"
		case h.Complete:
			ex["reassembly"] = "complete"
			ex["bytes"] = strconv.FormatUint(h.BodySize, 10)
			ex["response_size"] = strconv.FormatUint(h.BodySize, 10)
			ex["response_sha256"] = h.BodySHA256
		default:
			ex["reassembly"] = "incomplete"
			ex["bytes_seen"] = strconv.FormatUint(h.BodySize, 10)
		}
		set("reassembly_note", h.Incomplete)
		if h.RequestAbsent {
			ex["request_in_capture"] = "false: only the response was captured"
		}
		if h.Status == 206 && h.Complete {
			ex["partial_content"] = "true"
			ex["hash_of"] = "a byte range of the object (HTTP 206), not the whole object; it will not match the object's own hash"
		}
		if h.ContentEncoding != "" && h.Complete {
			ex["hash_of"] = "the body as sent, still " + h.ContentEncoding + "-encoded"
		}
		ts := h.RequestAt
		if ts.IsZero() {
			ts = h.ResponseAt
		}
		b.add(model.Event{
			Timestamp: ts.UTC(), EventType: model.EventWebRequest,
			NetworkSource: h.Client.String(), NetworkDest: h.Server.String(), NetworkDestPort: int(h.ServerPort), Extra: ex,
		}, fmt.Sprintf("http:%d", i+1),
			fmt.Sprintf("%s %s%s -> %d %s sha256=%s", h.Method, h.Host, h.URI, h.Status, h.Signature, h.BodySHA256))
	}

	// ---- clocks
	for i, c := range an.Clock {
		ex := map[string]string{
			"source": c.Source, "role": c.Role, "subject_ip": c.Subject.String(), "peer_ip": c.Peer.String(),
			"observed_utc": rfc(c.Observed), "capture_utc": rfc(c.CaptureAt),
			"meaning": "the subject's own clock as it wrote it, seen at the capture time shown; the difference includes network delay and the second-level resolution of the value",
		}
		if c.Source == "ntp" {
			ex["ntp_version"] = strconv.Itoa(c.Version)
			ex["stratum"] = strconv.Itoa(c.Stratum)
			if c.HasOrigin {
				ex["origin_utc"] = rfc(c.Origin)
				ex["receive_utc"] = rfc(c.Receive)
				ex["transmit_utc"] = rfc(c.Transmit)
			}
			if !c.RequestAt.IsZero() {
				ex["request_capture_utc"] = rfc(c.RequestAt)
			}
		}
		b.add(model.Event{
			Timestamp: c.CaptureAt.UTC(), EventType: model.EventClockObservation,
			NetworkSource: c.Subject.String(), NetworkDest: c.Peer.String(), Extra: ex,
		}, fmt.Sprintf("clock:%d", i+1), fmt.Sprintf("%s %s %s clock=%s seen=%s", c.Source, c.Role, c.Subject, rfc(c.Observed), rfc(c.CaptureAt)))
	}
	return b.out
}

func statusText(code int) string {
	if code == 0 {
		return ""
	}
	return strconv.Itoa(code)
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// urlFileName is the last path element of a request URL, without its query.
func urlFileName(uri string) string {
	if i := strings.IndexAny(uri, "?#"); i >= 0 {
		uri = uri[:i]
	}
	if strings.HasSuffix(uri, "/") {
		return ""
	}
	n := path.Base(uri)
	if n == "." || n == "/" || len(n) > 255 {
		return ""
	}
	return n
}
