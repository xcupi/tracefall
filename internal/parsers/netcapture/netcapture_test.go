package netcapture

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

var t0 = time.Date(2020, 9, 19, 2, 21, 47, 0, time.UTC)

type frame struct {
	t    time.Time
	data []byte
}

func ip4(s string) [4]byte { return netip.MustParseAddr(s).As4() }

func ipv4(src, dst string, proto byte, payload []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(payload)))
	h[8], h[9] = 64, proto
	s, d := ip4(src), ip4(dst)
	copy(h[12:], s[:])
	copy(h[16:], d[:])
	return append(append([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0}, h...), payload...)
}

func tcp(sp, dp uint16, seq, ack uint32, flags byte, p []byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:], sp)
	binary.BigEndian.PutUint16(h[2:], dp)
	binary.BigEndian.PutUint32(h[4:], seq)
	binary.BigEndian.PutUint32(h[8:], ack)
	h[12], h[13] = 5<<4, flags
	return append(h, p...)
}

func udp(sp, dp uint16, p []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:], sp)
	binary.BigEndian.PutUint16(h[2:], dp)
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(p)))
	return append(h, p...)
}

func capture(frames []frame) []byte {
	var b bytes.Buffer
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], 65535)
	binary.LittleEndian.PutUint32(hdr[20:], 1)
	b.Write(hdr)
	for _, f := range frames {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:], uint32(f.t.Unix()))
		binary.LittleEndian.PutUint32(rec[4:], uint32(f.t.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(f.data)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(f.data)))
		b.Write(rec)
		b.Write(f.data)
	}
	return b.Bytes()
}

func parse(t *testing.T, frames []frame) []model.Event {
	t.Helper()
	p := filepath.Join(t.TempDir(), "net.pcap")
	if err := os.WriteFile(p, capture(frames), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := New().Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != len(res.Raw) {
		t.Fatalf("events %d, raw %d", len(res.Events), len(res.Raw))
	}
	return res.Events
}

func ofType(ev []model.Event, typ string) []model.Event {
	var out []model.Event
	for _, e := range ev {
		if e.EventType == typ {
			out = append(out, e)
		}
	}
	return out
}

func httpFrames(body []byte, complete bool) []frame {
	at := t0
	var fr []frame
	add := func(c bool, flags byte, seq, ack uint32, p []byte) {
		if c {
			fr = append(fr, frame{at, ipv4("10.0.0.5", "203.0.113.9", 6, tcp(50000, 80, seq, ack, flags, p))})
		} else {
			fr = append(fr, frame{at, ipv4("203.0.113.9", "10.0.0.5", 6, tcp(80, 50000, seq, ack, flags, p))})
		}
		at = at.Add(10 * time.Millisecond)
	}
	req := []byte("GET /files/update.exe HTTP/1.1\r\nHost: dl.example\r\nUser-Agent: UA/1\r\n\r\n")
	add(true, 0x02, 1000, 0, nil)
	add(false, 0x12, 5000, 1001, nil)
	add(true, 0x10, 1001, 5001, nil)
	add(true, 0x18, 1001, 5001, req)
	resp := append([]byte("HTTP/1.1 200 OK\r\nDate: Sat, 19 Sep 2020 02:21:48 GMT\r\nContent-Length: "+itoa(len(body))+"\r\n\r\n"), body...)
	if !complete {
		resp = resp[:len(resp)-100]
	}
	add(false, 0x18, 5001, 1001+uint32(len(req)), resp)
	return fr
}

func itoa(n int) string { return strconv.Itoa(n) }

func body(n int) []byte {
	b := make([]byte, n)
	copy(b, "MZ\x90\x00")
	for i := 4; i < n; i++ {
		b[i] = byte(i * 3)
	}
	return b
}

func TestDetect(t *testing.T) {
	p := New()
	for _, ok := range []string{"a.pcap", "dir/a.PCAPNG", "x.cap", `[root]\c\a.pcap`} {
		if !p.Detect(ok) {
			t.Errorf("Detect(%q) = false", ok)
		}
	}
	if p.Detect("a.pcap.gz") || p.Detect("pcap") {
		t.Error("compressed or unnamed files must not be claimed")
	}
	c := capture([]frame{{t0, ipv4("10.0.0.5", "10.0.0.6", 17, udp(1, 2, []byte("x")))}})
	if !p.DetectContent(c[:64]) || !p.ConfirmContent(c[:64]) {
		t.Error("a classic capture should be recognised by its magic number")
	}
	if p.ConfirmContent([]byte("this is a text file called x.pcap")) {
		t.Error("a name match without the magic number must not be confirmed")
	}
	if p.DetectContent([]byte{0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Error("the pcapng block type alone is not enough; the byte-order magic must follow")
	}
}

func TestParse_HTTPObjectIsHashedAndCarriesTheFieldsRulesRead(t *testing.T) {
	b := body(2048)
	ev := parse(t, httpFrames(b, true))
	h := ofType(ev, model.EventWebRequest)
	if len(h) != 1 {
		t.Fatalf("got %d http events", len(h))
	}
	e := h[0]
	sum := sha256.Sum256(b)
	for k, want := range map[string]string{
		"method": "GET", "uri": "/files/update.exe", "status": "200", "http_host": "dl.example", "user_agent": "UA/1",
		"response_sha256": hex.EncodeToString(sum[:]), "response_size": "2048", "file_signature": "Windows executable (MZ)",
		"filename": "update.exe", "reassembly": "complete", "evidence_clock": "capture",
	} {
		if e.Extra[k] != want {
			t.Errorf("Extra[%s] = %q, want %q", k, e.Extra[k], want)
		}
	}
	if e.NetworkSource != "10.0.0.5" || e.NetworkDest != "203.0.113.9" || e.NetworkDestPort != 80 {
		t.Errorf("endpoints %s -> %s:%d", e.NetworkSource, e.NetworkDest, e.NetworkDestPort)
	}
	if !e.Timestamp.Equal(t0.Add(30 * time.Millisecond)) {
		t.Errorf("timestamp %v is the request's capture time", e.Timestamp)
	}
	if e.ArtifactType != model.ArtifactNetworkCapture || e.Host != "" {
		t.Errorf("the host of a capture is not known from the capture: %q %q", e.ArtifactType, e.Host)
	}
}

func TestParse_AnIncompleteBodyHasNoHash(t *testing.T) {
	ev := parse(t, httpFrames(body(2048), false))
	e := ofType(ev, model.EventWebRequest)[0]
	if e.Extra["response_sha256"] != "" || e.Extra["reassembly"] != "incomplete" {
		t.Errorf("a hash of a partial object would match nothing and mislead: %v", e.Extra)
	}
}

func TestParse_ConversationDNSClockAndSummary(t *testing.T) {
	q := []byte{0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 'e', 'v', 'i', 'l', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	r := append([]byte(nil), q...)
	r[2], r[3], r[7] = 0x81, 0x80, 1
	r = append(r, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 7)
	ntp := make([]byte, 48)
	ntp[0] = 4<<3 | 3
	sec := uint32(t0.Add(-time.Hour).Unix() + 2208988800)
	binary.BigEndian.PutUint32(ntp[40:], sec)
	fr := []frame{
		{t0, ipv4("10.0.0.5", "10.0.0.2", 17, udp(53124, 53, q))},
		{t0.Add(20 * time.Millisecond), ipv4("10.0.0.2", "10.0.0.5", 17, udp(53, 53124, r))},
		{t0.Add(time.Second), ipv4("10.0.0.5", "10.0.0.2", 17, udp(123, 123, ntp))},
	}
	ev := parse(t, fr)
	d := ofType(ev, model.EventDNSQuery)
	if len(d) != 1 || d[0].NetworkDest != "evil.com" || d[0].Extra["answers"] != "198.51.100.7" || d[0].NetworkSource != "10.0.0.5" {
		t.Fatalf("dns: %+v", d)
	}
	c := ofType(ev, model.EventClockObservation)
	if len(c) != 1 || c[0].Extra["role"] != "client" || c[0].Extra["subject_ip"] != "10.0.0.5" ||
		c[0].Extra["observed_utc"] != t0.Add(-time.Hour).Format(time.RFC3339Nano) {
		t.Fatalf("clock: %+v", c)
	}
	s := ofType(ev, model.EventCaptureSummary)
	if len(s) != 1 || s[0].Extra["packets"] != "3" || !strings.Contains(s[0].Extra["timestamps_are"], "capturing machine's clock") {
		t.Fatalf("summary: %+v", s)
	}
	conns := ofType(ev, model.EventNetworkConnection)
	apps := map[string]bool{}
	for _, e := range conns {
		apps[e.Extra["application"]] = true
	}
	if !apps["dns"] || !apps["ntp"] {
		t.Errorf("applications: %v", apps)
	}
	seen := map[string]bool{}
	for _, e := range ev {
		if seen[e.SourceReference] {
			t.Errorf("duplicate source reference %q: events would collapse", e.SourceReference)
		}
		seen[e.SourceReference] = true
	}
}

func TestParse_NotACaptureIsAnError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.pcap")
	os.WriteFile(p, []byte("not a capture at all"), 0o600)
	if _, err := New().Parse(p); err == nil {
		t.Fatal("a file that is not a capture must be an error, not an empty success")
	}
}

func TestParse_APartialContentBodyIsMarkedAsARange(t *testing.T) {
	fr := httpFrames(body(2048), true)
	for i := range fr {
		fr[i].data = bytes.Replace(fr[i].data, []byte("HTTP/1.1 200 OK"), []byte("HTTP/1.1 206 OK"), 1)
	}
	e := ofType(parse(t, fr), model.EventWebRequest)[0]
	if e.Extra["partial_content"] != "true" || !strings.Contains(e.Extra["hash_of"], "byte range") {
		t.Errorf("%v", e.Extra)
	}
}
