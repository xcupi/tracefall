package netcapture

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"tracefall/internal/correlate"
	"tracefall/internal/detect"
	"tracefall/internal/model"
)

const realCapturePin = "09abf49efea1852e047987d92907704d47f36d75f6c8056e2cafa6cc027791cb"

// A real 197 MB capture of a Remote Desktop password-guessing run followed by
// a program fetched over HTTP. Set TRACEFALL_REAL_PCAP to its path to run. The
// file is not in the repository and its SHA-256 is pinned. The expected
// counts were taken with tcpdump, not with these parsers: 411797 packets;
// 29309 distinct SYNs (source port plus initial sequence number) from the
// guessing client to port 3389; 229 HTTP transactions; the program's SHA-256
// as published by a public write-up of the same capture. NTP transmit times
// in the capture were read with tcpdump -vv and sit one hour after the packet
// times.
func TestRealCapture(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_PCAP")
	if path == "" {
		t.Skip("set TRACEFALL_REAL_PCAP to a real capture to run")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if hex.EncodeToString(h.Sum(nil)) != realCapturePin {
		t.Fatal("this is not the capture these counts were taken from")
	}

	res, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	events := res.Events
	for i := range events {
		events[i].ID = "e" + strconv.Itoa(i)
		events[i].CaseID = "real"
		events[i].SourceFileID = "cap"
	}

	var sum model.Event
	var web []model.Event
	for _, e := range events {
		switch e.EventType {
		case model.EventCaptureSummary:
			sum = e
		case model.EventWebRequest:
			web = append(web, e)
		}
	}
	if sum.Extra["packets"] != "411797" {
		t.Errorf("packets = %s, want 411797", sum.Extra["packets"])
	}
	if len(web) != 229 {
		t.Errorf("http transactions = %d, want 229", len(web))
	}
	const programSHA = "10f3b92002bb98467334161cf85d0b1730851f9256f83c27db125e9a0c1cfda6"
	fetched := 0
	for _, e := range web {
		if e.Extra["response_sha256"] == programSHA {
			fetched++
			if e.Extra["file_signature"] != "Windows executable (MZ)" || !strings.HasSuffix(e.Extra["filename"], ".exe") || e.Extra["response_size"] != "7168" {
				t.Errorf("program fetch: %v", e.Extra)
			}
		}
	}
	if fetched != 2 {
		t.Errorf("the program was fetched %d times, want 2 (two clients)", fetched)
	}

	// Remote Desktop: the client with by far the most connections to port 3389.
	var conv model.Event
	for _, e := range events {
		if e.EventType == model.EventNetworkConnection && e.NetworkDestPort == 3389 && e.Extra["session"] != "true" {
			if n, _ := strconv.Atoi(e.Extra["connections"]); n > func() int { v, _ := strconv.Atoi(conv.Extra["connections"]); return v }() {
				conv = e
			}
		}
	}
	longest := 0
	for _, e := range events {
		if e.Extra["session"] == "true" && e.NetworkSource == conv.NetworkSource && e.NetworkDestPort == 3389 {
			if p, _ := strconv.Atoi(e.Extra["packets"]); p > longest {
				longest = p
			}
		}
	}
	if conv.Extra["connections"] != "29309" {
		t.Errorf("connections = %q, want 29309", conv.Extra["connections"])
	}
	if longest < 1000 {
		t.Errorf("longest session = %d packets; the capture holds sessions of thousands (tcpdump counts 36915 on one port)", longest)
	}

	// The rules.
	var burst, fetchFindings int
	for _, r := range detect.All() {
		for _, f := range r.Evaluate(events) {
			switch f.RuleID {
			case "rdp-connection-burst":
				burst++
				if f.Severity != model.SeverityHigh {
					t.Errorf("burst followed by sessions should be high: %s", f.Severity)
				}
			case "executable-over-http-from-address":
				fetchFindings++
			}
		}
	}
	if burst != 1 || fetchFindings != 2 {
		t.Errorf("findings: burst %d (want 1), program fetches %d (want 2)", burst, fetchFindings)
	}

	// Clocks: both Windows hosts that spoke NTP read one hour ahead of the capture.
	cs, err := correlate.RunFrom("real", model.SliceSource(events))
	if err != nil {
		t.Fatal(err)
	}
	skews := 0
	for _, c := range cs {
		if c.Type == model.CorrelationClockSkew {
			skews++
		}
	}
	if skews != 2 {
		t.Errorf("clock offsets reported: %d, want 2 (the two hosts that used NTP)", skews)
	}
}
