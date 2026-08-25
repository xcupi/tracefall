package main

import (
	"bytes"
	"strings"
	"testing"

	"tracefall/internal/config"
)

func TestPrintStartupBanner_Loopback(t *testing.T) {
	cfg := config.Config{Host: "127.0.0.1", Port: "8080", DBPath: "./tracefall.db", DataDir: "./data"}
	var buf bytes.Buffer
	printStartupBanner(&buf, cfg)
	out := buf.String()

	for _, want := range []string{
		"Tracefall",
		"Listening: 127.0.0.1:8080",
		"URL: http://127.0.0.1:8080",
		"Data: ./data",
		"Database: ./tracefall.db",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("banner missing %q; full output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "LAN access") {
		t.Errorf("loopback banner should not mention LAN access; full output:\n%s", out)
	}
}

func TestPrintStartupBanner_LAN(t *testing.T) {
	cfg := config.Config{Host: "0.0.0.0", Port: "8080", DBPath: "./tracefall.db", DataDir: "./data"}
	var buf bytes.Buffer
	printStartupBanner(&buf, cfg)
	out := buf.String()

	for _, want := range []string{
		"Tracefall",
		"Listening: 0.0.0.0:8080",
		"LAN access: http://<host-ip>:8080",
		"Data: ./data",
		"Database: ./tracefall.db",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("banner missing %q; full output:\n%s", want, out)
		}
	}
	// A bare "URL:" line (as opposed to "LAN access:") would wrongly
	// imply http://0.0.0.0:8080 is something a browser can open.
	if strings.Contains(out, "URL: http://0.0.0.0") {
		t.Errorf("LAN banner should not print an unbrowsable 0.0.0.0 URL; full output:\n%s", out)
	}
}

func TestBrowserURL(t *testing.T) {
	cases := map[[2]string]string{
		{"127.0.0.1", "8080"}: "127.0.0.1:8080",
		{"0.0.0.0", "8080"}:   "localhost:8080",
		{"", "8080"}:          "localhost:8080",
	}
	for in, want := range cases {
		if got := browserURL(in[0], in[1]); got != want {
			t.Errorf("browserURL(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}
