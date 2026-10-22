package dockercontainer

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/model"
)

// Real-engine validation. TRACEFALL_REAL_DOCKER_DIR is the container's own
// directory (named by its 64 hex character id) holding the files a real Docker
// engine wrote. TRACEFALL_REAL_DOCKER_SECRET_FILE optionally names a file
// whose text is a secret the container was started with; it is read only to
// assert the secret appears nowhere in the output.
const (
	realLogSHA    = "219aec059015ec08efec472e43c907d35ec0bc80818f4212ea73636c93e73f7a"
	realConfigSHA = "9c6da8fb07d01a4182cb172b747c12114fa361290082c2c4427741464934a4ac"
	realHostSHA   = "03a4ebe3c7cdbcdcd659906624ab2750c71f7c8b0dcb401236adc03003da0f84"
	realLogLines  = 1312
)

func realDir(t *testing.T) (dir, id string) {
	t.Helper()
	dir = os.Getenv("TRACEFALL_REAL_DOCKER_DIR")
	if dir == "" {
		t.Skip("TRACEFALL_REAL_DOCKER_DIR not set")
	}
	return dir, filepath.Base(dir)
}

func sha(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func realSecret(t *testing.T) string {
	f := os.Getenv("TRACEFALL_REAL_DOCKER_SECRET_FILE")
	if f == "" {
		return ""
	}
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestReal_FilesArePinned(t *testing.T) {
	dir, id := realDir(t)
	for p, want := range map[string]string{
		filepath.Join(dir, id+"-json.log"):    realLogSHA,
		filepath.Join(dir, "config.v2.json"):  realConfigSHA,
		filepath.Join(dir, "hostconfig.json"): realHostSHA,
	} {
		if got := sha(t, p); got != want {
			t.Fatalf("%s: sha256 %s, pinned %s", filepath.Base(p), got, want)
		}
	}
}

func TestReal_JSONLog(t *testing.T) {
	dir, id := realDir(t)
	p := filepath.Join(dir, id+"-json.log")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines, requests := 0, 0
	for _, l := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		lines++
		// the log text sits inside a JSON string, so its quotes are escaped
		if strings.Contains(l, `msg=\"Request Completed\"`) {
			requests++
		}
	}
	if lines != realLogLines {
		t.Fatalf("independent line count = %d, pinned %d", lines, realLogLines)
	}
	r, err := New().Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Events) != realLogLines {
		t.Fatalf("events = %d, want %d", len(r.Events), realLogLines)
	}
	web := 0
	for _, e := range r.Events {
		if e.EventType == model.EventWebRequest {
			web++
		}
		if e.Timestamp.IsZero() || e.Extra["container_id"] != id {
			t.Fatalf("event %s: ts=%v id=%q", e.SourceReference, e.Timestamp, e.Extra["container_id"])
		}
	}
	t.Logf("log lines=%d events=%d web_request=%d lines containing Request Completed=%d", lines, len(r.Events), web, requests)
	if web != requests {
		t.Errorf("web_request events = %d, lines with Request Completed = %d", web, requests)
	}
	if r.Coverage.RecordsFailed != 0 || r.Coverage.LimitReached {
		t.Errorf("coverage = %+v", r.Coverage)
	}
	if s := realSecret(t); s != "" {
		assertNoLeak(t, r, s)
	}
}

func TestReal_ConfigAndHostConfig(t *testing.T) {
	dir, id := realDir(t)
	cr, err := New().Parse(filepath.Join(dir, "config.v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := cr.Events[0]
	if c.Extra["image"] != "grafana/grafana-oss:11.3.0" || c.Extra["container_id"] != id {
		t.Errorf("image/id = %q / %q", c.Extra["image"], c.Extra["container_id"])
	}
	if !strings.Contains(","+c.Extra["env_secret_names"]+",", ",GF_SECURITY_ADMIN_PASSWORD,") {
		t.Errorf("env_secret_names = %q", c.Extra["env_secret_names"])
	}
	if !c.Timestamp.IsZero() {
		t.Errorf("config has a timestamp: %v", c.Timestamp)
	}
	if c.Extra["published_ports"] != "127.0.0.1:13000->3000/tcp" {
		t.Errorf("published_ports = %q", c.Extra["published_ports"])
	}
	hr, err := New().Parse(filepath.Join(dir, "hostconfig.json"))
	if err != nil {
		t.Fatal(err)
	}
	h := hr.Events[0]
	if h.Extra["port_bindings"] != "127.0.0.1:13000->3000/tcp" || h.Extra["privileged"] != "false" || h.Extra["risky"] != "" {
		t.Errorf("hostconfig = %v", h.Extra)
	}
	if s := realSecret(t); s != "" {
		assertNoLeak(t, cr, s)
		assertNoLeak(t, hr, s)
	}
	t.Logf("config extra keys=%d image=%s state=%s secret names=%s", len(c.Extra), c.Extra["image"], c.Extra["state"], c.Extra["env_secret_names"])
}
