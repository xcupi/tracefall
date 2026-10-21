package packagelog

import (
	"os"
	"path/filepath"
	"testing"

	"tracefall/internal/model"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDetect(t *testing.T) {
	p := New()
	for _, ok := range []string{"dpkg.log", "var/log/dpkg.log", "DPKG.LOG", "dpkg.log.1"} {
		if !p.Detect(ok) {
			t.Errorf("Detect(%q) = false", ok)
		}
	}
	for _, no := range []string{"dpkg.log.gz", "dpkg.log.1.gz", "dpkg.logger", "apt.log"} {
		if p.Detect(no) {
			t.Errorf("Detect(%q) = true", no)
		}
	}
}

func TestParse_OnlyChangesAreEmitted(t *testing.T) {
	body := "" +
		"2020-04-19 12:00:17 startup archives unpack\n" +
		"2020-04-19 12:00:30 install pkg-a <none> 1.0-1\n" +
		"2020-04-19 12:00:30 status half-installed pkg-a 1.0-1\n" +
		"2020-04-19 12:00:31 configure pkg-a 1.0-1 <none>\n" +
		"2020-04-19 12:05:11 upgrade pkg-b:amd64 2.0-1 2.0-2\n" +
		"2020-04-19 12:06:02 remove pkg-c 3.1 3.1\n" +
		"2020-04-19 12:06:09 purge pkg-c 3.1 3.1\n" +
		"2020-04-19 12:06:10 trigproc man-db 2.5 2.5\n"
	res, err := New().Parse(write(t, "dpkg.log", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 4 {
		t.Fatalf("got %d events, want 4 (status, configure, trigproc and startup are steps, not changes)", len(res.Events))
	}
	e := res.Events[0]
	if e.EventType != model.EventPackageChange || e.Extra["action"] != "install" || e.Extra["package"] != "pkg-a" ||
		e.Extra["version_before"] != "" || e.Extra["version_after"] != "1.0-1" {
		t.Errorf("install: %+v", e.Extra)
	}
	if e.SourceReference != "line:2" {
		t.Errorf("reference %q", e.SourceReference)
	}
	up := res.Events[1]
	if up.Extra["package"] != "pkg-b" || up.Extra["architecture"] != "amd64" || up.Extra["version_before"] != "2.0-1" || up.Extra["version_after"] != "2.0-2" {
		t.Errorf("upgrade: %+v", up.Extra)
	}
}

func TestParse_LocalTimeIsNotTurnedIntoATimestamp(t *testing.T) {
	res, err := New().Parse(write(t, "dpkg.log", "2020-04-19 12:00:30 install pkg-a <none> 1.0-1\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := res.Events[0]
	if !e.Timestamp.IsZero() {
		t.Fatalf("dpkg names no time zone; Timestamp must stay zero, got %v", e.Timestamp)
	}
	if e.Extra["timestamp_local"] != "2020-04-19 12:00:30" || e.Extra["timestamp_known"] != "false" || e.Extra["timestamp_basis"] == "" {
		t.Errorf("local time must be kept as written with its basis: %v", e.Extra)
	}
}
