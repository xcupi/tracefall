package wtmp

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/model"
)

// mkRecord builds one 384-byte utmp record using the glibc x86-64 layout the
// parser documents: type@0 pid@4 line@8 user@44 host@76 tv_sec@340.
func mkRecord(typ int16, pid int32, line, user, host string, sec int32) []byte {
	r := make([]byte, recordSize)
	binary.LittleEndian.PutUint16(r[0:2], uint16(typ))
	binary.LittleEndian.PutUint32(r[4:8], uint32(pid))
	copy(r[8:40], line)
	copy(r[44:76], user)
	copy(r[76:332], host)
	binary.LittleEndian.PutUint32(r[340:344], uint32(sec))
	return r
}

func writeWtmp(t *testing.T, recs ...[]byte) string {
	t.Helper()
	var b []byte
	for _, r := range recs {
		b = append(b, r...)
	}
	p := filepath.Join(t.TempDir(), "wtmp")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// 1634550000 = 2021-10-18T10:00:00Z
const t0 = 1634550000

func TestDetect_OnlyWtmp(t *testing.T) {
	p := New()
	if !p.Detect("var/log/wtmp") || !p.Detect(`[root]\var\log\wtmp`) {
		t.Error("wtmp not detected")
	}
	for _, no := range []string{"btmp", "wtmp.1", "lastlog", "wtmp.gz"} {
		if p.Detect(no) {
			t.Errorf("Detect(%q) = true; only wtmp is in scope (btmp has different semantics)", no)
		}
	}
	if p.DetectContent(make([]byte, 384)) {
		t.Error("DetectContent claimed a file; utmp has no magic and must not be sniffed")
	}
}

func TestParse_SessionEventsWithRealTimestamps(t *testing.T) {
	p := writeWtmp(t,
		mkRecord(2, 0, "~", "reboot", "4.13.0-kali1-amd64", t0),
		mkRecord(7, 4321, "pts/1", "alice", "10.0.0.5", t0+60),
		mkRecord(8, 4321, "pts/1", "", "", t0+300),
	)
	res, err := New().Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 3 {
		t.Fatalf("events = %d, want 3", len(res.Events))
	}
	boot, login, logout := res.Events[0], res.Events[1], res.Events[2]

	if boot.EventType != model.EventSystemBoot || boot.User != "" {
		t.Errorf("boot = %q user %q", boot.EventType, boot.User)
	}
	if login.EventType != model.EventSessionStart || login.User != "alice" || login.PID != 4321 {
		t.Errorf("login = %q user %q pid %d", login.EventType, login.User, login.PID)
	}
	if login.Extra["terminal"] != "pts/1" || login.Extra["remote"] != "10.0.0.5" {
		t.Errorf("login terminal/remote = %q / %q", login.Extra["terminal"], login.Extra["remote"])
	}
	if want := time.Unix(t0+60, 0).UTC(); !login.Timestamp.Equal(want) {
		t.Errorf("login timestamp = %v, want %v", login.Timestamp, want)
	}
	if logout.EventType != model.EventSessionEnd || logout.User != "" {
		t.Errorf("logout = %q user %q; a logout carries no user and must not invent one", logout.EventType, logout.User)
	}
	if logout.SourceReference != "record:3" {
		t.Errorf("logout reference = %q, want record:3", logout.SourceReference)
	}
}

func TestParse_BookkeepingRecordsProduceNothing(t *testing.T) {
	p := writeWtmp(t,
		mkRecord(1, 0, "~", "runlevel", "4.13.0", t0), // RUN_LVL
		mkRecord(5, 0, "", "", "", t0),                // INIT_PROCESS
		mkRecord(9, 0, "", "", "", t0),                // ACCOUNTING
		mkRecord(0, 0, "", "", "", 0),                 // EMPTY
	)
	res, err := New().Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 || len(res.Raw) != 0 {
		t.Errorf("bookkeeping produced %d events / %d raw; want none", len(res.Events), len(res.Raw))
	}
}

func TestParse_ZeroTimestampStaysZero(t *testing.T) {
	p := writeWtmp(t, mkRecord(7, 1, "tty1", "root", ":0", 0))
	res, err := New().Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Events[0].Timestamp.IsZero() || res.Events[0].Extra["timestamp_known"] != "false" {
		t.Errorf("tv_sec 0 must mean unknown, got %v / %q", res.Events[0].Timestamp, res.Events[0].Extra["timestamp_known"])
	}
}

func TestParse_KeepsFileOrderNotTimeOrder(t *testing.T) {
	// Rotations and clock changes break time order; the file order is the
	// order the system wrote them, so it must be preserved.
	p := writeWtmp(t,
		mkRecord(7, 1, "pts/0", "bob", "", t0+500),
		mkRecord(7, 2, "pts/1", "carol", "", t0+100),
	)
	res, err := New().Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if res.Events[0].User != "bob" || res.Events[1].User != "carol" {
		t.Errorf("order changed: %q, %q", res.Events[0].User, res.Events[1].User)
	}
}

func TestParse_RejectsAFileThatIsNotWholeRecords(t *testing.T) {
	p := filepath.Join(t.TempDir(), "wtmp")
	if err := os.WriteFile(p, make([]byte, 384+10), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New().Parse(p)
	if !errors.Is(err, ErrNotUtmp) {
		t.Fatalf("err = %v, want ErrNotUtmp; a truncated file must not be read partially and silently", err)
	}
}

func TestUTMPTypeNames(t *testing.T) {
	if utmpTypeName(7) != "USER_PROCESS" || utmpTypeName(8) != "DEAD_PROCESS" {
		t.Error("known type names wrong")
	}
	if got := utmpTypeName(42); got != "UNKNOWN(42)" {
		t.Errorf("unknown type = %q, want UNKNOWN(42)", got)
	}
}

// Real-sample test: a Linux /var/log/wtmp, read from TRACEFALL_REAL_WTMP.
// Skipped unless TRACEFALL_REAL_WTMP points at an extracted copy. The
// SHA-256 pins the exact bytes; the expected counts were computed from
// the raw bytes independently of this decoder.
func TestReal_Wtmp(t *testing.T) {
	path := os.Getenv("TRACEFALL_REAL_WTMP")
	if path == "" {
		t.Skip("set TRACEFALL_REAL_WTMP to an extracted /var/log/wtmp to run")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	const wantSHA = "837969874406bca44aad71b549b0a814aaebe6494fbe9b00722ed7ab4626adf6"
	if got := hex.EncodeToString(sum[:]); got != wantSHA {
		t.Fatalf("sample sha256 = %s, want %s", got, wantSHA)
	}
	res, err := New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, ev := range res.Events {
		counts[ev.EventType]++
		if ev.Timestamp.IsZero() {
			t.Errorf("record %s has no timestamp; every wtmp record carries one", ev.SourceReference)
		}
	}
	// Type counts from the raw bytes: 9 USER_PROCESS, 3 DEAD_PROCESS,
	// 9 BOOT_TIME; the 17 RUN_LVL records are bookkeeping and skipped.
	want := map[string]int{model.EventSessionStart: 9, model.EventSessionEnd: 3, model.EventSystemBoot: 9}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("%s = %d, want %d", k, counts[k], v)
		}
	}
	if len(res.Events) != 21 {
		t.Errorf("events = %d, want 21", len(res.Events))
	}
}
