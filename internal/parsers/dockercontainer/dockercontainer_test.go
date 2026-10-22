package dockercontainer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

var cid = strings.Repeat("ab12", 16)

// writeIn writes content to <tmp>/<dir>/<name> and returns the path.
func writeIn(t *testing.T, dir, name, content string) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), dir)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func parse(t *testing.T, p string) parsers.ParseResult {
	t.Helper()
	r, err := New().Parse(p)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(r.Events) == 0 {
		t.Fatal("no events")
	}
	if len(r.Raw) != len(r.Events) {
		t.Fatalf("raw/event mismatch: %d/%d", len(r.Raw), len(r.Events))
	}
	return r
}

// dockerLine builds one json-file record exactly as the engine writes it.
func dockerLine(log, stream, ts string) string {
	// the engine's key order is log, stream, time
	return fmt.Sprintf(`{"log":%s,"stream":%q,"time":%q}`, mustJSON(log), stream, ts)
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

const (
	grafReq = `logger=context userId=0 orgId=0 uname= t=2026-10-22T08:21:07.910446864Z level=info msg="Request Completed" method=POST path=/login status=401 remote_addr=203.0.113.9 time_ms=0 duration=649.459µs size=107 referer= handler=/login status_source=server`
	grafSet = `logger=settings t=2026-10-22T08:21:00.941928132Z level=info msg="Starting Grafana" version=11.3.0`
)

// ---- Detect ----------------------------------------------------------

func TestDetect_NamesAndScopes(t *testing.T) {
	p := New()
	yes := []string{
		"var/lib/docker/containers/" + cid + "/" + cid + "-json.log",
		`C:\ProgramData\docker\containers\` + cid + `\` + cid + `-json.log`,
		cid + "-json.log.1",
		"x/" + cid + "-json.log.12",
		"var/lib/docker/containers/" + cid + "/config.v2.json",
		`C:\ProgramData\docker\containers\` + cid + `\config.v2.json`,
		"var/lib/docker/containers/" + cid + "/hostconfig.json",
		`C:\ProgramData\docker\containers\` + cid + `\hostconfig.json`,
	}
	no := []string{
		"var/lib/docker/containers/" + cid + "/config.json",
		"etc/app/config.v2.json",
		"config.v2.json",
		"etc/app/hostconfig.json",
		"abc-json.log",
		strings.Repeat("ab12", 15) + "-json.log",
		strings.Repeat("ab12", 16) + "0-json.log",
		strings.Repeat("zz12", 16) + "-json.log",
		cid + "-json.log.gz",
		cid + "-json.logx",
		"var/lib/docker/containers/" + strings.Repeat("ab12", 15) + "/config.v2.json",
		"var/lib/docker/containers/" + cid + "/hostconfig.json.bak",
	}
	for _, s := range yes {
		if !p.Detect(s) {
			t.Errorf("Detect(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if p.Detect(s) {
			t.Errorf("Detect(%q) = true, want false", s)
		}
	}
}

func TestConfirmContent(t *testing.T) {
	p := New()
	if !p.ConfirmContent([]byte(dockerLine("hi\n", "stdout", "2026-10-22T08:21:00.942044932Z"))) {
		t.Error("json-file record not confirmed")
	}
	if !p.ConfirmContent([]byte(`{"StreamConfig":{},"State":{"Running":false},"ID":"` + cid + `","Created":"x"`)) {
		t.Error("config.v2.json head not confirmed")
	}
	if !p.ConfirmContent([]byte(`{"Binds":null,"ContainerIDFile":"","NetworkMode":"bridge","PortBindings":{}`)) {
		t.Error("hostconfig head not confirmed")
	}
	for _, bad := range []string{"", "plain text\n", `{"foo":"bar"}`, "\x00\x01\x02", `[1,2,3]`} {
		if p.ConfirmContent([]byte(bad)) {
			t.Errorf("ConfirmContent(%q) = true", bad)
		}
	}
	if p.DetectContent([]byte(dockerLine("hi\n", "stdout", "2026-10-22T08:21:00.942044932Z"))) {
		t.Error("the parser must be name-driven: DetectContent has to stay false")
	}
}

func TestMeta(t *testing.T) {
	p := New()
	if p.Name() != "dockercontainer@1" || p.ArtifactType() != model.ArtifactContainerLog {
		t.Errorf("%s %s", p.Name(), p.ArtifactType())
	}
	got := p.EventArtifactTypes()
	if !reflect.DeepEqual(got, []string{model.ArtifactContainerConfig}) {
		t.Errorf("EventArtifactTypes = %v", got)
	}
}

// ---- JSON log --------------------------------------------------------

func TestLog_OneEventPerLine(t *testing.T) {
	body := dockerLine("first line\n", "stdout", "2026-10-22T08:21:00.942044932Z") + "\n" +
		dockerLine("second line\n", "stderr", "2026-10-22T08:21:01.5Z") + "\n"
	p := writeIn(t, cid, cid+"-json.log", body)
	r := parse(t, p)
	if len(r.Events) != 2 {
		t.Fatalf("events = %d", len(r.Events))
	}
	e := r.Events[0]
	if e.EventType != model.EventContainerLog || e.ArtifactType != model.ArtifactContainerLog {
		t.Errorf("types = %s / %s", e.EventType, e.ArtifactType)
	}
	if !e.Timestamp.Equal(time.Date(2026, 10, 22, 8, 21, 0, 942044932, time.UTC)) || e.Timestamp.Location() != time.UTC {
		t.Errorf("timestamp = %v", e.Timestamp)
	}
	if e.Extra["container_id"] != cid || e.Extra["stream"] != "stdout" || e.Extra["message"] != "first line" {
		t.Errorf("extra = %v", e.Extra)
	}
	if r.Events[1].Extra["stream"] != "stderr" || r.Events[1].Timestamp.Nanosecond() != 500000000 {
		t.Errorf("second = %v %v", r.Events[1].Extra, r.Events[1].Timestamp)
	}
	if e.Parser != "dockercontainer@1" || e.Confidence <= 0 {
		t.Errorf("parser/conf = %s %v", e.Parser, e.Confidence)
	}
	if e.SourceReference != "line:1" || r.Events[1].SourceReference != "line:2" || r.Raw[0].SourceReference != e.SourceReference {
		t.Errorf("refs = %q %q %q", e.SourceReference, r.Events[1].SourceReference, r.Raw[0].SourceReference)
	}
	if !strings.Contains(r.Raw[0].Raw, `"first line\n"`) {
		t.Errorf("raw = %q", r.Raw[0].Raw)
	}
	if r.Events[0].FilePath == r.Events[1].FilePath {
		t.Errorf("events of one file need distinct FilePath for dedup: %q", e.FilePath)
	}
	if r.Coverage == nil || r.Coverage.RecordsRead != 2 || r.Coverage.Mapped != 2 || r.Coverage.RecordsFailed != 0 || r.Coverage.LimitReached {
		t.Errorf("coverage = %+v", r.Coverage)
	}
}

func TestLog_RotatedNameAndEvidencePath(t *testing.T) {
	body := dockerLine("rotated\n", "stdout", "2026-10-22T08:21:00Z") + "\n"
	p := writeIn(t, "elsewhere", cid+"-json.log.1", body)
	r := parse(t, p)
	if r.Events[0].Extra["container_id"] != cid {
		t.Errorf("id = %q", r.Events[0].Extra["container_id"])
	}
	// the evidence path wins over a server storage name
	q := writeIn(t, "blob", "0001.bin", body)
	r2, err := New().ParseWithContext(q, parsers.ParseContext{EvidencePath: `C:\ProgramData\docker\containers\` + cid + `\` + cid + `-json.log`})
	if err != nil || len(r2.Events) != 1 || r2.Events[0].Extra["container_id"] != cid {
		t.Errorf("evidence path: %v %+v", err, r2.Events)
	}
}

func TestLog_PartialLinesKeptAsWritten(t *testing.T) {
	body := dockerLine("part one ", "stdout", "2026-10-22T08:21:00.1Z") + "\n" +
		dockerLine("part two\n", "stdout", "2026-10-22T08:21:00.2Z") + "\n"
	r := parse(t, writeIn(t, cid, cid+"-json.log", body))
	if len(r.Events) != 2 {
		t.Fatalf("events = %d (partial records must not be merged)", len(r.Events))
	}
	if r.Events[0].Extra["message"] != "part one " || r.Events[0].Extra["partial_line"] != "true" {
		t.Errorf("partial = %v", r.Events[0].Extra)
	}
	if r.Events[1].Extra["message"] != "part two" || r.Events[1].Extra["partial_line"] == "true" {
		t.Errorf("complete = %v", r.Events[1].Extra)
	}
}

func TestLog_MessageRedactedAndClippedOnRuneBoundary(t *testing.T) {
	long := strings.Repeat("é", 700) // 1400 bytes
	body := dockerLine("net user bob Zq9-secret-Pw /add\n", "stdout", "2026-10-22T08:21:00Z") + "\n" +
		dockerLine(long+"\n", "stdout", "2026-10-22T08:21:01Z") + "\n"
	r := parse(t, writeIn(t, cid, cid+"-json.log", body))
	if m := r.Events[0].Extra["message"]; strings.Contains(m, "Zq9-secret-Pw") || !strings.Contains(m, "net user bob") {
		t.Errorf("message not redacted: %q", m)
	}
	m := r.Events[1].Extra["message"]
	if len(m) > 1024 || !strings.HasPrefix(long, m) || len(m) < 1022 {
		t.Errorf("clip: len=%d", len(m))
	}
	if r.Events[1].Extra["message_truncated"] != "true" {
		t.Errorf("no truncation marker")
	}
}

func TestLog_GrafanaRequestBecomesWebRequest(t *testing.T) {
	engine := "2026-10-22T08:21:07.910573001Z"
	body := dockerLine(grafSet+"\n", "stdout", "2026-10-22T08:21:00.942044932Z") + "\n" +
		dockerLine(grafReq+"\n", "stdout", engine) + "\n" +
		dockerLine("plain text\n", "stderr", "2026-10-22T08:21:09Z") + "\n"
	r := parse(t, writeIn(t, cid, cid+"-json.log", body))
	if len(r.Events) != 3 {
		t.Fatalf("events = %d", len(r.Events))
	}
	req := r.Events[1]
	if req.EventType != model.EventWebRequest || req.NetworkSource != "203.0.113.9" {
		t.Fatalf("request = %s %s", req.EventType, req.NetworkSource)
	}
	if !req.Timestamp.Equal(time.Date(2026, 10, 22, 8, 21, 7, 910446864, time.UTC)) {
		t.Errorf("must use the Grafana t, got %v", req.Timestamp)
	}
	for k, want := range map[string]string{"container_received": engine, "container_id": cid, "stream": "stdout", "uri": "/login", "status": "401", "method": "POST"} {
		if req.Extra[k] != want {
			t.Errorf("Extra[%s] = %q, want %q", k, req.Extra[k], want)
		}
	}
	if req.ArtifactType != model.ArtifactContainerLog {
		t.Errorf("artifact = %s", req.ArtifactType)
	}
	if s := r.Events[0]; s.EventType != model.EventGrafanaLog || s.Extra["container_id"] != cid || s.Extra["container_received"] == "" {
		t.Errorf("non-request Grafana line = %s %v", s.EventType, s.Extra)
	}
	if r.Events[2].EventType != model.EventContainerLog {
		t.Errorf("plain = %s", r.Events[2].EventType)
	}
}

func TestLog_UnparsedLinesCountedNotGuessed(t *testing.T) {
	body := dockerLine("one\n", "stdout", "2026-10-22T08:21:00Z") + "\n" +
		"{this is not json\n" +
		`{"other":"object"}` + "\n" +
		"\n" +
		dockerLine("two\n", "stdout", "2026-10-22T08:21:02Z") + "\n"
	r := parse(t, writeIn(t, cid, cid+"-json.log", body))
	if len(r.Events) != 2 {
		t.Fatalf("events = %d", len(r.Events))
	}
	if r.Events[0].Extra["unparsed_lines"] != "3" {
		t.Errorf("unparsed_lines = %q", r.Events[0].Extra["unparsed_lines"])
	}
	if _, ok := r.Events[1].Extra["unparsed_lines"]; ok {
		t.Errorf("only the first event carries the count")
	}
	if r.Events[1].SourceReference != "line:5" {
		t.Errorf("line numbers must count the bad lines: %s", r.Events[1].SourceReference)
	}
	if r.Coverage.RecordsFailed != 3 || r.Coverage.RecordsRead != 5 || !r.Coverage.Incomplete() || !notesContain(r, "not valid JSON") {
		t.Errorf("coverage = %+v", r.Coverage)
	}
}

func notesContain(r parsers.ParseResult, s string) bool {
	if r.Coverage == nil {
		return false
	}
	for _, n := range r.Coverage.Notes {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

func TestLog_OnlyGarbageIsAnError(t *testing.T) {
	p := writeIn(t, cid, cid+"-json.log", "not json\n{broken\n\x00\x01\n")
	if r, err := New().Parse(p); err == nil {
		t.Fatalf("want error, got %d events", len(r.Events))
	}
	e := writeIn(t, cid, cid+"-json.log", "")
	if _, err := New().Parse(e); err == nil {
		t.Fatal("empty file must be an error")
	}
}

func TestLog_UndatedRecordStaysUndated(t *testing.T) {
	body := `{"log":"no time\n","stream":"stdout"}` + "\n" +
		`{"log":"bad time\n","stream":"stdout","time":"yesterday"}` + "\n"
	r := parse(t, writeIn(t, cid, cid+"-json.log", body))
	if len(r.Events) != 2 {
		t.Fatalf("events = %d", len(r.Events))
	}
	for _, e := range r.Events {
		if !e.Timestamp.IsZero() {
			t.Errorf("fabricated time %v", e.Timestamp)
		}
	}
	if r.Events[1].Extra["time_as_written"] != "yesterday" || r.Coverage.Undated != 2 {
		t.Errorf("extra=%v cov=%+v", r.Events[1].Extra, r.Coverage)
	}
}

func TestLog_OversizedLineCounted(t *testing.T) {
	big := dockerLine(strings.Repeat("A", 1<<20+10)+"\n", "stdout", "2026-10-22T08:21:00Z")
	if len(big) <= 1<<20 {
		t.Fatal("fixture not oversized")
	}
	body := dockerLine("before\n", "stdout", "2026-10-22T08:20:59Z") + "\n" + big + "\n" +
		dockerLine("after\n", "stdout", "2026-10-22T08:21:01Z") + "\n"
	r := parse(t, writeIn(t, cid, cid+"-json.log", body))
	if len(r.Events) != 2 || r.Events[1].Extra["message"] != "after" {
		t.Fatalf("events = %d", len(r.Events))
	}
	if r.Events[0].Extra["oversized_lines"] != "1" || !notesContain(r, "longer than") || r.Coverage.RecordsFailed != 1 {
		t.Errorf("oversized: %v %+v", r.Events[0].Extra, r.Coverage)
	}
	if r.Events[1].SourceReference != "line:3" {
		t.Errorf("ref = %s", r.Events[1].SourceReference)
	}
	// a file with ONLY an oversized line has no record
	only := writeIn(t, cid, cid+"-json.log", big+"\n")
	if _, err := New().Parse(only); err == nil {
		t.Error("only an oversized line: want error")
	}
}

func TestLog_RecordCapIsExplicit(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 250001; i++ {
		b.WriteString(`{"log":"x\n","stream":"stdout","time":"2026-10-22T08:21:00Z"}` + "\n")
	}
	r := parse(t, writeIn(t, cid, cid+"-json.log", b.String()))
	if len(r.Events) != 250000 {
		t.Fatalf("events = %d", len(r.Events))
	}
	if !r.Coverage.LimitReached || !notesContain(r, "250000") {
		t.Errorf("cap not stated: %+v", r.Coverage)
	}
}

func TestLog_DeterministicAndNoPanicOnCRLF(t *testing.T) {
	body := dockerLine("win\r\n", "stdout", "2026-10-22T08:21:00Z") + "\r\n" +
		dockerLine(grafReq+"\n", "stdout", "2026-10-22T08:21:07.91Z") + "\n"
	p := writeIn(t, cid, cid+"-json.log", body)
	a, b := parse(t, p), parse(t, p)
	if !reflect.DeepEqual(a, b) {
		t.Error("two parses differ")
	}
	if a.Events[0].Extra["message"] != "win" || len(a.Events) != 2 {
		t.Errorf("crlf: %v", a.Events[0].Extra)
	}
}
