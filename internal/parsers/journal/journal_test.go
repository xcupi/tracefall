package journal

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pierrec/lz4/v4"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

// The fixtures below are built from the layout the parser documents, not
// from this parser's own reader, so a wrong offset in the parser shows up as
// a test failure instead of agreeing with itself.

type jbuilder struct {
	buf    []byte
	dataAt map[string]uint64 // "NAME=value" -> object offset, for reuse
}

func newJournal() *jbuilder {
	b := &jbuilder{buf: make([]byte, 240), dataAt: map[string]uint64{}}
	copy(b.buf, magic)
	binary.LittleEndian.PutUint64(b.buf[headerSizeOffset:], 240)
	return b
}

func (b *jbuilder) appendObject(typ, flags byte, body []byte) uint64 {
	off := uint64(len(b.buf))
	hdr := make([]byte, 64)
	hdr[0] = typ
	hdr[1] = flags
	binary.LittleEndian.PutUint64(hdr[8:], uint64(len(hdr)+len(body)))
	b.buf = append(b.buf, hdr...)
	b.buf = append(b.buf, body...)
	for len(b.buf)%8 != 0 {
		b.buf = append(b.buf, 0)
	}
	return off
}

// data adds an uncompressed DATA object holding "NAME=value".
func (b *jbuilder) data(kv string) uint64 {
	if off, ok := b.dataAt[kv]; ok {
		return off
	}
	off := b.appendObject(objectData, 0, []byte(kv))
	b.dataAt[kv] = off
	return off
}

// dataLZ4 adds an LZ4-compressed DATA object: an 8-byte uncompressed size,
// then the LZ4 block. This is the layout journald writes.
func (b *jbuilder) dataLZ4(kv string) uint64 {
	src := []byte(kv)
	dst := make([]byte, len(src)*2+64)
	n, err := lz4.CompressBlock(src, dst, nil)
	if err != nil || n == 0 {
		panic("fixture: lz4 compress failed")
	}
	body := make([]byte, 8+n)
	binary.LittleEndian.PutUint64(body, uint64(len(src)))
	copy(body[8:], dst[:n])
	off := b.appendObject(objectData, objFlagLZ4, body)
	b.dataAt[kv] = off
	return off
}

// entry adds an ENTRY object referencing the given DATA objects. The layout
// is the documented one: seqnum at object offset 16, realtime at 24, boot id
// at 40, and the item list from offset 64, 16 bytes per item.
func (b *jbuilder) entry(seqnum, realtimeUsec uint64, refs ...uint64) uint64 {
	obj := make([]byte, entryItemsOffset+len(refs)*entryItemSize)
	obj[0] = objectEntry
	binary.LittleEndian.PutUint64(obj[8:], uint64(len(obj)))
	binary.LittleEndian.PutUint64(obj[16:], seqnum)
	binary.LittleEndian.PutUint64(obj[24:], realtimeUsec)
	copy(obj[40:56], "0123456789abcdef")
	for i, r := range refs {
		binary.LittleEndian.PutUint64(obj[entryItemsOffset+i*entryItemSize:], r)
	}
	return b.appendRaw(obj)
}

// appendRaw appends a complete object (header included) and pads it to 8
// bytes, as journald does.
func (b *jbuilder) appendRaw(obj []byte) uint64 {
	off := uint64(len(b.buf))
	b.buf = append(b.buf, obj...)
	for len(b.buf)%8 != 0 {
		b.buf = append(b.buf, 0)
	}
	return off
}

func (b *jbuilder) write(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b.buf, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// realtime for 2021-12-09T04:03:00Z in microseconds
const rt = 1639022580000000

func TestDetect(t *testing.T) {
	p := New()
	for _, ok := range []string{"system.journal", "system@25602ecd838648949ece61bc20d3a796-0000000003961e49-0005d2a79098df11.journal", "user-1000.JOURNAL"} {
		if !p.Detect(ok) {
			t.Errorf("Detect(%q) = false", ok)
		}
	}
	for _, no := range []string{"system.journal~", "journal.txt", "system.journal.gz"} {
		if p.Detect(no) {
			t.Errorf("Detect(%q) = true; the name rule is exact, so this must not match by name", no)
		}
	}
	// A set-aside journal is claimed by its signature, not its name.
	if !p.DetectContent([]byte(magic + "rest")) {
		t.Error("a journal with the signature must be claimed by content, including set-aside (.journal~) copies")
	}
	if !p.DetectContent([]byte(magic + "rest")) {
		t.Error("the journal signature was not recognised")
	}
	if p.DetectContent([]byte("LPKSHHR")) || p.DetectContent([]byte("not a journal at all")) {
		t.Error("a short or foreign header was claimed")
	}
}

func TestParse_EntriesBecomeDatedEvents(t *testing.T) {
	b := newJournal()
	refs := []uint64{
		b.data("MESSAGE=Started Session 4 of user alice."),
		b.data("_HOSTNAME=KarenHacker"),
		b.data("_COMM=systemd-logind"),
		b.data("_PID=812"),
		b.data("SYSLOG_IDENTIFIER=systemd-logind"),
		b.data("_SYSTEMD_UNIT=systemd-logind.service"),
		b.data("UNWANTED_FIELD=not kept"),
	}
	b.entry(42, rt, refs...)
	res, st, err := New().ParseDetailed(b.write(t, "system.journal"), parsers.ParseContext{})
	if err != nil {
		t.Fatal(err)
	}
	if st.Entries != 1 || st.Emitted != 1 || st.Excluded != 0 {
		t.Fatalf("stats = %+v", st)
	}
	ev := res.Events[0]
	if ev.EventType != model.EventJournalEntry || ev.ArtifactType != model.ArtifactJournal {
		t.Errorf("type/artifact = %q/%q", ev.EventType, ev.ArtifactType)
	}
	if want := time.UnixMicro(rt).UTC(); !ev.Timestamp.Equal(want) {
		t.Errorf("timestamp = %v, want %v (the file carries the year, so it must be kept)", ev.Timestamp, want)
	}
	if ev.Host != "KARENHACKER" || ev.ProcessName != "systemd-logind" || ev.PID != 812 || ev.Provider != "systemd-logind" {
		t.Errorf("host/comm/pid/provider = %q/%q/%d/%q", ev.Host, ev.ProcessName, ev.PID, ev.Provider)
	}
	if ev.Extra["message"] != "Started Session 4 of user alice." || ev.Extra["systemd_unit"] != "systemd-logind.service" {
		t.Errorf("extra = %v", ev.Extra)
	}
	if ev.SourceReference != "seqnum:42" || ev.Extra["seqnum"] != "42" {
		t.Errorf("reference = %q, seqnum = %q", ev.SourceReference, ev.Extra["seqnum"])
	}
	if strings.Contains(res.Raw[0].Raw, "UNWANTED_FIELD") {
		t.Error("a field outside the whitelist leaked into the raw record")
	}
	if ev.Extra["timestamp_known"] != "true" {
		t.Errorf("timestamp_known = %q", ev.Extra["timestamp_known"])
	}
}

func TestParse_LZ4PayloadsDecodeToTheSameFields(t *testing.T) {
	b := newJournal()
	long := "MESSAGE=" + strings.Repeat("payload that compresses well ", 40)
	refs := []uint64{b.dataLZ4(long), b.dataLZ4("_COMM=bash")}
	b.entry(7, rt, refs...)
	res, st, err := New().ParseDetailed(b.write(t, "system.journal"), parsers.ParseContext{})
	if err != nil {
		t.Fatal(err)
	}
	if st.UndecodableObjects != 0 {
		t.Fatalf("undecodable = %d for valid LZ4", st.UndecodableObjects)
	}
	if got := res.Events[0].Extra["message"]; got != strings.TrimPrefix(long, "MESSAGE=") {
		t.Errorf("LZ4 message did not round-trip: %q", got[:min(len(got), 60)])
	}
	if res.Events[0].ProcessName != "bash" {
		t.Errorf("comm = %q", res.Events[0].ProcessName)
	}
}

func TestParse_XZObjectsAreReportedNotGuessed(t *testing.T) {
	b := newJournal()
	xz := b.appendObject(objectData, objFlagXZ, []byte("MESSAGE=xz-compressed bytes we cannot read"))
	b.entry(1, rt, xz, b.data("_COMM=cron"))
	b.entry(2, rt, b.data("_COMM=kernel"))
	res, st, err := New().ParseDetailed(b.write(t, "system.journal"), parsers.ParseContext{})
	if err != nil {
		t.Fatal(err)
	}
	if st.UnsupportedObjects != 1 {
		t.Errorf("unsupported objects = %d, want 1", st.UnsupportedObjects)
	}
	if st.Excluded != 1 || st.Emitted != 1 {
		t.Errorf("stats = %+v; the cron entry must be excluded, the kernel one kept", st)
	}
	if res.Events[0].Extra["message"] != "" {
		t.Errorf("an unreadable message was guessed: %q", res.Events[0].Extra["message"])
	}
}

func TestParse_TextLogServicesAreExcluded(t *testing.T) {
	b := newJournal()
	b.entry(1, rt, b.data("SYSLOG_IDENTIFIER=sshd"), b.data("_COMM=sshd"))
	b.entry(2, rt, b.data("_COMM=sudo"))
	b.entry(3, rt, b.data("_COMM=su"))
	b.entry(4, rt, b.data("SYSLOG_IDENTIFIER=CRON"))
	b.entry(5, rt, b.data("_COMM=nginx"))
	res, st, err := New().ParseDetailed(b.write(t, "system.journal"), parsers.ParseContext{})
	if err != nil {
		t.Fatal(err)
	}
	if st.Entries != 5 || st.Excluded != 4 || len(res.Events) != 1 || res.Events[0].ProcessName != "nginx" {
		t.Errorf("stats = %+v, events = %d; sshd, sudo, su and cron must be left to the text parsers", st, len(res.Events))
	}
}

func TestParse_ZeroRealtimeStaysUndatedNotInvented(t *testing.T) {
	b := newJournal()
	b.entry(9, 0, b.data("_COMM=early"))
	res, err := New().Parse(b.write(t, "system.journal"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Events[0].Timestamp.IsZero() || res.Events[0].Extra["timestamp_known"] != "false" {
		t.Errorf("a zero realtime became %v", res.Events[0].Timestamp)
	}
}

func TestParse_RejectsWhatIsNotAJournal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "system.journal")
	if err := os.WriteFile(p, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New().Parse(p); err == nil {
		t.Fatal("a file without the signature was parsed")
	}
}

func TestParse_CorruptSizeStopsCleanly(t *testing.T) {
	b := newJournal()
	b.entry(1, rt, b.data("_COMM=ok"))
	// An object whose size runs past the end of the file must end the walk,
	// not panic or read past the buffer.
	bad := make([]byte, 64)
	bad[0] = objectData
	binary.LittleEndian.PutUint64(bad[8:], 1<<40)
	b.buf = append(b.buf, bad...)
	res, _, err := New().ParseDetailed(b.write(t, "system.journal"), parsers.ParseContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 {
		t.Errorf("events = %d, want the one valid entry before the corruption", len(res.Events))
	}
}

// auditRecord adds one audit record to the journal: the transport and serial
// fields journald gives every audit record, plus its MESSAGE.
func auditRecord(b *jbuilder, seq, realtime uint64, id string, extra []string, message string) {
	refs := []uint64{
		b.data("_TRANSPORT=audit"),
		b.data("_AUDIT_ID=" + id),
		b.data("_HOSTNAME=KarenHacker"),
		b.data("MESSAGE=" + message),
	}
	for _, kv := range extra {
		refs = append(refs, b.data(kv))
	}
	b.entry(seq, realtime, refs...)
}

func TestParse_ExecutionGroupBecomesOneProcessCreate(t *testing.T) {
	b := newJournal()
	const id = "17009727"
	auditRecord(b, 1, rt, id, []string{"_COMM=pkill", "_PID=18836"},
		`SYSCALL arch=c000003e syscall=59 success=yes exit=0 a0=55f4 items=2 ppid=15853 pid=18836 auid=1000 uid=1 gid=1 euid=1 exe="/usr/bin/pkill" comm="pkill"`)
	auditRecord(b, 2, rt+1, id, nil, `EXECVE argc=3 a0="pkill" a1="-9" a2="kdevtmpfsi"`)
	auditRecord(b, 3, rt+2, id, nil, `CWD cwd="/tmp"`)
	auditRecord(b, 4, rt+3, id, nil, `PATH item=0 name="/usr/bin/pkill" inode=4307`)
	auditRecord(b, 5, rt+4, id, nil, "PROCTITLE proctitle="+hex.EncodeToString([]byte("pkill\x00-9\x00kdevtmpfsi")))

	res, st, err := New().ParseDetailed(b.write(t, "system.journal"), parsers.ParseContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 || st.Executions != 1 {
		t.Fatalf("events = %d, executions = %d; five audit records of one execve must be one event", len(res.Events), st.Executions)
	}
	ev := res.Events[0]
	if ev.EventType != model.EventProcessCreate {
		t.Errorf("type = %q, want process_create", ev.EventType)
	}
	if ev.CommandLine != "pkill -9 kdevtmpfsi" {
		t.Errorf("command line = %q", ev.CommandLine)
	}
	if ev.PID != 18836 || ev.PPID != 15853 || ev.ProcessName != "pkill" || ev.ProcessPath != "/usr/bin/pkill" {
		t.Errorf("pid/ppid/comm/exe = %d/%d/%q/%q", ev.PID, ev.PPID, ev.ProcessName, ev.ProcessPath)
	}
	if ev.Extra["cwd"] != "/tmp" || ev.Extra["paths"] != "/usr/bin/pkill" || ev.Extra["record_count"] != "5" {
		t.Errorf("cwd/paths/records = %q/%q/%q", ev.Extra["cwd"], ev.Extra["paths"], ev.Extra["record_count"])
	}
	if ev.Extra["proctitle"] != "pkill -9 kdevtmpfsi" || ev.Extra["syscall_success"] != "yes" || ev.Extra["audit_id"] != id {
		t.Errorf("proctitle/success/audit_id = %q/%q/%q", ev.Extra["proctitle"], ev.Extra["syscall_success"], ev.Extra["audit_id"])
	}
	if ev.SourceReference != "audit:"+id || ev.Timestamp.UnixMicro() != int64(rt) {
		t.Errorf("reference %q, timestamp %v", ev.SourceReference, ev.Timestamp)
	}
}

func TestParse_ChunkedAndHexArgumentsAreRebuilt(t *testing.T) {
	b := newJournal()
	const id = "42"
	auditRecord(b, 1, rt, id, []string{"_COMM=sh", "_PID=7"},
		`SYSCALL arch=c000003e syscall=59 success=yes exit=0 pid=7 ppid=1 exe="/bin/sh" comm="sh"`)
	// "curl" split into two chunks, and "-n" written as bare hex (2D6E).
	auditRecord(b, 2, rt+1, id, nil, `EXECVE argc=3 a0[0]="cu" a0[1]="rl" a1=2D6E a2="http://10.0.0.5/x"`)
	res, err := New().Parse(b.write(t, "system.journal"))
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Events[0].CommandLine; got != "curl -n http://10.0.0.5/x" {
		t.Errorf("command line = %q; chunks must join and hex must decode", got)
	}
}

func TestParse_NonExecutionAuditGroupStaysPerRecord(t *testing.T) {
	b := newJournal()
	const id = "99"
	auditRecord(b, 1, rt, id, []string{"_COMM=login"}, `USER_START pid=10 uid=0 auid=1000 msg='op=PAM:session_open'`)
	auditRecord(b, 2, rt+1, id, []string{"_COMM=login"}, `CRED_ACQ pid=10 uid=0 msg='op=PAM:setcred'`)
	res, st, err := New().ParseDetailed(b.write(t, "system.journal"), parsers.ParseContext{})
	if err != nil {
		t.Fatal(err)
	}
	if st.Executions != 0 || len(res.Events) != 2 {
		t.Errorf("executions = %d, events = %d; a login group is not an execution and must keep both records", st.Executions, len(res.Events))
	}
	for _, ev := range res.Events {
		if ev.EventType != model.EventJournalEntry {
			t.Errorf("type = %q, want journal_entry for a non-execution record", ev.EventType)
		}
	}
}

func TestParse_CronExecutionIsLeftToTheSyslogParser(t *testing.T) {
	b := newJournal()
	const id = "5"
	auditRecord(b, 1, rt, id, []string{"_COMM=cron", "_PID=3"},
		`SYSCALL arch=c000003e syscall=59 success=yes exit=0 pid=3 ppid=1 exe="/usr/sbin/cron" comm="cron"`)
	auditRecord(b, 2, rt+1, id, nil, `EXECVE argc=1 a0="run-parts"`)
	res, st, err := New().ParseDetailed(b.write(t, "system.journal"), parsers.ParseContext{})
	if err != nil {
		t.Fatal(err)
	}
	if st.Excluded != 1 || len(res.Events) != 0 {
		t.Errorf("excluded = %d, events = %d; a cron execution is emitted by the syslog parser, not here", st.Excluded, len(res.Events))
	}
}

// A 32-bit execve on a 64-bit kernel reports arch=40000003 and syscall 11.
// The same number 11 on x86_64 is munmap, so only the arch makes it an execution.
func TestParse_ThirtyTwoBitExecveIsRecognisedAndMunmapIsNot(t *testing.T) {
	b := newJournal()
	auditRecord(b, 1, rt, "7", []string{"_COMM=legacy", "_PID=21"},
		`SYSCALL arch=40000003 syscall=11 success=yes exit=0 pid=21 ppid=1 exe="/usr/bin/legacy" comm="legacy"`)
	auditRecord(b, 2, rt+1, "7", nil, `EXECVE argc=1 a0="legacy"`)
	auditRecord(b, 3, rt+2, "8", []string{"_COMM=mmapuser", "_PID=22"},
		`SYSCALL arch=c000003e syscall=11 success=yes exit=0 pid=22 ppid=1 exe="/usr/bin/mmapuser" comm="mmapuser"`)

	res, st, err := New().ParseDetailed(b.write(t, "system.journal"), parsers.ParseContext{})
	if err != nil {
		t.Fatal(err)
	}
	if st.Executions != 1 {
		t.Fatalf("executions = %d, want 1: the 32-bit execve only", st.Executions)
	}
	var sawExec, sawMunmapAsEntry bool
	for _, ev := range res.Events {
		if ev.EventType == model.EventProcessCreate && ev.ProcessName == "legacy" {
			sawExec = true
		}
		if ev.EventType == model.EventJournalEntry && ev.ProcessName == "mmapuser" {
			sawMunmapAsEntry = true
		}
	}
	if !sawExec {
		t.Error("the 32-bit execve (arch 40000003, syscall 11) was not recognised as process_create")
	}
	if !sawMunmapAsEntry {
		t.Error("the x86_64 munmap (syscall 11) must stay a plain entry, not an execution")
	}
}
