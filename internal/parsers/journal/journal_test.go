package journal

import (
	"encoding/binary"
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
