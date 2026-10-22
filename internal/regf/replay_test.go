package regf

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"tracefall/internal/regf/regfgen"
)

// ---------- builders (from the documented layout, not from the reader) ----------

func put32(b []byte, o int, v uint32) { binary.LittleEndian.PutUint32(b[o:o+4], v) }

func fixChecksum(base []byte) {
	var x uint32
	for i := 0; i < 508; i += 4 {
		x ^= binary.LittleEndian.Uint32(base[i : i+4])
	}
	put32(base, 508, x)
}

func withSequences(hive []byte, s1, s2 uint32) []byte {
	out := append([]byte(nil), hive...)
	put32(out, 4, s1)
	put32(out, 8, s2)
	fixChecksum(out[:512])
	return out
}

type page struct {
	off  uint32 // relative to the start of the hive bins data
	data []byte
}

// entry builds one HvLE log entry: header, page references, page data, padded to
// 512 bytes, with both hashes.
func entry(seq, hbins uint32, pages []page) []byte {
	n := len(pages)
	body := 40 + 8*n
	for _, p := range pages {
		body += len(p.data)
	}
	size := (body + 511) &^ 511
	e := make([]byte, size)
	copy(e[0:4], "HvLE")
	put32(e, 4, uint32(size))
	put32(e, 8, 1)
	put32(e, 12, seq)
	put32(e, 16, hbins)
	put32(e, 20, uint32(n))
	pos := 40
	for _, p := range pages {
		put32(e, pos, p.off)
		put32(e, pos+4, uint32(len(p.data)))
		pos += 8
	}
	for _, p := range pages {
		copy(e[pos:], p.data)
		pos += len(p.data)
	}
	// Hash 1 covers everything after the header. Hash 2 covers the first 32
	// bytes, which include hash 1, so hash 1 must be stored first.
	binary.LittleEndian.PutUint64(e[24:32], marvin32(e[40:], logEntrySeed))
	binary.LittleEndian.PutUint64(e[32:40], marvin32(e[0:32], logEntrySeed))
	return e
}

// logFile builds a transaction log of the new format: a 512-byte base block
// whose primary sequence is the sequence of the first entry, then the entries.
func logFile(start, root, minor uint32, entries ...[]byte) []byte {
	b := make([]byte, 512)
	copy(b[0:4], "regf")
	put32(b, 4, start)
	put32(b, 8, start)
	put32(b, 20, 1)
	put32(b, 24, minor)
	put32(b, 28, 6)
	put32(b, 36, root)
	put32(b, 44, 1)
	fixChecksum(b)
	for _, e := range entries {
		b = append(b, e...)
	}
	return b
}

// diffPages returns the 4096-byte pages of newBins that differ from oldBins (or
// lie beyond it).
func diffPages(oldBins, newBins []byte) []page {
	var out []page
	for off := 0; off < len(newBins); off += 4096 {
		np := newBins[off : off+4096]
		if off+4096 <= len(oldBins) && string(oldBins[off:off+4096]) == string(np) {
			continue
		}
		out = append(out, page{uint32(off), append([]byte(nil), np...)})
	}
	return out
}

func bigTree(extra bool) *regfgen.Key {
	root := regfgen.NewKey("ROOT", regfgen.NewKey("Software", regfgen.NewKey("Vendor").WithValues(regfgen.StringValue("a", "one"))))
	if extra {
		blob := func(n int, fill byte) []byte {
			b := make([]byte, n)
			for i := range b {
				b[i] = fill
			}
			return b
		}
		root.Subkeys = append(root.Subkeys,
			regfgen.NewKey("Persist",
				regfgen.NewKey("Run").WithValues(
					regfgen.BinaryValue("b1", blob(5000, 'x')),
					regfgen.BinaryValue("b2", blob(5000, 'y')),
					regfgen.BinaryValue("b3", blob(5000, 'z')),
					regfgen.StringValue("cmd", `C:\Users\Public\x.exe`))))
	}
	return root
}

func binsOf(hive []byte) []byte { return hive[4096:] }

// world is a dirty primary and the state a log would bring it to.
type world struct {
	old, truth []byte
	pages      []page
	root       uint32
	hbins      uint32
}

func newWorld(t *testing.T) world {
	t.Helper()
	old := regfgen.Build("W", bigTree(false))
	truth := regfgen.Build("W", bigTree(true))
	w := world{old: old, truth: truth, pages: diffPages(binsOf(old), binsOf(truth)),
		root: binary.LittleEndian.Uint32(truth[36:40]), hbins: uint32(len(binsOf(truth)))}
	if len(w.pages) < 3 {
		t.Fatalf("the fixture must differ in at least 3 pages, got %d", len(w.pages))
	}
	return w
}

func writeFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// dump flattens a hive into path -> values so two hives can be compared.
func dump(t *testing.T, h *Hive) map[string]string {
	t.Helper()
	out := map[string]string{}
	_, err := h.Walk(func(k Key) error {
		var vs []string
		for _, v := range k.Values {
			vs = append(vs, v.Name+"="+string(v.Data))
		}
		sort.Strings(vs)
		out[k.Path] = strings.Join(vs, "|")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func dumpBytes(t *testing.T, b []byte) map[string]string {
	t.Helper()
	p := writeFile(t, t.TempDir(), "truth", b)
	h, err := Open(p, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	return dump(t, h)
}

func binsBytes(t *testing.T, h *Hive) []byte {
	t.Helper()
	b := make([]byte, h.binsDataSize)
	if _, err := h.r.ReadAt(b, hiveBinsOffset); err != nil {
		t.Fatal(err)
	}
	return b
}

// ---------- tests ----------

func TestMarvin32_MatchesTheReferenceImplementation(t *testing.T) {
	// Values produced by an independent implementation (yarp, Python) for the
	// bytes (i*7+3) mod 256, with the seed used by log entries.
	for n, want := range map[int]uint64{
		4: 0x223de12383fb1dcf, 8: 0x74d607a167e1fc, 32: 0x68c0034aa8cbef0,
		472: 0xcd5cdb8ee0d3028f, 4096: 0x20346ff1e9da22bd,
	} {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte((i*7 + 3) % 256)
		}
		if got := marvin32(b, logEntrySeed); got != want {
			t.Errorf("marvin32(%d bytes) = %#x, want %#x", n, got, want)
		}
	}
}

func TestOpenWithLogs_CleanHiveIgnoresItsLogs(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	p := writeFile(t, dir, "H", w.old) // sequences equal
	l := writeFile(t, dir, "H.LOG1", logFile(1, w.root, 5, entry(1, w.hbins, w.pages)))
	h, rec, err := OpenWithLogs(p, []string{l}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if rec.State != RecoveryClean || rec.Entries != 0 {
		t.Fatalf("%+v", rec)
	}
	if !reflect.DeepEqual(dump(t, h), dumpBytes(t, w.old)) {
		t.Fatal("a clean hive must read exactly as written")
	}
}

func TestOpenWithLogs_OneLogBringsTheHiveToTheNewerState(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	p := writeFile(t, dir, "H", withSequences(w.old, 3, 2))
	half := len(w.pages) / 2
	l := writeFile(t, dir, "H.LOG1", logFile(2, w.root, 5,
		entry(2, w.hbins, w.pages[:half]), entry(3, w.hbins, w.pages[half:])))
	h, rec, err := OpenWithLogs(p, []string{l}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if rec.State != RecoveryReplayed || rec.Entries != 2 || rec.FirstSeq != 2 || rec.LastSeq != 3 || rec.Pages != len(w.pages) {
		t.Fatalf("%+v", rec)
	}
	if !reflect.DeepEqual(dump(t, h), dumpBytes(t, w.truth)) {
		t.Fatal("the replayed hive differs from the state the log describes")
	}
	if rec.PrimarySeq1 != 3 || rec.PrimarySeq2 != 2 || !reflect.DeepEqual(rec.LogsApplied, []string{"H.LOG1"}) {
		t.Errorf("%+v", rec)
	}
}

func TestOpenWithLogs_ChainContinuesIntoTheSecondLogInEitherOrder(t *testing.T) {
	w := newWorld(t)
	half := len(w.pages) / 2
	for _, reversed := range []bool{false, true} {
		dir := t.TempDir()
		p := writeFile(t, dir, "H", withSequences(w.old, 3, 2))
		l1 := writeFile(t, dir, "H.LOG1", logFile(2, w.root, 5, entry(2, w.hbins, w.pages[:half])))
		l2 := writeFile(t, dir, "H.LOG2", logFile(3, w.root, 5, entry(3, w.hbins, w.pages[half:])))
		logs := []string{l1, l2}
		if reversed {
			logs = []string{l2, l1}
		}
		h, rec, err := OpenWithLogs(p, logs, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if rec.State != RecoveryReplayed || rec.Entries != 2 || !reflect.DeepEqual(rec.LogsApplied, []string{"H.LOG1", "H.LOG2"}) {
			t.Fatalf("reversed=%v %+v", reversed, rec)
		}
		if !reflect.DeepEqual(dump(t, h), dumpBytes(t, w.truth)) {
			t.Fatalf("reversed=%v: state differs", reversed)
		}
		h.Close()
	}
}

func TestOpenWithLogs_ALogOlderThanThePrimaryIsSkipped(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	p := writeFile(t, dir, "H", withSequences(w.old, 4, 3))
	stale := []page{{0, make([]byte, 4096)}} // would wreck the hive if applied
	l1 := writeFile(t, dir, "H.LOG1", logFile(2, w.root, 5, entry(2, w.hbins, stale)))
	l2 := writeFile(t, dir, "H.LOG2", logFile(3, w.root, 5, entry(3, w.hbins, w.pages[:2]), entry(4, w.hbins, w.pages[2:])))
	h, rec, err := OpenWithLogs(p, []string{l1, l2}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if rec.State != RecoveryReplayed || !reflect.DeepEqual(rec.LogsApplied, []string{"H.LOG2"}) || rec.LastSeq != 4 {
		t.Fatalf("%+v", rec)
	}
	if !reflect.DeepEqual(dump(t, h), dumpBytes(t, w.truth)) {
		t.Fatal("state differs")
	}
}

func TestOpenWithLogs_AGapBetweenThePrimaryAndTheLogIsNotGuessedAcross(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	p := writeFile(t, dir, "H", withSequences(w.old, 3, 2))
	l := writeFile(t, dir, "H.LOG1", logFile(10, w.root, 5, entry(10, w.hbins, w.pages)))
	h, rec, err := OpenWithLogs(p, []string{l}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if rec.State != RecoveryNotRecoverable || rec.Entries != 0 {
		t.Fatalf("%+v", rec)
	}
	for _, want := range []string{"10", "2", "3"} {
		if !strings.Contains(rec.Reason, want) {
			t.Errorf("reason %q should name sequence %s", rec.Reason, want)
		}
	}
	if !reflect.DeepEqual(dump(t, h), dumpBytes(t, w.old)) {
		t.Fatal("with a gap nothing may be applied: the hive must read as the primary file")
	}
}

func TestOpenWithLogs_ATornEntryEndsTheChainAndIsReportedPartial(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	p := writeFile(t, dir, "H", withSequences(w.old, 3, 2))
	half := len(w.pages) / 2
	e2 := entry(2, w.hbins, w.pages[:half])
	e3 := entry(3, w.hbins, w.pages[half:])
	e3[len(e3)-100] ^= 0xFF // damaged inside the data covered by hash 1
	if len(w.pages[half:]) > 0 && marvin32(e3[40:], logEntrySeed) == binary.LittleEndian.Uint64(e3[24:32]) {
		t.Fatal("the fixture did not actually damage the entry")
	}
	l := writeFile(t, dir, "H.LOG1", logFile(2, w.root, 5, e2, e3))
	h, rec, err := OpenWithLogs(p, []string{l}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if rec.State != RecoveryReplayedPartial || rec.Entries != 1 || rec.LastSeq != 2 {
		t.Fatalf("%+v", rec)
	}
	if !strings.Contains(rec.Reason, "3") {
		t.Errorf("reason should name the sequence the primary began: %q", rec.Reason)
	}
	// The intact entry's pages are applied exactly.
	got := make([]byte, half*4096)
	if _, err := h.r.ReadAt(got, hiveBinsOffset); err != nil {
		t.Fatal(err)
	}
	for _, pg := range w.pages[:half] {
		if string(got[pg.off:int(pg.off)+len(pg.data)]) != string(pg.data) {
			t.Fatalf("page at %d of the intact entry was not applied", pg.off)
		}
	}
	// The torn entry's pages are not applied, and the part of the hive that
	// only they described is unreadable: an error, never zeros.
	last := w.pages[len(w.pages)-1]
	if int(last.off) >= len(binsOf(w.old)) {
		buf := make([]byte, 16)
		if _, err := h.r.ReadAt(buf, int64(hiveBinsOffset)+int64(last.off)); err == nil {
			t.Fatal("a region described only by the torn entry was readable")
		}
	}
}

func TestOpenWithLogs_ALogThatEndsBeforeThePrimaryBeganItsTransactionIsPartial(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	p := writeFile(t, dir, "H", withSequences(w.old, 3, 2))
	l := writeFile(t, dir, "H.LOG1", logFile(2, w.root, 5, entry(2, w.hbins, w.pages)))
	h, rec, err := OpenWithLogs(p, []string{l}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if rec.State != RecoveryReplayedPartial || rec.LastSeq != 2 {
		t.Fatalf("%+v", rec)
	}
}

func TestOpenWithLogs_ASecondLogThatDoesNotContinueTheChainIsNotApplied(t *testing.T) {
	w := newWorld(t)
	half := len(w.pages) / 2
	dir := t.TempDir()
	p := writeFile(t, dir, "H", withSequences(w.old, 3, 2))
	l1 := writeFile(t, dir, "H.LOG1", logFile(2, w.root, 5, entry(2, w.hbins, w.pages[:half])))
	// Starts at 7, not 3: transactions 3 to 6 are in no file, so these pages
	// describe a state the first log's does not lead to.
	l2 := writeFile(t, dir, "H.LOG2", logFile(7, w.root, 5, entry(7, w.hbins, w.pages[half:])))
	h, rec, err := OpenWithLogs(p, []string{l1, l2}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if !reflect.DeepEqual(rec.LogsApplied, []string{"H.LOG1"}) || rec.LastSeq != 2 || rec.State != RecoveryReplayedPartial {
		t.Fatalf("%+v", rec)
	}
}

func TestOpenWithLogs_ASequenceThatSkipsEndsTheChain(t *testing.T) {
	w := newWorld(t)
	half := len(w.pages) / 2
	dir := t.TempDir()
	p := writeFile(t, dir, "H", withSequences(w.old, 3, 2))
	// 2 then 4: an entry with sequence 3 is missing, so 4 is not applied.
	l := writeFile(t, dir, "H.LOG1", logFile(2, w.root, 5, entry(2, w.hbins, w.pages[:half]), entry(4, w.hbins, w.pages[half:])))
	h, rec, err := OpenWithLogs(p, []string{l}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if rec.Entries != 1 || rec.LastSeq != 2 || rec.State != RecoveryReplayedPartial {
		t.Fatalf("%+v", rec)
	}
}

func TestOpenWithLogs_DirtyHiveWithoutLogsSaysSo(t *testing.T) {
	w := newWorld(t)
	p := writeFile(t, t.TempDir(), "H", withSequences(w.old, 3, 2))
	h, rec, err := OpenWithLogs(p, nil, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if rec.State != RecoveryNoLogs || rec.PrimarySeq1 != 3 || rec.PrimarySeq2 != 2 {
		t.Fatalf("%+v", rec)
	}
}

func TestOpenWithLogs_OldFormatLogIsNamedNotReplayed(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	p := writeFile(t, dir, "H", withSequences(w.old, 3, 2))
	old := logFile(2, w.root, 5, entry(2, w.hbins, w.pages))
	put32(old, 28, 1) // file type 1: the pre-Windows-8.1 log with a dirty vector
	fixChecksum(old[:512])
	l := writeFile(t, dir, "H.LOG1", old)
	h, rec, err := OpenWithLogs(p, []string{l}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if rec.State != RecoveryNotRecoverable || !strings.Contains(strings.ToLower(rec.Reason), "old") {
		t.Fatalf("%+v", rec)
	}
	if !reflect.DeepEqual(dump(t, h), dumpBytes(t, w.old)) {
		t.Fatal("an unsupported log must not change what is read")
	}
}

func TestOpenWithLogs_NeverWritesTheEvidence(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	p := writeFile(t, dir, "H", withSequences(w.old, 3, 2))
	l := writeFile(t, dir, "H.LOG1", logFile(2, w.root, 5, entry(2, w.hbins, w.pages[:2]), entry(3, w.hbins, w.pages[2:])))
	sum := func(path string) [32]byte { b, _ := os.ReadFile(path); return sha256.Sum256(b) }
	a, b := sum(p), sum(l)
	h, _, err := OpenWithLogs(p, []string{l}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	dump(t, h)
	h.Close()
	if sum(p) != a || sum(l) != b {
		t.Fatal("an input file changed")
	}
}

func TestOpenWithLogs_HostileEntriesNeverPanicAndNeverApply(t *testing.T) {
	w := newWorld(t)
	good := w.pages[:1]
	cases := map[string]func(e []byte){
		"page offset beyond the hive bins": func(e []byte) { put32(e, 40, w.hbins+4096) },
		"page offset overflows":            func(e []byte) { put32(e, 40, 0xFFFFFFF0) },
		"page size zero":                   func(e []byte) { put32(e, 44, 0) },
		"page size larger than the entry":  func(e []byte) { put32(e, 44, 0x7FFFFFF0) },
		"dirty page count huge":            func(e []byte) { put32(e, 20, 0xFFFFFFFF) },
		"dirty page count zero":            func(e []byte) { put32(e, 20, 0) },
		"entry size not a multiple of 512": func(e []byte) { put32(e, 4, 700) },
		"entry size larger than the file":  func(e []byte) { put32(e, 4, 0x10000000) },
		"hive bins size zero":              func(e []byte) { put32(e, 16, 0) },
		"hive bins size not page aligned":  func(e []byte) { put32(e, 16, 5000) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := writeFile(t, dir, "H", withSequences(w.old, 3, 2))
			e := entry(2, w.hbins, good)
			mutate(e) // hashes are now stale as well; also re-sign so the structural check is what refuses it
			resigned := append([]byte(nil), e...)
			if len(resigned) >= 40 {
				binary.LittleEndian.PutUint64(resigned[24:32], marvin32(resigned[40:], logEntrySeed))
				binary.LittleEndian.PutUint64(resigned[32:40], marvin32(resigned[0:32], logEntrySeed))
			}
			for _, variant := range [][]byte{e, resigned} {
				l := writeFile(t, dir, "H.LOG1", logFile(2, w.root, 5, variant))
				h, rec, err := OpenWithLogs(p, []string{l}, DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				if rec.Entries != 0 || rec.State == RecoveryReplayed {
					t.Fatalf("a malformed entry was applied: %+v", rec)
				}
				if !reflect.DeepEqual(dump(t, h), dumpBytes(t, w.old)) {
					t.Fatal("a malformed entry changed what is read")
				}
				h.Close()
			}
		})
	}
}

func TestOpenWithLogs_RandomCorruptionNeverPanics(t *testing.T) {
	w := newWorld(t)
	half := len(w.pages) / 2
	l1 := logFile(2, w.root, 5, entry(2, w.hbins, w.pages[:half]))
	l2 := logFile(3, w.root, 5, entry(3, w.hbins, w.pages[half:]))
	rng := rand.New(rand.NewSource(20261023))
	applied, refused := 0, 0
	for i := 0; i < 2000; i++ {
		dir := t.TempDir()
		pri := withSequences(w.old, 3, 2)
		a, b := append([]byte(nil), l1...), append([]byte(nil), l2...)
		for n := 0; n < 1+rng.Intn(4); n++ {
			target := []([]byte){pri, a, b}[rng.Intn(3)]
			target[rng.Intn(len(target))] ^= byte(1 + rng.Intn(255))
		}
		p := writeFile(t, dir, "H", pri)
		h, rec, err := OpenWithLogs(p, []string{writeFile(t, dir, "H.LOG1", a), writeFile(t, dir, "H.LOG2", b)}, DefaultLimits())
		if err != nil {
			refused++
			continue
		}
		if rec.Entries > 0 {
			applied++
		}
		h.Walk(func(Key) error { return nil }) // must not panic whatever was replayed
		h.Close()
	}
	if applied == 0 || refused == 0 && applied == 2000 {
		t.Logf("applied=%d refused=%d", applied, refused)
	}
	if applied == 0 {
		t.Fatal("no corrupted input still replayed: the test is not exercising the replay path")
	}
}

// ---------- real evidence ----------

// TRACEFALL_REAL_YARP_HIVES points at the test hives published with yarp
// (hives_for_tests). NewDirtyHive1 ships with RecoveredHive_Windows10: the hive
// Windows itself wrote after recovering the same primary file and logs, which is
// an independent answer for what replay must produce.
func TestOpenWithLogs_RealWindowsRecoveredHive(t *testing.T) {
	dir := os.Getenv("TRACEFALL_REAL_YARP_HIVES")
	if dir == "" {
		t.Skip("TRACEFALL_REAL_YARP_HIVES not set")
	}
	read := func(parts ...string) []byte {
		b, err := os.ReadFile(filepath.Join(append([]string{dir}, parts...)...))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	pin := sha256.Sum256(read("NewDirtyHive1", "NewDirtyHive"))
	if got := hexOf(pin[:]); got != yarpNewDirty1SHA256 {
		t.Fatalf("NewDirtyHive1 is not the pinned file: %s", got)
	}
	t.Run("NewDirtyHive1 equals the hive Windows recovered", func(t *testing.T) {
		base := filepath.Join(dir, "NewDirtyHive1", "NewDirtyHive")
		h, rec, err := OpenWithLogs(base, []string{base + ".LOG2", base + ".LOG1"}, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		if rec.State != RecoveryReplayed || rec.Entries != 4 || len(rec.LogsApplied) != 2 {
			t.Fatalf("%+v", rec)
		}
		recovered := read("NewDirtyHive1", "RecoveredHive_Windows10")
		// Windows keeps the file length and records the effective size of the
		// hive bins data in its base block; what follows is slack.
		effective := binary.LittleEndian.Uint32(recovered[40:44])
		if h.binsDataSize != effective {
			t.Fatalf("hive bins data size %d, Windows recorded %d", h.binsDataSize, effective)
		}
		want := recovered[4096 : 4096+int(effective)]
		got := binsBytes(t, h)
		if sha256.Sum256(got) != sha256.Sum256(want) {
			t.Fatal("the replayed hive bins data differ from the hive Windows recovered")
		}
	})
	t.Run("NewDirtyHive2 applies only the second log", func(t *testing.T) {
		base := filepath.Join(dir, "NewDirtyHive2", "NewDirtyHive")
		h, rec, err := OpenWithLogs(base, []string{base + ".LOG1", base + ".LOG2"}, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		if rec.State != RecoveryReplayed || rec.LastSeq != 5 || !reflect.DeepEqual(rec.LogsApplied, []string{"NewDirtyHive.LOG2"}) {
			t.Fatalf("%+v", rec)
		}
	})
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}

const yarpNewDirty1SHA256 = "1249ab3e9eb0612e83215ab5777d7d57abf6e3eb036917e825c948941b9581f6"

// TRACEFALL_REAL_REGF_DIR points at the Windows\System32\config folder of a
// real Windows 10 collection whose hives were copied while the system ran. The
// expected digests of the recovered hive bins data were produced by yarp, an
// independent implementation, not by this package.
func TestOpenWithLogs_RealLiveCollection(t *testing.T) {
	dir := os.Getenv("TRACEFALL_REAL_REGF_DIR")
	if dir == "" {
		t.Skip("TRACEFALL_REAL_REGF_DIR not set")
	}
	type want struct {
		primarySHA string
		state      RecoveryState
		lastSeq    uint32
		entries    int
		binsSHA    string // from yarp; empty where this package deliberately declines
		reason     []string
	}
	cases := map[string]want{
		"DEFAULT":  {"7088c9c292a99121e5881b07668ff86e7c0465a22809f1c0762c9c7f7d80c385", RecoveryReplayed, 124, 7, "706467cf08b3af83e4de746e5d5751cb9e7c213d006296790eda66d7a7eac7c4", nil},
		"SECURITY": {"9321f6fda2d1d00a4025a039d5c024be840fb21db8144522712e7dff9cd2aff1", RecoveryReplayedPartial, 122, 1, "bfd48d907278aac68932536e76bb9b0b3c6590ecf58f3966a4ccf2597af3845a", []string{"123"}},
		// yarp applies these logs; here they do not connect to the primary
		// file (it finished 586 and 1629; the logs start at 617 and 1738), so
		// nothing is applied.
		"SYSTEM":   {"62eac8667a6dcf0b793e0e8ac0460902d377d30b28cf28608ad2a9a41ba7987f", RecoveryNotRecoverable, 0, 0, "", []string{"617", "587"}},
		"SOFTWARE": {"5999fc6513f0c18438fd55febeb25674ad993cca14771098cffd5ee1da9d15db", RecoveryNotRecoverable, 0, 0, "", []string{"1738", "1630"}},
	}
	for name, w := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name)
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if sum := sha256.Sum256(b); hexOf(sum[:]) != w.primarySHA {
				t.Fatalf("%s is not the pinned file", name)
			}
			h, rec, err := OpenWithLogs(p, []string{p + ".LOG1", p + ".LOG2"}, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			if rec.State != w.state || rec.LastSeq != w.lastSeq || rec.Entries != w.entries {
				t.Fatalf("%+v", rec)
			}
			for _, s := range w.reason {
				if !strings.Contains(rec.Reason, s) {
					t.Errorf("reason %q should mention %s", rec.Reason, s)
				}
			}
			if w.binsSHA != "" {
				sum := sha256.Sum256(binsBytes(t, h))
				if got := hexOf(sum[:]); got != w.binsSHA {
					t.Fatalf("recovered hive bins data differ from yarp's: %s", got)
				}
			}
			// Whatever the state, the hive must be walkable.
			if _, err := h.Walk(func(Key) error { return nil }); err != nil {
				t.Errorf("walk: %v", err)
			}
		})
	}
}
