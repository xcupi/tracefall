package regf

// Replay of a registry transaction log, in memory.
//
// A hive that was not cleanly written has two different sequence numbers in its
// base block (offsets 4 and 8). The changes it is missing are in the transaction
// logs (HIVE.LOG1, HIVE.LOG2) beside it. Here those changes are laid over the
// primary file's bytes in memory and the hive is read through that overlay. No
// file is ever written, which is the rule for evidence, and the overlay is the
// only place the recovered state exists.
//
// Only the log format of Windows 8.1 and later is replayed (file type 6,
// entries signed "HvLE"). The older format (file types 1 and 2, with a dirty
// vector) is reported as not replayed rather than guessed at.
//
// The rules follow the reference implementation (yarp, by Maxim Suhanov) and are
// checked against a hive that Windows itself recovered (see the real-evidence
// test), with one deliberate addition: a log that does not connect to the
// primary file is not applied (see chooseChain).
//
// A log entry is applied only if every check passes: the signature, a size that
// is a multiple of 512 and lies inside the file, a hive-bins size that is a
// multiple of 4096, a sane page count, both Marvin32 hashes, the expected
// sequence number, and page references that lie wholly inside the entry and
// inside the hive bins. Entries are read in order from the first and the first
// failure ends the chain: what follows is stale remnant of an earlier use of the
// file, which the format leaves behind and which is normal.

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// RecoveryState says what became of a hive that was not cleanly written and of
// the transaction logs found beside it.
type RecoveryState string

const (
	// RecoveryClean: the hive was written completely; logs are not consulted.
	RecoveryClean RecoveryState = "clean"
	// RecoveryReplayed: every transaction the primary file had begun is covered
	// by the log, and the hive is read in the state the log describes.
	RecoveryReplayed RecoveryState = "replayed"
	// RecoveryReplayedPartial: logged changes were applied, but the log ends
	// before the transaction the primary file had begun. Changes of that
	// transaction, if any reached the primary file, are not covered.
	RecoveryReplayedPartial RecoveryState = "replayed_partial"
	// RecoveryNotRecoverable: the hive is dirty and the logs cannot be applied
	// safely. The hive is read as the primary file is, and what it is missing is
	// not recoverable from these files.
	RecoveryNotRecoverable RecoveryState = "not_recoverable"
	// RecoveryNoLogs: the hive is dirty and no log was given.
	RecoveryNoLogs RecoveryState = "no_logs"
)

// Recovery is the account of a replay, for the analyst and the report.
type Recovery struct {
	State RecoveryState
	// PrimarySeq1 and PrimarySeq2 are the primary file's two sequence numbers.
	// Seq2 is the last transaction it finished; Seq1 is the last it began.
	PrimarySeq1, PrimarySeq2 uint32
	// LogsApplied lists the base names of the logs used, in order.
	LogsApplied       []string
	FirstSeq, LastSeq uint32
	Entries, Pages    int
	// Reason explains any state other than clean and replayed.
	Reason string
}

const (
	logBaseBlockSize = 512
	logEntryHeader   = 40
	// logEntrySeed is the Marvin32 seed that signs log entries.
	logEntrySeed uint64 = 0x82EF4D887A4E55C5

	maxLogFileBytes   = 256 << 20
	maxLogEntryBytes  = 128 << 20
	maxOverlayBytes   = 512 << 20
	maxDirtyPageCount = 1 << 20
	fileTypeLogNew    = 6
)

// marvin32 is the Marvin32 hash as the registry uses it for log entries. Log
// entries are always a multiple of four bytes long, so the tail handling is the
// published algorithm's and is not exercised by any valid entry.
func marvin32(b []byte, seed uint64) uint64 {
	lo, hi := uint32(seed), uint32(seed>>32)
	mix := func(v uint32) {
		lo += v
		hi ^= lo
		lo = bits.RotateLeft32(lo, 20) + hi
		hi = bits.RotateLeft32(hi, 9) ^ lo
		lo = bits.RotateLeft32(lo, 27) + hi
		hi = bits.RotateLeft32(hi, 19)
	}
	for len(b) >= 4 {
		mix(binary.LittleEndian.Uint32(b))
		b = b[4:]
	}
	final := uint32(0x80)
	for i := len(b) - 1; i >= 0; i-- {
		final = final<<8 | uint32(b[i])
	}
	mix(final)
	mix(0)
	return uint64(hi)<<32 | uint64(lo)
}

// Recovery returns what was done to make this hive readable.
func (h *Hive) Recovery() Recovery { return h.recovery }

// logEntry is one validated entry. data is the whole entry.
type logEntry struct {
	seq   uint32
	hbins uint32
	data  []byte
	pages []pageRef
}

type pageRef struct {
	off, size uint32
	at        int // offset of the page data inside the entry
}

type parsedLog struct {
	name        string
	start       uint32
	root, minor uint32
	stamp       time.Time
	entries     []logEntry
}

// seqBefore reports whether a precedes b, treating the 32-bit counter as
// wrapping.
func seqBefore(a, b uint32) bool { return int32(a-b) < 0 }

// OpenWithLogs opens a hive and, when it is dirty, replays the transaction logs
// given (typically HIVE.LOG1 and HIVE.LOG2) in memory. The returned Recovery
// says exactly what was and was not done. A hive that is clean is opened as
// Open does and its logs are ignored.
//
// An error is returned only when the hive itself cannot be opened. Logs that
// cannot be used never cause an error: the hive is read as the primary file is
// and the Recovery says why.
func OpenWithLogs(path string, logPaths []string, lim Limits) (*Hive, Recovery, error) {
	h, err := Open(path, lim)
	if err != nil {
		return nil, Recovery{}, err
	}
	rec := Recovery{PrimarySeq1: h.seq1, PrimarySeq2: h.seq2}
	if h.seq1 == h.seq2 {
		rec.State = RecoveryClean
		h.recovery = rec
		return h, rec, nil
	}
	if !h.baseChecksum {
		rec.State, rec.Reason = RecoveryNotRecoverable, "the primary file's base block checksum is wrong, so its sequence numbers cannot be trusted and no log was applied"
		h.recovery = rec
		return h, rec, nil
	}
	if len(logPaths) == 0 {
		rec.State = RecoveryNoLogs
		rec.Reason = fmt.Sprintf("the hive was not cleanly written (sequence %d begun, %d finished) and no transaction log was found beside it", h.seq1, h.seq2)
		h.recovery = rec
		return h, rec, nil
	}

	var logs []*parsedLog
	var notes []string
	for _, p := range logPaths {
		lf, note := readLog(p)
		if note != "" {
			notes = append(notes, note)
		}
		if lf != nil && len(lf.entries) > 0 {
			logs = append(logs, lf)
		}
	}
	chain, why := chooseChain(logs, h.seq1, h.seq2)
	if len(chain) == 0 {
		rec.State = RecoveryNotRecoverable
		rec.Reason = why
		for _, n := range notes {
			rec.Reason += "; " + n
		}
		h.recovery = rec
		return h, rec, nil
	}

	ov := &overlay{base: h.r, baseSize: h.size, sectors: map[int64][]byte{}}
	var last *parsedLog
	for _, lf := range chain {
		for _, e := range lf.entries {
			if ov.bytes += int64(len(e.data)); ov.bytes > maxOverlayBytes {
				rec.State, rec.Reason = RecoveryNotRecoverable, "the log entries exceed the replay size limit"
				h.recovery = rec
				return h, rec, nil
			}
			for _, pg := range e.pages {
				ov.put(int64(hiveBinsOffset)+int64(pg.off), e.data[pg.at:pg.at+int(pg.size)])
				rec.Pages++
			}
			rec.Entries++
			rec.LastSeq = e.seq
			h.binsDataSize = e.hbins
		}
		last = lf
		rec.LogsApplied = append(rec.LogsApplied, lf.name)
	}
	rec.FirstSeq = chain[0].entries[0].seq
	ov.size = int64(hiveBinsOffset) + int64(h.binsDataSize)
	h.r = ov
	h.size = ov.size
	h.rootOffset, h.minorVersion = last.root, last.minor
	if !last.stamp.IsZero() {
		h.lastModified = last.stamp
	}
	if seqBefore(rec.LastSeq, h.seq1) {
		rec.State = RecoveryReplayedPartial
		rec.Reason = fmt.Sprintf("the log ends at sequence %d but the primary file had begun sequence %d; changes of that transaction, if any reached the primary file, are not covered", rec.LastSeq, h.seq1)
	} else {
		rec.State = RecoveryReplayed
	}
	h.recovery = rec
	return h, rec, nil
}

// chooseChain picks the logs to apply, in order, and says why if none.
//
// The first log must start at or after the last transaction the primary file
// finished (older content is a previous use of the file), and at or before the
// one it began. A log that starts later leaves transactions between the two that
// are in no file given: applying it anyway would write the newer changes onto a
// hive missing the older ones, a state that never existed. That case is refused.
// A second log continues the chain only when it starts at the sequence right
// after the first one's last entry.
func chooseChain(logs []*parsedLog, seq1, seq2 uint32) ([]*parsedLog, string) {
	if len(logs) == 0 {
		return nil, fmt.Sprintf("the hive was not cleanly written (sequence %d begun, %d finished) and none of the transaction logs holds a valid entry", seq1, seq2)
	}
	sort.SliceStable(logs, func(i, j int) bool { return seqBefore(logs[i].start, logs[j].start) })
	var first, gap *parsedLog
	for _, lf := range logs {
		if seqBefore(lf.start, seq2) {
			continue // older than what the primary file already finished
		}
		if seqBefore(seq1, lf.start) {
			if gap == nil {
				gap = lf
			}
			continue
		}
		first = lf
		break
	}
	if first == nil {
		if gap != nil {
			return nil, fmt.Sprintf("the primary file finished sequence %d and had begun %d, but the earliest usable log (%s) starts at %d: transactions %d to %d are in no log given, so nothing was applied and the registry changes of that period are missing",
				seq2, seq1, gap.name, gap.start, seq2+1, gap.start-1)
		}
		return nil, fmt.Sprintf("every transaction log ends before sequence %d, which the primary file finished: the logs hold nothing newer than the primary file", seq2)
	}
	chain := []*parsedLog{first}
	end := first.entries[len(first.entries)-1].seq
	for _, lf := range logs {
		if lf != first && lf.start == end+1 {
			chain = append(chain, lf)
			break
		}
	}
	return chain, ""
}

// readLog reads and validates the entries of one log. It returns nil and a note
// when the file is not a usable new-format log.
func readLog(path string) (*parsedLog, string) {
	name := filepath.Base(path)
	f, err := os.Open(path)
	if err != nil {
		return nil, name + ": could not be opened"
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, name + ": could not be read"
	}
	if st.Size() > maxLogFileBytes {
		return nil, name + ": larger than the replay limit"
	}
	if st.Size() < logBaseBlockSize {
		return nil, ""
	}
	base := make([]byte, logBaseBlockSize)
	if _, err := f.ReadAt(base, 0); err != nil {
		return nil, name + ": could not be read"
	}
	if string(base[:4]) != regfSignature {
		return nil, name + ": is not a registry log"
	}
	switch ft := binary.LittleEndian.Uint32(base[28:32]); ft {
	case fileTypeLogNew:
	case 1, 2:
		return nil, fmt.Sprintf("%s is a transaction log of the older format (file type %d, dirty vector), which Tracefall does not replay", name, ft)
	default:
		return nil, fmt.Sprintf("%s has file type %d, not a transaction log", name, ft)
	}
	if !baseChecksumOK(base) {
		return nil, name + ": base block checksum is wrong"
	}
	if binary.LittleEndian.Uint32(base[4:8]) != binary.LittleEndian.Uint32(base[8:12]) {
		return nil, name + ": was itself not cleanly written"
	}
	lf := &parsedLog{
		name:  name,
		start: binary.LittleEndian.Uint32(base[4:8]),
		root:  binary.LittleEndian.Uint32(base[36:40]),
		minor: binary.LittleEndian.Uint32(base[24:28]),
		stamp: fileTime(binary.LittleEndian.Uint64(base[12:20])),
	}
	pos, want := int64(logBaseBlockSize), lf.start
	for pos+logEntryHeader <= st.Size() {
		e, ok := readEntry(f, pos, st.Size(), want)
		if !ok {
			break
		}
		lf.entries = append(lf.entries, e)
		pos += int64(len(e.data))
		want++
	}
	return lf, ""
}

// readEntry reads and fully validates the entry at pos, which must carry the
// sequence number want.
func readEntry(r io.ReaderAt, pos, fileSize int64, want uint32) (logEntry, bool) {
	var h [logEntryHeader]byte
	if _, err := r.ReadAt(h[:], pos); err != nil || string(h[:4]) != "HvLE" {
		return logEntry{}, false
	}
	size := binary.LittleEndian.Uint32(h[4:8])
	seq := binary.LittleEndian.Uint32(h[12:16])
	hbins := binary.LittleEndian.Uint32(h[16:20])
	count := binary.LittleEndian.Uint32(h[20:24])
	if seq != want || size < 512 || size%512 != 0 || size > maxLogEntryBytes || pos+int64(size) > fileSize {
		return logEntry{}, false
	}
	if hbins < 4096 || hbins%4096 != 0 {
		return logEntry{}, false
	}
	if count == 0 || count > maxDirtyPageCount || uint64(count)*8 > uint64(size)-logEntryHeader {
		return logEntry{}, false
	}
	data := make([]byte, size)
	if _, err := r.ReadAt(data, pos); err != nil {
		return logEntry{}, false
	}
	if marvin32(data[0:32], logEntrySeed) != binary.LittleEndian.Uint64(data[32:40]) ||
		marvin32(data[logEntryHeader:], logEntrySeed) != binary.LittleEndian.Uint64(data[24:32]) {
		return logEntry{}, false
	}
	e := logEntry{seq: seq, hbins: hbins, data: data}
	at := logEntryHeader + int(count)*8
	for i := 0; i < int(count); i++ {
		off := binary.LittleEndian.Uint32(data[logEntryHeader+i*8:])
		sz := binary.LittleEndian.Uint32(data[logEntryHeader+i*8+4:])
		if sz == 0 || sz%512 != 0 || off%512 != 0 ||
			uint64(off)+uint64(sz) > uint64(hbins) ||
			uint64(at)+uint64(sz) > uint64(size) {
			return logEntry{}, false
		}
		e.pages = append(e.pages, pageRef{off: off, size: sz, at: at})
		at += int(sz)
	}
	return e, true
}

// overlay presents the primary file with log pages laid over it, 512 bytes at a
// time. The first 4096 bytes (the base block) always come from the primary file.
type overlay struct {
	base     io.ReaderAt
	baseSize int64
	size     int64
	sectors  map[int64][]byte
	bytes    int64
}

func (o *overlay) put(off int64, data []byte) {
	for i := 0; i+512 <= len(data); i += 512 {
		o.sectors[(off+int64(i))/512] = data[i : i+512]
	}
}

// ReadAt serves a range from the overlay where a log page covers it and from
// the primary file where one does not. A range that is in neither (a hive that
// grew, with no log page for the new part) is an error, never zeros.
func (o *overlay) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("regf: negative offset")
	}
	if off >= o.size {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && off < o.size {
		sec := off / 512
		in := int(off % 512)
		chunk := 512 - in
		if chunk > len(p)-n {
			chunk = len(p) - n
		}
		if off+int64(chunk) > o.size {
			chunk = int(o.size - off)
		}
		if s, ok := o.sectors[sec]; ok && off >= hiveBinsOffset {
			copy(p[n:n+chunk], s[in:in+chunk])
		} else if off+int64(chunk) <= o.baseSize {
			if _, err := o.base.ReadAt(p[n:n+chunk], off); err != nil {
				return n, err
			}
		} else {
			return n, fmt.Errorf("regf: offset %d is in neither the primary file nor a log page", off)
		}
		n += chunk
		off += int64(chunk)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
