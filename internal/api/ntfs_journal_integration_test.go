package api

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/ntfs/mftgen"
)

// End-to-end $UsnJrnl and $LogFile support alongside the existing $MFT.

var journalBase = time.Date(2026, 5, 10, 14, 0, 0, 0, time.UTC)

func sampleUsnJournal() []byte {
	return mftgen.BuildUsnJournal(4096, []mftgen.UsnEntry{
		{FileRecord: 64, FileSequence: 2, ParentRecord: 40, ParentSeq: 1, Usn: 0x1000,
			Timestamp: journalBase, Reason: mftgen.ReasonFileCreate, FileAttributes: 0x20, FileName: "notes.txt"},
		{FileRecord: 64, FileSequence: 2, ParentRecord: 40, ParentSeq: 1, Usn: 0x1100,
			Timestamp: journalBase.Add(time.Minute),
			Reason:    mftgen.ReasonDataExtend | mftgen.ReasonClose, FileAttributes: 0x20, FileName: "notes.txt"},
		{FileRecord: 64, FileSequence: 2, ParentRecord: 40, ParentSeq: 1, Usn: 0x1200,
			Timestamp: journalBase.Add(2 * time.Minute), Reason: mftgen.ReasonRenameOldName,
			FileAttributes: 0x20, FileName: "notes.txt"},
		{FileRecord: 64, FileSequence: 2, ParentRecord: 40, ParentSeq: 1, Usn: 0x1300,
			Timestamp: journalBase.Add(2 * time.Minute), Reason: mftgen.ReasonRenameNewName,
			FileAttributes: 0x20, FileName: "notes-final.txt"},
		{FileRecord: 99, FileSequence: 1, ParentRecord: 40, ParentSeq: 1, Usn: 0x1400,
			Timestamp: journalBase.Add(5 * time.Minute), Reason: mftgen.ReasonFileDelete,
			FileAttributes: 0x20, FileName: "removed.tmp"},
	})
}

func sampleLogFileBytes() []byte {
	restart := mftgen.LogRestart{
		MajorVersion: 1, MinorVersion: 1, CurrentLSN: 0x5000, ChkdskLSN: 0x10,
		FileSize: 3 * mftgen.LogPageSize,
		Clients:  []mftgen.LogClientEntry{{Name: "NTFS", OldestLSN: 0x1000, ClientRestartLSN: 0x4F00}},
	}
	return mftgen.BuildLogFile(
		mftgen.BuildRestartPage(restart),
		mftgen.BuildRestartPage(restart),
		mftgen.BuildRecordPage(0x4030, 1, 1, []mftgen.LogRec{
			{ThisLSN: 0x4000, TransactionID: 0x11, RedoOperation: 0x19},
			{ThisLSN: 0x4010, ClientPreviousLSN: 0x4000, TransactionID: 0x11, RedoOperation: 0x02, UndoOperation: 0x03},
			{ThisLSN: 0x4020, ClientPreviousLSN: 0x4010, TransactionID: 0x11, RedoOperation: 0x1A},
		}),
	)
}

// ntfsTriad is a collection holding all three NTFS structures.
func ntfsTriad() map[string][]byte {
	return map[string][]byte{
		"C/$MFT":                sampleMFT(),
		"C/$Extend/$UsnJrnl:$J": sampleUsnJournal(),
		"C/$LogFile":            sampleLogFileBytes(),
	}
}

// All three are classified as supported, each as its own artifact type.
func TestNTFS_AllThreeStructuresAreSupported(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "NTFS triad classification")
	disc := discoverBinaryDir(t, mux, c.ID, ntfsTriad())

	want := map[string]struct {
		artifact string
		label    string
		priority string
	}{
		"C/$MFT":                {model.ArtifactMFT, "NTFS $MFT", "high"},
		"C/$Extend/$UsnJrnl:$J": {model.ArtifactUsnJournal, "NTFS $UsnJrnl change journal", "high"},
		"C/$LogFile":            {model.ArtifactLogFile, "NTFS $LogFile transaction log", "medium"},
	}
	for path, w := range want {
		sf, ok := sourceFileByPath(disc.SourceFiles, path)
		if !ok {
			t.Errorf("%s was not discovered", path)
			continue
		}
		if !sf.Supported {
			t.Errorf("%s is not supported", path)
		}
		if sf.ArtifactType != w.artifact {
			t.Errorf("%s artifact type = %q, want %q", path, sf.ArtifactType, w.artifact)
		}
		if sf.TypeLabel != w.label {
			t.Errorf("%s label = %q, want %q", path, sf.TypeLabel, w.label)
		}
		if sf.Priority != w.priority {
			t.Errorf("%s priority = %q, want %q", path, sf.Priority, w.priority)
		}
		if sf.UnsupportedReason != "" {
			t.Errorf("%s carries an unsupported reason: %q", path, sf.UnsupportedReason)
		}
	}
	// The two high-value artifacts are recommended; $LogFile, which
	// yields no timeline events, deliberately is not.
	mft, _ := sourceFileByPath(disc.SourceFiles, "C/$MFT")
	usn, _ := sourceFileByPath(disc.SourceFiles, "C/$Extend/$UsnJrnl:$J")
	log, _ := sourceFileByPath(disc.SourceFiles, "C/$LogFile")
	if !mft.Recommended || !usn.Recommended {
		t.Error("$MFT and $UsnJrnl should both be recommended")
	}
	if log.Recommended {
		t.Error("$LogFile should not be recommended: it produces no timeline events")
	}
	// None may claim another's file.
	for path, sf := range map[string]TriagedSourceFile{"C/$MFT": mft, "C/$Extend/$UsnJrnl:$J": usn, "C/$LogFile": log} {
		if sf.ArtifactType != want[path].artifact {
			t.Errorf("%s was claimed by the wrong parser: %q", path, sf.ArtifactType)
		}
	}
}

// USN events reach the timeline, in their own category, distinguishable
// from $MFT events for the same file.
func TestNTFS_UsnEventsReachTheTimelineWithDistinctSource(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "USN timeline")
	disc := discoverBinaryDir(t, mux, c.ID, ntfsTriad())
	imp := importAllFrom(t, mux, c.ID, disc)
	if len(imp.ParseFailures) != 0 {
		t.Fatalf("parse failures: %+v", imp.ParseFailures)
	}

	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &events)

	byType := map[string]int{}
	var usnEvents, mftEvents int
	for _, e := range events {
		byType[e.EventType]++
		switch e.ArtifactType {
		case model.ArtifactUsnJournal:
			usnEvents++
			// Every USN event must name its source.
			if !strings.Contains(e.Extra["event_source"], "USN") {
				t.Errorf("USN event does not name its source: %q", e.Extra["event_source"])
			}
			if e.Extra["usn_reason_hex"] == "" {
				t.Error("USN event lost its raw reason mask")
			}
		case model.ArtifactMFT:
			mftEvents++
		case model.ArtifactLogFile:
			t.Error("the $LogFile parser produced a timeline event; it must produce none")
		}
	}
	if usnEvents != 5 {
		t.Errorf("got %d USN events, want 5", usnEvents)
	}
	if mftEvents == 0 {
		t.Error("the $MFT produced no events; its behaviour regressed")
	}
	for _, want := range []string{
		model.EventUsnCreate, model.EventUsnDelete, model.EventUsnModify, model.EventUsnRename,
	} {
		if byType[want] == 0 {
			t.Errorf("no %s events on the timeline", want)
		}
	}

	// The SAME file appears from both sources, and the two are
	// distinguishable rather than deduplicated away.
	var fromMFT, fromUSN bool
	for _, e := range events {
		if !strings.Contains(e.Extra["file_name"], "notepad.exe") && e.Extra["mft_record_number"] != "64" {
			continue
		}
		switch e.ArtifactType {
		case model.ArtifactMFT:
			fromMFT = true
		case model.ArtifactUsnJournal:
			fromUSN = true
		}
	}
	if !fromMFT || !fromUSN {
		t.Errorf("record 64 is not represented from both sources (mft=%v usn=%v)", fromMFT, fromUSN)
	}
}

// $LogFile imports successfully and records metadata without events.
func TestNTFS_LogFileImportsAsMetadataOnly(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "LogFile metadata")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{"C/$LogFile": sampleLogFileBytes()})
	imp := importAllFrom(t, mux, c.ID, disc)

	if len(imp.ParseFailures) != 0 {
		t.Fatalf("a valid $LogFile was reported as a parse failure: %+v", imp.ParseFailures)
	}
	if len(imp.Imported) != 1 {
		t.Fatalf("imported %d files, want 1", len(imp.Imported))
	}
	if imp.EventCount != 0 {
		t.Errorf("the $LogFile produced %d timeline events; it must produce none", imp.EventCount)
	}

	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &events)
	for _, e := range events {
		if e.ArtifactType == model.ArtifactLogFile {
			t.Errorf("a $LogFile event reached the timeline: %s", e.EventType)
		}
	}
}

// Provenance resolves for USN events end to end.
func TestNTFS_UsnEventProvenanceResolves(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "USN provenance")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{"C/$Extend/$UsnJrnl:$J": sampleUsnJournal()})
	importAllFrom(t, mux, c.ID, disc)

	var events []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &events)
	if len(events) == 0 {
		t.Fatal("no events")
	}
	var checked int
	for _, e := range events {
		if e.ArtifactType != model.ArtifactUsnJournal || checked >= 5 {
			continue
		}
		checked++
		var prov EventProvenance
		rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/"+e.ID, nil, &prov)
		if rec.Code != 200 {
			t.Fatalf("provenance for %s returned %d: %s", e.SourceReference, rec.Code, rec.Body.String())
		}
		if prov.RawEvidence.Raw == "" {
			t.Errorf("event %s resolved no raw evidence", e.SourceReference)
		}
		if !strings.Contains(prov.RawEvidence.Raw, "reason_flags") {
			t.Error("raw evidence lost the decoded reason flags")
		}
		if prov.SourceFile.OriginalFilename == "" {
			t.Error("provenance names no source file")
		}
	}
	if checked == 0 {
		t.Fatal("no USN events to check")
	}
}

// Ordinary journal and log records must not manufacture findings.
func TestNTFS_JournalAndLogProduceNoFalseFindings(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "No false findings")
	disc := discoverBinaryDir(t, mux, c.ID, ntfsTriad())
	importAllFrom(t, mux, c.ID, disc)
	doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/analyze", nil, nil)

	var findings []model.Finding
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/findings", nil, &findings)
	for _, f := range findings {
		t.Errorf("ordinary NTFS metadata produced a finding: %q (%s)", f.Title, f.Severity)
	}
}

// Timestamps are stored canonically in UTC.
func TestNTFS_UsnTimestampsAreCanonicalUTC(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "USN timezone")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{"C/$Extend/$UsnJrnl:$J": sampleUsnJournal()})
	importAllFrom(t, mux, c.ID, disc)

	// Changing the display timezone must not alter stored timestamps.
	var before []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &before)
	doJSON(t, mux, "PUT", "/api/settings", map[string]string{"timezone": "Asia/Tokyo"}, nil)
	var after []model.Event
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &after)

	if len(before) != len(after) {
		t.Fatalf("event count changed with the timezone: %d -> %d", len(before), len(after))
	}
	for i := range before {
		if !before[i].Timestamp.Equal(after[i].Timestamp) {
			t.Errorf("event %d timestamp changed with the display timezone", i)
		}
		if _, off := after[i].Timestamp.Zone(); off != 0 {
			t.Errorf("event %d is not stored in UTC", i)
		}
	}
	doJSON(t, mux, "PUT", "/api/settings", map[string]string{"timezone": "UTC"}, nil)
}

// Repeated imports are deterministic, and the $MFT is unaffected by the
// two new parsers existing.
func TestNTFS_DeterministicAndMFTUnchanged(t *testing.T) {
	var counts []int
	var mftCounts []int
	for i := 0; i < 3; i++ {
		mux := newTestRouter(t)
		c := mustCreateCase(t, mux, "NTFS determinism")
		disc := discoverBinaryDir(t, mux, c.ID, ntfsTriad())
		imp := importAllFrom(t, mux, c.ID, disc)
		counts = append(counts, imp.EventCount)

		var events []model.Event
		doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &events)
		var mftOnly int
		for _, e := range events {
			if e.ArtifactType == model.ArtifactMFT {
				mftOnly++
			}
		}
		mftCounts = append(mftCounts, mftOnly)
	}
	for i := 1; i < len(counts); i++ {
		if counts[i] != counts[0] {
			t.Errorf("import %d produced %d events, first produced %d", i, counts[i], counts[0])
		}
		if mftCounts[i] != mftCounts[0] {
			t.Errorf("import %d produced %d $MFT events, first produced %d", i, mftCounts[i], mftCounts[0])
		}
	}

	// The $MFT alone must produce exactly what it did before the journal
	// and log parsers existed.
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "MFT alone")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{"C/$MFT": sampleMFT()})
	alone := importAllFrom(t, mux, c.ID, disc)
	if alone.EventCount != mftCounts[0] {
		t.Errorf("the $MFT produced %d events alongside the journal but %d alone; the parsers interfere",
			mftCounts[0], alone.EventCount)
	}
}

// A file named like one of these that is not one fails cleanly.
func TestNTFS_MisnamedFilesFailCleanly(t *testing.T) {
	for path, want := range map[string]string{
		"C/$Extend/$UsnJrnl:$J": "not an NTFS USN change journal",
		"C/$LogFile":            "not an NTFS $LogFile",
	} {
		mux := newTestRouter(t)
		c := mustCreateCase(t, mux, "Misnamed "+path)
		disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
			path: []byte("this file has a reserved NTFS name but is plainly not one of those structures"),
		})
		imp := importAllFrom(t, mux, c.ID, disc)
		if len(imp.ParseFailures) != 1 {
			t.Errorf("%s: parse failures = %d, want 1", path, len(imp.ParseFailures))
			continue
		}
		f := imp.ParseFailures[0]
		if !strings.Contains(f.Message, want) {
			t.Errorf("%s: message %q does not contain %q", path, f.Message, want)
		}
		if f.PartialEvents {
			t.Errorf("%s: a failed parse claimed partial events", path)
		}
	}
}
