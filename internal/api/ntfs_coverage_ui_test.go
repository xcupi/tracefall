package api

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"tracefall/internal/model"
)

func ntfsFixtures() []*model.ParseCoverage {
	ev, zero := 40, 0
	off, zeroOff := int64(1000), int64(0)
	return []*model.ParseCoverage{
		{EmittedEvents: &ev, RecordsRead: 12, Mapped: 8, Unmapped: 4, Ntfs: &model.NtfsCoverage{Source: model.NtfsSourceMFT, ZeroSlots: 3, FreeMapped: 2, UnmappedNonBase: 1, UnmappedNoName: 2, UnmappedNoTime: 1, AttributeListRecords: 5}},
		{RecordsRead: 10, Mapped: 9, Unmapped: 1, Ntfs: &model.NtfsCoverage{Source: model.NtfsSourceUSN, NonRecordBytes: 4296, FirstNonRecordOffset: &off, UnmappedUndated: 1}},
		{EmittedEvents: &zero, Ntfs: &model.NtfsCoverage{Source: model.NtfsSourceUSN, Failed: true, FailureClass: model.NtfsFailureNotAJournal, FailureOffset: &zeroOff, NonRecordBytes: 100, FirstNonRecordOffset: &zeroOff}},
		{LimitReached: true, Ntfs: &model.NtfsCoverage{Source: model.NtfsSourceMFT, Failed: true, FailureClass: model.NtfsFailureLimit}},
		{EmittedEvents: &zero, RecordsRead: 20, Unmapped: 20, Ntfs: &model.NtfsCoverage{Source: model.NtfsSourceLogFile, LogRecords: 20, LogRecordsRetained: 5}},
		{Ntfs: &model.NtfsCoverage{Source: model.NtfsSourceMFT}},
	}
}

// The browser must say exactly what the server's summary says.
func TestUI_NtfsSummaryParity(t *testing.T) {
	src := appJS(t)
	type fx struct {
		C   *model.ParseCoverage `json:"c"`
		Sum string               `json:"sum"`
	}
	var fixtures []fx
	var rows []model.SourceFile
	for _, c := range ntfsFixtures() {
		if c.NtfsSummary() == "" {
			t.Fatalf("fixture has no summary: %+v", c.Ntfs)
		}
		fixtures = append(fixtures, fx{c, c.NtfsSummary()})
		rows = append(rows, model.SourceFile{ParseCoverage: c, ImportStatus: model.SourceFileImported})
	}
	data, err := json.Marshal(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	js := `const assert=require('node:assert/strict');
function parseCoverageText(` + functionBody(t, src, "function parseCoverageText(") + `
const fixtures=` + string(data) + `;
for (const f of fixtures) { const text=parseCoverageText(f.c); assert.ok(text.includes(f.sum), 'JS lacks the server sentence:\n'+f.sum+'\n--\n'+text); assert.match(text,/^read=\d+ mapped=\d+/); }
assert.equal(parseCoverageText({records_read:5,mapped:5}).includes('records read'), false);
console.log('ntfs summary parity '+fixtures.length);`
	out, err := exec.Command("node", "-e", js).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ntfs summary parity") {
		t.Fatalf("%v\n%s", err, out)
	}
	assertCoverageUI(t, rows)
}

func TestUI_NtfsOldImportReadsNotRecordedNeverComplete(t *testing.T) {
	src := appJS(t)
	js := `const assert=require('node:assert/strict'); const esc=s=>String(s).replaceAll('<','&lt;');
const artifactLabel=s=>s, fmtCount=String, fmtTime=String, fmtBytes=String, collectionLabel=String;
const PRIORITY_LABELS={},EVIDENCE_STATUS_LABELS={},SOURCE_FILE_STATUS_LABELS={},LEGACY_UNAVAILABLE='not recorded';
const evidenceStatusValue=f=>f.import_status,capabilityClassification=()=>'',renderCapabilityBoundary=()=>'',renderProvenanceCollection=()=>'',renderSourceFileRecords=()=>'';
function parseCoverageText(` + functionBody(t, src, "function parseCoverageText(") + `
function evidenceDetails(` + functionBody(t, src, "function evidenceDetails(") + `
const f={artifact_type:'ntfs_usnjrnl',import_status:'imported',parse_coverage:{records_read:5,mapped:5}};
assert.match(evidenceDetails(f),/NTFS coverage detail: not recorded/);
const failed={artifact_type:'ntfs_usnjrnl',import_status:'failed',parse_coverage:null};
assert.match(evidenceDetails(failed),/NTFS coverage detail: not recorded/);
const other={artifact_type:'evtx',import_status:'imported',parse_coverage:{records_read:5,mapped:5}};
assert.doesNotMatch(evidenceDetails(other),/NTFS coverage detail/);
console.log('ntfs old import ok');`
	out, err := exec.Command("node", "-e", js).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ntfs old import ok") {
		t.Fatalf("%v\n%s", err, out)
	}
}
