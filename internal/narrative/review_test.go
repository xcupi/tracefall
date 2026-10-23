package narrative

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"tracefall/internal/model"
)

func TestReview_UnflaggedEventsWithoutFindings(t *testing.T) {
	in := ReviewInput{CaseID: "c", Events: []model.Event{{ID: "event-real", CaseID: "c", CollectionID: "acq-real", SourceFileID: "source-real", EventType: "process_creation", Host: "host01", User: "alice"}}, Names: Names{Hosts: []string{"host01"}, Users: []string{"alice"}}}
	p, err := PrepareReview(in)
	if err != nil || p == nil {
		t.Fatalf("zero-findings review unavailable: %v", err)
	}
	if !strings.Contains(p.User, "unflagged_stratum") || !strings.Contains(p.User, "time_basis=unknown") {
		t.Fatalf("missing selection/time disclosure: %s", p.User)
	}
	for _, secret := range []string{"event-real", "acq-real", "source-real", "host01", "alice"} {
		if strings.Contains(p.User, secret) {
			t.Fatalf("leaked %s", secret)
		}
	}
	d, err := p.Validate("An unflagged observation is recorded. [E1]")
	if err != nil || len(d.Sentences) != 1 || d.Sentences[0].Cites[0].ID != "event-real" {
		t.Fatalf("citation: %+v %v", d, err)
	}
}
func TestReview_PacketCoverageContextAndStableSelection(t *testing.T) {
	in := ReviewInput{CaseID: "c", Findings: []model.Finding{{ID: "f", CaseID: "c", Title: "A rule lead", SupportingEvents: []string{"e000", "missing", "foreign"}}}, Correlations: []model.Correlation{{ID: "corr", CaseID: "c", Title: "A link", EventIDs: []string{"e001"}}}, Sources: []model.SourceFile{{ID: "s1", CaseID: "c", CollectionID: "a", ImportStatus: "imported", ParseCoverage: &model.ParseCoverage{RecordsRead: 300, Mapped: 250, Unmapped: 50, Notes: []string{"PRIVATE NOTE"}}}, {ID: "s2", CaseID: "c", CollectionID: "b", ImportStatus: "failed"}}}
	for i := 0; i < 200; i++ {
		a, s := "a", "s1"
		if i%2 == 1 {
			a, s = "b", "s2"
		}
		in.Events = append(in.Events, model.Event{ID: fmt.Sprintf("e%03d", i), CaseID: "c", CollectionID: a, SourceFileID: s, EventType: "process_creation", Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), Extra: map[string]string{"sql_statement": "PRIVATE SQL", "timestamp_basis": "PRIVATE BASIS"}})
	}
	in.Events = append(in.Events, model.Event{ID: "foreign", CaseID: "other"})
	p, err := PrepareReview(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.EventIDs) > 120 || len(p.EventIDs) < 3 {
		t.Fatalf("unbounded/no context: %d", len(p.EventIDs))
	}
	for _, want := range []string{"F1", "C1", "K1", "missing_supporting_refs=2", "events_total=200", "events_omitted=80", "sources_total=2", "parse_coverage=not_recorded", "records_read=300", "unmapped=50", "primary_reference", "unflagged_stratum", "time_basis=recorded_instant", "acquisition=A1", "acquisition=A2"} {
		if !strings.Contains(p.User, want) {
			t.Errorf("missing %q in %s", want, p.User)
		}
	}
	for _, bad := range []string{"PRIVATE", "foreign", "missing", "s1", "s2"} {
		if bad == "missing" {
			continue
		}
		if strings.Contains(p.User, bad) {
			t.Errorf("leaked %s", bad)
		}
	}
	for i, j := 0, len(in.Events)-1; i < j; i, j = i+1, j-1 {
		in.Events[i], in.Events[j] = in.Events[j], in.Events[i]
	}
	q, err := PrepareReview(in)
	if err != nil || p.User != q.User || !reflect.DeepEqual(p.EventIDs, q.EventIDs) {
		t.Fatal("selection changes with ordering", err)
	}
	d, err := p.Validate("A link warrants examiner review. [C1, E1]\nParse coverage is limited. [K1]\nInvented. [C99]")
	if err != nil || len(d.Sentences) != 2 || d.Rejected != 1 || d.Sentences[0].Cites[0].Kind != "correlation" {
		t.Fatalf("validation %+v %v", d, err)
	}
}
func TestReview_FingerprintChangesWithSameFindingIDs(t *testing.T) {
	in := ReviewInput{CaseID: "c", Events: []model.Event{{ID: "e", CaseID: "c", EventType: "process_creation"}}, Findings: []model.Finding{{ID: "f", CaseID: "c", SupportingEvents: []string{"e"}}}, Correlations: []model.Correlation{{ID: "c1", CaseID: "c", Description: "original"}}, Sources: []model.SourceFile{{ID: "s", CaseID: "c", ParseCoverage: &model.ParseCoverage{RecordsRead: 1}}}}
	old := ReviewFingerprint(in)
	in.Events[0].ProcessName = "different.exe"
	if old == ReviewFingerprint(in) {
		t.Fatal("same finding IDs conceal changed event")
	}
	old = ReviewFingerprint(in)
	in.Correlations[0].Description = "changed"
	if old == ReviewFingerprint(in) {
		t.Fatal("changed correlation not stale")
	}
	old = ReviewFingerprint(in)
	in.Sources[0].ParseCoverage.Unmapped = 2
	if old == ReviewFingerprint(in) {
		t.Fatal("changed coverage not stale")
	}
}
func TestReview_UnknownAndTiedTimesRemainAcquisitionScoped(t *testing.T) {
	tied := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	in := ReviewInput{CaseID: "case", Events: []model.Event{{ID: "u1", CaseID: "case", CollectionID: "collection-alpha", EventType: "process_creation"}, {ID: "u2", CaseID: "case", CollectionID: "collection-beta", EventType: "process_creation"}, {ID: "t1", CaseID: "case", CollectionID: "collection-alpha", Timestamp: tied}, {ID: "t2", CaseID: "case", CollectionID: "collection-beta", Timestamp: tied}}}
	p, err := PrepareReview(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(p.User, "time_basis=unknown") != 2 || strings.Count(p.User, "time_basis=recorded_instant") != 2 || strings.Count(p.User, "acquisition=A1") != 2 || strings.Count(p.User, "acquisition=A2") != 2 {
		t.Fatal("time/acquisition identities not preserved", p.User)
	}
	if !strings.Contains(p.System, "Never infer temporal ordering for unknown or tied times") || !strings.Contains(p.System, "Unknown hosts in different acquisitions are not one machine") {
		t.Fatal("missing temporal/identity limits")
	}
}
func TestReview_OnlyAllowlistedValuesAndSupportedCitations(t *testing.T) {
	in := ReviewInput{CaseID: "c", Names: Names{Users: []string{"alice"}}, Events: []model.Event{{ID: "e", CaseID: "c", User: "alice", EventType: "process_creation", CommandLine: "SELECT secret FROM cookies", SourceReference: "PRIVATE SQL", Parser: "PRIVATE ERROR", RawEvidenceID: "PRIVATE RAW", Extra: map[string]string{"sql_statement": "PRIVATE SQL", "cookie": "PRIVATE COOKIE", "outcome": "success"}}}, Sources: []model.SourceFile{{ID: "s", CaseID: "c", Path: "/server/private/path", OriginalFilename: "PRIVATE FILE", Parser: "PRIVATE ERROR", ParseCoverage: &model.ParseCoverage{Notes: []string{"PRIVATE NOTE"}}}}}
	p, err := PrepareReview(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"PRIVATE", "alice", "SELECT", "/server/private", "cookies"} {
		if strings.Contains(p.User, bad) {
			t.Errorf("forbidden %s", bad)
		}
	}
	d, err := p.Validate("An observation is recorded. [E1]\nMissing. [E99]\nFake token [HOST_999]. [E1]\nFake number 999999. [E1]\nNo ref.")
	if err != nil || len(d.Sentences) != 1 || d.Rejected != 4 {
		t.Fatalf("validation %+v %v", d, err)
	}
	// Validation deliberately does not prove the semantics of an anchored claim.
	d, err = p.Validate("This record proves everything is safe. [E1]")
	if err != nil || len(d.Sentences) != 1 {
		t.Fatal("contract changed: validator is not a semantic truth oracle")
	}
}
func TestReview_RejectsSQLAndCookieBodiesInOtherwiseAllowedProse(t *testing.T) {
	for _, body := range []string{"Observed SELECT account FROM payroll", "Cookie: session=synthetic-cookie-value", "Set-Cookie: session=synthetic-cookie-value"} {
		in := ReviewInput{CaseID: "c", Findings: []model.Finding{{ID: "f", CaseID: "c", Description: body}}, Events: []model.Event{{ID: "e", CaseID: "c"}}}
		p, err := PrepareReview(in)
		if err == nil || p != nil {
			t.Fatalf("prohibited body accepted: %s", body)
		}
	}
}
func TestReview_ByteCapIncludesInstructions(t *testing.T) {
	text := strings.Repeat("bounded observation ", 40)
	in := ReviewInput{CaseID: "c"}
	for i := 0; i < 25; i++ {
		in.Findings = append(in.Findings, model.Finding{ID: fmt.Sprint(i), CaseID: "c", Title: text, Description: text, RuleID: text, Severity: "low"})
		in.Correlations = append(in.Correlations, model.Correlation{ID: fmt.Sprint(i), CaseID: "c", Title: text, Description: text, Type: text})
	}
	for i := 0; i < 120; i++ {
		in.Events = append(in.Events, model.Event{ID: fmt.Sprint(i), CaseID: "c", ProcessName: text, ParentProcessName: text, FilePath: text, RegistryPath: text, NetworkSource: text, NetworkDest: text, Extra: map[string]string{"logon_type": text, "outcome": text, "action": text}})
		// Exercise the measured boundary, not every smaller packet; under -race
		// repeated pseudonymization of all smaller prefixes is needlessly costly.
		if i < 83 {
			continue
		}
		p, err := PrepareReview(in)
		if err != nil {
			if err != ErrReviewTooLarge {
				t.Fatal(err)
			}
			t.Logf("byte cap first refusal at %d events", i+1)
			return
		}
		if len(p.User)+len(p.System) > ReviewMaxBytes {
			t.Fatalf("instructions outside byte cap: user=%d system=%d", len(p.User), len(p.System))
		}
	}
	t.Fatal("stress fixture never reached byte cap")
}
func TestReview_AllSelectionCapsHaveExplicitOmissions(t *testing.T) {
	in := ReviewInput{CaseID: "c", Events: []model.Event{{ID: "e", CaseID: "c"}}}
	for i := 0; i < 40; i++ {
		in.Findings = append(in.Findings, model.Finding{ID: fmt.Sprintf("f%03d", i), CaseID: "c"})
		in.Correlations = append(in.Correlations, model.Correlation{ID: fmt.Sprintf("c%03d", i), CaseID: "c"})
	}
	for i := 0; i < 70; i++ {
		in.Sources = append(in.Sources, model.SourceFile{ID: fmt.Sprintf("s%03d", i), CaseID: "c"})
	}
	p, err := PrepareReview(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"findings_included=25 findings_omitted=15", "correlations_included=25 correlations_omitted=15", "sources_included=60 sources_omitted=10"} {
		if !strings.Contains(p.User, want) {
			t.Fatalf("missing explicit cap/omission %s", want)
		}
	}
}
func TestReview_SnapshotTimeBasisIsNotAnExecutionTime(t *testing.T) {
	p, err := PrepareReview(ReviewInput{CaseID: "c", Events: []model.Event{{ID: "e", CaseID: "c", Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), Extra: map[string]string{"timestamp_basis": "memory_snapshot"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.User, "basis_detail=memory_snapshot") || !strings.Contains(p.System, "Snapshot times are not execution times") {
		t.Fatal("snapshot time represented as an event execution instant", p.User)
	}
}
func TestReview_RemovesPositionalCommandSecretsInGeneratedProse(t *testing.T) {
	const password = "SyntheticPositionalPassword"
	in := ReviewInput{CaseID: "c", Findings: []model.Finding{{ID: "f", CaseID: "c", Description: "Recorded command: net user alice " + password + " /add"}}, Events: []model.Event{{ID: "e", CaseID: "c", User: "alice"}}}
	p, err := PrepareReview(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.User, password) {
		t.Fatal("positional account password left in generated prose")
	}
}
